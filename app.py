
"""ThreatConnect Playbook App"""
# standard library
import json
import re
import requests
from requests.exceptions import Timeout, RequestException

# third-party
from tcex import TcEx

# first-party
from playbook_app import PlaybookApp  # Import default Playbook App Class (Required)

INVALID_HASH_MSG = "Invalid hash format. Must be md5, sha1, sha256, sha512."
MAX_RETRIES = 3


class App(PlaybookApp):
    """Playbook App"""

    def __init__(self, _tcex: TcEx):
        """Initialize class properties.

        This method can be OPTIONALLY overridden.
        """
        super().__init__(_tcex)

        # What action is being performed [Needs to be at top of init()]
        self.action = self.in_.tc_action

        self.headers = {}
        # Initialize inputs
        if isinstance(self.in_.api_key, str):
            self.headers["x-api-key"] = self.in_.api_key # Store Api Key from string.
        else:
            self.headers["x-api-key"] = self.in_.api_key.value # Store Api Key from Key vault

        # ACTION: Analyze Binary
        if self.action == "Analyze Binary":
            self.upload_password = self.in_.file_password
            self.discard_unwrapped_archive = self.in_.discard_unwrapped_archive

        # Initialize outputs
        self.api_response_message = None # Variable to store the API response
        self.api_response_raw = None # Variable to store the API response
        self.match_list = None

        # Initialize other
        self.output_data = None # Store Temporary output data


    def handle_error(self, message=None, code=None):
        """Error Handling function"""

        if not message:
            message = "An error occurred in the app"

        self.tcex.log.error(message)

        if isinstance(code, int):
            self.tcex.exit.exit(code, msg=message)
        else:
            self.tcex.exit.exit(1, msg=message)


    def validate_input(self, hash_id):
        """Validate input"""

        # Validate length of hash
        valid_length = len(hash_id) in (32, 40, 64, 128)

        # Validate characters of hash
        valid_char = bool(re.fullmatch("[0-9a-fA-F]+", hash_id))

        return valid_length and valid_char


    def fetch_with_retry(self, url, method="get", params=None, data=None, files=None):
        """Fetch data with retries for timeouts."""
        attempt = 0
        while attempt < MAX_RETRIES:
            try:
                response = None
                if method == "get":
                    response = requests.get(url, params=params, headers=self.headers)
                elif method == "post":
                    response = requests.post(url, params=params, headers=self.headers, data=data, files=files)

                response.raise_for_status()
                return response
            except Timeout:
                self.tcex.log.warning(f"Timeout occurred on attempt {attempt + 1}/{MAX_RETRIES}. Retrying...")
                attempt += 1
            except RequestException as e:
                self.handle_error(f"Request failed: {e}")
                break
        return None


    def get_match_analysis_results(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Starting the App.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        params = {
            "read_mask": "*",
            "no_links": True,
        }

        file_request = self.fetch_with_retry(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}", method="get", params=params)

        self.output_data = file_request


    def create_byte_code_yara(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Creating Yara Rule")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        data = {
            "files": [hash_id],
        }


        params = {
            "no_links": True,
        }

        file_request = self.fetch_with_retry("https://api.magic.unknowncyber.com/v2/files/yara/",method="post", params=params, data=data)

        self.output_data = file_request


    def get_matched_malicious_hashes(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching Matched Malicious Hashes")
        DEFAULT_SIM = 1.0
        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        # Validate Hash
        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        # Validate min_similarity
        try:
            min_similarity = float(self.in_.min_similarity)
            if not 0.7 <= min_similarity <= 1:
                min_similarity = DEFAULT_SIM
        except (ValueError, TypeError):
            min_similarity = DEFAULT_SIM

        # Validate max_similarity
        try:
            max_similarity = float(self.in_.max_similarity)
            if not 0.7 <= max_similarity <= 1:
                max_similarity = DEFAULT_SIM
        except (ValueError, TypeError):
            max_similarity = DEFAULT_SIM

        # Ensure min_similarity is less than max_similarity
        if min_similarity >= max_similarity:
            min_similarity = max_similarity

        response_hash = self.in_.response_hash.lower()
        if response_hash == "sha1":
            response_hash = ""

        params={
            "read_mask": response_hash,
            "no_links": True,
            "max_threshold": max_similarity,
            "min_threshold": min_similarity,
            "page_size": 500,
            }

        file_request = self.fetch_with_retry(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}/similarities/", method="get", params=params)

        resources = file_request.json().get("resources", [])

        # Compile a list of sha1 values
        self.match_list = ", ".join([resource[self.in_.response_hash.lower()] for resource in resources])

        # Error for no matches. Else response is "".
        if self.in_.no_match_error and self.match_list == "":
            self.handle_error("No Matches for the given parameters.")
        self.output_data = file_request

    def analyze_binary(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Analyzing Binary.")

        # API files to be processed
        upload_data = {}
        if self.in_.filename and self.in_.file_sample:
            file_data_tuple = (self.in_.filename, self.in_.file_sample, 'application/octet-stream')
            upload_data["filedata"] = file_data_tuple

        # API Body Params
        data = {}
        if self.upload_password:
            data["password"] = self.upload_password

        # API Request Params
        post_params = {
            "no_links": True,
            "retain_wrapper": self.discard_unwrapped_archive,
        }

        file_response = self.fetch_with_retry("https://api.magic.unknowncyber.com/v2/files/",method="post", files=upload_data, params=post_params, data=data)

        try:
            response_json = file_response.json()
            resources = response_json.get("resources", [])
            sha256 = resources[0].get("sha256")
        except (IndexError, ValueError, KeyError) as e:
            self.handle_error(f"Error getting sha256 from upload: {e}. Response content: {file_response.text}")

        get_params = {
            "read_mask": "*",
            "no_links": True,
        }

        file_request = self.fetch_with_retry(f"https://api.magic.unknowncyber.com/v2/files/{sha256}",method="post", params=get_params)

        self.output_data = file_request


    def get_bo_llm_behavior_report(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching data from Bo.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        # Validate Hash
        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        # API Request Params
        params = {
            "no_links": True,
        }

        file_request = self.fetch_with_retry(f"https://api.magic.unknowncyber.com/v2/ai/{hash_id}", params=params)

        self.output_data = file_request

    def write_output(self):
        """Write the Playbook output variables.

        This method should be overridden with the output variables defined in the install.json
        configuration file.
        """
        if not self.output_data is None:
            output = self.output_data.json()
        else:
            output = {}
        self.log.info('Writing Output')
        self.out.variable("tc.action", self.action)
        self.out.variable("uc.response.status_code", output.get("status"))
        self.out.variable("uc.response.success", output.get("success"))
        self.out.variable("uc.response.errors", json.dumps(output.get("errors", {}), indent=2))
        if self.action == "Get Match Analysis Results":
            self.out.variable("uc.response.md5", output.get("resource", {}).get("md5"))
            self.out.variable("uc.response.sha1", output.get("resource", {}).get("sha1"))
            self.out.variable("uc.response.sha256", output.get("resource", {}).get("sha256"))
            self.out.variable("uc.response.sha512", output.get("resource", {}).get("sha512"))
            self.out.variable("uc.response.matches", output.get("resource", {}).get("match_count"))
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Create Byte Code Yara":
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Get Matched Malicious Hashes":
            self.out.variable("uc.response.match_list", self.match_list)
            self.out.variable("uc.response.response", json.dumps(output.get("resources", {}), indent=2))
        elif self.action == "Analyze Binary":
            resource = output.get("resource", {})
            children = resource.get("children", [])
            unique_children = list(dict.fromkeys(children))
            self.out.variable("uc.response.md5", resource.get("md5"))
            self.out.variable("uc.response.sha1", resource.get("sha1"))
            self.out.variable("uc.response.sha256", resource.get("sha256"))
            self.out.variable("uc.response.sha512", resource.get("sha512"))
            self.out.variable("uc.response.children", unique_children)
            self.out.variable("uc.response.children_count", len(unique_children))
            self.out.variable("uc.response.response", json.dumps(resource, indent=2))
        else:
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
