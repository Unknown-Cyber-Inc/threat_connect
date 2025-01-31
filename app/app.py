
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
TIMEOUT = 600

# Only change if you understand what the consequences are.
RETAIN_WRAPPER = True

def get_list(value, name):
    """Convert String or StringArray to List of Strings"""
    if isinstance(value, str):
        return [value]
    elif isinstance(value, list):
        return [str(item) for item in value]
    elif hasattr(value, "value"):
        if isinstance(value.value, list):
            return [str(item) for item in value.value]
        elif isinstance(value.value, str):
            return [value.value]
    return []


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
            self.upload_passwords = get_list(self.in_.file_password, "file_password")

        # Initialize outputs
        self.api_response_message = None # Variable to store the API response
        self.api_response_raw = None # Variable to store the API response
        self.match_list = None
        self.processed = True

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
                    response = requests.get(
                        url,
                        params=params,
                        headers=self.headers,
                        timeout=TIMEOUT
                    )
                elif method == "post":
                    response = requests.post(
                        url,
                        params=params,
                        headers=self.headers,
                        data=data,
                        files=files,
                        timeout=TIMEOUT
                    )

                response.raise_for_status()
                return response
            except Timeout:
                self.tcex.log.warning(
                    f"Timeout occurred on attempt {attempt + 1}/{MAX_RETRIES}. Retrying..."
                )
                attempt += 1
            except RequestException as e:
                if re.search(r"/ai/", url) and response is not None:
                    self.handle_error("Prompt is Empty. Check file type.")
                self.handle_error(f"Request failed: {e}")
                break
        return None


    def get_match_analysis_results(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching match analysis results.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        params = {
            "read_mask": "*",
            "no_links": True,
        }

        file_request = self.fetch_with_retry(
            f"https://api.magic.unknowncyber.com/v2/files/{hash_id}", method="get", params=params
        )

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

        file_request = self.fetch_with_retry(
            "https://api.magic.unknowncyber.com/v2/files/yara/",
            method="post",
            params=params,
            data=data
        )

        self.output_data = file_request


    def get_matched_malicious_hashes(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching Matched Malicious Hashes")
        default_sim = 1.0
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
                min_similarity = default_sim
        except (ValueError, TypeError):
            min_similarity = default_sim

        # Validate max_similarity
        try:
            max_similarity = float(self.in_.max_similarity)
            if not 0.7 <= max_similarity <= 1:
                max_similarity = default_sim
        except (ValueError, TypeError):
            max_similarity = default_sim

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

        file_request = self.fetch_with_retry(
            f"https://api.magic.unknowncyber.com/v2/files/{hash_id}/similarities/",
            method="get",
            params=params
        )

        resources = file_request.json().get("resources", [])

        # Compile a list of sha1 values
        self.match_list = ", ".join(
            [resource[self.in_.response_hash.lower()] for resource in resources]
        )

        if self.match_list == "":
            self.match_list = None

        # Error for no matches. Else response is "".
        if self.in_.no_match_error and not self.match_list:
            self.handle_error("No Matches for the given parameters.")
        self.output_data = file_request

    def get_processing_status(self):
        """Run the App main logic.

        Checks the status of a file
        """
        self.tcex.log.info("Checking file status.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = self.validate_input(hash_id)

        if not validate:
            self.handle_error(INVALID_HASH_MSG)

        params = {
            "no_links": True,
        }

        file_response = self.fetch_with_retry(
            f"https://api.magic.unknowncyber.com/v2/files/{hash_id}/status/",
            method="get",
            params=params
        )

        response_json = file_response.json()
        resource = response_json.get("resource", [])
        status = resource.get("status", "pending")
        if status in {"failure", "pending", "started"}:
            self.processed = False
        self.output_data = file_response

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
        if self.upload_passwords:
            password_params = "&".join(f"passwords={p}" for p in self.upload_passwords)
        else:
            password_params = ""

        # API Request Params
        post_params = {
            "no_links": True,
            "retain_wrapper": RETAIN_WRAPPER,
        }

        file_response = self.fetch_with_retry(
            f"https://api.magic.unknowncyber.com/v2/files/?{password_params}",
            method="post",
            files=upload_data,
            params=post_params,
            data=data
        )

        self.output_data = file_response


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

        file_request = self.fetch_with_retry(
            f"https://api.magic.unknowncyber.com/v2/ai/{hash_id}/",
            method="get",
            params=params
        )

        self.output_data = file_request

    def write_output(self):
        """Write the Playbook output variables.

        This method should be overridden with the output variables defined in the install.json
        configuration file.
        """
        output = self.output_data.json() if self.output_data is not None else {}
        self.log.info('Writing Output')
        self.out.variable("tc.action", self.action)
        self.out.variable("uc.response.status_code", output.get("status"))
        self.out.variable("uc.response.success", output.get("success"))
        self.out.variable("uc.response.errors", json.dumps(output.get("errors", {}), indent=2))

        def write_variables(variables_dict):
            for var_name, value in variables_dict.items():
                self.out.variable(var_name, value)

        match self.action:
            case "Get Match Analysis Results":
                resource = output.get("resource", {})
                exif = resource.get("exif", {})
                children = resource.get("children", [])
                unique_children = list(dict.fromkeys(children))
                variables = {
                    "uc.response.md5": resource.get("md5"),
                    "uc.response.sha1": resource.get("sha1"),
                    "uc.response.sha256": resource.get("sha256"),
                    "uc.response.sha512": resource.get("sha512"),
                    "uc.response.threat_level": resource.get("threat"),
                    "uc.response.evasiveness": resource.get("evasiveness"),
                    "uc.response.category": resource.get("category"),
                    "uc.response.family": resource.get("family"),
                    "uc.response.self_link": resource.get("_self"),
                    "uc.response.match_count": resource.get("match_count"),
                    "uc.get_match_analysis_results.object_class": resource.get("object_class"),
                    "uc.get_match_analysis_results.file_type": exif.get("FileType"),
                    "uc.get_match_analysis_results.file_type_extension": exif.get("FileTypeExtension"),
                    "uc.response.children": unique_children,
                    "uc.response.json": json.dumps(resource, indent=2),
                }
                write_variables(variables)
            case "Create Byte Code Yara":
                resource = output.get("resource", {})
                variables = {
                    "uc.create_yara.yara_rule": resource.get("rule"),
                    "uc.create_yara.yara_name": resource.get("name"),
                    "uc.response.json": json.dumps(resource, indent=2),
                }
                write_variables(variables)
            case "Get Matched Malicious Hashes":
                resource = output.get("resources", {})
                variables = {
                    "uc.response.match_list": self.match_list,
                    "uc.response.json": json.dumps(resource, indent=2)
                }
                write_variables(variables)
            case "Get Processing Status":
                resource = output.get("resource", {})
                variables = {
                    "uc.response.processing_completed": self.processed,
                    "uc.response.json": json.dumps(resource, indent=2)
                }
                write_variables(variables)
            case "Analyze Binary":
                resources = output.get("resources", [])
                resource = resources[0] if resources else {}
                variables = {
                    "uc.analyze_binary.md5": resource.get("md5"),
                    "uc.analyze_binary.sha1": resource.get("sha1"),
                    "uc.analyze_binary.sha256": resource.get("sha256"),
                    "uc.analyze_binary.sha512": resource.get("sha512"),
                    "uc.analyze_binary.filesize": resource.get("filesize"),
                    "uc.analyze_binary.json": json.dumps(resource, indent=2),
                }
                write_variables(variables)
            case _:
                resource = output.get("resource", {})
                variables = {
                    "uc.response.json": json.dumps(resource, indent=2),
                }
                write_variables(variables)
