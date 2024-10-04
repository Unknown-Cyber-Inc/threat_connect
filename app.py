
"""ThreatConnect Playbook App"""
# standard library
import json
import requests
import re

# third-party
from tcex import TcEx

# first-party
from playbook_app import PlaybookApp  # Import default Playbook App Class (Required)

invalid_hash_msg = "Invalid hash format. Must be md5, sha1, sha256, sha512."

def validate_input(self, hash_id):
    """Validate input"""

    # Validate length of hash
    valid_length = len(hash_id) in (32, 40, 64, 128)
    self.tcex.log.debug(f"Valid Length: '{valid_length}'")
    
    # Validate characters of hash
    valid_char = bool(re.fullmatch("[0-9a-fA-F]+", hash_id))
    self.tcex.log.debug(f"Valid Char: '{valid_char}'")
    
    return valid_length and valid_char


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
        self.error_message = None # Variable to store the API error_message

        # Initialize other
        self.output_data = None # Store Temporary output data

    def handle_error(self, message=None, code=None):
        """Error Handling function"""

        if not message:
            message = "An error occured in the app"
        
        self.tcex.log.error(message)

        if isinstance(code, int):
            self.tcex.exit.exit(code, msg=message)
        else:
            self.tcex.exit.exit(1, msg=message)

    def get_match_analysis_results(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Starting the App.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = validate_input(self, hash_id)
        
        if not validate:
            self.handle_error(invalid_hash_msg)
        
        params = {
            "read_mask": "*",
            "no_links": True,
        }

        file_request = requests.get(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}", params=params, headers=self.headers)

        self.output_data = file_request

    def create_byte_code_yara(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Creating Yara Rule")
        
        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = validate_input(self, hash_id)
        
        if not validate:
            self.handle_error(invalid_hash_msg)
        
        data = {
            "files": [hash_id],
        }

        
        params = {
            "no_links": True,
        }
        
        file_request = requests.post(f"https://api.magic.unknowncyber.com/v2/files/yara/", params=params, data=data)

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
        validate = validate_input(self, hash_id)
        
        if not validate:
            self.handle_error(invalid_hash_msg)
        
        # Validate min_similarity
        try:
            min_similarity = float(self.in_.min_similarity)
            if not 0 <= min_similarity <= 1:
                min_similarity = DEFAULT_SIM
        except (ValueError, TypeError):
            min_similarity = DEFAULT_SIM

        # Validate max_similarity
        try:
            max_similarity = float(self.in_.max_similarity)
            if not 0 <= max_similarity <= 1:
                max_similarity = DEFAULT_SIM
        except (ValueError, TypeError):
            max_similarity = DEFAULT_SIM

        # Ensure min_similarity is less than max_similarity
        if min_similarity >= max_similarity:
            min_similarity = max_similarity

        params={
            "read_mask": "*",
            "no_links": True,
            "max_threshold": max_similarity,
            "min_threshold": min_similarity
            }
        
        file_request = requests.get(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}/similarities/", params=params, headers=self.headers)

        
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
        params = {
            "no_links": True,
            "retain_wrapper": self.discard_unwrapped_archive,
        }

        file_request = requests.post("https://api.magic.unknowncyber.com/v2/files/", files=upload_data, params=params, headers=self.headers, data=data)

        self.output_data = file_request


    def get_bo_llm_behavior_report(self):
         """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching data from Bo.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        # Validate Hash
        validate = validate_input(self, hash_id)
        
        if not validate:
            self.handle_error(invalid_hash_msg)

        # API Request Params
        params = {
            "no_links": True,
            "binary_id": hash_id,
        }

        file_request = requests.get("https://api.magic.unknowncyber.com/v2/ai/", params=params, headers=self.headers)

        self.output_data = file_request

    def write_output(self):
        """Write the Playbook output variables.

        This method should be overridden with the output variables defined in the install.json
        configuration file.
        """
        if not self.output_data == None:
            output = self.output_data.json()
            self.log.debug(f'Raw JSON output: {json.dumps(output, indent=2)}')
        else:
            output = {}
        self.log.info('Writing Output')
        self.out.variable("tc.action", self.action)
        self.out.variable("uc.response.status_code", output.get("status"))
        self.out.variable("uc.response.success", output.get("success"))
        self.out.variable("uc.response.raw", json.dumps(output, indent=2))
        self.out.variable("uc.error_message", self.error_message)
        self.out.variable("uc.response.errors", json.dumps(output.get("errors", {}), indent=2))
        if self.action == "Get Match Analysis Results":
            self.out.variable("uc.response.md5", output.get("resource", {}).get("md5"))
            self.out.variable("uc.response.sha1", output.get("resource", {}).get("sha1"))
            self.out.variable("uc.response.sha256", output.get("resource", {}).get("sha256"))
            self.out.variable("uc.response.sha512", output.get("resource", {}).get("sha512"))
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Create Byte Code Yara":
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Get Matched Malicious Hashes":
            self.out.variable("uc.response.response", json.dumps(output.get("resources", {}), indent=2))
        elif self.action == "Analyze Binary":
            self.out.variable("uc.response.md5", output.get("resources", {})[0].get("md5"))
            self.out.variable("uc.response.sha1", output.get("resources", {})[0].get("sha1"))
            self.out.variable("uc.response.sha256", output.get("resources", {})[0].get("sha256"))
            self.out.variable("uc.response.sha512", output.get("resources", {})[0].get("sha512"))
            self.out.variable("uc.response.response", json.dumps(output.get("resources", {}), indent=2))
        else:
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))