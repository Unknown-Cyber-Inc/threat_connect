
"""ThreatConnect Playbook App"""
# standard library
import json
import requests
import re

# third-party
from tcex import TcEx

# first-party
from playbook_app import PlaybookApp  # Import default Playbook App Class (Required)

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
        
        # ACTION: 
        # if self.action == "Analyze Binary":
        #     self.upload_password = self.in_.file_password

        # ACTION: 
        # if self.action == "Analyze Binary":
        #     self.upload_password = self.in_.file_password

        # ACTION: 
        # if self.action == "Analyze Binary":
        #     self.upload_password = self.in_.file_password

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

    def get_file_data(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Starting the App.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = validate_input(self, hash_id)
        
        if not validate:
            self.response = None
            self.error_message = "Invalid hash format."
            self.tcex.exit.exit(1, "Invalid Hash Format")
        
        params = {
            "read_mask": "*",
            "no_links": True,
        }

        file_request = requests.get(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}", params=params, headers=self.headers)

        self.output_data = file_request

    def get_yara_data(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Creating Yara Rule")
        
        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = validate_input(self, hash_id)
        
        if not validate:
            self.response = None
            self.error_message = "Invalid hash format."
            # self.write_output()
            # self.tcex.exit.exit(code=1, msg="Error validating Hash")
        
        data = {
            "files": [hash_id],
        }

        
        params = {
            "no_links": True,
        }
        
        file_request = requests.post(f"https://api.magic.unknowncyber.com/v2/files/yara/", params=params, data=data)

        self.output_data = file_request

    def get_similarities_data(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Fetching similarities")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip().lower()

        validate = validate_input(self, hash_id)
        
        if not validate:
            self.response = None
            self.error_message = "Invalid hash format."
            # self.write_output()
            # self.tcex.exit.exit(code=1, msg="Error validating Hash")
            self.tcex.exit.exit(1, "Invalid Hash Format")

        params={
            "read_mask": "*",
            "no_links": True
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
            # "ioc": False,
            # "reprocess": False,
            # "extract": True,
            # "recursive": True,
        }

        file_request = requests.post("https://api.magic.unknowncyber.com/v2/files/", files=upload_data, params=params, headers=self.headers, data=data)

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
        if self.action == "Get File Data":
            self.out.variable("uc.response.md5", output.get("resource", {}).get("md5"))
            self.out.variable("uc.response.sha1", output.get("resource", {}).get("sha1"))
            self.out.variable("uc.response.sha256", output.get("resource", {}).get("sha256"))
            self.out.variable("uc.response.sha512", output.get("resource", {}).get("sha512"))
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Get Yara Data":
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))
        elif self.action == "Get Similarities Data":
            self.out.variable("uc.response.response", json.dumps(output.get("resources", {}), indent=2))
        elif self.action == "Analyse Binary":
            self.out.variable("uc.response.md5", output.get("resource", {}).get("md5"))
            self.out.variable("uc.response.sha1", output.get("resource", {}).get("sha1"))
            self.out.variable("uc.response.sha256", output.get("resource", {}).get("sha256"))
            self.out.variable("uc.response.sha512", output.get("resource", {}).get("sha512"))
            self.out.variable("uc.response.response", json.dumps(output.get("resources", {}), indent=2))
        else:
            self.out.variable("uc.response.response", json.dumps(output.get("resource", {}), indent=2))