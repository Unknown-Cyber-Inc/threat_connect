
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
        
        # Initialize inputs
        self.api_key = self.in_.api_key # Store Api Key

        # Initialize outputs
        self.api_response_message = None # Variable to store the API response
        self.api_response_raw = None # Variable to store the API response
        self.error_message = None # Variable to store the API error_message

    def run(self):
        """Run the App main logic.

        This method should contain the core logic of the App.
        """
        self.tcex.log.info("Starting the App.")

        # Trim leading and trailing whitespace and initialize hash_id var
        hash_id = self.in_.hash_id.strip()

        self.tcex.log.debug(f"Hash is '{hash_id}'")

        validate = validate_input(self, hash_id)
        
        self.tcex.log.debug(f"The input validation is: '{validate}'")
        
        if not validate:
            self.response = None
            self.error_message = "Invalid hash format."
            # self.write_output()
            # self.tcex.exit.exit(code=1, msg="Error validating Hash")
        
        file_request = requests.get(f"https://api.magic.unknowncyber.com/v2/files/{hash_id}", params={"apikey": self.api_key, "read_mask": "*", "no_links": True})

        self.api_response_raw = json.dumps(file_request.json(), indent=4)


    def write_output(self):
        """Write the Playbook output variables.

        This method should be overridden with the output variables defined in the install.json
        configuration file.
        """
        self.log.info('Writing Output')
        self.out.variable("uc.response.response", self.api_response_message)
        self.out.variable("uc.response.raw", self.api_response_raw)
        self.out.variable("uc.response.error_message", self.error_message)