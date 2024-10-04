"""App Inputs"""
# pyright: reportGeneralTypeIssues=false

# standard library
from typing import Annotated, Union

# third-party
from pydantic import BaseModel
from tcex.input.field_type import Choice, String, Sensitive, Binary
from tcex.input.input import Input
from tcex.input.model.app_playbook_model import AppPlaybookModel


class AppBaseModel(AppPlaybookModel):
    """Base model for the App containing any common inputs."""

    # pbd: String, vv: ${KEYCHAIN}
    api_key: Union[String, Sensitive]
    # vv: Get Match Analysis Results|Create Byte Code Yara|Get Matched Malicious Hashes|Analyze Binary
    tc_action: Annotated[str, Choice]

class AnalyzeBinary(AppBaseModel):
    """Action Model"""
    # pbd: String, vv: ${TEXT}
    filename: String
    # pbd: Binary, vv: ${BINARY}
    file_sample: Binary
    # pbd: String, vv: ${TEXT}
    file_password: String | None
    discard_unwrapped_archive: bool = False

class GetMatchAnalysisResults(AppBaseModel):
    """Action Model"""
    
    # pbd: String, vv: ${TEXT}
    hash_id: String


class CreateByteCodeYara(AppBaseModel):
    """Action Model"""
    
    # pbd: String, vv: ${TEXT}
    hash_id: String

class GetMatchedMaliciousHashes(AppBaseModel):
    """Action Model"""
    
    # pbd: String, vv: ${TEXT}
    hash_id: String
    # pbd: String
    max_similarity: String
    # pbd: String
    min_similarity: String

class GetBoLLMBehaviorReport:
    """Action Model"""

    # pbd: String, vv: ${TEXT}
    hash_id: String

class AppInputs:
    """App Inputs"""

    def __init__(self, inputs: Input):
        """Initialize instance properties."""
        self.inputs = inputs

    def action_model_map(self, tc_action: str) -> type[BaseModel]:
        """Return action model map."""
        _action_model_map = {
            "analyze_binary": AnalyzeBinary,
            "get_match_analysis_results": GetMatchAnalysisResults,
            "create_byte_code_yara": CreateByteCodeYara,
            "get_matched_malicious_hashes": GetMatchedMaliciousHashes,
            "get_bo_llm_behavior_report": GetBoLLMBehaviorReport,
        }
        tc_action_key = tc_action.lower().replace(' ', '_')
        return _action_model_map.get(tc_action_key)

    def get_model(self, tc_action: str | None = None) -> type[BaseModel]:
        """Return the model based on the current action."""
        tc_action = tc_action or self.inputs.model_unresolved.tc_action  # type: ignore
        if tc_action is None:
            raise RuntimeError('No action (tc_action) found in inputs.')

        action_model = self.action_model_map(tc_action.lower())
        if action_model is None:
            # pylint: disable=broad-exception-raised
            raise RuntimeError(
                'No model found for action: '
                f'{self.inputs.model_unresolved.tc_action}'  # type: ignore
            )

        return action_model

    def update_inputs(self):
        """Add custom App model to inputs.

        Input will be validate when the model is added an any exceptions will
        cause the App to exit with a status code of 1.
        """
        self.inputs.add_model(self.get_model())
