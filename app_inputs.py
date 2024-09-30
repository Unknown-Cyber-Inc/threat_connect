"""App Inputs"""
# pyright: reportGeneralTypeIssues=false

# standard library
from typing import Annotated, Union

# third-party
from pydantic import BaseModel
from tcex.input.field_type import Choice, String, Sensitive, Binary, Boolean
from tcex.input.input import Input
from tcex.input.model.app_playbook_model import AppPlaybookModel


class AppBaseModel(AppPlaybookModel):
    """Base model for the App containing any common inputs."""

    # pbd: String, vv: ${KEYCHAIN}
    api_key: Union[String, Sensitive]
    # vv: Get File Data|Get Yara Data|Get Similarities Data
    tc_action: Annotated[str, Choice]

class AnalyzeBinary(AppBaseModel):
    """Action Model"""
    # pbd: String, vv: ${TEXT}
    filename: String
    # pbd: Binary, vv: ${BINARY}
    file_sample: Binary
    # pbd: String, vv: ${TEXT}
    file_password: String | None
    # pbd: Boolean
    discard_unwrapped_archive: Boolean

class GetFileDataModel(AppBaseModel):
    """Action Model"""
    
    # pbd: String, vv: ${TEXT}
    hash_id: String


class GetYaraDataModel(AppBaseModel):
    """Action Model"""
    
    # pbd: String, vv: ${TEXT}
    hash_id: String

class GetSimilaritiesModel(AppBaseModel):
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
            "get_file_data": GetFileDataModel,
            "get_yara_data": GetYaraDataModel,
            "get_similarities_data": GetSimilaritiesModel,
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
