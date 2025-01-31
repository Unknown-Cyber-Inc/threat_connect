# Unknown Cyber

## Release Notes

### 1.0.0
* Initial Release

## Description

At UnknownCyber, our mission is to use AI and ML to combat the exponentially increasing threat from AI obfuscated malware. Deployed in government and enterprise, we use automation to assess thousands of alert backlogs in a day saving your SOC and threat investigators hundreds of hours of time. Our core technology is the result of over a decade of research funded by US Department of Defense and independently evaluated by MIT Lincoln Labs. Our global team is constantly building, iterating and innovating to empower organizations so they can clear EDR triggered alerts, save time and money in threat investigations and detect previously unknown and Zero Day malware.

## Examples

See ThreatConnect's Github for examples.

## Videos

0. [TC Unknown Cyber Overview](https://drive.google.com/file/d/1zVaUd7KocbCppnuZ1gcAPZs-e4yrXRJS/view?usp=drive_link) - Shows an overview of the three example playbooks in action.
1. [Adding Unknown Cyber API Key to TC](https://drive.google.com/file/d/1YaMNAGW4Tj79kA0yBTo_hn6IoqJWcHyi/view?usp=drive_link) - Explanation of how to add an Unknown Cyber API Key to Threat Connect's Keychain Variables.
2. [Adding Unknown Cyber Example Playbooks to TC](https://drive.google.com/file/d/1IQjn8qD0-uUGdFvgDvBWewv4YTaUNe-H/view?usp=drive_link) - Adding Unknown Cyber's example playbooks to Threat Connect.
3. [Upload File to Unknown Cyber Playbook Example](https://drive.google.com/file/d/1fEnvjZZ_dRwyTnHbriyGVuoCpdhFyO3K/view?usp=drive_link) - An overview of how the "1. Upload File to Unknown Cyber" playbook works.
4. [Check Processing Status Playbook Example](https://drive.google.com/file/d/1qjkfKBico03kbZ1-g-hAAbexO28dgNdM/view?usp=drive_link) - An overview of how the "2. Check Processing Status" playbook works.
5. [Get Matches Playbook Example](https://drive.google.com/file/d/1aniMp5Wy_0XBWFn89whT6wGoYvKorvto/view?usp=drive_link) - An overview of how the "3. Get Matches" playbook works.

## App

Unknown Cyber's app is called "Unknown Cyber". In a Threat Connect Playbook, you can use as may instances of the UnknownCyber app as you like. Each of the instances are called `Jobs`. A Job houses different operations based on the selected action. Below are the available actions and the standard parameters used for the Unknown Cyber app.

#### General Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Job Name* | *String* | | This is the name given to this particular instance of a Job. |
| API Key* | *String,$Keychain* | | A user's Unknown Cyber API Key. |
| TC Action* | *Dropdown* | Get Match Analysis Results | This is the action to be performed. |

#### General Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| tc.action | *String* | The type of action chosen for this job | |
| uc.response.status_code | *String* | The api requestâs status code.  | |
| uc.response.success | *String* | True if the api request was successful and false if not. | |
| uc.response.errors | *String* | The api requestâs error message if the request errored. | |
| uc.response.json | *String* | The raw JSON response from Unknown Cyber's api. | |

---

### Get Match Analysis Results

Retrieve Unknown Cyber's analysis for a specified file hash. For a more granular look at a hashes data, use the `uc.response.json`.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512 |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.response.md5 | *String* | The md5 of the requested hash | |
| uc.response.sha1 | *String* | The sha1 of the requested hash.  | |
| uc.response.sha256 | *String* | The sha256 of the requested hash | |
| uc.response.sha512 | *String* | The sha512 of the requested hash | |
| uc.response.threat_level | *String* | The threat level of the hash. | *New, Caution, High, Medium, Low* |
| uc.response.evasiveness | *String* | A value from 0 to 1.0 indicating how many scanners have seen the file | |
| uc.response.category | *String* | Returns the top category for the file | |
| uc.response.family | *String* | Returns the top family for the file | |
| uc.response.self_link | *String* | The link to the resource using Unknown Cyber's api | |
| uc.response.match_count | *String* | The number of matches for the requested hash | |
| uc.response.children | *StringArray* | A list of children (If any)| An archives contents |

---

### Get Processing Status

Retrieves the processing status for a hash. Once the file is done processing, it will set the `uc.response.processing_completed` to True. For a more granular look at the current file status, use the `uc.response.json`.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.response.processing_completed | *string* | Has the processing of the file through Unknown Cyber's system finished | *True, False* |

---

### Create Byte Code Yara

Automatically generates a Yara rule for the specified hash.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.create_yara.yara_rule | *string* | The automatically created yara rule for the hash | |
| uc.create_yara.yara_name | *string* | The name for the automatically created yara rule | |

---

### Get Matched Malicious Hashes

Gets a list of hashes that match the entered hash. By default, only perfect matches, 1.0, are retrieved. This can be adjusted using the Max and Min Similarity options.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |
| Min Similarity* | *String,$Text* | 1 | Minimum similarity threshold between 0.7 and 1. |
| Max Similarity* | *String,$Text* | 1 | Maximum similarity threshold between 0.7 and 1. |
| Response Hash | *Dropdown* | Sha1 | This allows other hashes besides the default to be returned. |
| No Match Error | *Boolean* | False | Setting this to True will cause the app to throw an error if there are no matches. |

> [!NOTE]
> If you enter a minimum similarity score higher than the maximum similarity score, the scores will be set to equal the Max Similarity entered.

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.response.match_list | *StringArray* | A list of matches between the Max Similarity and Min Similarity. If no matches are found the value will be `None`.| |

---

### Analyze Binary

Upload a binary sample to Unknown Cyber for analysis.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| File Sample* | *Binary,$File* | | Binary content to upload. |
| Filename | *String,$Text* | | Name for the uploaded file. |
| File Password | *String,$Text* | | Password used for file extraction from archive. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.response.md5 | *String* | The md5 of the requested hash | |
| uc.response.sha1 | *String* | The sha1 of the requested hash.  | |
| uc.response.sha256 | *String* | The sha256 of the requested hash | |
| uc.response.sha512 | *String* | The sha512 of the requested hash | |

---

### Get Bo LLM Behavior Report

Ask's Unknown Cyber's AI assistant for a human readable version of the byte code and gives its analysis on the code.

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |

> [!NOTE]
> Their are no custom output variables for Get Bo LLM Behavior Report. Use the `uc.response.json`.
