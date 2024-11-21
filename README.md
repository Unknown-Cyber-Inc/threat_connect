![Unknown Cyber Logo](./unknowncyberlogo.png)

# Unknown Cyber - Threat Connect Integration

At UnknownCyber, our mission is to use AI and ML to combat the exponentially increasing threat from AI obfuscated malware. Deployed in government and enterprise, we use automation to assess thousands of alert backlogs in a day saving your SOC and threat investigators hundreds of hours of time. Our core technology is the result of over a decade of research funded by US Department of Defense and independently evaluated by MIT Lincoln Labs. Our global team is constantly building, iterating and innovating to empower organizations so they can clear EDR triggered alerts, save time and money in threat investigations and detect previously unknown and Zero Day malware.

<!-- ## Dashboard

TODO

 -->

## Playbooks

A ThreatConnect Playbook is a feature that automates cybersecurity workflows by linking various tasks and tools into a visual, logic-driven sequence. It enables users to streamline processes like threat detection, data enrichment, and incident response, all within the ThreatConnect platform.

### Examples

- [1 - Upload File to Unknown Cyber](./ExamplePlaybooks/External/1%20-%20Upload%20File%20to%20Unknown%20Cyber.pbxz)
- [2 - Check Processing Status](./ExamplePlaybooks/External/2%20-%20Check%20Processing%20Status.pbxz)
- [3 - Get Matches](./ExamplePlaybooks/External/3%20-%20Get%20Matches.pbxz)

### Videos

- [Overview](https://drive.google.com/file/d/1wd51GFKGZtmgr4PLGnbt8SkS56ifW_st/view?usp=sharing) - Shows an overview of the three example playbooks in action.

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
| uc.response.status_code | *String* | The api request’s status code.  | |
| uc.response.success | *String* | True if the api request was successful and false if not. | |
| uc.response.errors | *String* | The api request’s error message if the request errored. | |
| uc.response.json | *String* | The raw JSON response from Unknown Cyber's api. | |

---

### Get Match Analysis Results

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

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |
| Min Similarity* | *String,$Text* | 1 | Minimum similarity threshold between 0.7 and 1. |
| Max Similarity* | *String,$Text* | 1 | Maximum similarity threshold between 0.7 and 1. |
| Response Hash | *Dropdown* | Sha1 | This allows other hashes besides the default to be returned. |
| No Match Error | *Boolean* | False | Setting this to True will cause the app to throw an error is their are no matches. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |
| uc.response.match_list | *StringArray* | A list of matches between the Max Similarity and Min Similarity. If no matches are found the value will be `None`.| |

---

### Analyze Binary

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

#### Inputs

| Variable | Type | Default | Description |
| ----- | ---- | ---- | ----------- |
| Hash ID* | *String,$Text* | | The hash of a file to receive details on. Must be a MD5, SHA1, SHA256, or SHA512. |

#### Outputs

| Variable | Type | Description | Examples |
| -------- | ---- | ----------- | -------- |

## Docs and Help

- [App Builder](https://knowledge.threatconnect.com/docs/app-builder-overview)
- [TcEx Repo](https://github.com/ThreatConnect-Inc/tcex)
- [Threat Connect Example Repos](https://github.com/ThreatConnect-Inc/threatconnect-playbooks)

Modified: 11/20/24
