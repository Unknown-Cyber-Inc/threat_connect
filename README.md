![Unknown Cyber Logo](./unknowncyberlogo.png)

# Unknown Cyber - Threat Connect Integration

At UnknownCyber, our mission is to use AI and ML to combat the exponentially increasing threat from AI obfuscated malware. Deployed in government and enterprise, we use automation to assess thousands of alert backlogs in a day saving your SOC and threat investigators hundreds of hours of time. Our core technology is the result of over a decade of research funded by US Department of Defense and independently evaluated by MIT Lincoln Labs. Our global team is constantly building, iterating and innovating to empower organizations so they can clear EDR triggered alerts, save time and money in threat investigations and detect previously unknown and Zero Day malware.

<!-- ## Dashboard

TODO

 -->

## Playbooks

A ThreatConnect Playbook is a feature that automates cybersecurity workflows by linking various tasks and tools into a visual, logic-driven sequence. It enables users to streamline processes like threat detection, data enrichment, and incident response, all within the ThreatConnect platform.

### Examples

- [1 - Upload File to Unknown Cyber](./ExamplePlaybooks/External/1%20-%20Upload%20File%20to%20Unknown%20Cyber.pbxz) - This is example playbook 1 of 3 for processing a file through Unknown Cyber. This playbook demonstrates how to use the "Analyze Binary" action in the Unknown Cyber App. When a document is uploaded to TC, it takes the document and it's archive password, if included, and sends it to Unknown Cyber for Analysis. It then creates a file indicator in TC and appends a "uc-processing" tag to the indicator to let stage 2 know the file being processed.

- [2 - Check Processing Status](./ExamplePlaybooks/External/2%20-%20Check%20Processing%20Status.pbxz) - This is example playbook 2 of 3 for processing a file through Unknown Cyber. This playbook is designed to run every 5 minutes and checks the status of all files and documents in TC tagged with "uc-processing." If the file or document has successfully been processed by Unknown Cyber with a response of "success", then the "uc-processing" tag will be removed and a "uc-processed" tag will be added to it. In the event of an error in the Unknown Cyber app, the file will be skipped, and try again in 5 minutes.

- [3 - Get Matches](./ExamplePlaybooks/External/3%20-%20Get%20Matches.pbxz) - This is example playbook 3 of 3 for processing a file through Unknown Cyber. This playbook triggers when a file is first tagged with "uc-processed" and proceeds to get similar matches for the file and checks for children of the file, which will be added to TC's file indicators and given a tag of "uc-processing" to repeat stage 2 and 3 with.

> Note: Not all files will have matches and some files that have matches will not be 1.0 matches. The similarity score can be adjusted between 0.7 and 1.0 when using the "Get Matches Malicious Hashes" action in the Unknown Cyber App. The default is to only show 1.0 matches.

### Videos

0. [TC Unknown Cyber Overview](https://drive.google.com/file/d/1wd51GFKGZtmgr4PLGnbt8SkS56ifW_st/view?usp=sharing) - Shows an overview of the three example playbooks in action.
1. [Adding Unknown Cyber API Key to TC](https://drive.google.com/file/d/1GW4sRRiErd3xa3fJvOrwMfrh5eVnrjAJ/view?usp=sharing) - Explanation of how to add an Unknown Cyber API Key to Threat Connect's Keychain Variables.
2. [Adding Unknown Cyber Example Playbooks to TC](https://drive.google.com/file/d/16RtRhplNEapFxRhrHSVsFgicfFsyAxwh/view?usp=sharing) - Adding Unknown Cyber's example playbooks to Threat Connect.
3. [Upload File to Unknown Cyber Playbook Example](https://drive.google.com/file/d/1DX17AMmEDz9XChVWKf-zK0B_E5FRw9S4/view?usp=sharing) - An overview of how the "1. Upload File to Unknown Cyber" playbook works.
4. [Check Processing Status Playbook Example](https://drive.google.com/file/d/1FfgjxUzRE0MI6zV8-vYDdIUJ-wB7P8cV/view?usp=sharing) - An overview of how the "2. Check Processing Status" playbook works.
5. [Get Matches Playbook Example](https://drive.google.com/file/d/1TiACFtKTYzHj2_vJo8SWso28zAu_ogB3/view?usp=sharing) - An overview of how the "3. Get Matches" playbook works.

## App

Unknown Cyber's app is called "Unknown Cyber". In a Threat Connect Playbook, you can use as may instances of the UnknownCyber app as you like. Each of the instances are called `Jobs`. A Job houses different operations based on the selected action. Below are the available actions and the standard parameters used for the Unknown Cyber app.

<!-- markdownlint-disable MD001 -->
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
| No Match Error | *Boolean* | False | Setting this to True will cause the app to throw an error is their are no matches. |

> Note: If you enter a minimum similarity score higher than the maximum similarity score, the scores will be set to equal the Max Similarity entered.

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

## Docs and Help

- [App Builder](https://knowledge.threatconnect.com/docs/app-builder-overview)
- [TcEx Repo](https://github.com/ThreatConnect-Inc/tcex)
- [Threat Connect Example Repos](https://github.com/ThreatConnect-Inc/threatconnect-playbooks)

Modified: 11/20/24
