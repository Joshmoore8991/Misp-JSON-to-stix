

Overview

The MISP to STIX Converter is a Python script that transforms MISP (Malware Information Sharing Platform) threat actor data into STIX 2.0 (Structured Threat Information Expression) format. This tool allows security analysts and threat intelligence teams to seamlessly convert MISP JSON files into STIX-compatible formats for enhanced cyber threat sharing and analysis.

Features

✅ Parses MISP JSON threat actor data.
✅ Converts MISP threat actors into STIX 2.0 Threat Actor objects.
✅ Establishes relationships between threat actors.
✅ Generates a STIX Bundle JSON file as output.
✅ Implements logging for error tracking and debugging.

Installation

Prerequisites

Ensure you have Python 3.7+ installed.

Install Dependencies

Run the following command to install required Python packages:

pip install stix2

Usage

Running the Converter

python misp_to_stix_converter.py

By default, the script will look for misp_data.json as input and generate stix_output_2_0.json.

Command-Line Arguments

You can specify a custom input and output file:

python misp_to_stix_converter.py <input_file> <output_file>

Example:

python misp_to_stix_converter.py misp_input.json stix_output.json

Input Format (MISP JSON)

The input file should be in MISP JSON format:

{
    "values": [
        {
            "uuid": "1234-5678-91011",
            "value": "APT Example",
            "meta": {
                "synonyms": ["Advanced Persistent Threat Example"],
                "country": "USA",
                "targeted-sector": "Finance",
                "refs": ["https://threatintel.com/apt-example"]
            },
            "related": [
                {
                    "dest-uuid": "1111-2222-3333",
                    "type": "ally"
                }
            ]
        }
    ]
}

Output Format (STIX 2.0 JSON)

The script generates a STIX 2.0 Bundle containing ThreatActor and Relationship objects:

{
    "type": "bundle",
    "id": "bundle--abcd-efgh-ijkl",
    "spec_version": "2.0",
    "objects": [
        {
            "type": "threat-actor",
            "id": "threat-actor--1234-5678-91011",
            "name": "APT Example",
            "aliases": ["Advanced Persistent Threat Example"],
            "labels": ["Country: USA", "Targeted Sector: Finance"],
            "external_references": [
                {"source_name": "MISP", "url": "https://threatintel.com/apt-example"}
            ],
            "confidence": 50
        },
        {
            "type": "relationship",
            "id": "relationship--xyz-1234",
            "relationship_type": "related-to",
            "source_ref": "threat-actor--1234-5678-91011",
            "target_ref": "threat-actor--1111-2222-3333",
            "description": "Relationship type: ally",
            "confidence": 80
        }
    ]
}

Logging

All conversion steps are logged, including warnings and errors. Logs are displayed in the console:

2025-03-27 12:00:01 - INFO: Loaded MISP JSON data.
2025-03-27 12:00:02 - INFO: Created Threat Actor: APT Example
2025-03-27 12:00:02 - INFO: Created Relationship: relationship--xyz-1234
2025-03-27 12:00:03 - INFO: ✅ STIX 2.0 JSON saved as stix_output_2_0.json

Error Handling

If the script encounters errors, they are logged, and an exception is raised. Possible issues include:

Invalid JSON structure: Ensure input follows the MISP format.

Missing required fields: uuid and value must be present.

File read/write issues: Check file permissions.

License

This project is licensed under the MIT License.

Contributing

Contributions are welcome! Please submit issues or pull requests on GitHub.

Author

Joshua Moore
