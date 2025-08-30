import json
import uuid
import datetime

def sparta_to_attackflow(sparta_json):
    marking_definition = f"marking-definition--{uuid.uuid4()}"
    created_by_ref = f"identity--{uuid.uuid4()}",
    x_mitre_contents = []
    object_attacks = []
    for i, item in enumerate(sparta_json):
        print(item)
        now = datetime.datetime.now(datetime.UTC).isoformat() + "Z"  
        object_ref = f"attack-pattern--{uuid.uuid4()}"
        object_modified = now
        x_mitre_content = {
            "object_ref": object_ref,
            "object_modified": object_modified
        }
        x_mitre_contents.append(x_mitre_content)
        new_item = {
            "x_mitre_platforms": item["x_mitre_platforms"],
            "x_mitre_domains": item["x_mitre_domains"],
            "object_marking_refs": [marking_definition],
            "id": f"attack-pattern--{uuid.uuid4()}",
            "type": "attack-pattern",
            "created": now,
            "created_by_ref": created_by_ref,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": item["technique"],
                    "url": f'https://sparta.aerospace.org/technique/{item["technique"]}/'
                },
            ],
            "modified": now,
            "name": item["name"],
            "description": item["description"],
            "kill_chain_phases": [],
            "x_mitre_detection": [],
            "x_mitre_is_subtechnique": item["x_mitre_is_subtechnique"],
            "x_mitre_version": "1.0",
            "x_mitre_modified_by_ref": created_by_ref,
            "x_mitre_data_sources": [],
            "x_mitre_defense_bypassed": [],
            "spec_version": "2.1",
            "x_mitre_attack_spec_version": "2.1.0"
        }
        object_attacks.append(new_item)
        print(x_mitre_content)
    
    flow = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": f"x-mitre-collection--{uuid.uuid4()}",
                "spec_version": "2.1",
                "x_mitre_attack_spec_version": "2.1.0",
                "name": "SPARTA TTPs",
                "x_mitre_version": "11.1",
                "description": "The Aerospace Corporation created the Space Attack Research and Tactic Analysis (SPARTA) matrix to address the information and communication barriers that hinder the identification and sharing of space-system Tactic, Techniques, and Procedures (TTP). SPARTA is intended to provide unclassified information to space professionals about how spacecraft may be compromised via cyber and traditional counterspace means.",
                "created_by_ref": created_by_ref,
                "created": "2018-01-17T12:56:55.080Z",
                "modified": "2022-05-11T14:00:00.188Z",
                "object_marking_refs": [
                    marking_definition
                ],
                "x_mitre_contents": x_mitre_contents,
            }
        ]
    }
    flow["objects"].extend(object_attacks)
    return flow

# Ejemplo de SPARTA JSON
sparta_data = [
    {
        "technique": "REC-0001",
        "name": "Gather Spacecraft Design Information",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0002",
        "name": "Gather Spacecraft Descriptors",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0003",
        "name": "Gather Spacecraft Communications Informaationn",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0004",
        "name": "Gather Launch Information",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0005",
        "name": "Eavesdropping",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0006",
        "name": "Gather FSW Development Innformation",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0007",
        "name": "Monitor for Safe-Mode Indicators",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0008",
        "name": "Gather Supply Chain Information",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
    {
        "technique": "REC-0009",
        "name": "Gather Mission Information",
        "description": "",
        "x_mitre_platforms": [],
        "x_mitre_domains": ["sparta-attack"],
        "x_mitre_is_subtechnique": "true"
    },
]

flow_json = sparta_to_attackflow(sparta_data)

with open("../src/attack_flow_builder/data/sparta_attack.json", "w") as f:
    json.dump(flow_json, f, indent=2)

print("Archivo generado: sparta_attackflow.json")
