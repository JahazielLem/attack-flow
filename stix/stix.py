import json
import uuid
import datetime
from pprint import pprint
import requests
from bs4 import BeautifulSoup
class StixObject:
  def __init__(self):
    self.now = datetime.datetime.now(datetime.UTC).isoformat() + "Z"
    self.marking_definition = f"marking-definition--{uuid.uuid4()}"
    self.created_by_ref = f"identity--{uuid.uuid4()}"
    
    self.tactics_list = []
    self.object_ref_list = []
  
  def create_object_ref(self, object_id):
    return {"object_ref": object_id, "object_modified": self.now}

  def create_tactic(self, tactic):
    x_mitre_tactic = f"x-mitre-tactic--{uuid.uuid4()}"
    tactic_object = {
      "x_mitre_domains": [
          "space-attack"
      ],
      "object_marking_refs": [self.marking_definition],
      "id": x_mitre_tactic,
      "type": "x-mitre-tactic",
      "created": self.now,
      "created_by_ref": self.created_by_ref,
      "external_references": [
          {
              "external_id": tactic['external_id'],
              "url": f"https://sparta.aerospace.org/tactic/{tactic['external_id']}",
              "source_name": "mitre-attack"
          }
      ],
      "modified": self.now,
      "name": tactic['name'],
      "description": tactic['description'],
      "x_mitre_version": "1.0",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_modified_by_ref": self.created_by_ref,
      "x_mitre_shortname": tactic['name'].lower().replace(" ", "-"),
      "spec_version": "2.1"
    }
    self.tactics_list.append(x_mitre_tactic)
    # self.object_ref_list.append(self.create_object_ref(x_mitre_tactic))
    return tactic_object, x_mitre_tactic
  
  def create_technique(self, technnique):
    tactic_type = technnique["x_mitre_tactic_type"]
    if isinstance(tactic_type, list):
      tactic_type = tactic_type[0]
    attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
    technnique_object = {
      "x_mitre_platforms": ["Spacecraft", "Ground Station"],
      "x_mitre_domains": ["space-attack"],
      "object_marking_refs": [self.marking_definition],
      "type": "attack-pattern",
      "id": attack_pattern_id,
      "created": self.now,
      "x_mitre_version": "1.0",
      "external_references": [
          {
              "source_name": "mitre-attack",
              "external_id": technnique['external_id'],
              "url": f"https://sparta.aerospace.org/technique/{technnique['external_id']}"
          }
      ],
      "x_mitre_deprecated": False,
      "revoked": False,
      "description": technnique['description'],
      "modified": self.now,
      "created_by_ref": self.created_by_ref,
      "name": technnique['name'],
      "x_mitre_detection": "",
      "kill_chain_phases": [
        {
        "kill_chain_name": "mitre-attack",
        "phase_name": tactic_type.lower().replace(" ", "-")

        }
      ],
      "x_mitre_tactics": [technnique["x_mitre_tactic_type"]],
      "x_mitre_is_subtechnique": False,
      "x_mitre_tactic_type": [technnique["x_mitre_tactic_type"]],
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_modified_by_ref": self.created_by_ref,
      "x_mitre_data_sources": [],
      "spec_version": "2.1"
    }
    print(technnique["x_mitre_tactic_type"])
    self.object_ref_list.append(self.create_object_ref(attack_pattern_id))
    return technnique_object
  
  def create_relationship_asset(self, source_ref, target_ref):
    relation_id = f"relationship--{uuid.uuid4()}"
    relation = {
      "object_marking_refs": [self.marking_definition],
      "type": "relationship",
      "id": relation_id,
      "created": self.now,
      "x_mitre_version": "0.1",
      "external_references": [],
      "x_mitre_deprecated": False,
      "revoked": False,
      "description": "",
      "modified": self.now,
      "relationship_type": "uses",
      "source_ref": source_ref,
      "target_ref": target_ref,
      "x_mitre_attack_spec_version": "2.1.0",
      "created_by_ref": self.created_by_ref,
      "x_mitre_modified_by_ref": self.created_by_ref,
      "spec_version": "2.1",
      "x_mitre_domains": ["space-attack"]
    }
    self.object_ref_list.append(self.create_object_ref(relation_id))
    return relation

  def create_tactic_refs(self):
    attack_pattern_id = f"x-mitre-matrix--{uuid.uuid4()}"
    tactics_ref = {
      "tactic_refs": self.tactics_list,
      "object_marking_refs": [self.marking_definition],
      "type": "x-mitre-matrix",
      "id": attack_pattern_id,
      "created": self.now,
      "x_mitre_version": "2.0",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "space-attack",
          "url": "https://sparta.aerospace.org/"
        }
      ],
      "x_mitre_deprecated": False,
      "revoked": False,
      "description": "The Aerospace Corporation created the Space Attack Research and Tactic Analysis (SPARTA) matrix to address the information and communication barriers that hinder the identification and sharing of space-system Tactic, Techniques, and Procedures (TTP).",
      "modified": self.now,
      "created_by_ref": self.created_by_ref,
      "name": "SPARTA TTPS",
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_modified_by_ref": self.created_by_ref,
      "spec_version": "2.1",
      "x_mitre_domains": ["space-attack"]
    }
    self.object_ref_list.append(self.create_object_ref(attack_pattern_id))
    return tactics_ref

  def sparta_to_attackflow(self, sparta_json):
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
          "created_by_ref": self.created_by_ref,
          "created": "2018-01-17T12:56:55.080Z",
          "modified": "2022-05-11T14:00:00.188Z",
          "object_marking_refs": [self.marking_definition],
          "x_mitre_contents": self.object_ref_list,
        }
      ]
    }
    for _, item in enumerate(sparta_json):
      # print(item)
      if item["type"] == "tactic":
        tactic_obj, tactic_id = self.create_tactic(item)
        flow["objects"].append(tactic_obj)
        for _, subitem in enumerate(item["techniques"]):
          technique_obj = self.create_technique(subitem)
          flow["objects"].append(technique_obj)
          # relation_obj = self.create_relationship_asset(technique_obj["id"], tactic_id)
          # flow["objects"].append(relation_obj)
    flow["objects"].append(self.create_tactic_refs())
    with open("../src/attack_flow_builder/data/sparta-attack.json", "w") as f:
      json.dump(flow, f, indent=2)
      

# Ejemplo de SPARTA JSON
sparta_data = [
  {
    "type": "tactic",
    "external_id": "ST0001",
    "name": "Reconnaissance",
    "description": "Threat actor is trying to gather information they can use to plan future operations.",
    "techniques": [
      {
        "external_id": "REC-0001",
        "name": "Gather Spacecraft Design Information",
        "description": "Threat actors may gather information about the victim spacecraft's design that can be used for future campaigns or to help perpetuate other techniques. Information about the spacecraft can include software, firmware, encryption type, purpose, as well as various makes and models of subsystems.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0002",
        "name": "Gather Spacecraft Descriptors",
        "description": "Threat actors may gather information about the victim spacecraft's descriptors that can be used for future campaigns or to help perpetuate other techniques. Information about the descriptors may include a variety of details such as identity attributes, organizational structures, and mission operational parameters.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0003",
        "name": "Gather Spacecraft Communications Information",
        "description": "Threat actors may obtain information on the victim spacecraft's communication channels in order to determine specific commands, protocols, and types. Information gathered can include commanding patterns, antenna shape and location, beacon frequency and polarization, and various transponder information.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0004",
        "name": "Gather Launch Information",
        "description": "Threat actors may gather the launch date and time, location of the launch (country & specific site), organizations involved, launch vehicle, etc. This information can provide insight into protocols, regulations, and provide further targets for the threat actor, including specific vulnerabilities with the launch vehicle itself.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0005",
        "name": "Eavesdropping",
        "description": "Threat actors may seek to capture network communications throughout the ground station and radio frequency (RF) communication used for uplink and downlink communications. RF communication frequencies vary between 30MHz and 60 GHz. Threat actors may capture RF communications using specialized hardware, such as software defined radio (SDR), handheld radio, or a computer with radio demodulator turned to the communication frequency. Network communications may be captured using packet capture software while the threat actor is on the target network.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0006",
        "name": "Gather FSW Development Information",
        "description": "Threat actors may obtain information regarding the flight software (FSW) development environment for the victim spacecraft. This information may include the development environment, source code, compiled binaries, testing tools, and fault management.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0007",
        "name": "Monitor for Safe-Mode Indicators",
        "description": "Threat actors may gather information regarding safe-mode indicators on the victim spacecraft. Safe-mode is when all non-essential systems are shut down and only essential functions within the spacecraft are active. During this mode, several commands are available to be processed that are not normally processed. Further, many protections may be disabled at this time.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0008",
        "name": "Gather Supply Chain Information",
        "description": "Threat actors may gather information about a mission's supply chain or product delivery mechanisms that can be used for future campaigns or to help perpetuate other techniques.",
        "x_mitre_tactic_type": "Reconnaissance"
      },
      {
        "external_id": "REC-0009",
        "name": "Gather Mission Information",
        "description": "Threat actors may initially seek to gain an understanding of a target mission by gathering information commonly captured in a Concept of Operations (or similar) document and related artifacts. Information of interest includes, but is not limited to: - the needs, goals, and objectives of the system - system overview and key elements/instruments - modes of operations (including operational constraints) - proposed capabilities and the underlying science/technology used to provide capabilities (i.e., scientific papers, research studies, etc.) - physical and support environments.",
        "x_mitre_tactic_type": "Reconnaissance"
      }
    ]
  },
  {
    "type": "tactic",
    "external_id": "ST0002",
    "name": "Resource Development",
    "description": "Threat actor is trying to establish resources they can use to support operations.",
    "techniques": [
      {
        "external_id": "RD-0001",
        "name": "Acquire Infrastructure",
        "description": "Threat actors may buy, lease, or rent infrastructure that can be used for future campaigns or to perpetuate other techniques. A wide variety of infrastructure exists for threat actors to connect to and communicate with target spacecraft.",
        "x_mitre_tactic_type": "Resource Development"
      },
      {
        "external_id": "RD-0002",
        "name": "Compromise Infrastructure",
        "description": "Threat actors may compromise third-party infrastructure that can be used for future campaigns or to perpetuate other techniques. Infrastructure solutions include physical devices such as antenna, amplifiers, and convertors, as well as software used by satellite communicators. Instead of buying or renting infrastructure, a threat actor may compromise infrastructure and use it during other phases of the campaign's lifecycle.",
        "x_mitre_tactic_type": "Resource Development"
      },
      {
        "external_id": "RD-0003",
        "name": "Obtain Cyber Capabilities",
        "description": "Threat actors may buy and/or steal cyber capabilities that can be used for future campaigns or to perpetuate other techniques. Rather than developing their own capabilities in-house, threat actors may purchase, download, or steal them. Activities may include the acquisition of malware, software, exploits, and information relating to vulnerabilities. Threat actors may obtain capabilities to support their operations throughout numerous phases of the campaign lifecycle.",
        "x_mitre_tactic_type": "Resource Development"
      },
      {
        "external_id": "RD-0004",
        "name": "Stage Capabilities",
        "description": "Threat actors may upload, install, or otherwise set up capabilities that can be used for future campaigns or to perpetuate other techniques. To support their operations, a threat actor may need to develop their own capabilities or obtain them in some way in order to stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased or rented by the threat actor or was otherwise compromised by them.",
        "x_mitre_tactic_type": "Resource Development"
      },
      {
        "external_id": "RD-0005",
        "name": "Obtain Non-Cyber Capabilities",
        "description": "Threat actors may obtain non-cyber capabilities, primarily physical counterspace weapons or systems. These counterspace capabilities vary significantly in the types of effects they create, the level of technological sophistication required, and the level of resources needed to develop and deploy them. These diverse capabilities also differ in how they are employed and how easy they are to detect and attribute and the permanence of the effects they have on their target.",
        "x_mitre_tactic_type": "Resource Development"
      },
    ]
  },
  {
    "type": "tactic",
    "external_id": "ST0003",
    "name": "Initial Access",
    "description": "Threat actor is trying to get point of presence/command execution on the spacecraft",
    "techniques": [
      {
        "external_id": "IA-0001",
        "name": "Compromise Supply Chain",
        "description": "Threat actors may manipulate or compromise products or product delivery mechanisms before the customer receives them in order to achieve data or system compromise.",
        "x_mitre_tactic_type": "Initial Access"
      }
    ]
  }
]

if __name__ == "__main__":
  stix = StixObject()
  stix.sparta_to_attackflow(sparta_data)
