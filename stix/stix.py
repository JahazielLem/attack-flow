import json
import uuid
import datetime
from pprint import pprint

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
      "x_mitre_shortname": "remote-service-effects",
      "spec_version": "2.1"
    }
    self.tactics_list.append(x_mitre_tactic)
    self.object_ref_list.append(self.create_object_ref(x_mitre_tactic))
    return tactic_object
  
  def create_technique(self, technnique):
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
      "x_mitre_deprecated": "false",
      "revoked": "false",
      "description": technnique['description'],
      "modified": self.now,
      "created_by_ref": self.created_by_ref,
      "name": technnique['name'],
      "x_mitre_detection": "",
      "kill_chain_phases": [],
      "x_mitre_is_subtechnique": "true",
      "x_mitre_tactic_type": [technnique["x_mitre_tactic_type"]],
      "x_mitre_attack_spec_version": "2.1.0",
      "x_mitre_modified_by_ref": self.created_by_ref,
      "x_mitre_data_sources": [],
      "spec_version": "2.1"
    }
    self.object_ref_list.append(self.create_object_ref(attack_pattern_id))
    return technnique_object
  
  def create_relationship_asset(self, source_ref, target_ref):
    relation = {
      "object_marking_refs": [self.marking_definition],
      "type": "relationship",
      "id": f"relationship--{uuid.uuid4()}",
      "created": self.now,
      "x_mitre_version": "0.1",
      "external_references": [],
      "x_mitre_deprecated": "false",
      "revoked": "false",
      "description": "",
      "modified": self.now,
      "relationship_type": "subtechnique-of",
      "source_ref": source_ref,
      "target_ref": target_ref,
      "x_mitre_attack_spec_version": "2.1.0",
      "created_by_ref": self.created_by_ref,
      "x_mitre_modified_by_ref": self.created_by_ref,
      "spec_version": "2.1",
      "x_mitre_domains": ["space-attack"]
    }
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
      "x_mitre_deprecated": "false",
      "revoked": "false",
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
      print(item)
      if item["type"] == "tactic":
        tactic_obj = self.create_tactic(item)
        flow["objects"].append(tactic_obj)
        for _, subitem in enumerate(item["techniques"]):
          flow["objects"].append(self.create_technique(subitem))
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
        "x_mitre_tactic_type": "Acquire Infrastructure"
      },
    ]
  },
]


if __name__ == "__main__":
  stix = StixObject()
  stix.sparta_to_attackflow(sparta_data)
