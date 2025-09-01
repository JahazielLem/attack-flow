import json
import uuid
import datetime
from pprint import pprint
import requests

SPARTA_VERSION = "3.0"

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
      "x_mitre_attack_spec_version": SPARTA_VERSION,
      "x_mitre_modified_by_ref": self.created_by_ref,
      "x_mitre_shortname": tactic['name'].lower().replace(" ", "-"),
      "spec_version": "2.1"
    }
    self.tactics_list.append(x_mitre_tactic)
    return tactic_object, x_mitre_tactic
  
  def create_technique(self, technique):
    tactic_type = technique["x_mitre_tactic_type"]
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
              "external_id": technique['external_id'],
              "url": f"https://sparta.aerospace.org/technique/{technique['external_id']}"
          }
      ],
      "x_mitre_deprecated": False,
      "revoked": False,
      "description": technique['description'],
      "modified": self.now,
      "created_by_ref": self.created_by_ref,
      "name": technique['name'],
      "x_mitre_detection": "",
      "kill_chain_phases": [
        {
        "kill_chain_name": "mitre-attack",
        "phase_name": tactic_type.lower().replace(" ", "-")

        }
      ],
      "x_mitre_tactics": [technique["x_mitre_tactic_type"]],
      "x_mitre_is_subtechnique": False,
      "x_mitre_tactic_type": [technique["x_mitre_tactic_type"]],
      "x_mitre_attack_spec_version": SPARTA_VERSION,
      "x_mitre_modified_by_ref": self.created_by_ref,
      "x_mitre_data_sources": [],
      "spec_version": "2.1"
    }
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
      "x_mitre_attack_spec_version": SPARTA_VERSION,
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
      "x_mitre_attack_spec_version": SPARTA_VERSION,
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
          "x_mitre_attack_spec_version": SPARTA_VERSION,
          "name": "Aerospace SPARTA",
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
      if item["type"] == "tactic":
        tactic_obj, tactic_id = self.create_tactic(item)
        flow["objects"].append(tactic_obj)
        for _, subitem in enumerate(item["techniques"]):
          technique_obj = self.create_technique(subitem)
          flow["objects"].append(technique_obj)
    flow["objects"].append(self.create_tactic_refs())
    with open("../src/attack_flow_builder/data/sparta-attack.json", "w") as f:
      json.dump(flow, f, indent=2)
      

if __name__ == "__main__":
  stix = StixObject()
  with open("input.json", "r") as f:
    input_data = json.loads(f.read())
    stix.sparta_to_attackflow(input_data)
