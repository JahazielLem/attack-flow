from attack_flow_api.services.afb_fusion_contracts import FusionConflictCategory, FusionProvenanceKind
from attack_flow_api.services.afb_fusion_dedup import (
    dedupe_attack_refs_deterministic_first,
    dedupe_entities_deterministic_first,
    fuse_attachment_metadata_deterministic_first,
    merge_conditions_deterministic_first,
    merge_attack_actions_deterministic_first,
    MergedAttachmentBundle,
    MergedAttackAction,
    MergedCondition,
    MergedEntity,
    MergedOperator,
    MergedRelationship,
    merge_operators_deterministic_first,
    merge_relationships_deterministic_first,
)


def test_attack_refs_merge_with_deterministic_first_provenance() -> None:
    result = dedupe_attack_refs_deterministic_first(
        [
            {
                "technique_id": "T1059",
                "source_object_id": "attack-pattern--det",
                "source_object_type": "attack-pattern",
                "source_field": "x_mitre_attack_spec",
                "confidence": 0.4,
            }
        ],
        [
            {
                "technique_id": "T1059",
                "source_object_id": "attack-pattern--ai",
                "source_object_type": "attack-pattern",
                "source_field": "ai_output",
                "confidence": 0.7,
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.technique_id == "T1059"
    assert merged.source_object_id == "attack-pattern--det"
    assert merged.confidence == 1.0
    assert merged.deterministic_confidence == 0.4
    assert merged.ai_confidences == [0.7]
    assert [item.kind for item in merged.provenance] == [
        FusionProvenanceKind.DETERMINISTIC,
        FusionProvenanceKind.AI_DERIVED,
    ]
    assert merged.provenance[0].source_object_id == "attack-pattern--det"
    assert merged.provenance[1].source_object_id == "attack-pattern--ai"


def test_attack_refs_merge_duplicate_sources_keep_provenance() -> None:
    result = dedupe_attack_refs_deterministic_first(
        [
            {
                "technique_id": "T1059",
                "source_object_id": "attack-pattern--det-1",
                "confidence": 0.5,
            },
            {
                "technique_id": "T1059",
                "source_object_id": "attack-pattern--det-2",
                "confidence": 0.7,
            },
        ],
        [
            {
                "technique_id": "T1059",
                "source_object_id": "attack-pattern--ai",
                "confidence": 0.8,
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.source_object_id == "attack-pattern--det-1"
    assert merged.deterministic_confidence == 0.5
    assert merged.ai_confidences == [0.8]
    assert len(merged.provenance) == 3
    assert [item.source_object_id for item in merged.provenance] == [
        "attack-pattern--det-1",
        "attack-pattern--det-2",
        "attack-pattern--ai",
    ]


def test_entities_merge_union_lists_without_overwriting_deterministic_fields() -> None:
    result = dedupe_entities_deterministic_first(
        [
            {
                "object_id": "malware--1",
                "object_type": "malware",
                "display_name": "Deterministic Malware",
                "description": "deterministic description",
                "labels": ["label-a"],
                "value": "hxxps://source[.]example",
                "confidence": 0.8,
            }
        ],
        [
            {
                "object_id": "malware--1",
                "object_type": "malware",
                "display_name": "AI Malware",
                "description": "ai description",
                "labels": ["label-b", "label-a"],
                "observed_data_refs": ["observed-data--1"],
                "value": "https://provider.example",
                "confidence": 0.6,
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.object_id == "malware--1"
    assert merged.display_name == "Deterministic Malware"
    assert merged.description == "deterministic description"
    assert merged.labels == ["label-a", "label-b"]
    assert merged.observed_data_refs == ["observed-data--1"]
    assert merged.stix_properties["value"] == "hxxps://source[.]example"
    assert any("STIX property 'value'" in conflict.message for conflict in merged.conflicts)
    assert merged.confidence == 0.8
    assert merged.deterministic_confidence == 0.8
    assert merged.ai_confidences == [0.6]
    assert [item.kind for item in merged.provenance] == [
        FusionProvenanceKind.DETERMINISTIC,
        FusionProvenanceKind.AI_DERIVED,
    ]


def test_entities_duplicate_sources_merge_conservatively() -> None:
    result = dedupe_entities_deterministic_first(
        [
            {
                "object_id": "malware--1",
                "object_type": "malware",
                "display_name": "Deterministic Malware",
                "description": "deterministic description",
                "labels": ["label-a"],
                "confidence": 0.8,
            }
        ],
        [
            {
                "object_id": "malware--1",
                "object_type": "malware",
                "display_name": "AI Malware",
                "description": "ai description",
                "labels": ["label-b"],
                "observed_data_refs": ["observed-data--1"],
                "confidence": 0.6,
            }
        ],
    )

    merged = result[0]
    assert merged.display_name == "Deterministic Malware"
    assert merged.description == "deterministic description"
    assert merged.labels == ["label-a", "label-b"]
    assert merged.observed_data_refs == ["observed-data--1"]
    assert merged.confidence == 0.8
    assert [item.kind for item in merged.provenance] == [
        FusionProvenanceKind.DETERMINISTIC,
        FusionProvenanceKind.AI_DERIVED,
    ]


def test_actions_merge_keep_deterministic_verbatim_description() -> None:
    result = merge_attack_actions_deterministic_first(
        [
            {
                "id": "attack-action--1",
                "name": "Deterministic step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-action--1",
                "name": "AI step",
                "description": "Paraphrased summary that must not replace the deterministic description.",
                "confidence": 0.6,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Paraphrased summary that must not replace the deterministic description.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.id == "attack-action--1"
    assert merged.name == "Deterministic step"
    assert merged.description == "Observed command exactly as reported."
    assert merged.confidence == 0.9
    assert merged.deterministic_confidence == 0.9
    assert merged.ai_confidences == [0.6]
    assert [item.kind for item in merged.provenance] == [
        FusionProvenanceKind.DETERMINISTIC,
        FusionProvenanceKind.AI_DERIVED,
    ]
    assert merged.evidence == [
        {
            "source": "narrative",
            "excerpt": "Observed command exactly as reported.",
        }
    ]


def test_actions_preserve_verbatim_no_technique_steps() -> None:
    result = merge_attack_actions_deterministic_first(
        [],
        [
            {
                "id": "attack-action--2",
                "name": "Unmapped source-grounded step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.6,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.description == "Observed command exactly as reported."
    assert merged.technique is None
    assert merged.deterministic_confidence is None
    assert merged.ai_confidences == [0.6]
    assert merged.evidence == [
        {
            "source": "narrative",
            "excerpt": "Observed command exactly as reported.",
        }
    ]


def test_actions_preserve_source_grounded_steps_without_attack_mappings() -> None:
    result = merge_attack_actions_deterministic_first(
        [],
        [
            {
                "id": "attack-action--4",
                "name": "Source-grounded step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.6,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.technique is None
    assert merged.description == "Observed command exactly as reported."
    assert merged.evidence == [
        {
            "source": "narrative",
            "excerpt": "Observed command exactly as reported.",
        }
    ]


def test_actions_do_not_upgrade_deterministic_no_technique_steps() -> None:
    result = merge_attack_actions_deterministic_first(
        [
            {
                "id": "attack-action--3",
                "name": "Deterministic unmapped step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-action--3",
                "name": "AI mapped step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.6,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 0.6,
                    "grounded_by": "explicit_attack_id_in_source",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.technique is None
    assert merged.description == "Observed command exactly as reported."
    assert merged.ai_confidences == [0.6]


def test_relationships_merge_conservatively_and_preserve_provenance() -> None:
    result = merge_relationships_deterministic_first(
        [
            {
                "relationship_id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--1",
                "source_object_type": "threat-actor",
            }
        ],
        [
            {
                "relationship_id": "relationship--1",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--2",
                "source_object_type": "threat-actor",
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.relationship_id == "relationship--1"
    assert merged.source_ref == "threat-actor--1"
    assert merged.target_ref == "malware--1"
    assert len(merged.provenance) == 2
    assert len(merged.conflicts) == 1
    assert merged.conflicts[0].category.value == "conflicting_attachment"


def test_conditions_merge_conservatively_and_keep_deterministic_branching() -> None:
    result = merge_conditions_deterministic_first(
        [
            {
                "id": "attack-condition--1",
                "description": "Observed branch decision exactly as reported.",
                "value": "true",
                "confidence": 0.9,
                "on_true_refs": ["attack-action--1"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branch decision exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-condition--1",
                "description": "Observed branch decision exactly as reported.",
                "value": "false",
                "confidence": 0.4,
                "on_false_refs": ["attack-action--2"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branch decision exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.value == "true"
    assert merged.on_true_refs == ["attack-action--1"]
    assert merged.on_false_refs == []
    assert len(merged.provenance) == 2
    assert len(merged.conflicts) == 2
    assert {item.category.value for item in merged.conflicts} == {"conflicting_ordering"}


def test_conditions_only_true_false_are_preserved() -> None:
    result = merge_conditions_deterministic_first(
        [
            {
                "id": "attack-condition--2",
                "description": "Observed branch decision exactly as reported.",
                "value": "true",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branch decision exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-condition--3",
                "description": "Unsupported condition value",
                "value": "maybe",
                "confidence": 0.4,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Unsupported condition value",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.value == "true"
    assert merged.conflicts == []


def test_operators_merge_only_supported_values_and_record_conflicts() -> None:
    result = merge_operators_deterministic_first(
        [
            {
                "id": "attack-operator--1",
                "operator": "AND",
                "confidence": 0.9,
                "effect_refs": ["attack-action--1", "attack-action--2"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-operator--1",
                "operator": "XOR",
                "confidence": 0.4,
                "effect_refs": ["attack-action--3"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert len(result) == 1
    merged = result[0]
    assert merged.operator == "AND"
    assert merged.effect_refs == ["attack-action--1", "attack-action--2"]
    assert len(merged.provenance) == 1
    assert len(merged.conflicts) == 1
    assert merged.conflicts[0].category.value == "unsupported_branching_operator_type"


def test_operators_only_and_or_are_preserved() -> None:
    result = merge_operators_deterministic_first(
        [
            {
                "id": "attack-operator--2",
                "operator": "AND",
                "confidence": 0.9,
                "effect_refs": ["attack-action--1", "attack-action--2"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
            },
            {
                "id": "attack-operator--3",
                "operator": "OR",
                "confidence": 0.8,
                "effect_refs": ["attack-action--3", "attack-action--4"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
            },
        ],
        [
            {
                "id": "attack-operator--4",
                "operator": "XOR",
                "confidence": 0.4,
                "effect_refs": ["attack-action--5"],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
            }
        ],
    )

    assert [item.operator for item in result] == ["AND", "OR"]


def test_attachment_fusion_preserves_relationship_backed_refs_and_list_metadata() -> None:
    result = fuse_attachment_metadata_deterministic_first(
        deterministic_authors=["analyst-a"],
        ai_authors=["analyst-b"],
        deterministic_external_references=["https://example.com/a"],
        ai_external_references=["https://example.com/b"],
        attack_actions=[
            MergedAttackAction(
                id="attack-action--1",
                name="Deterministic step",
                description="Observed command exactly as reported.",
                confidence=0.9,
                object_refs=["malware--1", "malware--2"],
                evidence=[
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                        "source_object_id": "report--1",
                    },
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                        "source_object_id": "unrelated--1",
                    },
                ],
            )
        ],
        attack_assets=[
            MergedEntity(
                object_id="malware--1",
                object_type="malware",
                display_name="Malware",
                confidence=0.8,
            ),
            MergedEntity(
                object_id="malware--3",
                object_type="malware",
                display_name="Ignored Malware",
                confidence=0.7,
            ),
        ],
        relationships=[
            MergedRelationship(
                relationship_id="relationship--1",
                relationship_type="uses",
                source_ref="threat-actor--1",
                target_ref="malware--1",
                source_object_type="threat-actor",
                confidence=1.0,
            )
        ],
    )

    assert result.attack_flow_authors == ["analyst-a", "analyst-b"]
    assert result.attack_flow_external_references == ["https://example.com/a", "https://example.com/b"]
    assert result.attack_actions[0].object_refs == ["malware--1"]
    assert result.attack_actions[0].evidence == [
        {
            "source": "narrative",
            "excerpt": "Observed command exactly as reported.",
            "source_object_id": "report--1",
        },
        {
            "source": "narrative",
            "excerpt": "Observed command exactly as reported.",
            "source_object_id": "unrelated--1",
        },
    ]
    assert [asset.object_id for asset in result.attack_assets] == ["malware--1"]
    assert result.preserved_object_refs == ["malware--1", "threat-actor--1"]
    assert result.preserved_evidence_refs == ["report--1", "unrelated--1"]


def test_attachment_fusion_preserves_lists_without_heuristic_expansion() -> None:
    result = fuse_attachment_metadata_deterministic_first(
        deterministic_authors=["analyst-a"],
        ai_authors=["analyst-b"],
        deterministic_external_references=["https://example.com/a"],
        ai_external_references=["https://example.com/b"],
        attack_actions=[
            MergedAttackAction(
                id="attack-action--5",
                name="Deterministic step",
                description="Observed command exactly as reported.",
                confidence=0.9,
                object_refs=["malware--1", "malware--2"],
                evidence=[
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                        "source_object_id": "report--1",
                    }
                ],
            )
        ],
        attack_assets=[
            MergedEntity(
                object_id="malware--1",
                object_type="malware",
                display_name="Malware",
                confidence=0.8,
            )
        ],
        relationships=[
            MergedRelationship(
                relationship_id="relationship--1",
                relationship_type="uses",
                source_ref="threat-actor--1",
                target_ref="malware--1",
                source_object_type="threat-actor",
                confidence=1.0,
            )
        ],
    )

    assert result.attack_flow_authors == ["analyst-a", "analyst-b"]
    assert result.attack_flow_external_references == ["https://example.com/a", "https://example.com/b"]
    assert result.attack_actions[0].object_refs == ["malware--1"]
    assert result.attack_assets[0].object_id == "malware--1"


def test_conflicts_record_deterministic_facts_as_authoritative() -> None:
    action = merge_attack_actions_deterministic_first(
        [
            {
                "id": "attack-action--6",
                "name": "Deterministic step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-action--6",
                "name": "AI step",
                "description": "Different description that must not replace the deterministic one.",
                "confidence": 0.6,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 0.6,
                    "grounded_by": "explicit_attack_id_in_source",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Different description that must not replace the deterministic one.",
                    }
                ],
            }
        ],
    )[0]

    assert action.description == "Observed command exactly as reported."
    assert {item.category for item in action.conflicts} == {
        FusionConflictCategory.CONFLICTING_DESCRIPTION,
        FusionConflictCategory.UNSUPPORTED_INFERRED_TECHNIQUE,
    }


def test_conflicts_are_recorded_without_overwriting_deterministic_facts() -> None:
    action = merge_attack_actions_deterministic_first(
        [
            {
                "id": "attack-action--4",
                "name": "Deterministic step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.9,
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
            }
        ],
        [
            {
                "id": "attack-action--4",
                "name": "AI step",
                "description": "Different description that must not replace the deterministic one.",
                "confidence": 0.6,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 0.6,
                    "grounded_by": "explicit_attack_id_in_source",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Different description that must not replace the deterministic one.",
                    }
                ],
            }
        ],
    )[0]

    entity = dedupe_entities_deterministic_first(
        [
            {
                "object_id": "malware--2",
                "object_type": "malware",
                "display_name": "Deterministic Malware",
                "description": "deterministic description",
                "confidence": 0.8,
            }
        ],
        [
            {
                "object_id": "malware--2",
                "object_type": "malware",
                "display_name": "AI Malware",
                "description": "ai description",
                "confidence": 0.5,
            }
        ],
    )[0]

    relationship = merge_relationships_deterministic_first(
        [
            {
                "relationship_id": "relationship--2",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--1",
                "source_object_type": "threat-actor",
            }
        ],
        [
            {
                "relationship_id": "relationship--2",
                "relationship_type": "uses",
                "source_ref": "threat-actor--1",
                "target_ref": "malware--9",
                "source_object_type": "threat-actor",
            }
        ],
    )[0]

    assert action.description == "Observed command exactly as reported."
    assert action.conflicts
    assert {item.category.value for item in action.conflicts} == {
        "conflicting_description",
        "unsupported_inferred_technique",
    }
    assert entity.display_name == "Deterministic Malware"
    assert entity.description == "deterministic description"
    assert entity.conflicts
    assert {item.category.value for item in entity.conflicts} == {"conflicting_description"}
    assert relationship.target_ref == "malware--1"
    assert relationship.conflicts
    assert {item.category.value for item in relationship.conflicts} == {"conflicting_attachment"}
