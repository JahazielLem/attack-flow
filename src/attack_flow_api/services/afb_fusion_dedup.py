from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from attack_flow_api.services.afb_fusion_contracts import (
    FusionConflictCategory,
    FusionConflictRecord,
    FusionFindingProvenance,
    FusionInputSourceKind,
    FusionProvenanceKind,
)


class MergedAttackRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str | None = None
    technique_ref: str | None = None
    source_object_id: str | None = None
    source_object_type: str | None = None
    source_field: str | None = None
    external_source_name: str | None = None
    external_url: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    deterministic_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ai_confidences: list[float] = Field(default_factory=list)
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedEntity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    object_id: str | None = None
    object_type: str = "attack-asset"
    display_name: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    stix_properties: dict[str, Any] = Field(default_factory=dict)
    labels: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float | None = None
    deterministic_confidence: float | None = None
    ai_confidences: list[float] = Field(default_factory=list)
    pattern: str | None = None
    source_ref: str | None = None
    target_ref: str | None = None
    object_ref: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    observed_data_refs: list[str] = Field(default_factory=list)
    created_by_ref: str | None = None
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedAttackAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    technique: dict[str, Any] | None = None
    tactic: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    asset_refs: list[str] = Field(default_factory=list)
    object_refs: list[str] = Field(default_factory=list)
    effect_refs: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    deterministic_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ai_confidences: list[float] = Field(default_factory=list)
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship_id: str | None = None
    relationship_type: str
    source_ref: str
    target_ref: str
    source_object_type: str | None = None
    confidence: float | None = None
    deterministic_confidence: float | None = None
    ai_confidences: list[float] = Field(default_factory=list)
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    on_true_refs: list[str] = Field(default_factory=list)
    on_false_refs: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    deterministic_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ai_confidences: list[float] = Field(default_factory=list)
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedOperator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    operator: str
    confidence: float = Field(ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    effect_refs: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    deterministic_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    ai_confidences: list[float] = Field(default_factory=list)
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)


class MergedAttachmentBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_flow_authors: list[str] = Field(default_factory=list)
    attack_flow_external_references: list[str] = Field(default_factory=list)
    attack_actions: list[MergedAttackAction] = Field(default_factory=list)
    attack_assets: list[MergedEntity] = Field(default_factory=list)
    preserved_object_refs: list[str] = Field(default_factory=list)
    preserved_evidence_refs: list[str] = Field(default_factory=list)


def dedupe_attack_refs_deterministic_first(
    deterministic_attack_refs: Sequence[Mapping[str, Any]],
    ai_attack_refs: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedAttackRef]:
    merged: dict[str, MergedAttackRef] = {}
    for item in deterministic_attack_refs:
        key = _attack_ref_key(item)
        if key is None or not _is_explicit_attack_ref(item):
            continue
        if key not in merged:
            merged[key] = _build_attack_ref(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_attack_ref(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_attack_refs or []:
        key = _attack_ref_key(item)
        if key is None or not _is_explicit_attack_ref(item):
            continue
        if key not in merged:
            merged[key] = _build_attack_ref(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_attack_ref(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def dedupe_entities_deterministic_first(
    deterministic_entities: Sequence[Mapping[str, Any]],
    ai_entities: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedEntity]:
    merged: dict[str, MergedEntity] = {}
    for item in deterministic_entities:
        key = _entity_key(item)
        if key is None or not _is_explicit_entity(item):
            continue
        if key not in merged:
            merged[key] = _build_entity(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_entity(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_entities or []:
        key = _entity_key(item)
        if key is None or not _is_explicit_entity(item):
            continue
        if key not in merged:
            merged[key] = _build_entity(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_entity(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def merge_attack_actions_deterministic_first(
    deterministic_actions: Sequence[Mapping[str, Any]],
    ai_actions: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedAttackAction]:
    merged: dict[str, MergedAttackAction] = {}
    for item in deterministic_actions:
        key = _action_key(item)
        if key is None:
            continue
        if key not in merged:
            merged[key] = _build_action(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_action(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_actions or []:
        key = _action_key(item)
        if key is None:
            continue
        if not _is_source_grounded_action(item):
            continue
        if key not in merged:
            merged[key] = _build_action(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_action(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def merge_relationships_deterministic_first(
    deterministic_relationships: Sequence[Mapping[str, Any]],
    ai_relationships: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedRelationship]:
    merged: dict[str, MergedRelationship] = {}
    for item in deterministic_relationships:
        key = _relationship_key(item)
        if key is None or not _is_explicit_relationship(item):
            continue
        if key not in merged:
            merged[key] = _build_relationship(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_relationship(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_relationships or []:
        key = _relationship_key(item)
        if key is None or not _is_explicit_relationship(item):
            continue
        if key not in merged:
            merged[key] = _build_relationship(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_relationship(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def merge_conditions_deterministic_first(
    deterministic_conditions: Sequence[Mapping[str, Any]],
    ai_conditions: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedCondition]:
    merged: dict[str, MergedCondition] = {}
    for item in deterministic_conditions:
        key = _condition_key(item)
        if key is None or not _is_source_grounded_condition(item):
            continue
        if key not in merged:
            merged[key] = _build_condition(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_condition(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_conditions or []:
        key = _condition_key(item)
        if key is None or not _is_source_grounded_condition(item):
            continue
        if key not in merged:
            merged[key] = _build_condition(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_condition(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def merge_operators_deterministic_first(
    deterministic_operators: Sequence[Mapping[str, Any]],
    ai_operators: Sequence[Mapping[str, Any]] | None = None,
    *,
    deterministic_source_label: str = "deterministic_stix_opencti",
    ai_source_label: str = "ai_derived",
) -> list[MergedOperator]:
    merged: dict[str, MergedOperator] = {}
    for item in deterministic_operators:
        key = _operator_key(item)
        if key is None or not _is_supported_operator(item) or not _is_source_grounded_operator(item):
            continue
        if key not in merged:
            merged[key] = _build_operator(
                item,
                kind=FusionProvenanceKind.DETERMINISTIC,
                source_label=deterministic_source_label,
                deterministic=True,
            )
            continue
        merged[key] = _merge_operator(
            merged[key],
            item,
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label=deterministic_source_label,
            deterministic=True,
        )

    for item in ai_operators or []:
        key = _operator_key(item)
        if key is None:
            continue
        if not _is_supported_operator(item):
            if key in merged:
                merged[key].conflicts.append(
                    _build_conflict(
                        category=FusionConflictCategory.UNSUPPORTED_BRANCHING_OPERATOR_TYPE,
                        source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION,
                        message="unsupported operator type was rejected",
                        ai_ref=_as_str(item.get("operator")),
                    )
                )
            continue
        if not _is_source_grounded_operator(item):
            continue
        if key not in merged:
            merged[key] = _build_operator(
                item,
                kind=FusionProvenanceKind.AI_DERIVED,
                source_label=ai_source_label,
                deterministic=False,
            )
            continue
        merged[key] = _merge_operator(
            merged[key],
            item,
            kind=FusionProvenanceKind.AI_DERIVED,
            source_label=ai_source_label,
            deterministic=False,
        )

    return list(merged.values())


def fuse_attachment_metadata_deterministic_first(
    *,
    deterministic_authors: Sequence[str] | None = None,
    ai_authors: Sequence[str] | None = None,
    deterministic_external_references: Sequence[str] | None = None,
    ai_external_references: Sequence[str] | None = None,
    attack_actions: Sequence[MergedAttackAction] | None = None,
    attack_assets: Sequence[MergedEntity] | None = None,
    relationships: Sequence[MergedRelationship] | None = None,
) -> MergedAttachmentBundle:
    preserved_object_refs = _build_allowed_object_refs(relationships or [])
    preserved_evidence_refs = _build_allowed_evidence_refs(attack_actions or [])
    preserved_asset_refs = set(preserved_object_refs)
    for action in attack_actions or []:
        preserved_asset_refs.update(action.asset_refs)
        preserved_asset_refs.update(action.object_refs)

    fused_actions = [
        action.model_copy(
            update={
                "object_refs": _filter_preserved_refs(action.object_refs, preserved_object_refs),
                "evidence": _filter_preserved_action_evidence(action.evidence),
            }
        )
        for action in attack_actions or []
    ]

    fused_assets = [
        asset
        for asset in attack_assets or []
        if asset.object_type == "attack-asset"
        or asset.object_id is None
        or asset.object_id in preserved_asset_refs
    ]

    return MergedAttachmentBundle(
        attack_flow_authors=_dedupe_preserve_order(_as_str_list(deterministic_authors) + _as_str_list(ai_authors)),
        attack_flow_external_references=_dedupe_preserve_order(
            _as_str_list(deterministic_external_references) + _as_str_list(ai_external_references)
        ),
        attack_actions=fused_actions,
        attack_assets=fused_assets,
        preserved_object_refs=sorted(preserved_object_refs),
        preserved_evidence_refs=sorted(preserved_evidence_refs),
    )


def _build_attack_ref(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedAttackRef:
    confidence = 1.0 if deterministic else _coerce_confidence(item.get("confidence"), default=1.0)
    deterministic_confidence = _coerce_confidence(item.get("confidence"), default=1.0) if deterministic else None
    return MergedAttackRef(
        technique_id=_as_str(item.get("technique_id")),
        technique_ref=_as_str(item.get("technique_ref")),
        source_object_id=_as_str(item.get("source_object_id")),
        source_object_type=_as_str(item.get("source_object_type")),
        source_field=_as_str(item.get("source_field")),
        external_source_name=_as_str(item.get("external_source_name")),
        external_url=_as_str(item.get("external_url")),
        confidence=confidence,
        deterministic_confidence=deterministic_confidence,
        ai_confidences=[] if deterministic else [confidence],
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _merge_attack_ref(
    current: MergedAttackRef,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedAttackRef:
    provenance = list(current.provenance)
    conflicts = list(current.conflicts)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence
    ai_confidences = list(current.ai_confidences)
    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=1.0)
        confidence = 1.0
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        ai_confidences.append(ai_confidence)
        if deterministic_confidence is None:
            confidence = ai_confidence

    for field_name in (
        "technique_id",
        "technique_ref",
        "source_object_id",
        "source_object_type",
        "source_field",
        "external_source_name",
        "external_url",
    ):
        value = _as_str(item.get(field_name))
        if value and getattr(current, field_name) is None:
            setattr(current, field_name, value)
        elif value and value != getattr(current, field_name):
            conflicts.append(
                _build_conflict(
                    category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                    source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                    message=f"attack ref {field_name} conflicts with deterministic source fact",
                    deterministic_ref=current.source_object_id or current.technique_id or current.technique_ref,
                    ai_ref=value,
                )
            )

    provenance.append(
        _build_provenance(
            item,
            kind=kind,
            source_label=source_label,
            confidence=_coerce_confidence(item.get("confidence"), default=confidence),
        )
    )
    return current.model_copy(
        update={
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "provenance": provenance,
            "conflicts": conflicts,
        }
    )


def _build_entity(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedEntity:
    deterministic_confidence = _coerce_confidence(item.get("confidence"), default=None) if deterministic else None
    confidence = deterministic_confidence if deterministic_confidence is not None else _coerce_confidence(
        item.get("confidence"),
        default=1.0,
    )
    labels = _as_str_list(item.get("labels"))
    tags = _as_str_list(item.get("tags"))
    observed_data_refs = _as_str_list(item.get("observed_data_refs"))
    known_keys = {
        "object_id",
        "entity_id",
        "entity_ref",
        "id",
        "object_type",
        "entity_type",
        "kind",
        "type",
        "display_name",
        "name",
        "description",
        "tags",
        "labels",
        "first_seen",
        "last_seen",
        "confidence",
        "deterministic_confidence",
        "ai_confidences",
        "pattern",
        "source_ref",
        "target_ref",
        "observed_data_refs",
        "created_by_ref",
        "provenance",
        "conflicts",
        "fact_origin",
    }
    stix_properties = {key: value for key, value in item.items() if key not in known_keys}
    return MergedEntity(
        object_id=_as_str(item.get("object_id")),
        object_type=_as_str(item.get("object_type")) or "unknown",
        display_name=_as_str(item.get("display_name")),
        description=_as_str(item.get("description")),
        tags=tags,
        stix_properties=stix_properties,
        labels=labels,
        first_seen=_as_str(item.get("first_seen")),
        last_seen=_as_str(item.get("last_seen")),
        confidence=confidence,
        deterministic_confidence=deterministic_confidence,
        ai_confidences=[] if deterministic else [confidence],
        pattern=_as_str(item.get("pattern")),
        source_ref=_as_str(item.get("source_ref")),
        target_ref=_as_str(item.get("target_ref")),
        observed_data_refs=observed_data_refs,
        created_by_ref=_as_str(item.get("created_by_ref")),
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _merge_entity(
    current: MergedEntity,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedEntity:
    provenance = list(current.provenance)
    conflicts = list(current.conflicts)
    ai_confidences = list(current.ai_confidences)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence

    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        confidence = deterministic_confidence if deterministic_confidence is not None else confidence
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence if current.confidence is not None else 1.0)
        ai_confidences.append(ai_confidence)
        if deterministic_confidence is None and confidence is None:
            confidence = ai_confidence

    for field_name in ("display_name", "description", "first_seen", "last_seen", "pattern", "source_ref", "target_ref", "created_by_ref"):
        value = _as_str(item.get(field_name))
        if value and getattr(current, field_name) is None:
            setattr(current, field_name, value)
        elif value and value != getattr(current, field_name):
            conflicts.append(
                _build_conflict(
                    category=FusionConflictCategory.CONFLICTING_DESCRIPTION if field_name in {"display_name", "description"} else FusionConflictCategory.CONFLICTING_ATTACHMENT,
                    source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                    message=f"entity {field_name} conflicts with deterministic source fact",
                    deterministic_ref=current.object_id or current.display_name,
                    ai_ref=value,
                )
            )

    current.labels = _dedupe_preserve_order(current.labels + _as_str_list(item.get("labels")))
    current.tags = _dedupe_preserve_order(current.tags + _as_str_list(item.get("tags")))
    current.observed_data_refs = _dedupe_preserve_order(current.observed_data_refs + _as_str_list(item.get("observed_data_refs")))
    incoming_properties = {k: v for k, v in item.items() if k not in {
        "object_id", "entity_id", "entity_ref", "id", "object_type", "entity_type", "kind", "type",
        "display_name", "name", "description", "tags", "labels", "first_seen", "last_seen", "confidence",
        "deterministic_confidence", "ai_confidences", "pattern", "source_ref", "target_ref", "observed_data_refs",
        "created_by_ref", "provenance", "conflicts", "fact_origin",
    }}
    for key, value in incoming_properties.items():
        if key not in current.stix_properties:
            current.stix_properties[key] = value
        elif current.stix_properties[key] != value:
            conflicts.append(
                _build_conflict(
                    category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                    source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                    message=f"entity STIX property '{key}' conflicts with deterministic source fact",
                    deterministic_ref=current.object_id or current.display_name,
                    ai_ref=str(value),
                )
            )

    provenance.append(
        _build_provenance(
            item,
            kind=kind,
            source_label=source_label,
            confidence=_coerce_confidence(item.get("confidence"), default=confidence),
        )
    )
    return current.model_copy(
        update={
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "provenance": provenance,
            "labels": current.labels,
            "observed_data_refs": current.observed_data_refs,
            "conflicts": conflicts,
        }
    )


def _build_provenance(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    confidence: float | None,
) -> FusionFindingProvenance:
    return FusionFindingProvenance(
        kind=kind,
        source_label=source_label,
        confidence=confidence,
        source_object_id=_as_str(item.get("source_object_id")),
        source_field=_as_str(item.get("source_field")),
        notes=_as_str(item.get("notes")),
    )


def _build_action(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedAttackAction:
    description = _as_str(item.get("description"))
    if description is None:
        description = ""
    confidence = _coerce_confidence(item.get("confidence"), default=1.0)
    deterministic_confidence = _coerce_confidence(item.get("confidence"), default=1.0) if deterministic else None
    evidence = _filter_verbatim_evidence(item.get("evidence"), description)
    return MergedAttackAction(
        id=_as_str(item.get("id")) or "action--unknown",
        name=_as_str(item.get("name")) or "",
        description=description,
        confidence=confidence,
        technique=_mapping_to_dict(item.get("technique")),
        tactic=_mapping_to_dict(item.get("tactic")),
        tags=_as_str_list(item.get("tags")),
        asset_refs=_as_str_list(item.get("asset_refs")),
        object_refs=_as_str_list(item.get("object_refs")),
        effect_refs=_as_str_list(item.get("effect_refs")),
        evidence=evidence,
        citations=_as_str_list(item.get("citations")),
        deterministic_confidence=deterministic_confidence,
        ai_confidences=[] if deterministic else [confidence],
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _build_relationship(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedRelationship:
    confidence = _coerce_confidence(item.get("confidence"), default=None)
    return MergedRelationship(
        relationship_id=_as_str(item.get("relationship_id")),
        relationship_type=_as_str(item.get("relationship_type")) or "",
        source_ref=_as_str(item.get("source_ref")) or "",
        target_ref=_as_str(item.get("target_ref")) or "",
        source_object_type=_as_str(item.get("source_object_type")),
        confidence=confidence,
        deterministic_confidence=confidence if deterministic else None,
        ai_confidences=[] if deterministic or confidence is None else [confidence],
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _merge_relationship(
    current: MergedRelationship,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedRelationship:
    conflicts = list(current.conflicts)
    provenance = list(current.provenance)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence
    ai_confidences = list(current.ai_confidences)

    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        confidence = deterministic_confidence if deterministic_confidence is not None else current.confidence
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        if ai_confidence is not None:
            ai_confidences.append(ai_confidence)

    candidate_relationship_type = _as_str(item.get("relationship_type"))
    candidate_source_ref = _as_str(item.get("source_ref"))
    candidate_target_ref = _as_str(item.get("target_ref"))
    candidate_source_object_type = _as_str(item.get("source_object_type"))

    if candidate_relationship_type and candidate_relationship_type != current.relationship_type:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="relationship type conflicts with deterministic source fact",
                deterministic_ref=current.relationship_id or current.source_ref,
                ai_ref=_as_str(item.get("relationship_id")) or candidate_relationship_type,
            )
        )
    if candidate_source_ref and candidate_source_ref != current.source_ref:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="relationship source ref conflicts with deterministic source fact",
                deterministic_ref=current.source_ref,
                ai_ref=candidate_source_ref,
            )
        )
    if candidate_target_ref and candidate_target_ref != current.target_ref:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="relationship target ref conflicts with deterministic source fact",
                deterministic_ref=current.target_ref,
                ai_ref=candidate_target_ref,
            )
        )
    if candidate_source_object_type and candidate_source_object_type != current.source_object_type:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="relationship source object type conflicts with deterministic source fact",
                deterministic_ref=current.source_object_type,
                ai_ref=candidate_source_object_type,
            )
        )

    provenance.append(_build_provenance(item, kind=kind, source_label=source_label, confidence=_coerce_confidence(item.get("confidence"), default=confidence)))
    return current.model_copy(
        update={
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "provenance": provenance,
            "conflicts": conflicts,
        }
    )


def _build_condition(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedCondition:
    confidence = _coerce_confidence(item.get("confidence"), default=1.0)
    value = _condition_value(item)
    description = _as_str(item.get("description")) or ""
    evidence = _filter_verbatim_evidence(item.get("evidence"), description)
    return MergedCondition(
        id=_as_str(item.get("id")) or "condition--unknown",
        description=description,
        value=value,
        confidence=confidence,
        tags=_as_str_list(item.get("tags")),
        on_true_refs=_as_str_list(item.get("on_true_refs")),
        on_false_refs=_as_str_list(item.get("on_false_refs")),
        evidence=evidence,
        citations=_as_str_list(item.get("citations")),
        deterministic_confidence=confidence if deterministic else None,
        ai_confidences=[] if deterministic else [confidence],
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _merge_condition(
    current: MergedCondition,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedCondition:
    conflicts = list(current.conflicts)
    provenance = list(current.provenance)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence
    ai_confidences = list(current.ai_confidences)

    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        confidence = deterministic_confidence if deterministic_confidence is not None else current.confidence
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        ai_confidences.append(ai_confidence)

    candidate_description = _as_str(item.get("description")) or ""
    candidate_value = _condition_value(item)
    candidate_true_refs = _as_str_list(item.get("on_true_refs"))
    candidate_false_refs = _as_str_list(item.get("on_false_refs"))

    if candidate_description and candidate_description != current.description:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_DESCRIPTION,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="condition description conflicts with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )
    if candidate_value != current.value:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ORDERING,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="condition branch value conflicts with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )
    if candidate_true_refs and candidate_true_refs != current.on_true_refs:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ORDERING,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="condition on_true refs conflict with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )
    if candidate_false_refs and candidate_false_refs != current.on_false_refs:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ORDERING,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="condition on_false refs conflict with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )

    merged_true_refs = list(current.on_true_refs)
    merged_false_refs = list(current.on_false_refs)
    merged_evidence = _merge_verbatim_evidence(current.evidence, item.get("evidence"), current.description)
    merged_citations = _dedupe_preserve_order(current.citations + _as_str_list(item.get("citations")))
    provenance.append(_build_provenance(item, kind=kind, source_label=source_label, confidence=_coerce_confidence(item.get("confidence"), default=confidence)))
    return current.model_copy(
        update={
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "on_true_refs": merged_true_refs,
            "on_false_refs": merged_false_refs,
            "evidence": merged_evidence,
            "citations": merged_citations,
            "provenance": provenance,
            "conflicts": conflicts,
            "tags": _dedupe_preserve_order(current.tags + _as_str_list(item.get("tags"))),
        }
    )


def _build_operator(
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedOperator:
    confidence = _coerce_confidence(item.get("confidence"), default=1.0)
    operator = _operator_value(item)
    evidence = _filter_operator_evidence(item.get("evidence"))
    return MergedOperator(
        id=_as_str(item.get("id")) or "operator--unknown",
        operator=operator,
        confidence=confidence,
        tags=_as_str_list(item.get("tags")),
        effect_refs=_as_str_list(item.get("effect_refs")),
        evidence=evidence,
        citations=_as_str_list(item.get("citations")),
        deterministic_confidence=confidence if deterministic else None,
        ai_confidences=[] if deterministic else [confidence],
        provenance=[_build_provenance(item, kind=kind, source_label=source_label, confidence=confidence)],
        conflicts=[],
    )


def _merge_operator(
    current: MergedOperator,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedOperator:
    conflicts = list(current.conflicts)
    provenance = list(current.provenance)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence
    ai_confidences = list(current.ai_confidences)

    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        confidence = deterministic_confidence if deterministic_confidence is not None else current.confidence
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        ai_confidences.append(ai_confidence)

    candidate_operator = _operator_value(item)
    if candidate_operator != current.operator:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.UNSUPPORTED_BRANCHING_OPERATOR_TYPE,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="operator conflicts with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )

    candidate_effect_refs = _as_str_list(item.get("effect_refs"))
    if candidate_effect_refs and candidate_effect_refs != current.effect_refs:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ORDERING,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="operator effect refs conflict with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )

    merged_evidence = _merge_operator_evidence(current.evidence, item.get("evidence"))
    merged_citations = _dedupe_preserve_order(current.citations + _as_str_list(item.get("citations")))
    provenance.append(_build_provenance(item, kind=kind, source_label=source_label, confidence=_coerce_confidence(item.get("confidence"), default=confidence)))
    return current.model_copy(
        update={
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "effect_refs": current.effect_refs,
            "evidence": merged_evidence,
            "citations": merged_citations,
            "provenance": provenance,
            "conflicts": conflicts,
            "tags": _dedupe_preserve_order(current.tags + _as_str_list(item.get("tags"))),
        }
    )


def _merge_action(
    current: MergedAttackAction,
    item: Mapping[str, Any],
    *,
    kind: FusionProvenanceKind,
    source_label: str,
    deterministic: bool,
) -> MergedAttackAction:
    provenance = list(current.provenance)
    conflicts = list(current.conflicts)
    ai_confidences = list(current.ai_confidences)
    confidence = current.confidence
    deterministic_confidence = current.deterministic_confidence

    if deterministic:
        if deterministic_confidence is None:
            deterministic_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        confidence = deterministic_confidence if deterministic_confidence is not None else current.confidence
    else:
        ai_confidence = _coerce_confidence(item.get("confidence"), default=current.confidence)
        ai_confidences.append(ai_confidence)
        if deterministic_confidence is None and confidence is None:
            confidence = ai_confidence

    name = current.name or (_as_str(item.get("name")) or "")
    description = current.description or (_as_str(item.get("description")) or "")

    merged_asset_refs = _dedupe_preserve_order(current.asset_refs + _as_str_list(item.get("asset_refs")))
    merged_object_refs = _dedupe_preserve_order(current.object_refs + _as_str_list(item.get("object_refs")))
    merged_effect_refs = list(current.effect_refs)
    merged_citations = _dedupe_preserve_order(current.citations + _as_str_list(item.get("citations")))
    merged_evidence = _merge_verbatim_evidence(current.evidence, item.get("evidence"), description)

    candidate_description = _as_str(item.get("description"))
    if candidate_description and candidate_description != current.description:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_DESCRIPTION,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="action description conflicts with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )

    candidate_technique = _mapping_to_dict(item.get("technique"))
    if candidate_technique is not None:
        if current.technique is None:
            conflicts.append(
                _build_conflict(
                    category=FusionConflictCategory.UNSUPPORTED_INFERRED_TECHNIQUE,
                    source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                    message="AI-derived technique is not allowed to replace or infer a deterministic no-technique step",
                    deterministic_ref=current.id,
                    ai_ref=_as_str(item.get("id")),
                )
            )
        elif candidate_technique != current.technique:
            conflicts.append(
                _build_conflict(
                    category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                    source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                    message="action technique conflicts with deterministic source fact",
                    deterministic_ref=current.id,
                    ai_ref=_as_str(item.get("id")),
                )
            )

    candidate_object_refs = _as_str_list(item.get("object_refs"))
    if candidate_object_refs and candidate_object_refs != current.object_refs:
        conflicts.append(
            _build_conflict(
                category=FusionConflictCategory.CONFLICTING_ATTACHMENT,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION if not deterministic else FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="action object refs conflict with deterministic source fact",
                deterministic_ref=current.id,
                ai_ref=_as_str(item.get("id")),
            )
        )

    for field_name in ("technique", "tactic"):
        value = _mapping_to_dict(item.get(field_name))
        if value and getattr(current, field_name) is None and deterministic_confidence is None:
            setattr(current, field_name, value)

    provenance.append(
        _build_provenance(
            item,
            kind=kind,
            source_label=source_label,
            confidence=_coerce_confidence(item.get("confidence"), default=confidence),
        )
    )
    return current.model_copy(
        update={
            "name": name,
            "description": description,
            "confidence": confidence,
            "deterministic_confidence": deterministic_confidence,
            "ai_confidences": ai_confidences,
            "asset_refs": merged_asset_refs,
            "object_refs": merged_object_refs,
            "effect_refs": merged_effect_refs,
            "citations": merged_citations,
            "evidence": merged_evidence,
            "provenance": provenance,
            "technique": current.technique,
            "tactic": current.tactic,
            "conflicts": conflicts,
        }
    )


def _attack_ref_key(item: Mapping[str, Any]) -> str | None:
    technique_id = _as_str(item.get("technique_id"))
    if technique_id:
        return f"technique_id:{technique_id}"
    technique_ref = _as_str(item.get("technique_ref"))
    if technique_ref:
        return f"technique_ref:{technique_ref}"
    return None


def _action_key(item: Mapping[str, Any]) -> str | None:
    action_id = _as_str(item.get("id"))
    if action_id:
        return f"id:{action_id}"

    description = _as_str(item.get("description"))
    if description is None or not _is_source_grounded_action(item):
        return None

    technique_key = _action_technique_key(item)
    if technique_key:
        return f"{technique_key}|description:{description}"
    return f"description:{description}"


def _relationship_key(item: Mapping[str, Any]) -> str | None:
    relationship_id = _as_str(item.get("relationship_id"))
    if relationship_id:
        return f"id:{relationship_id}"

    relationship_type = _as_str(item.get("relationship_type"))
    source_ref = _as_str(item.get("source_ref"))
    target_ref = _as_str(item.get("target_ref"))
    if not relationship_type or not source_ref or not target_ref:
        return None
    return f"{relationship_type}|{source_ref}|{target_ref}"


def _is_explicit_relationship(item: Mapping[str, Any]) -> bool:
    return bool(_relationship_key(item))


def _condition_key(item: Mapping[str, Any]) -> str | None:
    condition_id = _as_str(item.get("id"))
    if condition_id:
        return f"id:{condition_id}"
    description = _as_str(item.get("description"))
    if description is None:
        return None
    return f"description:{description}"


def _condition_value(item: Mapping[str, Any]) -> str | None:
    value = _as_str(item.get("value"))
    if value in {"true", "false"}:
        return value
    return None


def _is_source_grounded_condition(item: Mapping[str, Any]) -> bool:
    description = _as_str(item.get("description"))
    if description is None:
        return False
    return _condition_value(item) in {"true", "false"} and any(
        excerpt == description for excerpt in _extract_evidence_excerpts(item.get("evidence"))
    )


def _operator_key(item: Mapping[str, Any]) -> str | None:
    operator_id = _as_str(item.get("id"))
    if operator_id:
        return f"id:{operator_id}"
    operator = _operator_value(item)
    if operator is None:
        return None
    return f"operator:{operator}"


def _operator_value(item: Mapping[str, Any], *, allow_unknown: bool = False) -> str:
    operator = _as_str(item.get("operator"))
    if operator in {"AND", "OR"}:
        return operator
    return operator if allow_unknown and operator is not None else "UNKNOWN"


def _is_supported_operator(item: Mapping[str, Any]) -> bool:
    return _operator_value(item) in {"AND", "OR"}


def _is_source_grounded_operator(item: Mapping[str, Any]) -> bool:
    if not _is_supported_operator(item):
        return False
    return bool(_as_str_list(item.get("effect_refs")) or _extract_evidence_excerpts(item.get("evidence")))


def _filter_operator_evidence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        out.append({k: v for k, v in item.items() if isinstance(k, str)})
    return out


def _merge_operator_evidence(existing: list[dict[str, Any]], incoming: Any) -> list[dict[str, Any]]:
    merged = list(existing)
    seen = {_stable_mapping_key(item) for item in merged}
    if not isinstance(incoming, list):
        return merged
    for item in incoming:
        if not isinstance(item, Mapping):
            continue
        normalized = {k: v for k, v in item.items() if isinstance(k, str)}
        marker = _stable_mapping_key(normalized)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(normalized)
    return merged


def _build_conflict(
    *,
    category: FusionConflictCategory,
    source_kind: FusionInputSourceKind,
    message: str,
    deterministic_ref: str | None = None,
    ai_ref: str | None = None,
    ) -> FusionConflictRecord:
    return FusionConflictRecord(
        category=category,
        source_kind=source_kind,
        message=message,
        deterministic_ref=deterministic_ref,
        ai_ref=ai_ref,
        unresolved=True,
    )


def _build_allowed_object_refs(relationships: Sequence[MergedRelationship]) -> set[str]:
    allowed: set[str] = set()
    for relationship in relationships:
        if relationship.source_ref:
            allowed.add(relationship.source_ref)
        if relationship.target_ref:
            allowed.add(relationship.target_ref)
    return allowed


def _build_allowed_evidence_refs(actions: Sequence[MergedAttackAction]) -> set[str]:
    allowed: set[str] = set()
    for action in actions:
        for entry in action.evidence:
            entry_dict = _entry_to_dict(entry)
            source_object_id = _as_str(entry_dict.get("source_object_id")) if entry_dict is not None else None
            if source_object_id:
                allowed.add(source_object_id)
    return allowed


def _filter_preserved_refs(values: Sequence[str], allowed_refs: set[str]) -> list[str]:
    return [value for value in _dedupe_preserve_order(_as_str_list(values)) if value in allowed_refs]


def _filter_preserved_action_evidence(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in evidence:
        normalized = _entry_to_dict(entry)
        if normalized is None:
            continue
        marker = _stable_mapping_key(normalized)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(normalized)
    return out


def _entry_to_dict(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, Mapping):
        return {k: v for k, v in entry.items() if isinstance(k, str)}
    if isinstance(entry, BaseModel):
        dumped = entry.model_dump(mode="json")
        if isinstance(dumped, dict):
            return {k: v for k, v in dumped.items() if isinstance(k, str)}
    return None


def _action_technique_key(item: Mapping[str, Any]) -> str | None:
    technique = item.get("technique")
    if not isinstance(technique, Mapping):
        return None
    technique_id = _as_str(technique.get("technique_id"))
    if technique_id:
        return f"technique_id:{technique_id}"
    technique_ref = _as_str(technique.get("technique_ref"))
    if technique_ref:
        return f"technique_ref:{technique_ref}"
    return None


def _is_source_grounded_action(item: Mapping[str, Any]) -> bool:
    description = _as_str(item.get("description"))
    if description is None:
        return False
    return any(excerpt == description for excerpt in _extract_evidence_excerpts(item.get("evidence")))


def _extract_evidence_excerpts(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        excerpt = _as_str(item.get("excerpt"))
        if excerpt is not None:
            out.append(excerpt)
    return out


def _mapping_to_dict(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {k: v for k, v in value.items() if isinstance(k, str)}


def _filter_verbatim_evidence(value: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        excerpt = _as_str(item.get("excerpt"))
        if excerpt != description:
            continue
        out.append({k: v for k, v in item.items() if isinstance(k, str)})
    return out


def _merge_verbatim_evidence(existing: list[dict[str, Any]], incoming: Any, description: str) -> list[dict[str, Any]]:
    merged = list(existing)
    seen = {json_key for json_key in (_stable_mapping_key(item) for item in merged)}
    if not isinstance(incoming, list):
        return merged
    for item in incoming:
        if not isinstance(item, Mapping):
            continue
        excerpt = _as_str(item.get("excerpt"))
        if excerpt != description:
            continue
        normalized = {k: v for k, v in item.items() if isinstance(k, str)}
        marker = _stable_mapping_key(normalized)
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(normalized)
    return merged


def _stable_mapping_key(item: Mapping[str, Any]) -> str:
    pieces: list[str] = []
    for key in sorted(item.keys()):
        value = item[key]
        pieces.append(f"{key}={value!r}")
    return "|".join(pieces)


def _entity_key(item: Mapping[str, Any]) -> str | None:
    object_id = _as_str(item.get("object_id"))
    if object_id:
        return f"object_id:{object_id}"

    object_type = _as_str(item.get("object_type"))
    if not object_type:
        return None

    discriminator = "|".join(
        [
            object_type,
            _as_str(item.get("display_name")),
            _as_str(item.get("source_ref")),
            _as_str(item.get("target_ref")),
            _as_str(item.get("created_by_ref")),
            _as_str(item.get("pattern")),
        ]
    )
    return f"entity:{discriminator}"


def _is_explicit_attack_ref(item: Mapping[str, Any]) -> bool:
    if _attack_ref_key(item) is None:
        return False
    return any(
        _as_str(item.get(field_name))
        for field_name in ("source_object_id", "source_field", "external_source_name", "external_url")
    )


def _is_explicit_entity(item: Mapping[str, Any]) -> bool:
    if not _as_str(item.get("object_type")):
        return False
    return any(
        _as_str(item.get(field_name))
        for field_name in ("object_id", "display_name", "source_ref", "target_ref", "created_by_ref", "pattern")
    )


def _as_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate or None


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        candidate = _as_str(item)
        if candidate is not None:
            out.append(candidate)
    return out


def _coerce_confidence(value: Any, *, default: float | None) -> float:
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric < 0.0:
            return 0.0
        if numeric > 1.0:
            return 1.0
        return numeric
    if default is None:
        return 1.0
    return default


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
