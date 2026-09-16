from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult, AttackFlowMetadata
from attack_flow_api.services.afb_extraction_contracts import FactOrigin
from attack_flow_api.services.afb_fusion_contracts import FusionConflictRecord
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedAttachmentBundle,
    MergedCondition,
    MergedEntity,
    MergedOperator,
    MergedRelationship,
    dedupe_attack_refs_deterministic_first,
    dedupe_entities_deterministic_first,
    merge_relationships_deterministic_first,
    fuse_attachment_metadata_deterministic_first,
)
from attack_flow_api.services.afb_fusion_contracts import FusionFindingProvenance, FusionProvenanceKind


class FusedOutputCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="afb-v2-fused-candidate")
    fusion_validation_state: str = Field(default="ready")

    attack_flow: AttackFlowMetadata
    attack_refs: list[MergedAttackRef] = Field(default_factory=list)
    entities: list[MergedEntity] = Field(default_factory=list)
    relationships: list[MergedRelationship] = Field(default_factory=list)
    attack_actions: list[MergedAttackAction] = Field(default_factory=list)
    attack_conditions: list[MergedCondition] = Field(default_factory=list)
    attack_operators: list[MergedOperator] = Field(default_factory=list)
    attack_assets: list[MergedEntity] = Field(default_factory=list)
    source_grounded_attachments: MergedAttachmentBundle = Field(default_factory=MergedAttachmentBundle)
    provenance: dict[str, Any] = Field(default_factory=dict)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)

    def to_json_ready(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def build_fused_output_candidate_from_sources(
    *,
    normalized_package: dict[str, Any],
    extraction_result: AfbExtractionResult,
    validation_state: str = "ready",
) -> FusedOutputCandidate:
    attack_refs = list(normalized_package.get("attack_refs") or [])
    entities = list(normalized_package.get("entities") or [])
    relationships = list(normalized_package.get("relationships") or [])
    merged_package = _normalize_source_package(normalized_package)

    merged_attack_refs = dedupe_attack_refs_deterministic_first(attack_refs, [])
    # Entities extracted from the report give action object references their
    # human-readable identity (for example, software-1 -> PowerShell).  Keep
    # deterministic source entities authoritative when both sources describe
    # the same object, while retaining AI-only report entities.
    merged_entities = dedupe_entities_deterministic_first(
        entities,
        extraction_result.deterministic_entities,
    )
    merged_relationships = merge_relationships_deterministic_first(
        relationships,
        extraction_result.deterministic_relationships,
    )

    merged_actions = _merge_extraction_items(extraction_result.attack_actions, MergedAttackAction)
    merged_assets = _merge_attack_assets(extraction_result.attack_assets)
    merged_conditions = _merge_extraction_items(extraction_result.attack_conditions, MergedCondition)
    merged_operators = _merge_extraction_items(extraction_result.attack_operators, MergedOperator)

    attachment_bundle = fuse_attachment_metadata_deterministic_first(
        deterministic_authors=merged_package["authors"],
        deterministic_external_references=merged_package["external_references"],
        attack_actions=merged_actions,
        attack_assets=merged_assets,
        relationships=merged_relationships,
    )

    return build_fused_output_candidate(
        attack_flow=extraction_result.attack_flow,
        attack_refs=merged_attack_refs,
        entities=merged_entities,
        relationships=merged_relationships,
        attack_actions=merged_actions,
        attack_conditions=merged_conditions,
        attack_operators=merged_operators,
        attachment_bundle=attachment_bundle,
        validation_state=validation_state,
        provenance=merged_package["provenance"],
        conflicts=_collect_conflicts(extraction_result.attack_actions)
        + _collect_conflicts(extraction_result.attack_conditions)
        + _collect_conflicts(extraction_result.attack_operators)
        + _collect_conflicts(attachment_bundle.attack_assets),
    )


def build_fused_output_candidate(
    *,
    attack_flow: AttackFlowMetadata,
    attack_refs: Sequence[MergedAttackRef] | None = None,
    entities: Sequence[MergedEntity] | None = None,
    relationships: Sequence[MergedRelationship] | None = None,
    attack_actions: Sequence[MergedAttackAction] | None = None,
    attack_conditions: Sequence[MergedCondition] | None = None,
    attack_operators: Sequence[MergedOperator] | None = None,
    attachment_bundle: MergedAttachmentBundle | None = None,
    validation_state: str = "ready",
    provenance: dict[str, Any] | None = None,
    conflicts: Sequence[FusionConflictRecord] | None = None,
) -> FusedOutputCandidate:
    bundle = attachment_bundle or MergedAttachmentBundle()
    merged_attack_refs = list(attack_refs or [])
    merged_entities = list(entities or [])
    merged_relationships = list(relationships or [])
    merged_actions = list(attack_actions or [])
    merged_conditions = list(attack_conditions or [])
    merged_operators = list(attack_operators or [])
    merged_conflicts = list(conflicts or [])
    merged_conflicts.extend(_collect_conflicts(merged_attack_refs))
    merged_conflicts.extend(_collect_conflicts(merged_entities))
    merged_conflicts.extend(_collect_conflicts(merged_relationships))
    merged_conflicts.extend(_collect_conflicts(merged_actions))
    merged_conflicts.extend(_collect_conflicts(merged_conditions))
    merged_conflicts.extend(_collect_conflicts(merged_operators))
    merged_conflicts.extend(_collect_conflicts(bundle.attack_assets))

    fused_attack_flow = attack_flow.model_copy(
        update={
            "authors": bundle.attack_flow_authors or attack_flow.authors,
            "external_references": bundle.attack_flow_external_references or attack_flow.external_references,
        }
    )

    return FusedOutputCandidate(
        attack_flow=fused_attack_flow,
        attack_refs=merged_attack_refs,
        entities=merged_entities,
        relationships=merged_relationships,
        attack_actions=merged_actions,
        attack_conditions=merged_conditions,
        attack_operators=merged_operators,
        attack_assets=list(bundle.attack_assets),
        source_grounded_attachments=bundle.model_copy(
            update={
                "attack_actions": merged_actions,
                "attack_assets": list(bundle.attack_assets),
            }
        ),
        fusion_validation_state=validation_state,
        provenance={
            **(provenance or {}),
            "attack_ref_source_object_ids": sorted(
                {item.source_object_id for item in merged_attack_refs if item.source_object_id is not None}
            ),
            "entity_object_ids": sorted({item.object_id for item in merged_entities if item.object_id is not None}),
            "relationship_ids": sorted(
                {item.relationship_id for item in merged_relationships if item.relationship_id is not None}
            ),
            "action_ids": sorted({item.id for item in attack_actions or []}),
            "condition_ids": sorted({item.id for item in attack_conditions or []}),
            "operator_ids": sorted({item.id for item in attack_operators or []}),
            "preserved_object_refs": list(bundle.preserved_object_refs),
            "preserved_evidence_refs": list(bundle.preserved_evidence_refs),
        },
        conflicts=_dedupe_conflicts(merged_conflicts),
    )


def _collect_conflicts(items: Sequence[BaseModel]) -> list[FusionConflictRecord]:
    collected: list[FusionConflictRecord] = []
    for item in items:
        conflicts = getattr(item, "conflicts", None)
        if not isinstance(conflicts, list):
            continue
        for conflict in conflicts:
            if isinstance(conflict, FusionConflictRecord):
                collected.append(conflict)
    return collected


def _dedupe_conflicts(conflicts: Sequence[FusionConflictRecord]) -> list[FusionConflictRecord]:
    seen: set[tuple[str, str, str | None, str | None]] = set()
    out: list[FusionConflictRecord] = []
    for conflict in conflicts:
        key = (
            conflict.category.value,
            conflict.message,
            conflict.deterministic_ref,
            conflict.ai_ref,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(conflict)
    return out


def _filter_model_dump(item: Any, target_model: type[BaseModel]) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        payload = item.model_dump(mode="json")
    elif isinstance(item, dict):
        payload = item
    else:
        payload = {}

    allowed_keys = set(target_model.model_fields.keys())
    return {key: value for key, value in payload.items() if key in allowed_keys}


def _merge_extraction_items(items: Sequence[Any], target_model: type[BaseModel]) -> list[Any]:
    merged: list[Any] = []
    for item in items:
        obj = target_model.model_validate(_filter_model_dump(item, target_model))
        if target_model is MergedAttackAction:
            obj = _ensure_attack_action_provenance(obj, item)
        elif target_model is MergedOperator:
            obj = _ensure_attack_operator_provenance(obj, item)
        merged.append(obj)
    return merged


def _merge_attack_assets(items: Sequence[Any]) -> list[MergedEntity]:
    merged: list[MergedEntity] = []
    for item in items:
        merged.append(
            MergedEntity(
                object_id=item.id,
                object_type=item.type,
                display_name=item.name,
                description=item.description,
                tags=list(item.tags),
                object_ref=item.object_ref,
                evidence=[entry.model_dump(mode="json") for entry in item.evidence],
                confidence=item.confidence,
                ai_confidences=[item.confidence],
                provenance=[
                    FusionFindingProvenance(
                        kind=(
                            FusionProvenanceKind.DETERMINISTIC
                            if item.fact_origin == FactOrigin.DETERMINISTIC_SOURCE
                            else FusionProvenanceKind.AI_DERIVED
                        ),
                        source_label=(
                            "deterministic_source"
                            if item.fact_origin == FactOrigin.DETERMINISTIC_SOURCE
                            else "ai_generated"
                        ),
                        confidence=item.confidence,
                        source_object_id=item.id,
                    )
                ],
            )
        )
    return merged


def _ensure_attack_action_provenance(action: MergedAttackAction, source_item: Any) -> MergedAttackAction:
    if action.provenance:
        return action

    fact_origin = getattr(source_item, "fact_origin", None)
    if fact_origin is None and isinstance(source_item, dict):
        fact_origin = source_item.get("fact_origin")

    if fact_origin == FactOrigin.DETERMINISTIC_SOURCE or fact_origin == FactOrigin.DETERMINISTIC_SOURCE.value:
        provenance = FusionFindingProvenance(
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label="deterministic_source",
            confidence=action.confidence,
            source_object_id=action.id,
        )
        return action.model_copy(update={"provenance": [provenance]})

    provenance = FusionFindingProvenance(
        kind=FusionProvenanceKind.AI_DERIVED,
        source_label="ai_generated",
        confidence=action.confidence,
        source_object_id=action.id,
    )
    return action.model_copy(update={"provenance": [provenance]})


def _ensure_attack_operator_provenance(operator: MergedOperator, source_item: Any) -> MergedOperator:
    if operator.provenance:
        return operator

    fact_origin = getattr(source_item, "fact_origin", None)
    if fact_origin is None and isinstance(source_item, dict):
        fact_origin = source_item.get("fact_origin")

    if fact_origin == FactOrigin.DETERMINISTIC_SOURCE or fact_origin == FactOrigin.DETERMINISTIC_SOURCE.value:
        provenance = FusionFindingProvenance(
            kind=FusionProvenanceKind.DETERMINISTIC,
            source_label="deterministic_source",
            confidence=operator.confidence,
            source_object_id=operator.id,
        )
        return operator.model_copy(update={"provenance": [provenance]})

    provenance = FusionFindingProvenance(
        kind=FusionProvenanceKind.AI_DERIVED,
        source_label="ai_generated",
        confidence=operator.confidence,
        source_object_id=operator.id,
    )
    return operator.model_copy(update={"provenance": [provenance]})


def _normalize_source_package(normalized_package: dict[str, Any]) -> dict[str, Any]:
    metadata = normalized_package.get("metadata") if isinstance(normalized_package.get("metadata"), dict) else {}
    authors = list(metadata.get("authors") or [])
    external_references = list(metadata.get("external_references") or [])

    return {
        "authors": authors,
        "external_references": external_references,
        "provenance": {
            "source_type": normalized_package.get("source_type"),
            "mode": normalized_package.get("mode"),
            "normalized_package_version": normalized_package.get("version"),
        },
    }
