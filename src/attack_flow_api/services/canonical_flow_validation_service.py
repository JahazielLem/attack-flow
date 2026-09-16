from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from attack_flow_api.services.afb_fusion_contracts import FusionConflictRecord
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowEdge,
    CanonicalFlowEdgeKind,
    CanonicalFlowNode,
    CanonicalFlowNodeKind,
    CanonicalFlowOperatorNode,
    CanonicalFlowOutput,
    CanonicalFlowProvenanceKind,
    CanonicalFlowValidationCategory,
    CanonicalFlowValidationError,
)


@dataclass(frozen=True, slots=True)
class CanonicalFlowValidationResult:
    valid: bool
    canonical_flow: CanonicalFlowOutput | None
    errors: list[CanonicalFlowValidationError] = field(default_factory=list)


class CanonicalFlowValidator:
    def validate(self, canonical_flow: CanonicalFlowOutput | dict[str, Any]) -> CanonicalFlowValidationResult:
        try:
            flow = canonical_flow if isinstance(canonical_flow, CanonicalFlowOutput) else CanonicalFlowOutput.model_validate(canonical_flow)
        except ValidationError as exc:
            return CanonicalFlowValidationResult(
                valid=False,
                canonical_flow=None,
                errors=[
                    CanonicalFlowValidationError(
                        code="canonical_flow_schema_invalid",
                        message=str(exc),
                        category=CanonicalFlowValidationCategory.INVALID_REFERENCE,
                    )
                ],
            )

        errors: list[CanonicalFlowValidationError] = []
        self._validate_metadata(flow, errors)
        node_index = self._validate_nodes(flow, errors)
        self._validate_attack_refs(flow, node_index, errors)
        self._validate_attachments(flow, node_index, errors)
        self._validate_edges(flow, node_index, errors)
        self._validate_start_refs(flow, node_index, errors)

        return CanonicalFlowValidationResult(valid=not errors, canonical_flow=flow if not errors else None, errors=errors)

    def _validate_metadata(self, flow: CanonicalFlowOutput, errors: list[CanonicalFlowValidationError]) -> None:
        metadata = flow.metadata
        if not metadata.flow_id.strip():
            errors.append(_error("flow_metadata_missing", "flow_id is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
        if not metadata.name.strip():
            errors.append(_error("flow_metadata_missing", "name is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
        if not metadata.scope.strip():
            errors.append(_error("flow_metadata_missing", "scope is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
        if not isinstance(metadata.start_refs, list):
            errors.append(_error("flow_metadata_invalid", "start_refs must be a list", CanonicalFlowValidationCategory.INVALID_REFERENCE))

    def _validate_nodes(
        self,
        flow: CanonicalFlowOutput,
        errors: list[CanonicalFlowValidationError],
    ) -> dict[str, CanonicalFlowNode]:
        node_index: dict[str, CanonicalFlowNode] = {}
        for node in flow.nodes:
            if node.id in node_index:
                errors.append(_error("duplicate_node_id", f"duplicate node id: {node.id}", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
                continue
            node_index[node.id] = node

            self._validate_node_common(node, errors)
            if isinstance(node, CanonicalFlowActionNode):
                self._validate_action_node(node, errors)
            elif isinstance(node, CanonicalFlowConditionNode):
                self._validate_condition_node(node, errors)
            elif isinstance(node, CanonicalFlowOperatorNode):
                self._validate_operator_node(node, errors)
            elif isinstance(node, CanonicalFlowAssetNode):
                self._validate_asset_node(node, errors)
            else:
                errors.append(_error("unsupported_node_type", f"unsupported node type: {type(node).__name__}", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=getattr(node, "id", None)))
        return node_index

    def _validate_node_common(self, node: CanonicalFlowNode, errors: list[CanonicalFlowValidationError]) -> None:
        if not node.id.strip():
            errors.append(_error("node_missing_id", "node id is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
        if not isinstance(node.provenance, list):
            errors.append(_error("node_invalid_provenance", "node provenance must be a list", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if not isinstance(node.conflicts, list):
            errors.append(_error("node_invalid_conflicts", "node conflicts must be a list", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if node.description is not None and not node.description.strip():
            errors.append(_error("node_empty_description", "node description must not be blank", CanonicalFlowValidationCategory.NON_VERBATIM_DESCRIPTION, node_id=node.id))

    def _validate_action_node(self, node: CanonicalFlowActionNode, errors: list[CanonicalFlowValidationError]) -> None:
        if node.technique is not None:
            if node.technique.confidence is None:
                errors.append(_error("action_technique_missing_confidence", "technique confidence is required when technique mapping exists", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
            if not node.technique.provenance:
                errors.append(_error("action_technique_missing_provenance", "technique provenance is required when technique mapping exists", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
            if any(item.source_kind == CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT for item in node.technique.provenance) and node.technique.confidence != 1.0:
                errors.append(_error("deterministic_technique_confidence_not_default", "deterministic ATT&CK refs must retain default confidence 1.0", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if node.description and node.evidence:
            excerpts = {item.excerpt for item in node.evidence}
            if node.description not in excerpts:
                errors.append(_error("action_description_not_verbatim", "action description must match a verbatim evidence excerpt", CanonicalFlowValidationCategory.NON_VERBATIM_DESCRIPTION, node_id=node.id))
        if not node.provenance:
            errors.append(_error("action_missing_provenance", "action provenance is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if not node.evidence:
            errors.append(_error("action_missing_evidence", "action evidence is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))

    def _validate_condition_node(self, node: CanonicalFlowConditionNode, errors: list[CanonicalFlowValidationError]) -> None:
        if node.condition_value not in {"true", "false"}:
            errors.append(_error("condition_invalid_value", "condition value must be true or false", CanonicalFlowValidationCategory.UNSUPPORTED_CONDITION_VALUE, node_id=node.id))
        if node.description and node.evidence:
            excerpts = {item.excerpt for item in node.evidence}
            if node.description not in excerpts:
                errors.append(_error("condition_description_not_verbatim", "condition description must match a verbatim evidence excerpt", CanonicalFlowValidationCategory.NON_VERBATIM_DESCRIPTION, node_id=node.id))
        if not node.provenance:
            errors.append(_error("condition_missing_provenance", "condition provenance is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if not node.evidence:
            errors.append(_error("condition_missing_evidence", "condition evidence is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))

    def _validate_operator_node(self, node: CanonicalFlowOperatorNode, errors: list[CanonicalFlowValidationError]) -> None:
        if node.operator not in {"AND", "OR"}:
            errors.append(_error("operator_invalid_value", "operator must be AND or OR", CanonicalFlowValidationCategory.UNSUPPORTED_OPERATOR_TYPE, node_id=node.id))
        if not node.provenance:
            errors.append(_error("operator_missing_provenance", "operator provenance is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))
        if not node.evidence:
            errors.append(_error("operator_missing_evidence", "operator evidence is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, node_id=node.id))

    def _validate_asset_node(self, node: CanonicalFlowAssetNode, errors: list[CanonicalFlowValidationError]) -> None:
        if node.object_ref is not None and not node.object_ref.strip():
            errors.append(_error("asset_invalid_object_ref", "asset object_ref must not be blank", CanonicalFlowValidationCategory.NON_SOURCE_GROUNDED_ATTACHMENT, node_id=node.id))
        if not node.provenance and node.object_ref is not None:
            errors.append(_error("asset_missing_provenance", "asset provenance is required when object_ref is present", CanonicalFlowValidationCategory.NON_SOURCE_GROUNDED_ATTACHMENT, node_id=node.id))

    def _validate_attack_refs(
        self,
        flow: CanonicalFlowOutput,
        node_index: dict[str, CanonicalFlowNode],
        errors: list[CanonicalFlowValidationError],
    ) -> None:
        for ref in flow.attack_refs:
            if ref.confidence is None:
                errors.append(_error("attack_ref_missing_confidence", "attack ref confidence is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
            if not ref.provenance:
                errors.append(_error("attack_ref_missing_provenance", "attack ref provenance is required", CanonicalFlowValidationCategory.INVALID_REFERENCE))
            if any(item.source_kind == CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT for item in ref.provenance) and ref.confidence != 1.0:
                errors.append(_error("attack_ref_confidence_not_default", "deterministic attack refs must preserve default confidence 1.0", CanonicalFlowValidationCategory.INVALID_REFERENCE))
            if ref.technique_id is None and ref.technique_ref is None and ref.technique_name is None:
                errors.append(_error("attack_ref_missing_identifier", "attack ref must include technique_id, technique_ref, or technique_name", CanonicalFlowValidationCategory.INVALID_REFERENCE))

    def _validate_attachments(
        self,
        flow: CanonicalFlowOutput,
        node_index: dict[str, CanonicalFlowNode],
        errors: list[CanonicalFlowValidationError],
    ) -> None:
        asset_ids = {node.id for node in node_index.values() if node.node_kind == CanonicalFlowNodeKind.ATTACK_ASSET}
        asset_object_refs = {
            node.object_ref for node in node_index.values() if node.node_kind == CanonicalFlowNodeKind.ATTACK_ASSET and node.object_ref
        }
        allowed_attachment_refs = asset_ids | asset_object_refs

        for node in flow.nodes:
            if node.node_kind != CanonicalFlowNodeKind.ATTACK_ACTION:
                continue
            for ref in node.asset_refs + node.object_refs:
                if ref not in allowed_attachment_refs:
                    errors.append(
                        _error(
                            "non_source_grounded_attachment",
                            f"attachment ref must target a known asset node or object_ref: {ref}",
                            CanonicalFlowValidationCategory.NON_SOURCE_GROUNDED_ATTACHMENT,
                            node_id=node.id,
                        )
                    )

    def _validate_edges(
        self,
        flow: CanonicalFlowOutput,
        node_index: dict[str, CanonicalFlowNode],
        errors: list[CanonicalFlowValidationError],
    ) -> None:
        for edge in flow.edges:
            if not edge.source_ref.strip():
                errors.append(_error("edge_missing_source", "edge source_ref is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
            if not edge.target_ref.strip():
                errors.append(_error("edge_missing_target", "edge target_ref is required", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
            if edge.edge_type == CanonicalFlowEdgeKind.RELATIONSHIP and not edge.relationship_type:
                errors.append(_error("relationship_edge_missing_type", "relationship edges require relationship_type", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))

            source = node_index.get(edge.source_ref)
            target = node_index.get(edge.target_ref)
            if edge.edge_type != CanonicalFlowEdgeKind.RELATIONSHIP:
                if source is None:
                    errors.append(_error("edge_source_missing_node", f"edge source does not reference an existing node: {edge.source_ref}", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
                if target is None:
                    errors.append(_error("edge_target_missing_node", f"edge target does not reference an existing node: {edge.target_ref}", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
            if source is not None and target is not None:
                self._validate_edge_semantics(edge, source, target, errors)

    def _validate_edge_semantics(
        self,
        edge: CanonicalFlowEdge,
        source: CanonicalFlowNode,
        target: CanonicalFlowNode,
        errors: list[CanonicalFlowValidationError],
    ) -> None:
        if edge.edge_type == CanonicalFlowEdgeKind.START:
            errors.append(_error("unexpected_start_edge", "start edges are represented via metadata.start_refs", CanonicalFlowValidationCategory.INVALID_SEQUENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
        if source.node_kind == CanonicalFlowNodeKind.ATTACK_OPERATOR and edge.edge_type not in {CanonicalFlowEdgeKind.EFFECT, CanonicalFlowEdgeKind.RELATIONSHIP}:
            errors.append(_error("invalid_operator_edge", "operator nodes may only emit effect or relationship edges", CanonicalFlowValidationCategory.INVALID_SEQUENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))
        if source.node_kind == CanonicalFlowNodeKind.ATTACK_CONDITION and edge.edge_type not in {CanonicalFlowEdgeKind.TRUE_BRANCH, CanonicalFlowEdgeKind.FALSE_BRANCH, CanonicalFlowEdgeKind.RELATIONSHIP}:
            errors.append(_error("invalid_condition_edge", "condition nodes may only emit true/false or relationship edges", CanonicalFlowValidationCategory.INVALID_SEQUENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))

        if source.node_kind == CanonicalFlowNodeKind.ATTACK_ACTION and edge.edge_type == CanonicalFlowEdgeKind.ASSET:
            if target.node_kind != CanonicalFlowNodeKind.ATTACK_ASSET:
                errors.append(_error("action_asset_edge_target_invalid", "asset edges must target asset nodes", CanonicalFlowValidationCategory.INVALID_REFERENCE, edge_id=f"{edge.source_ref}->{edge.target_ref}"))

    def _validate_start_refs(
        self,
        flow: CanonicalFlowOutput,
        node_index: dict[str, CanonicalFlowNode],
        errors: list[CanonicalFlowValidationError],
    ) -> None:
        for ref in flow.metadata.start_refs:
            node = node_index.get(ref)
            if node is None:
                errors.append(_error("start_ref_missing_node", f"start ref does not reference an existing node: {ref}", CanonicalFlowValidationCategory.INVALID_REFERENCE))
                continue
            if node.node_kind not in {CanonicalFlowNodeKind.ATTACK_ACTION, CanonicalFlowNodeKind.ATTACK_CONDITION}:
                errors.append(_error("start_ref_invalid_node_kind", f"start refs may only point to action or condition nodes: {ref}", CanonicalFlowValidationCategory.INVALID_SEQUENCE))


def validate_canonical_flow_output(canonical_flow: CanonicalFlowOutput | dict[str, Any]) -> CanonicalFlowValidationResult:
    return CanonicalFlowValidator().validate(canonical_flow)


def _error(
    code: str,
    message: str,
    category: CanonicalFlowValidationCategory,
    *,
    node_id: str | None = None,
    edge_id: str | None = None,
) -> CanonicalFlowValidationError:
    return CanonicalFlowValidationError(
        code=code,
        message=message,
        category=category,
        node_id=node_id,
        edge_id=edge_id,
    )
