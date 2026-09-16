import json
from dataclasses import dataclass
from typing import Any
from typing import Literal
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from attack_flow.schema import ATTACK_FLOW_EXTENSION_ID
from attack_flow_api.services.canonical_flow_contracts import CanonicalFlowOutput
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowOperatorNode,
)


class StixExportValidationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    object_ref: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class StixExportBundleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["bundle"] = "bundle"
    id: str = Field(min_length=1)
    spec_version: Literal["2.1"] = "2.1"
    object_count: int = Field(default=0, ge=0)
    authors: list[str] = Field(default_factory=list)
    external_references: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    supporting_object_refs: list[str] = Field(default_factory=list)


class StixExportObjectCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objects: list[dict[str, Any]] = Field(default_factory=list)


class StixExportBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metadata: StixExportBundleMetadata
    objects: StixExportObjectCollection = Field(default_factory=StixExportObjectCollection)
    validation_errors: list[StixExportValidationError] = Field(default_factory=list)

    def to_json_ready(self) -> dict[str, Any]:
        return {
            "type": self.metadata.type,
            "id": self.metadata.id,
            "spec_version": self.metadata.spec_version,
            "objects": list(self.objects.objects),
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_json_ready(), sort_keys=True, separators=(",", ":")).encode("utf-8")


class StixExportAttackFlowObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-flow"] = "attack-flow"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    scope: str = Field(min_length=1)
    start_refs: list[str] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class StixExportAttackActionObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-action"] = "attack-action"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    technique_id: str | None = None
    technique_ref: str | None = None
    tactic_id: str | None = None
    tactic_ref: str | None = None
    asset_refs: list[str] = Field(default_factory=list)
    effect_refs: list[str] = Field(default_factory=list)
    execution_start: str | None = None
    execution_end: str | None = None
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class StixExportAttackConditionObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-condition"] = "attack-condition"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    description: str | None = None
    on_true_refs: list[str] = Field(default_factory=list)
    on_false_refs: list[str] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class StixExportAttackOperatorObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-operator"] = "attack-operator"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    operator: Literal["AND", "OR"]
    effect_refs: list[str] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class StixExportAttackAssetObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-asset"] = "attack-asset"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    object_ref: str | None = None
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StixExportValidationResult:
    valid: bool
    errors: list[StixExportValidationError]
    bundle_id: str
    object_count: int


def build_attack_flow_root_object(canonical_flow: CanonicalFlowOutput, *, extension_id: str = ATTACK_FLOW_EXTENSION_ID) -> StixExportAttackFlowObject:
    metadata = canonical_flow.metadata
    extensions = {extension_id: {"extension_type": "new-sdo"}}
    description = _coerce_root_description(metadata.description)
    return StixExportAttackFlowObject(
        id=metadata.flow_id,
        name=metadata.name,
        description=description,
        scope=metadata.scope,
        start_refs=[],
        external_references=_build_external_reference_objects(metadata.external_references),
        extensions=extensions,
    )


def build_attack_action_objects(canonical_flow: CanonicalFlowOutput) -> list[StixExportAttackActionObject]:
    action_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowActionNode)]
    return [_build_attack_action_object(node) for node in action_nodes]


def _build_attack_action_object(node: Any, *, extension_id: str = ATTACK_FLOW_EXTENSION_ID) -> StixExportAttackActionObject:
    extensions = {extension_id: {"extension_type": "new-sdo"}}
    description = _coerce_root_description(getattr(node, "description", None))
    technique = getattr(node, "technique", None)
    return StixExportAttackActionObject(
        id=node.id,
        name=node.name or node.id,
        description=description,
        technique_id=_coerce_non_empty_str(getattr(technique, "technique_id", None)),
        technique_ref=_coerce_non_empty_str(getattr(technique, "technique_ref", None)),
        tactic_id=_coerce_non_empty_str(getattr(node, "tactic_id", None)),
        tactic_ref=_coerce_non_empty_str(getattr(node, "tactic_ref", None)),
        asset_refs=_coerce_string_list(getattr(node, "asset_refs", None)),
        effect_refs=_coerce_string_list(getattr(node, "effect_refs", None)),
        extensions=extensions,
    )


def build_attack_condition_objects(canonical_flow: CanonicalFlowOutput) -> list[StixExportAttackConditionObject]:
    condition_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowConditionNode)]
    return [_build_attack_condition_object(node) for node in condition_nodes]


def _build_attack_condition_object(
    node: CanonicalFlowConditionNode,
    *,
    extension_id: str = ATTACK_FLOW_EXTENSION_ID,
) -> StixExportAttackConditionObject:
    return StixExportAttackConditionObject(
        id=node.id,
        description=_coerce_root_description(node.description),
        on_true_refs=_coerce_string_list(node.on_true_refs),
        on_false_refs=_coerce_string_list(node.on_false_refs),
        extensions={extension_id: {"extension_type": "new-sdo"}},
    )


def build_attack_operator_objects(canonical_flow: CanonicalFlowOutput) -> list[StixExportAttackOperatorObject]:
    operator_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowOperatorNode)]
    return [_build_attack_operator_object(node) for node in operator_nodes]


def _build_attack_operator_object(
    node: CanonicalFlowOperatorNode,
    *,
    extension_id: str = ATTACK_FLOW_EXTENSION_ID,
) -> StixExportAttackOperatorObject:
    return StixExportAttackOperatorObject(
        id=node.id,
        operator=node.operator.value if hasattr(node.operator, "value") else node.operator,
        effect_refs=_coerce_string_list(node.effect_refs),
        extensions={extension_id: {"extension_type": "new-sdo"}},
    )


def build_attack_asset_objects(canonical_flow: CanonicalFlowOutput) -> list[StixExportAttackAssetObject]:
    asset_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowAssetNode)]
    return [_build_attack_asset_object(node) for node in asset_nodes]


def build_stix_export_objects(canonical_flow: CanonicalFlowOutput) -> list[Any]:
    return [
        build_attack_flow_root_object(canonical_flow),
        *build_attack_action_objects(canonical_flow),
        *build_attack_condition_objects(canonical_flow),
        *build_attack_operator_objects(canonical_flow),
        *build_attack_asset_objects(canonical_flow),
    ]


def _build_attack_asset_object(
    node: CanonicalFlowAssetNode,
    *,
    extension_id: str = ATTACK_FLOW_EXTENSION_ID,
) -> StixExportAttackAssetObject:
    return StixExportAttackAssetObject(
        id=node.id,
        name=node.name or node.id,
        description=_coerce_root_description(node.description),
        object_ref=_coerce_non_empty_str(node.object_ref),
        extensions={extension_id: {"extension_type": "new-sdo"}},
    )


def assemble_stix_export_bundle(canonical_flow: CanonicalFlowOutput) -> StixExportBundle:
    bundle_id = _build_deterministic_bundle_id(canonical_flow.metadata.flow_id)
    export_objects = build_stix_export_objects(canonical_flow)
    _normalize_export_object_refs(export_objects)
    root_object = export_objects[0]
    root_object.start_refs = _normalize_export_ref_list(canonical_flow.metadata.start_refs, _first_export_target_id(export_objects))

    bundle = build_stix_export_bundle(
        bundle_id,
        canonical_flow=canonical_flow,
    )
    bundle.metadata.object_count = len(export_objects)
    bundle.objects.objects = [obj.model_dump(mode="json") for obj in export_objects]

    validation = validate_stix_export_bundle(bundle)
    bundle.validation_errors = list(validation.errors)
    return bundle


def validate_stix_export_bundle(bundle: StixExportBundle) -> StixExportValidationResult:
    errors: list[StixExportValidationError] = []

    _validate_bundle_header(bundle, errors)
    object_index = _validate_export_objects(bundle, errors)
    _validate_object_references(bundle, object_index, errors)

    return StixExportValidationResult(
        valid=not errors,
        errors=errors,
        bundle_id=bundle.metadata.id,
        object_count=len(bundle.objects.objects),
    )


def _coerce_root_description(description: str | None) -> str | None:
    if description is None:
        return None
    stripped = description.strip()
    return stripped or None


def _coerce_non_empty_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _coerce_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if stripped:
            output.append(stripped)
    return output


class StixExportArtifactMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_state: str = Field(default="pending")
    bundle_id: str | None = None
    object_count: int | None = None
    exported_at: str | None = None
    export_status: str = Field(default="pending")
    error_code: str | None = None
    error_message: str | None = None
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)


def build_stix_export_bundle_metadata(
    bundle_id: str,
    canonical_flow: CanonicalFlowOutput | None = None,
) -> StixExportBundleMetadata:
    if canonical_flow is None:
        return StixExportBundleMetadata(id=bundle_id)

    supporting_object_refs = _build_supporting_object_refs(canonical_flow)
    return StixExportBundleMetadata(
        id=bundle_id,
        authors=list(canonical_flow.metadata.authors),
        external_references=list(canonical_flow.metadata.external_references),
        provenance=dict(canonical_flow.provenance),
        supporting_object_refs=supporting_object_refs,
    )


def build_stix_export_bundle(
    bundle_id: str,
    canonical_flow: CanonicalFlowOutput | None = None,
) -> StixExportBundle:
    return StixExportBundle(metadata=build_stix_export_bundle_metadata(bundle_id, canonical_flow=canonical_flow))


def _build_external_reference_objects(external_references: list[str]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for reference in external_references:
        if not reference.strip():
            continue
        parsed = urlparse(reference)
        if parsed.scheme and (parsed.netloc or parsed.path):
            refs.append({"source_name": parsed.netloc or parsed.path or reference, "url": reference})
            continue
        refs.append({"source_name": reference, "description": reference})
    return refs


def _build_supporting_object_refs(canonical_flow: CanonicalFlowOutput) -> list[str]:
    refs: list[str] = []
    for node in canonical_flow.nodes:
        if isinstance(node, CanonicalFlowAssetNode) and node.object_ref:
            ref = _coerce_non_empty_str(node.object_ref)
            if ref is not None:
                refs.append(ref)
    return _dedupe_preserve_order(refs)


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _build_deterministic_bundle_id(flow_id: str) -> str:
    return f"bundle--{uuid5(NAMESPACE_URL, f'attack-flow-export:{flow_id}')}"


def _filter_valid_start_refs(start_refs: list[str], export_objects: list[Any]) -> list[str]:
    allowed_ids = {
        obj.id
        for obj in export_objects
        if isinstance(obj, (StixExportAttackActionObject, StixExportAttackConditionObject))
    }
    exemplar_id = next(iter(allowed_ids), None)
    return [ref for ref in _normalize_export_ref_list(_coerce_string_list(start_refs), exemplar_id) if ref in allowed_ids]


def _normalize_export_object_refs(export_objects: list[Any]) -> None:
    target_id = _first_export_target_id(export_objects)
    for obj in export_objects:
        if isinstance(obj, StixExportAttackActionObject):
            obj.asset_refs = _normalize_export_ref_list(obj.asset_refs, target_id)
            obj.effect_refs = _normalize_export_ref_list(obj.effect_refs, target_id)
        elif isinstance(obj, StixExportAttackConditionObject):
            obj.on_true_refs = _normalize_export_ref_list(obj.on_true_refs, target_id)
            obj.on_false_refs = _normalize_export_ref_list(obj.on_false_refs, target_id)
        elif isinstance(obj, StixExportAttackOperatorObject):
            obj.effect_refs = _normalize_export_ref_list(obj.effect_refs, target_id)
        elif isinstance(obj, StixExportAttackFlowObject) and target_id is not None:
            obj.start_refs = _normalize_export_ref_list(obj.start_refs, target_id)


def _first_export_target_id(export_objects: list[Any]) -> str | None:
    for obj in export_objects:
        if isinstance(obj, (StixExportAttackActionObject, StixExportAttackConditionObject)):
            return obj.id
    return None


def _normalize_export_ref_list(refs: list[str], exemplar_id: str | None) -> list[str]:
    return [_normalize_export_ref(ref, exemplar_id) for ref in refs]


def _normalize_export_ref(ref: str, exemplar_id: str | None) -> str:
    if not isinstance(ref, str) or not ref:
        return ref
    if exemplar_id is None:
        return ref
    exemplar_long = exemplar_id.startswith("attack-") and "--" in exemplar_id
    prefix, separator, suffix = ref.partition("--")
    if not separator:
        if exemplar_long:
            short_prefix, short_sep, short_suffix = ref.partition("-")
            if not short_sep:
                return ref
            mapped_prefix = {
                "action": "attack-action",
                "condition": "attack-condition",
                "operator": "attack-operator",
                "asset": "attack-asset",
            }.get(short_prefix)
            if mapped_prefix is None:
                return ref
            return f"{mapped_prefix}--{short_suffix}"
        return ref
    if exemplar_long:
        return ref
    mapped_prefix = {
        "attack-action": "action",
        "attack-condition": "condition",
        "attack-operator": "operator",
        "attack-asset": "asset",
    }.get(prefix)
    if mapped_prefix is None:
        return ref
    return f"{mapped_prefix}-{suffix}"


def _validate_bundle_header(bundle: StixExportBundle, errors: list[StixExportValidationError]) -> None:
    if bundle.metadata.type != "bundle":
        errors.append(_validation_error("bundle_type_invalid", "bundle type must be 'bundle'"))
    if bundle.metadata.spec_version != "2.1":
        errors.append(_validation_error("bundle_spec_version_invalid", "bundle spec_version must be '2.1'"))
    if not bundle.metadata.id.startswith("bundle--"):
        errors.append(_validation_error("bundle_id_invalid", "bundle id must start with 'bundle--'"))
    if not isinstance(bundle.objects.objects, list):
        errors.append(_validation_error("bundle_objects_invalid", "bundle objects must be a list"))


def _validate_export_objects(
    bundle: StixExportBundle,
    errors: list[StixExportValidationError],
) -> dict[str, dict[str, Any]]:
    object_index: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    root_seen = False

    for item in bundle.objects.objects:
        if not isinstance(item, dict):
            errors.append(_validation_error("bundle_object_invalid", "bundle object entries must be JSON objects"))
            continue

        object_type = _coerce_non_empty_str(item.get("type"))
        object_id = _coerce_non_empty_str(item.get("id"))
        if object_type is None or object_id is None:
            errors.append(_validation_error("bundle_object_missing_fields", "bundle objects require type and id", object_ref=object_id))
            continue

        if object_id in seen_ids:
            errors.append(_validation_error("bundle_object_duplicate_id", f"duplicate exported object id: {object_id}", object_ref=object_id))
            continue
        seen_ids.add(object_id)
        object_index[object_id] = item

        if object_type == "attack-flow":
            root_seen = True
            _validate_attack_flow_object(item, errors)
        elif object_type == "attack-action":
            _validate_attack_action_object(item, errors)
        elif object_type == "attack-condition":
            _validate_attack_condition_object(item, errors)
        elif object_type == "attack-operator":
            _validate_attack_operator_object(item, errors)
        elif object_type == "attack-asset":
            _validate_attack_asset_object(item, errors)

    if not root_seen:
        errors.append(_validation_error("attack_flow_missing", "bundle must contain exactly one attack-flow object"))

    return object_index


def _validate_attack_flow_object(item: dict[str, Any], errors: list[StixExportValidationError]) -> None:
    for field_name in ("id", "name", "scope", "start_refs"):
        if field_name not in item:
            errors.append(_validation_error("attack_flow_field_missing", f"attack-flow object missing required field: {field_name}", object_ref=_coerce_non_empty_str(item.get("id"))))

    extensions = item.get("extensions")
    if not isinstance(extensions, dict) or ATTACK_FLOW_EXTENSION_ID not in extensions:
        errors.append(_validation_error("attack_flow_extension_missing", "attack-flow object must include the Attack Flow extension reference", object_ref=_coerce_non_empty_str(item.get("id"))))

    start_refs = item.get("start_refs")
    if not isinstance(start_refs, list):
        errors.append(_validation_error("attack_flow_start_refs_invalid", "attack-flow start_refs must be a list", object_ref=_coerce_non_empty_str(item.get("id"))))


def _validate_attack_action_object(item: dict[str, Any], errors: list[StixExportValidationError]) -> None:
    if not isinstance(item.get("name"), str) or not item.get("name", "").strip():
        errors.append(_validation_error("attack_action_name_invalid", "attack-action name must be a non-empty string", object_ref=_coerce_non_empty_str(item.get("id"))))
    if item.get("description") is not None and (not isinstance(item.get("description"), str) or not item.get("description", "").strip()):
        errors.append(_validation_error("attack_action_description_invalid", "attack-action description must be a non-empty string when present", object_ref=_coerce_non_empty_str(item.get("id"))))


def _validate_attack_condition_object(item: dict[str, Any], errors: list[StixExportValidationError]) -> None:
    description = item.get("description")
    if description is not None and (not isinstance(description, str) or not description.strip()):
        errors.append(_validation_error("attack_condition_description_invalid", "attack-condition description must be a non-empty string when present", object_ref=_coerce_non_empty_str(item.get("id"))))
    for field_name in ("on_true_refs", "on_false_refs"):
        refs = item.get(field_name)
        if refs is not None and not isinstance(refs, list):
            errors.append(_validation_error("attack_condition_refs_invalid", f"{field_name} must be a list when present", object_ref=_coerce_non_empty_str(item.get("id"))))


def _validate_attack_operator_object(item: dict[str, Any], errors: list[StixExportValidationError]) -> None:
    if item.get("operator") not in {"AND", "OR"}:
        errors.append(_validation_error("attack_operator_invalid", "attack-operator must use AND or OR", object_ref=_coerce_non_empty_str(item.get("id"))))
    refs = item.get("effect_refs")
    if refs is not None and not isinstance(refs, list):
        errors.append(_validation_error("attack_operator_refs_invalid", "attack-operator effect_refs must be a list when present", object_ref=_coerce_non_empty_str(item.get("id"))))


def _validate_attack_asset_object(item: dict[str, Any], errors: list[StixExportValidationError]) -> None:
    if not isinstance(item.get("name"), str) or not item.get("name", "").strip():
        errors.append(_validation_error("attack_asset_name_invalid", "attack-asset name must be a non-empty string", object_ref=_coerce_non_empty_str(item.get("id"))))
    if item.get("object_ref") is not None and not isinstance(item.get("object_ref"), str):
        errors.append(_validation_error("attack_asset_object_ref_invalid", "attack-asset object_ref must be a string when present", object_ref=_coerce_non_empty_str(item.get("id"))))


def _validate_object_references(
    bundle: StixExportBundle,
    object_index: dict[str, dict[str, Any]],
    errors: list[StixExportValidationError],
) -> None:
    exported_ids = set(object_index)
    attack_asset_ids = {object_id for object_id, item in object_index.items() if item.get("type") == "attack-asset"}
    supporting_refs = set(bundle.metadata.supporting_object_refs)

    flow = next((item for item in object_index.values() if item.get("type") == "attack-flow"), None)
    if isinstance(flow, dict):
        for ref in _coerce_string_list(flow.get("start_refs")):
            if ref not in exported_ids:
                errors.append(_validation_error("attack_flow_start_ref_invalid", f"attack-flow start_ref does not target an exported object: {ref}", object_ref=ref))
            elif object_index[ref].get("type") not in {"attack-action", "attack-condition"}:
                errors.append(_validation_error("attack_flow_start_ref_type_invalid", f"attack-flow start_ref must target an attack-action or attack-condition: {ref}", object_ref=ref))

    for object_id, item in object_index.items():
        object_type = item.get("type")
        if object_type == "attack-action":
            for ref in _coerce_string_list(item.get("asset_refs")):
                if ref not in attack_asset_ids:
                    errors.append(_validation_error("attack_action_asset_ref_invalid", f"attack-action asset_ref does not target an exported attack-asset: {ref}", object_ref=object_id, details={"target_ref": ref}))
            for ref in _coerce_string_list(item.get("effect_refs")):
                if ref not in exported_ids:
                    errors.append(_validation_error("attack_action_effect_ref_invalid", f"attack-action effect_ref does not target an exported object: {ref}", object_ref=object_id, details={"target_ref": ref}))
        elif object_type == "attack-condition":
            for field_name in ("on_true_refs", "on_false_refs"):
                for ref in _coerce_string_list(item.get(field_name)):
                    if ref not in exported_ids:
                        errors.append(_validation_error("attack_condition_ref_invalid", f"attack-condition {field_name} does not target an exported object: {ref}", object_ref=object_id, details={"target_ref": ref, "field": field_name}))
        elif object_type == "attack-operator":
            for ref in _coerce_string_list(item.get("effect_refs")):
                if ref not in exported_ids:
                    errors.append(_validation_error("attack_operator_ref_invalid", f"attack-operator effect_ref does not target an exported object: {ref}", object_ref=object_id, details={"target_ref": ref}))
        elif object_type == "attack-asset":
            object_ref = _coerce_non_empty_str(item.get("object_ref"))
            if object_ref is not None and supporting_refs and object_ref not in supporting_refs:
                errors.append(_validation_error("attack_asset_object_ref_unregistered", f"attack-asset object_ref is not registered in bundle metadata: {object_ref}", object_ref=object_id, details={"target_ref": object_ref}))


def _validation_error(
    code: str,
    message: str,
    *,
    object_ref: str | None = None,
    details: dict[str, Any] | None = None,
) -> StixExportValidationError:
    return StixExportValidationError(
        code=code,
        message=message,
        object_ref=object_ref,
        details=details or {},
    )
