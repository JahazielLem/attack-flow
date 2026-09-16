from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OrchestrationMode(str, Enum):
    FULL_EXTRACTION = "full_extraction"
    ENRICHMENT = "enrichment"


@dataclass(frozen=True, slots=True)
class SourceConstraints:
    explicit_attack_refs_only: bool = False
    no_missing_technique_inference: bool = False
    descriptions_must_be_verbatim_excerpts: bool = True
    conditions_must_be_source_grounded: bool = True
    operators_must_be_source_grounded: bool = True
    allowed_operator_values: tuple[str, str] = ("AND", "OR")
    allowed_condition_values: tuple[str, str] = ("true", "false")


@dataclass(frozen=True, slots=True)
class ProviderOrchestrationInput:
    mode: OrchestrationMode
    deterministic_input_sufficient: bool
    source_type: str
    normalized_text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    structured_summary: dict[str, Any] = field(default_factory=dict)
    deterministic_attack_refs: list[dict[str, Any]] = field(default_factory=list)
    deterministic_entities: list[dict[str, Any]] = field(default_factory=list)
    deterministic_relationships: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    constraints: SourceConstraints = field(default_factory=SourceConstraints)


def select_orchestration_mode(normalized_package: dict[str, object]) -> OrchestrationMode:
    source_type = str(normalized_package.get("source_type", "")).strip()
    if source_type == "stix_structured":
        return OrchestrationMode.ENRICHMENT
    return OrchestrationMode.FULL_EXTRACTION


def build_provider_orchestration_input(
    normalized_package: dict[str, object],
) -> ProviderOrchestrationInput:
    mode = select_orchestration_mode(normalized_package)
    source_type = str(normalized_package.get("source_type", "")).strip()
    normalized_text = _as_str(normalized_package.get("normalized_text"))
    metadata = _as_dict(normalized_package.get("metadata"))
    structured_summary = _as_dict(normalized_package.get("structured_summary"))
    attack_refs = _as_dict_list(normalized_package.get("attack_refs"))
    entities = _as_dict_list(normalized_package.get("entities"))
    relationships = _as_dict_list(normalized_package.get("relationships"))
    provenance = _as_dict(normalized_package.get("provenance"))

    # Only skip provider work when we have deterministic attack refs to seed the flow.
    deterministic_input_sufficient = mode == OrchestrationMode.ENRICHMENT and bool(attack_refs)

    return ProviderOrchestrationInput(
        mode=mode,
        deterministic_input_sufficient=deterministic_input_sufficient,
        source_type=source_type,
        normalized_text=normalized_text,
        metadata=metadata,
        structured_summary=structured_summary,
        deterministic_attack_refs=attack_refs,
        deterministic_entities=entities,
        deterministic_relationships=relationships,
        provenance=provenance,
    )


def _as_str(value: object) -> str:
    return value if isinstance(value, str) else ""


def _as_dict(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _as_dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
