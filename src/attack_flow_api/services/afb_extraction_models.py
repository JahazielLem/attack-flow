from dataclasses import asdict, dataclass, field
from typing import Literal


AttackOperator = Literal["AND", "OR"]
AttackConditionValue = Literal["true", "false"]
OrchestrationMode = Literal["full_extraction", "ai_enrichment"]
ValidationState = Literal["valid", "invalid", "repaired"]


@dataclass(frozen=True, slots=True)
class AfbEvidenceSnippet:
    source: str
    excerpt: str
    citation: str | None = None


@dataclass(frozen=True, slots=True)
class AfbActionTechnique:
    technique_id: str | None = None
    technique_name: str | None = None
    confidence: float | None = None
    grounded_by: str | None = None


@dataclass(frozen=True, slots=True)
class AfbActionTactic:
    tactic_id: str | None = None
    tactic_name: str | None = None
    confidence: float | None = None
    grounded_by: str | None = None


@dataclass(frozen=True, slots=True)
class AfbAttackAction:
    action_id: str
    description_excerpt: str
    confidence: float
    technique: AfbActionTechnique | None = None
    tactic: AfbActionTactic | None = None
    evidence: list[AfbEvidenceSnippet] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    attack_assets: list[dict[str, str]] = field(default_factory=list)
    object_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AfbAttackCondition:
    condition_id: str
    value: AttackConditionValue
    evidence: list[AfbEvidenceSnippet] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AfbAttackOperator:
    operator_id: str
    operator: AttackOperator
    evidence: list[AfbEvidenceSnippet] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AfbFlowMetadata:
    start_refs: list[str] = field(default_factory=list)
    source_classification: str | None = None
    authors: list[str] = field(default_factory=list)
    external_references: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AfbExtractionIntermediate:
    schema_version: str
    orchestration_mode: OrchestrationMode
    provider_invoked: bool
    provider_id: str | None
    model: str | None
    validation_state: ValidationState
    repair_attempted: bool
    flow_metadata: AfbFlowMetadata = field(default_factory=AfbFlowMetadata)
    attack_actions: list[AfbAttackAction] = field(default_factory=list)
    attack_conditions: list[AfbAttackCondition] = field(default_factory=list)
    attack_operators: list[AfbAttackOperator] = field(default_factory=list)
    deterministic_attack_refs: list[dict[str, str]] = field(default_factory=list)
    deterministic_entities: list[dict[str, object]] = field(default_factory=list)
    deterministic_relationships: list[dict[str, object]] = field(default_factory=list)
    provenance: dict[str, object] = field(default_factory=dict)

    def to_json_ready(self) -> dict[str, object]:
        return asdict(self)


def build_empty_afb_extraction_intermediate(
    *,
    orchestration_mode: OrchestrationMode,
    provider_invoked: bool,
    provider_id: str | None,
    model: str | None,
    source_classification: str | None,
    authors: list[str] | None = None,
    external_references: list[str] | None = None,
) -> AfbExtractionIntermediate:
    return AfbExtractionIntermediate(
        schema_version="afb-v2-intermediate",
        orchestration_mode=orchestration_mode,
        provider_invoked=provider_invoked,
        provider_id=provider_id,
        model=model,
        validation_state="valid",
        repair_attempted=False,
        flow_metadata=AfbFlowMetadata(
            source_classification=source_classification,
            authors=authors or [],
            external_references=external_references or [],
        ),
    )
