from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class OrchestrationMode(str, Enum):
    FULL_EXTRACTION = "full_extraction"
    AI_ENRICHMENT = "ai_enrichment"


class SourceClassification(str, Enum):
    NARRATIVE_TEXT = "narrative_text"
    URL_EXTRACTED_TEXT = "url_extracted_text"
    DOCUMENT_EXTRACTED_TEXT = "document_extracted_text"
    STIX_STRUCTURED = "stix_structured"
    MIXED = "mixed"


class AttackOperatorType(str, Enum):
    AND = "AND"
    OR = "OR"


class ConditionValue(str, Enum):
    TRUE = "true"
    FALSE = "false"


class ExtractionValidationState(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    REPAIRED = "repaired"


class FactOrigin(str, Enum):
    DETERMINISTIC_SOURCE = "deterministic_source"
    AI_GENERATED = "ai_generated"


class EvidenceCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    excerpt: str = Field(min_length=1)
    citation: str | None = None
    source_object_id: str | None = None
    source_field: str | None = None


class TechniqueGrounding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str | None = None
    technique_ref: str | None = None
    technique_name: str | None = None
    description: str | None = None
    aliases: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    grounded_by: str

    @model_validator(mode="after")
    def _require_technique_identifier(self) -> "TechniqueGrounding":
        if not self.technique_id and not self.technique_ref and not self.technique_name:
            raise ValueError("technique_id, technique_ref, or technique_name is required when technique grounding is present")
        return self


class TacticGrounding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic_id: str | None = None
    tactic_ref: str | None = None
    tactic_name: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    grounded_by: str

    @model_validator(mode="after")
    def _require_tactic_identifier(self) -> "TacticGrounding":
        if not self.tactic_id and not self.tactic_ref and not self.tactic_name:
            raise ValueError("tactic_id, tactic_ref, or tactic_name is required when tactic grounding is present")
        return self


class AttackFlowMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str = Field(default="attack-flow")
    spec_version: str = Field(default="2.1")
    name: str
    scope: str
    start_refs: list[str] = Field(default_factory=list)
    description: str | None = None
    orchestration_mode: OrchestrationMode
    source_classification: SourceClassification
    authors: list[str] = Field(default_factory=list)
    external_references: list[str] = Field(default_factory=list)
    provenance: dict[str, object] = Field(default_factory=dict)


class AttackAssetNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str = Field(default="attack-asset")
    spec_version: str = Field(default="2.1")
    name: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    object_ref: str | None = None
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    fact_origin: FactOrigin = FactOrigin.AI_GENERATED


class AttackActionNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str = Field(default="attack-action")
    spec_version: str = Field(default="2.1")
    name: str
    description: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    technique: TechniqueGrounding | None = None
    tactic: TacticGrounding | None = None
    asset_refs: list[str] = Field(default_factory=list)
    object_refs: list[str] = Field(default_factory=list)
    effect_refs: list[str] = Field(default_factory=list)
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    fact_origin: FactOrigin = FactOrigin.AI_GENERATED


class AttackConditionNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str = Field(default="attack-condition")
    spec_version: str = Field(default="2.1")
    description: str = Field(min_length=1)
    value: ConditionValue
    confidence: float = Field(ge=0.0, le=1.0)
    on_true_refs: list[str] = Field(default_factory=list)
    on_false_refs: list[str] = Field(default_factory=list)
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    fact_origin: FactOrigin = FactOrigin.AI_GENERATED


class AttackOperatorNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    type: str = Field(default="attack-operator")
    spec_version: str = Field(default="2.1")
    operator: AttackOperatorType
    confidence: float = Field(ge=0.0, le=1.0)
    effect_refs: list[str] = Field(default_factory=list)
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    fact_origin: FactOrigin = FactOrigin.AI_GENERATED


class AfbExtractionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="afb-v2-intermediate")
    validation_state: ExtractionValidationState
    repair_attempted: bool = False
    provider_invoked: bool
    provider_id: str | None = None
    model: str | None = None

    attack_flow: AttackFlowMetadata
    attack_actions: list[AttackActionNode] = Field(default_factory=list)
    attack_conditions: list[AttackConditionNode] = Field(default_factory=list)
    attack_operators: list[AttackOperatorNode] = Field(default_factory=list)
    attack_assets: list[AttackAssetNode] = Field(default_factory=list)

    deterministic_attack_refs: list[dict[str, object]] = Field(default_factory=list)
    deterministic_entities: list[dict[str, object]] = Field(default_factory=list)
    deterministic_relationships: list[dict[str, object]] = Field(default_factory=list)
