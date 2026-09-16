from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult


class FusionInputSourceKind(str, Enum):
    DETERMINISTIC_STIX_OPENCTI = "deterministic_stix_opencti"
    AI_AFB_EXTRACTION = "ai_afb_extraction"


class FusionProvenanceKind(str, Enum):
    DETERMINISTIC = "deterministic"
    AI_DERIVED = "ai_derived"


class FusionConflictCategory(str, Enum):
    DUPLICATE_ATTACK_REF = "duplicate_attack_ref"
    DUPLICATE_ENTITY = "duplicate_entity"
    DUPLICATE_STEP = "duplicate_step"
    CONFLICTING_DESCRIPTION = "conflicting_description"
    CONFLICTING_ATTACHMENT = "conflicting_attachment"
    CONFLICTING_ORDERING = "conflicting_ordering"
    UNSUPPORTED_INFERRED_TECHNIQUE = "unsupported_inferred_technique"
    UNSUPPORTED_BRANCHING_OPERATOR_TYPE = "unsupported_branching_operator_type"


FUSION_CONFLICT_CATEGORIES: tuple[FusionConflictCategory, ...] = (
    FusionConflictCategory.DUPLICATE_ATTACK_REF,
    FusionConflictCategory.DUPLICATE_ENTITY,
    FusionConflictCategory.DUPLICATE_STEP,
    FusionConflictCategory.CONFLICTING_DESCRIPTION,
    FusionConflictCategory.CONFLICTING_ATTACHMENT,
    FusionConflictCategory.CONFLICTING_ORDERING,
    FusionConflictCategory.UNSUPPORTED_INFERRED_TECHNIQUE,
    FusionConflictCategory.UNSUPPORTED_BRANCHING_OPERATOR_TYPE,
)


class FusionFindingProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: FusionProvenanceKind
    source_label: str = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_object_id: str | None = None
    source_field: str | None = None
    notes: str | None = None


class DeterministicFusionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: FusionInputSourceKind = Field(default=FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI)
    provenance: dict[str, object] = Field(default_factory=dict)
    attack_refs: list[dict[str, object]] = Field(default_factory=list)
    entities: list[dict[str, object]] = Field(default_factory=list)
    relationships: list[dict[str, object]] = Field(default_factory=list)


class AiExtractionFusionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_kind: FusionInputSourceKind = Field(default=FusionInputSourceKind.AI_AFB_EXTRACTION)
    extraction: AfbExtractionResult


class FusionConflictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: FusionConflictCategory
    source_kind: FusionInputSourceKind
    message: str = Field(min_length=1)
    deterministic_ref: str | None = None
    ai_ref: str | None = None
    provenance: list[FusionFindingProvenance] = Field(default_factory=list)
    unresolved: bool = True


class FusionInputBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deterministic: DeterministicFusionInput
    ai: AiExtractionFusionInput
    provenance: dict[str, object] = Field(default_factory=dict)
    conflicts: list[FusionConflictRecord] = Field(default_factory=list)
