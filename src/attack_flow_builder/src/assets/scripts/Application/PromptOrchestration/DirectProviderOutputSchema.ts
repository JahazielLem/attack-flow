import { STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION } from "../StructuredExtraction";

const evidenceSchema = {
    type: "object",
    required: ["source", "excerpt"],
    properties: {
        source: { type: "string" },
        excerpt: { type: "string", minLength: 1 },
        citation: { type: "string" },
        source_object_id: { type: "string" },
        source_field: { type: "string" }
    }
};

const groundingProperties = {
    confidence: { type: "number", minimum: 0, maximum: 1 },
    grounded_by: { type: "string" }
};

export const DIRECT_PROVIDER_OUTPUT_SCHEMA: Record<string, unknown> = {
    type: "object",
    required: [
        "schema_version",
        "validation_state",
        "repair_attempted",
        "provider_invoked",
        "attack_flow"
    ],
    properties: {
        schema_version: { const: STRUCTURED_EXTRACTION_RESULT_SCHEMA_VERSION },
        validation_state: { enum: ["valid", "invalid", "repaired"] },
        repair_attempted: { type: "boolean" },
        provider_invoked: { type: "boolean" },
        provider_id: { type: ["string", "null"] },
        model: { type: ["string", "null"] },
        attack_flow: {
            type: "object",
            required: ["id", "type", "spec_version", "name", "scope", "orchestration_mode", "source_classification"],
            properties: {
                id: { type: "string" },
                type: { const: "attack-flow" },
                spec_version: { const: "2.1" },
                name: { type: "string" },
                scope: { enum: ["incident", "campaign", "threat-actor", "malware", "emulation-plan", "attack-tree", "other"] },
                start_refs: { type: "array", items: { type: "string" } },
                description: { type: "string" },
                orchestration_mode: { type: "string" },
                source_classification: { type: "string" },
                authors: { type: "array", items: { type: "string" } },
                external_references: { type: "array", items: { type: "string" } },
                provenance: { type: "object" }
            }
        },
        attack_actions: {
            type: "array",
            items: {
                type: "object",
                required: ["id", "type", "spec_version", "name", "description", "confidence", "evidence"],
                properties: {
                    id: { type: "string" },
                    type: { const: "attack-action" },
                    spec_version: { const: "2.1" },
                    name: { type: "string" },
                    description: { type: "string", minLength: 1 },
                    confidence: { type: "number", minimum: 0, maximum: 1 },
                    technique: {
                        anyOf: [
                            { type: "null" },
                            {
                                type: "object",
                                required: ["confidence", "grounded_by"],
                                properties: {
                                    technique_id: { type: "string" },
                                    technique_ref: { type: "string" },
                                    technique_name: { type: "string" },
                                    description: { type: "string" },
                                    aliases: { type: "array", items: { type: "string" } },
                                    kill_chain_phases: { type: "array", items: { type: "string" } },
                                    tags: { type: "array", items: { type: "string" } },
                                    ...groundingProperties
                                }
                            }
                        ]
                    },
                    tactic: {
                        anyOf: [
                            { type: "null" },
                            {
                                type: "object",
                                required: ["confidence", "grounded_by"],
                                properties: {
                                    tactic_id: { type: "string" },
                                    tactic_ref: { type: "string" },
                                    tactic_name: { type: "string" },
                                    ...groundingProperties
                                }
                            }
                        ]
                    },
                    asset_refs: { type: "array", items: { type: "string" } },
                    object_refs: { type: "array", items: { type: "string" } },
                    effect_refs: { type: "array", items: { type: "string" } },
                    evidence: { type: "array", items: evidenceSchema },
                    citations: { type: "array", items: { type: "string" } },
                    fact_origin: { enum: ["deterministic_source", "ai_generated"] }
                }
            }
        },
        attack_conditions: {
            type: "array",
            items: {
                type: "object",
                required: ["id", "type", "spec_version", "description", "value", "confidence", "evidence"],
                properties: {
                    id: { type: "string" },
                    type: { const: "attack-condition" },
                    spec_version: { const: "2.1" },
                    description: { type: "string", minLength: 1 },
                    value: { enum: ["true", "false"] },
                    confidence: { type: "number", minimum: 0, maximum: 1 },
                    on_true_refs: { type: "array", items: { type: "string" } },
                    on_false_refs: { type: "array", items: { type: "string" } },
                    evidence: { type: "array", items: evidenceSchema },
                    citations: { type: "array", items: { type: "string" } },
                    fact_origin: { enum: ["deterministic_source", "ai_generated"] }
                }
            }
        },
        attack_operators: {
            type: "array",
            items: {
                type: "object",
                required: ["id", "type", "spec_version", "operator", "confidence", "evidence"],
                properties: {
                    id: { type: "string" },
                    type: { const: "attack-operator" },
                    spec_version: { const: "2.1" },
                    operator: { enum: ["AND", "OR"] },
                    confidence: { type: "number", minimum: 0, maximum: 1 },
                    effect_refs: { type: "array", items: { type: "string" } },
                    evidence: { type: "array", items: evidenceSchema },
                    citations: { type: "array", items: { type: "string" } },
                    fact_origin: { enum: ["deterministic_source", "ai_generated"] }
                }
            }
        },
        attack_assets: {
            type: "array",
            items: {
                type: "object",
                required: ["id", "type", "spec_version", "name", "confidence", "evidence"],
                properties: {
                    id: { type: "string" },
                    type: { const: "attack-asset" },
                    spec_version: { const: "2.1" },
                    name: { type: "string" },
                    description: { type: "string" },
                    tags: {
                        anyOf: [
                            { type: "null" },
                            { type: "array", items: { type: "string" } },
                            { type: "object", additionalProperties: { type: "boolean" } }
                        ]
                    },
                    object_ref: { type: ["string", "null"] },
                    evidence: { type: "array", items: evidenceSchema },
                    confidence: { type: "number", minimum: 0, maximum: 1 },
                    fact_origin: { enum: ["deterministic_source", "ai_generated"] }
                }
            }
        },
        deterministic_attack_refs: { type: "array", items: { type: "object" } },
        deterministic_entities: {
            type: "array",
            items: {
                type: "object",
                required: ["object_id", "object_type"],
                properties: {
                    object_id: { type: "string" },
                    object_type: { type: "string" },
                    display_name: { type: "string" }
                }
            }
        },
        deterministic_relationships: {
            type: "array",
            items: {
                type: "object",
                required: ["relationship_type", "source_ref", "target_ref"],
                properties: {
                    relationship_id: { type: "string" },
                    relationship_type: { type: "string" },
                    source_ref: { type: "string" },
                    target_ref: { type: "string" }
                }
            }
        }
    }
};
