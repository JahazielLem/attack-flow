import type { RuntimeProviderConfig } from "../Configuration";
import type { NormalizedInputPackage } from "../InputNormalization";
import type { StructuredGenerationRequest } from "../Providers";
import {
    DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME
} from "./DirectProviderAfbIntermediateShape";
import { buildDirectProviderInputPayload } from "./DirectProviderInputPackager";
import {
    DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
    type DirectProviderInputPayload,
    type DirectProviderStructuredGenerationRequestModel
} from "./DirectProviderRequestModels";
import {
    buildDirectProviderStructuredGenerationRequest
} from "./DirectProviderStructuredGenerationRequestBuilder";
import {
    buildDirectProviderSystemInstructionModel
} from "./DirectProviderSystemInstructionBuilder";

export interface DirectProviderRequestPipelineParams {
    normalizedInput: NormalizedInputPackage;
    provider: Pick<RuntimeProviderConfig, "providerType" | "endpoint" | "apiKey" | "model" | "useAzure" | "azureApiVersion" | "extraHeaders">;
    providerId?: string;
    timeoutSeconds?: number;
    metadata?: Record<string, string>;
    promptMode?: "full_extraction" | "enrichment";
    promptSourceType?: string;
    promptContext?: Pick<
        DirectProviderInputPayload,
        "structuredSummary" |
        "deterministicAttackRefs" |
        "deterministicEntities" |
        "deterministicRelationships" |
        "provenance"
    >;
}

/**
 * Minimal end-to-end request pipeline for Direct Provider Mode.
 * It packages normalized input and assembles a provider-agnostic structured
 * generation request without executing provider calls or validating output.
 */
export function buildDirectProviderRequestPipeline(
    params: DirectProviderRequestPipelineParams
): StructuredGenerationRequest {
    const requestModel: DirectProviderStructuredGenerationRequestModel = {
        version: DIRECT_PROVIDER_REQUEST_MODEL_VERSION,
        mode: "direct_provider",
        sourceType: params.normalizedInput.sourceType,
        promptMode: params.promptMode,
        promptSourceType: params.promptSourceType,
        systemInstructions: buildDirectProviderSystemInstructionModel(),
        input: {
            ...buildDirectProviderInputPayload(params.normalizedInput),
            ...params.promptContext
        },
        responseSchema: {
            format: "json_object",
            schemaName: DIRECT_PROVIDER_AFB_INTERMEDIATE_SCHEMA_NAME
        },
        metadata: params.metadata
    };

    return buildDirectProviderStructuredGenerationRequest({
        provider: params.provider,
        request: requestModel,
        providerId: params.providerId,
        timeoutSeconds: params.timeoutSeconds
    });
}
