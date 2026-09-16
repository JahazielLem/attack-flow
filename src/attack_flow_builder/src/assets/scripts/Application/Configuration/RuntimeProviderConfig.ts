export const SUPPORTED_RUNTIME_PROVIDER_TYPES = ["openai_compatible", "gemini"] as const;

export type SupportedRuntimeProviderType =
    typeof SUPPORTED_RUNTIME_PROVIDER_TYPES[number];

/**
 * Non-secret header bag for runtime-only provider requests.
 * Secret values are intentionally excluded from persisted state.
 */
export type RuntimeProviderHeaders = Record<string, string>;

/**
 * Browser-side runtime provider configuration.
 *
 * `apiKey` is runtime-only and is not persisted by default.
 */
export interface RuntimeProviderConfig {
    providerType: SupportedRuntimeProviderType;
    endpoint: string;
    apiKey: string;
    model: string;
    useAzure?: boolean;
    azureApiVersion?: string;
    extraHeaders?: RuntimeProviderHeaders;
}
