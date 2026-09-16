import { API_BASE_URL } from "@/config/api";

const HEALTH_URL = `${API_BASE_URL.replace(/\/+$/, "")}/health`;

export interface HealthCheckRequestOptions {
    signal?: AbortSignal;
}

export interface HealthCheckResponse {
    status: string;
    service: string;
    version: string;
    time: string;
    request_id: string;
}

interface ApiErrorResponse {
    error?: {
        code?: string;
        message?: string;
    };
}

/**
 * Fetches the current API health status.
 * @param requestOptions
 *  Optional abort signal for cancelling the request.
 * @returns
 *  The parsed health check response payload.
 */
export async function fetchHealthCheck(
    requestOptions: HealthCheckRequestOptions = {}
): Promise<HealthCheckResponse> {
    const response = await fetch(HEALTH_URL, {
        method: "GET",
        signal: requestOptions.signal
    });

    const payload = await parseApiResponse(response);
    if (!isHealthCheckResponse(payload)) {
        throw new Error("health check response did not match the expected API shape");
    }

    return payload;
}

/**
 * Parses an API response and throws a normalized error for non-success responses.
 * @param response
 *  The HTTP response returned by the API.
 * @returns
 *  The parsed response payload.
 */
async function parseApiResponse(response: Response): Promise<unknown> {
    const payload = await parseResponseBody(response);

    if (!response.ok) {
        const apiError = payload && typeof payload === "object"
            ? payload as ApiErrorResponse
            : null;
        const errorCode = apiError?.error?.code?.trim();
        const errorMessage = apiError?.error?.message?.trim();
        const responseStatus = `${response.status} ${response.statusText}`.trim();
        throw new Error(
            errorCode && errorMessage
                ? `${errorCode}: ${errorMessage}`
                : errorMessage || `API request failed (${responseStatus})`
        );
    }

    return payload;
}

/**
 * Parses a response body as JSON when possible.
 * @param response
 *  The HTTP response whose body should be parsed.
 * @returns
 *  The parsed response payload, or null when the body is empty.
 */
async function parseResponseBody(response: Response): Promise<unknown> {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }

    const text = await response.text();
    return text || null;
}

/**
 * Returns whether a parsed payload matches the API health response shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required health response fields.
 */
function isHealthCheckResponse(payload: unknown): payload is HealthCheckResponse {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        typeof candidate.status === "string"
    && typeof candidate.service === "string"
    && typeof candidate.version === "string"
    && typeof candidate.time === "string"
    && typeof candidate.request_id === "string"
    );
}
