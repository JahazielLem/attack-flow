import { API_BASE_URL } from "@/config/api";

export type JobSubmissionMetadata = Record<string, unknown>;
export const RUNTIME_PROVIDER_OVERRIDE_TYPES = [
    "openai",
    "openai_compatible",
    "azure_openai",
    "anthropic",
    "gemini"
] as const;

export type RuntimeProviderOverrideType =
  typeof RUNTIME_PROVIDER_OVERRIDE_TYPES[number];

export interface JobProviderOverridePayload {
    provider_type: RuntimeProviderOverrideType;
    endpoint?: string;
    api_key?: string;
    model?: string;
    api_version?: string;
    deployment?: string;
    extra_headers?: Record<string, string>;
}

export interface JobSubmissionOptionsPayload extends Record<string, unknown> {
    provider_id?: string;
    provider_override?: JobProviderOverridePayload;
    model?: string;
}

export interface JobSubmissionRequestOptions {
    metadata?: JobSubmissionMetadata;
    options?: JobSubmissionOptionsPayload;
    signal?: AbortSignal;
}

export interface JobPollRequestOptions {
    signal?: AbortSignal;
}

export interface SubmittedJob {
    job_id: string;
    status: string;
    submitted_at: string;
    poll_url: string;
    request_id: string;
}

export interface JobInputSummary {
    input_type: string | null;
    original_filename: string | null;
    title: string | null;
}

export interface JobArtifactOutcomeSummary {
    valid: boolean | null;
    validation_state: string | null;
    export_status: string | null;
    validation_error_count: number | null;
    checksum: string | null;
    size_bytes: number | null;
    created_at: string | null;
    error_code: string | null;
    error_message: string | null;
}

export interface JobArtifactsSummary {
    has_stix: boolean;
    has_afb: boolean;
    stix_url: string | null;
    afb_url: string | null;
    stix_outcome: JobArtifactOutcomeSummary | null;
    afb_outcome: JobArtifactOutcomeSummary | null;
}

export interface JobStatusResponse {
    job_id: string;
    status: string;
    stage: string;
    created_at: string;
    updated_at: string;
    completed_at: string | null;
    error_code: string | null;
    error_message: string | null;
    input: JobInputSummary;
    artifacts: JobArtifactsSummary;
    request_id: string;
}

export interface JobResultResponse {
    job_id: string;
    status: string;
    result: Record<string, unknown>;
    error_code: string | null;
    error_message: string | null;
    artifacts: JobArtifactsSummary | null;
    request_id: string;
}

interface ApiErrorResponse {
    error?: {
        code?: string;
        message?: string;
    };
}

/**
 * Submits a new plaintext job to the Attack Flow API.
 * @param text
 *  The report text to submit for extraction.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitPlaintextJob(
    text: string,
    requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
    return submitJsonJob(
        {
            input_type: "text",
            text
        },
        requestOptions
    );
}

/**
 * Submits a new URL-backed job to the Attack Flow API.
 * @param url
 *  The report URL to submit for asynchronous retrieval and extraction.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitUrlJob(
    url: string,
    requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
    return submitJsonJob(
        {
            input_type: "url",
            url
        },
        requestOptions
    );
}

/**
 * Submits a new file upload job to the Attack Flow API.
 * @param file
 *  The file to upload as multipart form data.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
export async function submitFileJob(
    file: File,
    requestOptions: JobSubmissionRequestOptions = {}
): Promise<SubmittedJob> {
    const formData = new FormData();
    formData.set("file", file);

    if (requestOptions.metadata) {
        formData.set("metadata", JSON.stringify(requestOptions.metadata));
    }

    if (requestOptions.options) {
        formData.set("options", JSON.stringify(requestOptions.options));
    }

    const response = await fetch(JOBS_URL, {
        method: "POST",
        body: formData,
        signal: requestOptions.signal
    });

    return parseSubmittedJob(response);
}

/**
 * Polls a submitted job status URL.
 * @param pollUrl
 *  The poll URL returned by the jobs submission response.
 * @param requestOptions
 *  Optional abort signal for cancelling the request.
 * @returns
 *  The parsed polling response payload.
 */
export async function pollJob(
    pollUrl: string,
    requestOptions: JobPollRequestOptions = {}
): Promise<JobStatusResponse> {
    const response = await fetch(buildPollUrl(pollUrl), {
        method: "GET",
        signal: requestOptions.signal
    });

    const payload = await parseApiResponse(response);
    if (!isJobStatusResponse(payload)) {
        throw new Error("job polling response did not match the expected API shape");
    }

    return payload;
}

/**
 * Retrieves the structured result payload for a completed job.
 * @param jobId
 *  The job identifier returned by the submission response.
 * @param requestOptions
 *  Optional abort signal for cancelling the request.
 * @returns
 *  The parsed job result response payload.
 */
export async function fetchJobResult(
    jobId: string,
    requestOptions: JobPollRequestOptions = {}
): Promise<JobResultResponse> {
    const response = await fetch(buildJobResultUrl(jobId), {
        method: "GET",
        signal: requestOptions.signal
    });

    const payload = await parseApiResponse(response);
    if (!isJobResultResponse(payload)) {
        throw new Error("job result response did not match the expected API shape");
    }

    return payload;
}

/**
 * Fetch job result JSON artifact.
 * @param jobId the job id
 * @param artifactType stix or afb
 * @returns the artifact contents as a JSON string
 */
export async function fetchJobResultArtifact(
    jobId: string,
    artifactType: "afb" | "stix"
): Promise<string> {
    const endpoint = `${API_BASE_URL}/jobs/${jobId}/artifacts/${artifactType}`;
    const response = await fetch(endpoint);

    if (!response.ok) {
        throw new Error("An error occurred while fetching the job result artifact.");
    }

    const payload = await response.text();

    try {
        //validate json
        JSON.parse(payload);
    } catch {
        throw new Error("The job result artifact was not valid json.");
    }


    return payload;
}

/**
 * Submits a JSON-backed text or URL job request.
 * @param body
 *  The JSON payload required by the jobs endpoint.
 * @param requestOptions
 *  Optional metadata, job options, and abort signal.
 * @returns
 *  The queued job response, including the job ID used for polling.
 */
async function submitJsonJob(
    body: {
        input_type: "text" | "url";
        text?: string;
        url?: string;
    },
    requestOptions: JobSubmissionRequestOptions
): Promise<SubmittedJob> {
    const response = await fetch(JOBS_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            ...body,
            ...(requestOptions.metadata ? { metadata: requestOptions.metadata } : {}),
            ...(requestOptions.options ? { options: requestOptions.options } : {})
        }),
        signal: requestOptions.signal
    });

    return parseSubmittedJob(response);
}

const JOBS_URL = `${API_BASE_URL.replace(/\/+$/, "")}/jobs`;

/**
 * Resolves a poll URL against the configured API base URL when needed.
 * @param pollUrl
 *  The relative or absolute poll URL returned by the API.
 * @returns
 *  The absolute poll URL to request.
 */
function buildPollUrl(pollUrl: string): string {
    const apiBaseUrl = new URL(
        `${API_BASE_URL.replace(/\/+$/, "")}/`,
        window.location.origin
    );
    return new URL(pollUrl, apiBaseUrl).toString();
}

/**
 * Builds the result URL for a submitted job.
 * @param jobId
 *  The job identifier returned by the API.
 * @returns
 *  The absolute result URL to request.
 */
function buildJobResultUrl(jobId: string): string {
    return `${JOBS_URL}/${encodeURIComponent(jobId)}/result`;
}

/**
 * Parses and validates a queued job submission response.
 * @param response
 *  The HTTP response returned by the jobs endpoint.
 * @returns
 *  The validated queued job response payload.
 */
async function parseSubmittedJob(response: Response): Promise<SubmittedJob> {
    const payload = await parseApiResponse(response);

    if (!isSubmittedJob(payload)) {
        throw new Error("jobs submission response did not include a valid job identifier");
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
 * Returns whether a parsed payload matches the queued job response shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required submitted job fields.
 */
function isSubmittedJob(payload: unknown): payload is SubmittedJob {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        typeof candidate.job_id === "string"
    && typeof candidate.status === "string"
    && typeof candidate.submitted_at === "string"
    && typeof candidate.poll_url === "string"
    && typeof candidate.request_id === "string"
    );
}

/**
 * Returns whether a parsed payload matches the job status response shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required job status fields.
 */
function isJobStatusResponse(payload: unknown): payload is JobStatusResponse {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        typeof candidate.job_id === "string"
    && typeof candidate.status === "string"
    && typeof candidate.stage === "string"
    && typeof candidate.created_at === "string"
    && typeof candidate.updated_at === "string"
    && (typeof candidate.completed_at === "string" || candidate.completed_at === null)
    && (typeof candidate.error_code === "string" || candidate.error_code === null)
    && (typeof candidate.error_message === "string" || candidate.error_message === null)
    && isJobInputSummary(candidate.input)
    && isJobArtifactsSummary(candidate.artifacts)
    && typeof candidate.request_id === "string"
    );
}

/**
 * Returns whether a parsed payload matches the job result response shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required job result fields.
 */
function isJobResultResponse(payload: unknown): payload is JobResultResponse {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        typeof candidate.job_id === "string"
    && typeof candidate.status === "string"
    && !!candidate.result
    && typeof candidate.result === "object"
    && !Array.isArray(candidate.result)
    && (typeof candidate.error_code === "string" || candidate.error_code === null)
    && (typeof candidate.error_message === "string" || candidate.error_message === null)
    && (isJobArtifactsSummary(candidate.artifacts) || candidate.artifacts === null)
    && typeof candidate.request_id === "string"
    );
}

/**
 * Returns whether a parsed payload matches the job input summary shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required job input summary fields.
 */
function isJobInputSummary(payload: unknown): payload is JobInputSummary {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        (typeof candidate.input_type === "string" || candidate.input_type === null)
    && (typeof candidate.original_filename === "string" || candidate.original_filename === null)
    && (typeof candidate.title === "string" || candidate.title === null)
    );
}

/**
 * Returns whether a parsed payload matches the job artifacts summary shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required job artifacts summary fields.
 */
function isJobArtifactsSummary(payload: unknown): payload is JobArtifactsSummary {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        typeof candidate.has_stix === "boolean"
    && typeof candidate.has_afb === "boolean"
    && (typeof candidate.stix_url === "string" || candidate.stix_url === null)
    && (typeof candidate.afb_url === "string" || candidate.afb_url === null)
    && (isJobArtifactOutcomeSummary(candidate.stix_outcome) || candidate.stix_outcome === null)
    && (isJobArtifactOutcomeSummary(candidate.afb_outcome) || candidate.afb_outcome === null)
    );
}

/**
 * Returns whether a parsed payload matches the job artifact outcome summary shape.
 * @param payload
 *  The parsed response payload.
 * @returns
 *  True when the payload includes the required job artifact outcome summary fields.
 */
function isJobArtifactOutcomeSummary(payload: unknown): payload is JobArtifactOutcomeSummary {
    if (!payload || typeof payload !== "object") {
        return false;
    }

    const candidate = payload as Record<string, unknown>;
    return (
        (typeof candidate.valid === "boolean" || candidate.valid === null)
    && (typeof candidate.validation_state === "string" || candidate.validation_state === null)
    && (typeof candidate.export_status === "string" || candidate.export_status === null)
    && (typeof candidate.validation_error_count === "number" || candidate.validation_error_count === null)
    && (typeof candidate.checksum === "string" || candidate.checksum === null)
    && (typeof candidate.size_bytes === "number" || candidate.size_bytes === null)
    && (typeof candidate.created_at === "string" || candidate.created_at === null)
    && (typeof candidate.error_code === "string" || candidate.error_code === null)
    && (typeof candidate.error_message === "string" || candidate.error_message === null)
    );
}

/**
 * Run the flow entire generation request pipeline from job submission to polling to fetching results.
 * Return the result response.
 * This function intentionally has many points of failure, so it should be wrapped in a try-catch.
 * @param sourceType text, upload (for a pdf report), or url
 * @param sourceData the plantext string, the pdf file, or the url string
 * @param requestOptions request options object which may include llm provider overrides
 * @returns The response object from fetching the job result. This response status may not be "complete,"
 * so it should be checked.
 */
export async function runJobToResult(
    sourceType: "text" | "upload" | "url",
    sourceData: string | File,
    requestOptions: JobSubmissionRequestOptions = {}
) : Promise<JobResultResponse> {
    let submissionResponse : SubmittedJob | null = null;

    switch (sourceType) {
        case "text": {
            if (typeof sourceData != "string") {
                throw new TypeError(`Text source requires string data. Got ${typeof sourceData}.`);
            }

            submissionResponse = await submitPlaintextJob(sourceData, requestOptions);
            break;
        }
        case "upload": {
            if (!(sourceData instanceof File)) {
                throw new TypeError("File source data requires File instance.");
            }

            submissionResponse = await submitFileJob(sourceData, requestOptions);
            break;
        }
        case "url": {
            if (typeof sourceData != "string") {
                throw new TypeError(`URL source requires string. Got ${typeof sourceData}.`);
            }

            submissionResponse = await submitUrlJob(sourceData, requestOptions);
            break;
        }
    }

    if (submissionResponse) {
        // First, poll until the job is complete.
        const cooldownMs = 1000;
        const maxRetries = 240;

        let currentTry = 1;

        let jobComplete = false;

        while (currentTry <= maxRetries) {
            const pollRes = await pollJob(submissionResponse.poll_url);
            console.debug(`Polling attempt ${currentTry}.`, pollRes);
            if (pollRes.status === "completed") {
                jobComplete = true;
                console.debug("Job completed.");
                break;
            } else if (pollRes.status === "failed") {
                throw new Error(`Queued job failed: ${pollRes.error_message}`);
            }
            await new Promise(resolve => setTimeout(resolve, cooldownMs));
            currentTry += 1;
        }

        // Then, fetch the job result.
        if (jobComplete) {
            const result = await fetchJobResult(submissionResponse.job_id);
            return result;
        } else {
            throw new Error("Queued job timed out.");
        }
    } else {
        throw new Error("Job submission failed.");
    }
}
