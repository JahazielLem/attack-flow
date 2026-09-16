import json
import logging
import os
import time
from dataclasses import dataclass
from http.client import HTTPSConnection
from typing import Callable
from urllib.parse import quote, urlsplit

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapter, ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import (
    NormalizedProviderError,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderTokenUsage,
    ProviderValidationRequest,
    ProviderValidationResult,
    StructuredFinishReason,
    StructuredGenerationRequest,
    StructuredGenerationResult,
    StructuredResponseFormat,
    build_normalized_provider_error,
)


_logger = logging.getLogger("attack_flow_api.provider_gemini")


@dataclass(frozen=True, slots=True)
class GeminiHttpRequest:
    method: str
    url: str
    headers: dict[str, str]
    json_body: dict[str, object] | None = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class GeminiHttpResponse:
    status_code: int
    json_body: dict[str, object]


@dataclass(frozen=True, slots=True)
class GeminiHttpError(RuntimeError):
    status_code: int
    response_body: str | None = None
    response_headers: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class GeminiRequestError(RuntimeError):
    request: GeminiHttpRequest
    original_error: Exception
    details: dict[str, str]


class GeminiProviderAdapter(ProviderAdapter):
    def __init__(
        self,
        provider_config: ProviderConfig,
        *,
        runtime_api_key: str | None = None,
        request_executor: Callable[[GeminiHttpRequest], GeminiHttpResponse] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ):
        self._provider = provider_config
        self._runtime_api_key = runtime_api_key
        self._request_executor = request_executor or _default_gemini_request_executor
        self._sleep_fn = sleep_fn or time.sleep
        self._logger = logging.getLogger("attack_flow_api.provider_gemini")

    @property
    def provider_id(self) -> str:
        return self._provider.provider_id

    @property
    def provider_type(self) -> str:
        return self._provider.provider_type

    def validate(self, request: ProviderValidationRequest) -> ProviderValidationResult:
        api_key = self._resolve_api_key(operation=ProviderOperation.VALIDATE)
        model = self._resolve_model(request.model, operation=ProviderOperation.VALIDATE)
        gemini_request = self._build_gemini_request(
            api_key=api_key,
            timeout_seconds=self._resolve_timeout_seconds(request.timeout_seconds),
            method="POST",
            url=self._generate_content_url(model),
            json_body={
                "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 16},
            },
        )
        self._execute_with_retry(
            operation=ProviderOperation.VALIDATE,
            request=gemini_request,
            action=lambda: self._request_executor(gemini_request),
            model=model,
        )
        return ProviderValidationResult(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            is_valid=True,
            checked_model=model,
        )

    def generate_structured(self, request: StructuredGenerationRequest) -> StructuredGenerationResult:
        api_key = self._resolve_api_key(operation=ProviderOperation.STRUCTURED_GENERATION)
        model = self._resolve_model(request.model, operation=ProviderOperation.STRUCTURED_GENERATION)
        prompt = _build_gemini_prompt(request.prompt)
        gemini_request = self._build_gemini_request(
            api_key=api_key,
            timeout_seconds=self._resolve_timeout_seconds(request.timeout_seconds),
            method="POST",
            url=self._generate_content_url(model),
            json_body=_build_gemini_generation_body(
                prompt=prompt,
                response_format=request.response_format,
                temperature=request.temperature,
                max_output_tokens=request.max_output_tokens,
            ),
        )

        response = self._execute_with_retry(
            operation=ProviderOperation.STRUCTURED_GENERATION,
            request=gemini_request,
            action=lambda: self._request_executor(gemini_request),
            model=model,
        )

        output_text = _extract_output_text(response.json_body)
        return StructuredGenerationResult(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            model=model,
            finish_reason=_extract_finish_reason(response.json_body),
            output_text=output_text,
            output_json=_extract_output_json(output_text, request.response_format),
            usage=_extract_usage(response.json_body),
        )

    def _resolve_api_key(self, *, operation: ProviderOperation) -> str:
        if self._runtime_api_key is not None and self._runtime_api_key.strip():
            return self._runtime_api_key

        env_var = (self._provider.api_key_env or "").strip()
        if not env_var:
            raise ProviderAdapterInvocationError(
                build_normalized_provider_error(
                    category=ProviderErrorCategory.CONFIGURATION_ERROR,
                    code="provider_api_key_env_missing",
                    message="provider api key environment variable is not configured",
                    operation=operation,
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                )
            )
        api_key = os.environ.get(env_var)
        if api_key is None or not api_key.strip():
            raise ProviderAdapterInvocationError(
                build_normalized_provider_error(
                    category=ProviderErrorCategory.AUTH_FAILURE,
                    code="provider_api_key_missing",
                    message="provider api key is missing",
                    operation=operation,
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    details={"api_key_env": env_var},
                )
            )
        return api_key

    def _build_gemini_request(
        self,
        *,
        api_key: str,
        timeout_seconds: float,
        method: str,
        url: str,
        json_body: dict[str, object] | None,
    ) -> GeminiHttpRequest:
        return GeminiHttpRequest(
            method=method,
            url=url,
            headers={
                "x-goog-api-key": api_key,
                "Content-Type": "application/json",
            },
            timeout_seconds=timeout_seconds,
            json_body=json_body,
        )

    def _resolve_model(self, requested_model: str | None, *, operation: ProviderOperation) -> str:
        if requested_model is not None and requested_model.strip():
            selected = requested_model.strip()
            if self._provider.allowed_models and selected not in self._provider.allowed_models:
                raise ProviderAdapterInvocationError(
                    build_normalized_provider_error(
                        category=ProviderErrorCategory.CONFIGURATION_ERROR,
                        code="provider_model_not_allowed",
                        message="requested provider model is not allowed",
                        operation=operation,
                        provider_id=self.provider_id,
                        provider_type=self.provider_type,
                        model=selected,
                    )
                )
            return selected
        if self._provider.default_model is not None and self._provider.default_model.strip():
            return self._provider.default_model.strip()
        if self._provider.allowed_models:
            return self._provider.allowed_models[0]
        raise ProviderAdapterInvocationError(
            build_normalized_provider_error(
                category=ProviderErrorCategory.CONFIGURATION_ERROR,
                code="provider_model_missing",
                message="provider model is not configured",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
            )
        )

    def _resolve_timeout_seconds(self, request_timeout_seconds: float) -> float:
        provider_timeout = self._provider.timeout_seconds
        if provider_timeout is None:
            return request_timeout_seconds
        return min(request_timeout_seconds, provider_timeout)

    def _generate_content_url(self, model: str) -> str:
        base_url = (self._provider.base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        model_name = model.removeprefix("models/")
        return f"{base_url}/models/{quote(model_name, safe='')}:generateContent"

    def _execute_with_retry(
        self,
        *,
        operation: ProviderOperation,
        action: Callable[[], GeminiHttpResponse],
        model: str,
        request: GeminiHttpRequest | None = None,
    ) -> GeminiHttpResponse:
        max_attempts = self._provider.retry_max_attempts if self._provider.retry_max_attempts is not None else 1
        base_delay_ms = self._provider.retry_base_delay_ms if self._provider.retry_base_delay_ms is not None else 200
        max_delay_ms = self._provider.retry_max_delay_ms if self._provider.retry_max_delay_ms is not None else 2000

        last_error: NormalizedProviderError | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return action()
            except ProviderAdapterInvocationError as exc:
                last_error = exc.error
            except Exception as exc:  # pragma: no cover - mapped below
                last_error = self._map_exception_to_normalized_error(
                    exc,
                    operation=operation,
                    model=model,
                    request=request,
                )

            if last_error is None:
                continue
            is_last_attempt = attempt >= max_attempts
            if is_last_attempt or not last_error.retryable:
                raise ProviderAdapterInvocationError(last_error)

            delay_seconds = min(base_delay_ms * (2 ** (attempt - 1)), max_delay_ms) / 1000.0
            self._sleep_fn(delay_seconds)

        raise ProviderAdapterInvocationError(
            last_error
            or build_normalized_provider_error(
                category=ProviderErrorCategory.UNAVAILABLE,
                code="provider_request_failed",
                message="provider request failed",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )
        )

    def _map_exception_to_normalized_error(
        self,
        exc: Exception,
        *,
        operation: ProviderOperation,
        model: str,
        request: GeminiHttpRequest | None = None,
    ) -> NormalizedProviderError:
        if isinstance(exc, TimeoutError):
            details = _request_diagnostics(request)
            _logger.warning(
                "provider timeout operation=%s provider_id=%s provider_type=%s model=%s details=%s error_type=%s error=%s",
                operation.value,
                self.provider_id,
                self.provider_type,
                model,
                details,
                type(exc).__name__,
                exc,
                exc_info=exc,
            )
            return build_normalized_provider_error(
                category=ProviderErrorCategory.TIMEOUT,
                code="provider_timeout",
                message="provider request timed out",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
                details=details,
            )

        if isinstance(exc, GeminiRequestError):
            details = dict(exc.details)
            details.update(_request_diagnostics(exc.request))
            original_error = exc.original_error
            _logger.warning(
                "provider network error operation=%s provider_id=%s provider_type=%s model=%s details=%s error_type=%s error=%s",
                operation.value,
                self.provider_id,
                self.provider_type,
                model,
                details,
                type(original_error).__name__,
                original_error,
                exc_info=original_error,
            )
            if isinstance(original_error, TimeoutError):
                return build_normalized_provider_error(
                    category=ProviderErrorCategory.TIMEOUT,
                    code="provider_timeout",
                    message="provider request timed out",
                    operation=operation,
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    model=model,
                    details=details,
                )
            return build_normalized_provider_error(
                category=ProviderErrorCategory.UNAVAILABLE,
                code="provider_network_error",
                message="provider network request failed",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
                details=details,
            )

        if isinstance(exc, GeminiHttpError):
            status_code = exc.status_code
            response_headers = exc.response_headers or {}
            self._logger.warning(
                "provider http error provider_type=%s operation=%s status_code=%s request_id=%s error_status=%s",
                self.provider_type,
                operation.value,
                status_code,
                response_headers.get("x-request-id") or response_headers.get("x-goog-request-id"),
                _extract_gemini_error_status(exc.response_body),
            )
            if status_code in {401, 403}:
                category = ProviderErrorCategory.AUTH_FAILURE
                code = "provider_auth_failed"
                message = "provider authentication failed"
            elif status_code == 429:
                category = ProviderErrorCategory.RATE_LIMIT
                code = "provider_rate_limited"
                message = "provider rate limit exceeded"
            elif status_code in {408} or 500 <= status_code <= 599:
                category = ProviderErrorCategory.TIMEOUT if status_code == 408 else ProviderErrorCategory.UNAVAILABLE
                code = "provider_timeout" if status_code == 408 else "provider_unavailable"
                message = "provider request timed out" if status_code == 408 else "provider unavailable"
            elif status_code in {400, 404, 422}:
                category = ProviderErrorCategory.CONFIGURATION_ERROR
                code = "provider_request_invalid"
                message = "provider request configuration is invalid"
            else:
                category = ProviderErrorCategory.INVALID_RESPONSE
                code = "provider_invalid_response"
                message = "provider returned an invalid response"

            return build_normalized_provider_error(
                category=category,
                code=code,
                message=message,
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
                status_code=status_code,
                details=_provider_error_details(response_headers),
            )

        if isinstance(exc, (OSError, ConnectionError)):
            details = _request_diagnostics(request)
            _logger.warning(
                "provider network error operation=%s provider_id=%s provider_type=%s model=%s details=%s error_type=%s error=%s",
                operation.value,
                self.provider_id,
                self.provider_type,
                model,
                details,
                type(exc).__name__,
                exc,
                exc_info=exc,
            )
            return build_normalized_provider_error(
                category=ProviderErrorCategory.UNAVAILABLE,
                code="provider_network_error",
                message="provider network request failed",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
                details=details,
            )

        if isinstance(exc, (ValueError, json.JSONDecodeError)):
            return build_normalized_provider_error(
                category=ProviderErrorCategory.INVALID_RESPONSE,
                code="provider_invalid_response",
                message="provider returned an invalid response",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )

        return build_normalized_provider_error(
            category=ProviderErrorCategory.UNAVAILABLE,
            code="provider_request_failed",
            message="provider request failed",
            operation=operation,
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            model=model,
        )


def _default_gemini_request_executor(request: GeminiHttpRequest) -> GeminiHttpResponse:
    parsed = urlsplit(request.url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("gemini request url must be https with hostname")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body = b""
    if request.json_body is not None:
        body = json.dumps(request.json_body).encode("utf-8")

    _logger.debug("gemini request details=%s", _request_diagnostics(request))
    connection = HTTPSConnection(host=parsed.hostname, port=parsed.port, timeout=request.timeout_seconds)
    try:
        connection.request(request.method, path, body=body, headers=request.headers)
        response = connection.getresponse()
        payload_bytes = response.read()
        payload_text = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else "{}"

        if response.status >= 400:
            raise GeminiHttpError(
                status_code=response.status,
                response_body=payload_text,
                response_headers=_normalize_headers(response.getheaders()),
            )

        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json response from provider") from exc
        if not isinstance(payload, dict):
            raise ValueError("provider response payload must be an object")
        return GeminiHttpResponse(status_code=response.status, json_body=payload)
    except TimeoutError as exc:
        raise GeminiRequestError(request=request, original_error=exc, details=_request_diagnostics(request)) from exc
    except (OSError, ConnectionError) as exc:
        raise GeminiRequestError(request=request, original_error=exc, details=_request_diagnostics(request)) from exc
    finally:
        connection.close()


def _request_diagnostics(request: GeminiHttpRequest | None) -> dict[str, str]:
    if request is None:
        return {}

    parsed = urlsplit(request.url)
    details: dict[str, str] = {
        "request_method": request.method,
        "request_scheme": parsed.scheme,
        "request_host": parsed.hostname or "",
        "request_path": parsed.path or "/",
        "request_port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "request_timeout_seconds": str(request.timeout_seconds),
        "ssl_cert_file_set": str(bool(os.environ.get("SSL_CERT_FILE"))).lower(),
        "requests_ca_bundle_set": str(bool(os.environ.get("REQUESTS_CA_BUNDLE"))).lower(),
        "https_proxy_set": str(bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))).lower(),
        "http_proxy_set": str(bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))).lower(),
        "no_proxy_set": str(bool(os.environ.get("NO_PROXY") or os.environ.get("no_proxy"))).lower(),
    }
    ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    if ssl_cert_file:
        details["ssl_cert_file"] = ssl_cert_file
    requests_ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    if requests_ca_bundle:
        details["requests_ca_bundle"] = requests_ca_bundle
    return details


def _extract_usage(payload: dict[str, object]) -> ProviderTokenUsage:
    usage_raw = payload.get("usageMetadata")
    if not isinstance(usage_raw, dict):
        return ProviderTokenUsage()
    input_tokens = usage_raw.get("promptTokenCount")
    output_tokens = usage_raw.get("candidatesTokenCount")
    total_tokens = usage_raw.get("totalTokenCount")
    return ProviderTokenUsage(
        input_tokens=input_tokens if isinstance(input_tokens, int) and input_tokens >= 0 else None,
        output_tokens=output_tokens if isinstance(output_tokens, int) and output_tokens >= 0 else None,
        total_tokens=total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else None,
    )


def _extract_output_text(payload: dict[str, object]) -> str | None:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return None
    first_candidate = candidates[0]
    if not isinstance(first_candidate, dict):
        return None
    content = first_candidate.get("content")
    if not isinstance(content, dict):
        return None
    parts = content.get("parts")
    if not isinstance(parts, list):
        return None

    text_parts: list[str] = []
    for part in parts:
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            text_parts.append(part["text"])
    if not text_parts:
        return None
    return "".join(text_parts)


def _extract_finish_reason(payload: dict[str, object]) -> StructuredFinishReason:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return StructuredFinishReason.UNKNOWN
    first_candidate = candidates[0]
    if not isinstance(first_candidate, dict):
        return StructuredFinishReason.UNKNOWN
    finish_reason = first_candidate.get("finishReason")
    if finish_reason == "STOP":
        return StructuredFinishReason.STOP
    if finish_reason == "MAX_TOKENS":
        return StructuredFinishReason.LENGTH
    if finish_reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"}:
        return StructuredFinishReason.CONTENT_FILTER
    return StructuredFinishReason.UNKNOWN


def _extract_output_json(
    output_text: str | None,
    response_format: StructuredResponseFormat,
) -> dict[str, object] | None:
    if response_format != StructuredResponseFormat.JSON_OBJECT:
        return None
    if output_text is None:
        return None
    try:
        parsed = json.loads(output_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _normalize_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers}


def _provider_error_details(headers: dict[str, str]) -> dict[str, str]:
    details: dict[str, str] = {}
    for key in ("x-request-id", "x-goog-request-id", "retry-after"):
        value = headers.get(key)
        if isinstance(value, str) and value.strip():
            details[key] = value.strip()
    return details


def _extract_gemini_error_status(response_body: str | None) -> str | None:
    if response_body is None:
        return None
    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    if not isinstance(error, dict):
        return None
    status = error.get("status")
    return status if isinstance(status, str) and status.strip() else None


def _build_gemini_generation_body(
    *,
    prompt: str,
    response_format: StructuredResponseFormat,
    temperature: float | None,
    max_output_tokens: int | None,
) -> dict[str, object]:
    generation_config: dict[str, object] = {}
    if temperature is not None:
        generation_config["temperature"] = temperature
    if max_output_tokens is not None:
        generation_config["maxOutputTokens"] = max_output_tokens
    if response_format == StructuredResponseFormat.JSON_OBJECT:
        generation_config["responseMimeType"] = "application/json"

    body: dict[str, object] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
    }
    if generation_config:
        body["generationConfig"] = generation_config
    return body


def _build_gemini_prompt(prompt: str) -> str:
    system_prefix = "SYSTEM_INSTRUCTION:\n"
    user_prefix = "\n\nUSER_PROMPT:\n"
    schema_prefix = "\n\nOUTPUT_SCHEMA:\n"

    if prompt.startswith(system_prefix) and user_prefix in prompt and schema_prefix in prompt:
        system_end = prompt.index(user_prefix)
        user_start = system_end + len(user_prefix)
        user_end = prompt.index(schema_prefix)
        system_prompt = prompt[len(system_prefix):system_end]
        user_prompt = prompt[user_start:user_end]
        schema_prompt = prompt[user_end + len(schema_prefix):]
        return (
            f"SYSTEM_INSTRUCTION:\n{system_prompt}\n\n"
            f"USER_PROMPT:\n{user_prompt}\n\n"
            f"Return a JSON object matching this schema:\n{schema_prompt}"
        )

    return prompt
