import pytest

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import ProviderValidationRequest, StructuredGenerationRequest
from attack_flow_api.providers.gemini_adapter import (
    GeminiHttpError,
    GeminiHttpResponse,
    GeminiProviderAdapter,
)


def _provider_config() -> ProviderConfig:
    return ProviderConfig(
        provider_id="gemini-primary",
        provider_type="gemini",
        enabled=True,
        api_key_env="GEMINI_API_KEY",
        default_model="gemini-1.5-flash",
        allowed_models=["gemini-1.5-flash", "gemini-1.5-pro"],
        retry_max_attempts=3,
        retry_base_delay_ms=1,
        retry_max_delay_ms=1,
    )


def test_validate_succeeds_with_injected_executor(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return GeminiHttpResponse(status_code=200, json_body={"ok": True})

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini")
    )

    assert result.is_valid is True
    assert result.checked_model == "gemini-1.5-flash"
    request = seen["request"]
    assert request is not None
    assert request.url == "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    assert request.headers["x-goog-api-key"] == "test-key"
    assert request.json_body == {
        "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
        "generationConfig": {"maxOutputTokens": 16},
    }


def test_generate_structured_returns_text_json_usage_and_finish_reason(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return GeminiHttpResponse(
            status_code=200,
            json_body={
                "candidates": [
                    {
                        "content": {"parts": [{"text": '{"risk_level":"high"}'}]},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 12,
                    "candidatesTokenCount": 8,
                    "totalTokenCount": 20,
                },
            },
        )

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="gemini-primary",
            provider_type="gemini",
            model="gemini-1.5-flash",
            prompt=(
                "SYSTEM_INSTRUCTION:\nParse the report\n\n"
                "USER_PROMPT:\nSummarize the findings\n\n"
                "OUTPUT_SCHEMA:\n{}"
            ),
            max_output_tokens=5,
        )
    )

    request = seen["request"]
    assert request is not None
    assert request.json_body["contents"] == [
        {
            "role": "user",
            "parts": [
                {
                    "text": (
                        "SYSTEM_INSTRUCTION:\nParse the report\n\n"
                        "USER_PROMPT:\nSummarize the findings\n\n"
                        "Return a JSON object matching this schema:\n{}"
                    )
                }
            ],
        }
    ]
    assert request.json_body["generationConfig"] == {
        "maxOutputTokens": 5,
        "responseMimeType": "application/json",
    }
    assert result.output_text == '{"risk_level":"high"}'
    assert result.output_json == {"risk_level": "high"}
    assert result.finish_reason.value == "stop"
    assert result.usage.input_tokens == 12
    assert result.usage.output_tokens == 8
    assert result.usage.total_tokens == 20


def test_validate_maps_auth_error(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    adapter = GeminiProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(GeminiHttpError(status_code=401)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert exc.value.error.category.value == "auth_failure"
    assert exc.value.error.code == "provider_auth_failed"
    assert exc.value.error.retryable is False


def test_validate_retries_and_maps_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise GeminiHttpError(status_code=429)
        return GeminiHttpResponse(status_code=200, json_body={"ok": True})

    sleeps: list[float] = []
    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini")
    )

    assert result.is_valid is True
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_generate_structured_maps_timeout(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    adapter = GeminiProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(TimeoutError("timed out")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="gemini-primary",
                provider_type="gemini",
                model="gemini-1.5-flash",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "timeout"
    assert exc.value.error.code == "provider_timeout"
    assert exc.value.error.retryable is True


def test_generate_structured_rejects_disallowed_model_override(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    adapter = GeminiProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="gemini-primary",
                provider_type="gemini",
                model="gemini-2.0-flash",
                prompt="risk summary",
            )
        )

    assert exc.value.error.code == "provider_model_not_allowed"
    assert exc.value.error.category.value == "configuration_error"


def test_generate_structured_allows_configured_model_override(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen = {"url": None}

    def executor(request):
        seen["url"] = request.url
        return GeminiHttpResponse(
            status_code=200,
            json_body={
                "candidates": [{"content": {"parts": [{"text": "{}"}]}, "finishReason": "STOP"}]
            },
        )

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="gemini-primary",
            provider_type="gemini",
            model="gemini-1.5-pro",
            prompt="risk summary",
        )
    )

    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
    assert result.model == "gemini-1.5-pro"


def test_validate_uses_default_model_when_request_model_missing(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    seen = {"url": None}

    def executor(request):
        seen["url"] = request.url
        return GeminiHttpResponse(status_code=200, json_body={"ok": True})

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert result.checked_model == "gemini-1.5-flash"
    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


def test_request_timeout_is_capped_by_provider_timeout(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    config = _provider_config()
    config.timeout_seconds = 3
    seen = {"timeout": None}

    def executor(request):
        seen["timeout"] = request.timeout_seconds
        return GeminiHttpResponse(status_code=200, json_body={"ok": True})

    adapter = GeminiProviderAdapter(config, request_executor=executor)
    adapter.validate(
        ProviderValidationRequest(
            provider_id="gemini-primary",
            provider_type="gemini",
            timeout_seconds=10,
        )
    )

    assert seen["timeout"] == 3


def test_auth_failure_is_not_retried(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        raise GeminiHttpError(status_code=401)

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError):
        adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert attempts["count"] == 1


def test_retry_backoff_respects_zero_delay(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    config = _provider_config()
    config.retry_base_delay_ms = 0
    config.retry_max_delay_ms = 0
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise GeminiHttpError(status_code=503)
        return GeminiHttpResponse(status_code=200, json_body={"ok": True})

    adapter = GeminiProviderAdapter(config, request_executor=executor, sleep_fn=sleeps.append)
    adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert attempts["count"] == 3
    assert sleeps == [0.0, 0.0]


def test_transient_failure_retries_until_bounded_limit(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        raise GeminiHttpError(status_code=503, response_headers={"x-goog-request-id": "req_123"})

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert exc.value.error.category.value == "unavailable"
    assert exc.value.error.code == "provider_unavailable"
    assert exc.value.error.retryable is True
    assert exc.value.error.status_code == 503
    assert exc.value.error.details["x-goog-request-id"] == "req_123"
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_network_error_details_do_not_include_api_key(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def executor(request):
        raise OSError("certificate verify failed")

    adapter = GeminiProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="gemini-primary", provider_type="gemini"))

    assert exc.value.error.code == "provider_network_error"
    assert exc.value.error.details["request_path"] == "/v1beta/models/gemini-1.5-flash:generateContent"
    assert "test-key" not in str(exc.value.error.model_dump())
