import pytest

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.anthropic_adapter import (
    AnthropicHttpError,
    AnthropicHttpResponse,
    AnthropicProviderAdapter,
)
from attack_flow_api.providers.contracts import ProviderValidationRequest, StructuredGenerationRequest


def _provider_config() -> ProviderConfig:
    return ProviderConfig(
        provider_id="anthropic-primary",
        provider_type="anthropic",
        enabled=True,
        api_key_env="ANTHROPIC_API_KEY",
        default_model="claude-3-5-haiku-latest",
        allowed_models=["claude-3-5-haiku-latest", "claude-3-5-sonnet-latest"],
        retry_max_attempts=3,
        retry_base_delay_ms=1,
        retry_max_delay_ms=1,
    )


def test_validate_succeeds_with_injected_executor(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return AnthropicHttpResponse(status_code=200, json_body={"ok": True})

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic")
    )

    assert result.is_valid is True
    assert result.checked_model == "claude-3-5-haiku-latest"
    request = seen["request"]
    assert request is not None
    assert request.url == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == "test-key"
    assert request.headers["anthropic-version"] == "2023-06-01"
    assert request.json_body == {
        "model": "claude-3-5-haiku-latest",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "ping"}],
    }


def test_generate_structured_returns_text_json_usage_and_finish_reason(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return AnthropicHttpResponse(
            status_code=200,
            json_body={
                "content": [{"type": "text", "text": '{"risk_level":"high"}'}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 12, "output_tokens": 8},
            },
        )

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="anthropic-primary",
            provider_type="anthropic",
            model="claude-3-5-haiku-latest",
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
    assert request.json_body["system"] == "Parse the report"
    assert request.json_body["messages"] == [
        {
            "role": "user",
            "content": "Summarize the findings\n\nReturn a JSON object matching this schema:\n{}",
        }
    ]
    assert request.json_body["max_tokens"] == 5
    assert result.output_text == '{"risk_level":"high"}'
    assert result.output_json == {"risk_level": "high"}
    assert result.finish_reason.value == "stop"
    assert result.usage.input_tokens == 12
    assert result.usage.output_tokens == 8
    assert result.usage.total_tokens == 20


def test_validate_maps_auth_error(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    adapter = AnthropicProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(AnthropicHttpError(status_code=401)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic"))

    assert exc.value.error.category.value == "auth_failure"
    assert exc.value.error.code == "provider_auth_failed"
    assert exc.value.error.retryable is False


def test_validate_retries_and_maps_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise AnthropicHttpError(status_code=429)
        return AnthropicHttpResponse(status_code=200, json_body={"ok": True})

    sleeps: list[float] = []
    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic")
    )

    assert result.is_valid is True
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_generate_structured_maps_timeout(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    adapter = AnthropicProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(TimeoutError("timed out")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="anthropic-primary",
                provider_type="anthropic",
                model="claude-3-5-haiku-latest",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "timeout"
    assert exc.value.error.code == "provider_timeout"
    assert exc.value.error.retryable is True


def test_generate_structured_rejects_disallowed_model_override(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    adapter = AnthropicProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="anthropic-primary",
                provider_type="anthropic",
                model="claude-4-opus",
                prompt="risk summary",
            )
        )

    assert exc.value.error.code == "provider_model_not_allowed"
    assert exc.value.error.category.value == "configuration_error"


def test_generate_structured_allows_configured_model_override(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    seen = {"model": None}

    def executor(request):
        assert request.json_body is not None
        seen["model"] = request.json_body.get("model")
        return AnthropicHttpResponse(
            status_code=200,
            json_body={"content": [{"type": "text", "text": "{}"}]},
        )

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="anthropic-primary",
            provider_type="anthropic",
            model="claude-3-5-sonnet-latest",
            prompt="risk summary",
        )
    )

    assert seen["model"] == "claude-3-5-sonnet-latest"
    assert result.model == "claude-3-5-sonnet-latest"


def test_validate_uses_default_model_when_request_model_missing(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    seen = {"model": None}

    def executor(request):
        assert request.json_body is not None
        seen["model"] = request.json_body.get("model")
        return AnthropicHttpResponse(status_code=200, json_body={"ok": True})

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.validate(
        ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic")
    )

    assert result.checked_model == "claude-3-5-haiku-latest"
    assert seen["model"] == "claude-3-5-haiku-latest"


def test_request_timeout_is_capped_by_provider_timeout(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    config = _provider_config()
    config.timeout_seconds = 3
    seen = {"timeout": None}

    def executor(request):
        seen["timeout"] = request.timeout_seconds
        return AnthropicHttpResponse(status_code=200, json_body={"ok": True})

    adapter = AnthropicProviderAdapter(config, request_executor=executor)
    adapter.validate(
        ProviderValidationRequest(
            provider_id="anthropic-primary",
            provider_type="anthropic",
            timeout_seconds=10,
        )
    )

    assert seen["timeout"] == 3


def test_auth_failure_is_not_retried(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        raise AnthropicHttpError(status_code=401)

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError):
        adapter.validate(ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic"))

    assert attempts["count"] == 1


def test_retry_backoff_respects_zero_delay(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    config = _provider_config()
    config.retry_base_delay_ms = 0
    config.retry_max_delay_ms = 0
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise AnthropicHttpError(status_code=503)
        return AnthropicHttpResponse(status_code=200, json_body={"ok": True})

    adapter = AnthropicProviderAdapter(config, request_executor=executor, sleep_fn=sleeps.append)
    adapter.validate(ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic"))

    assert attempts["count"] == 3
    assert sleeps == [0.0, 0.0]


def test_transient_failure_retries_until_bounded_limit(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        raise AnthropicHttpError(status_code=503, response_headers={"request-id": "req_123"})

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic"))

    assert exc.value.error.category.value == "unavailable"
    assert exc.value.error.code == "provider_unavailable"
    assert exc.value.error.retryable is True
    assert exc.value.error.status_code == 503
    assert exc.value.error.details["request-id"] == "req_123"
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_network_error_details_do_not_include_api_key(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    def executor(request):
        raise OSError("certificate verify failed")

    adapter = AnthropicProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="anthropic-primary", provider_type="anthropic"))

    assert exc.value.error.code == "provider_network_error"
    assert exc.value.error.details["request_path"] == "/v1/messages"
    assert "test-key" not in str(exc.value.error.model_dump())
