import pytest

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import ProviderValidationRequest, StructuredGenerationRequest
from attack_flow_api.providers.openai_adapter import (
    OpenAIHttpError,
    OpenAIHttpResponse,
    OpenAIProviderAdapter,
)


def _provider_config() -> ProviderConfig:
    return ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini", "gpt-4.1"],
        retry_max_attempts=3,
        retry_base_delay_ms=1,
        retry_max_delay_ms=1,
    )


def _azure_provider_config() -> ProviderConfig:
    return ProviderConfig(
        provider_id="azure-openai",
        provider_type="azure_openai",
        enabled=True,
        base_url="https://example.openai.azure.com",
        api_version="2024-10-21",
        azure_ad_token_env="AZURE_AD_TOKEN",
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini", "gpt-4.1"],
        retry_max_attempts=1,
        retry_base_delay_ms=1,
        retry_max_delay_ms=1,
    )


def test_validate_succeeds_with_injected_executor(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: OpenAIHttpResponse(status_code=200, json_body={"ok": True}),
    )

    result = adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
        )
    )

    assert result.is_valid is True
    assert result.checked_model == "gpt-4.1-mini"


def test_azure_validate_uses_chat_completions_request(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return OpenAIHttpResponse(status_code=200, json_body={"choices": []})

    adapter = OpenAIProviderAdapter(_azure_provider_config(), request_executor=executor)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="azure-openai", provider_type="azure_openai")
    )

    assert result.is_valid is True
    request = seen["request"]
    assert request is not None
    assert request.url == (
        "https://example.openai.azure.com/openai/deployments/gpt-4.1-mini/chat/completions"
        "?api-version=2024-10-21"
    )
    assert request.headers["Authorization"] == "Bearer azure-token"
    assert request.json_body == {
        "messages": [{"role": "user", "content": "ping"}],
        "max_completion_tokens": 16,
    }


def test_validate_maps_auth_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(OpenAIHttpError(status_code=401)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(
            ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
        )

    assert exc.value.error.category.value == "auth_failure"
    assert exc.value.error.code == "provider_auth_failed"
    assert exc.value.error.retryable is False


def test_validate_retries_and_maps_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise OpenAIHttpError(status_code=429)
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    sleeps: list[float] = []
    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
    )

    assert result.is_valid is True
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_generate_structured_returns_text_and_json(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: OpenAIHttpResponse(
            status_code=200,
            json_body={
                "output_text": '{"risk_level":"high"}',
                "usage": {"input_tokens": 12, "output_tokens": 8, "total_tokens": 20},
            },
        ),
    )

    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="default-openai",
            provider_type="openai",
            model="gpt-4.1-mini",
            prompt="risk summary",
        )
    )

    assert result.output_text == '{"risk_level":"high"}'
    assert result.output_json == {"risk_level": "high"}
    assert result.usage.total_tokens == 20


def test_azure_generate_structured_parses_chat_completion_response(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return OpenAIHttpResponse(
            status_code=200,
            json_body={
                "choices": [{"message": {"content": '{"risk_level":"high"}'}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
            },
        )

    adapter = OpenAIProviderAdapter(_azure_provider_config(), request_executor=executor)
    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="azure-openai",
            provider_type="azure_openai",
            model="gpt-4.1-mini",
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
    assert request.json_body["messages"] == [
        {"role": "system", "content": "Parse the report"},
        {"role": "user", "content": "Summarize the findings"},
    ]
    assert request.json_body["max_completion_tokens"] == 5
    assert "response_format" not in request.json_body
    assert result.output_text == '{"risk_level":"high"}'
    assert result.output_json == {"risk_level": "high"}
    assert result.usage.input_tokens == 12
    assert result.usage.output_tokens == 8
    assert result.usage.total_tokens == 20


def test_azure_base_url_with_openai_suffix_preserves_openai_path(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return OpenAIHttpResponse(status_code=200, json_body={"choices": []})

    config = _azure_provider_config()
    config.base_url = "https://example.openai.azure.com/openai"
    adapter = OpenAIProviderAdapter(config, request_executor=executor)
    adapter.validate(ProviderValidationRequest(provider_id="azure-openai", provider_type="azure_openai"))

    request = seen["request"]
    assert request is not None
    assert request.url == (
        "https://example.openai.azure.com/openai/deployments/gpt-4.1-mini/chat/completions"
        "?api-version=2024-10-21"
    )


def test_azure_list_model_ids_queries_azure_models_endpoint(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return OpenAIHttpResponse(
            status_code=200,
            json_body={
                "data": [
                    {"id": "gpt-5.5"},
                    {"id": "gpt-5.5-pro"},
                    {"id": "gpt-5.5"},
                ]
            },
        )

    adapter = OpenAIProviderAdapter(_azure_provider_config(), request_executor=executor)

    model_ids = adapter.list_model_ids()

    request = seen["request"]
    assert request is not None
    assert request.method == "GET"
    assert request.url == "https://example.openai.azure.com/openai/models?api-version=2024-10-21"
    assert model_ids == ["gpt-5.5", "gpt-5.5-pro"]


def test_azure_list_model_ids_preserves_openai_suffix(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")
    seen = {"request": None}

    def executor(request):
        seen["request"] = request
        return OpenAIHttpResponse(status_code=200, json_body={"data": []})

    config = _azure_provider_config()
    config.base_url = "https://example.openai.azure.com/openai"
    adapter = OpenAIProviderAdapter(config, request_executor=executor)

    assert adapter.list_model_ids() == []
    request = seen["request"]
    assert request is not None
    assert request.url == "https://example.openai.azure.com/openai/models?api-version=2024-10-21"


def test_generate_structured_maps_timeout(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(TimeoutError("timed out")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-4.1-mini",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "timeout"
    assert exc.value.error.code == "provider_timeout"
    assert exc.value.error.retryable is True


def test_validate_maps_unavailable_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(OpenAIHttpError(status_code=503)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(
            ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
        )

    assert exc.value.error.category.value == "unavailable"
    assert exc.value.error.code == "provider_unavailable"
    assert exc.value.error.retryable is True


def test_validate_maps_network_error_with_diagnostics(monkeypatch, caplog) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("SSL_CERT_FILE", "/Users/youngrm/mitre.pem")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8080")

    def executor(request):
        raise OSError("certificate verify failed")

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)

    with caplog.at_level("WARNING", logger="attack_flow_api.provider_openai"):
        with pytest.raises(ProviderAdapterInvocationError) as exc:
            adapter.validate(
                ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
            )

    assert exc.value.error.category.value == "unavailable"
    assert exc.value.error.code == "provider_network_error"
    assert exc.value.error.details["request_method"] == "POST"
    assert exc.value.error.details["request_path"] == "/v1/responses"
    assert exc.value.error.details["request_host"] == "api.openai.com"
    assert exc.value.error.details["ssl_cert_file"] == "/Users/youngrm/mitre.pem"
    assert exc.value.error.details["https_proxy_set"] == "true"

    message = " ".join(record.message for record in caplog.records)
    assert "provider network error" in message
    assert "certificate verify failed" in message


def test_rate_limit_error_logs_response_headers(monkeypatch, caplog) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def executor(request):
        raise OpenAIHttpError(
            status_code=429,
            response_body='{"error":"rate limit"}',
            response_headers={
                "x-request-id": "req_123",
                "retry-after": "60",
                "x-ratelimit-limit-requests": "10",
                "x-ratelimit-remaining-requests": "0",
                "x-ratelimit-reset-requests": "2026-06-11T21:10:00Z",
            },
        )

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)

    with caplog.at_level("WARNING", logger="attack_flow_api.provider_openai"):
        with pytest.raises(ProviderAdapterInvocationError):
            adapter.validate(
                ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
            )

    message = " ".join(record.message for record in caplog.records)
    assert "req_123" in message
    assert "retry-after" not in message
    assert "status_code=429" in message


def test_http_error_logs_safe_excerpt(monkeypatch, caplog) -> None:
    monkeypatch.setenv("AZURE_AD_TOKEN", "azure-token")

    def executor(request):
        raise OpenAIHttpError(
            status_code=400,
            response_body='{"error":{"type":"invalid_request_error","message":"bad request"}}',
            response_headers={"x-request-id": "req_456"},
        )

    adapter = OpenAIProviderAdapter(_azure_provider_config(), request_executor=executor)

    with caplog.at_level("WARNING", logger="attack_flow_api.provider_openai"):
        with pytest.raises(ProviderAdapterInvocationError):
            adapter.validate(ProviderValidationRequest(provider_id="azure-openai", provider_type="azure_openai"))

    message = " ".join(record.message for record in caplog.records)
    assert "provider http error" in message
    assert "provider_type=azure_openai" in message
    assert "status_code=400" in message
    assert "req_456" in message
    assert "invalid_request_error" in message
    assert "bad request" in message


def test_quota_exceeded_is_not_retryable(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(
            OpenAIHttpError(
                status_code=429,
                response_body='{"error":{"type":"insufficient_quota","code":"insufficient_quota"}}',
                response_headers={"x-request-id": "req_123"},
            )
        ),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert exc.value.error.code == "provider_quota_exceeded"
    assert exc.value.error.category.value == "configuration_error"
    assert exc.value.error.retryable is False


def test_generate_structured_maps_invalid_response_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(ValueError("bad response")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-4.1-mini",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "invalid_response"
    assert exc.value.error.code == "provider_invalid_response"
    assert exc.value.error.retryable is False


def test_generate_structured_rejects_disallowed_model_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-5",
                prompt="risk summary",
            )
        )

    assert exc.value.error.code == "provider_model_not_allowed"
    assert exc.value.error.category.value == "configuration_error"


def test_list_model_ids_returns_accessible_models(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: OpenAIHttpResponse(
            status_code=200,
            json_body={
                "data": [
                    {"id": "gpt-5.5"},
                    {"id": "gpt-5.5-pro"},
                    {"id": "gpt-5.5"},
                ]
            },
        ),
    )

    model_ids = adapter.list_model_ids()

    assert model_ids == ["gpt-5.5", "gpt-5.5-pro"]


def test_validate_uses_provider_default_model_when_request_model_missing(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    seen = {"model": None}

    def executor(request):
        assert request.json_body is not None
        seen["model"] = request.json_body.get("model")
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
        )
    )

    assert result.checked_model == "gpt-4.1-mini"
    assert seen["model"] == "gpt-4.1-mini"


def test_request_timeout_is_capped_by_provider_timeout(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    config = _provider_config()
    config.timeout_seconds = 3
    seen = {"timeout": None}

    def executor(request):
        seen["timeout"] = request.timeout_seconds
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    adapter = OpenAIProviderAdapter(config, request_executor=executor)
    adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
            timeout_seconds=10,
        )
    )
    assert seen["timeout"] == 3


def test_auth_failure_is_not_retried(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        raise OpenAIHttpError(status_code=401)

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError):
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert attempts["count"] == 1


def test_unavailable_failure_retries_until_bounded_limit(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        raise OpenAIHttpError(status_code=503)

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert exc.value.error.category.value == "unavailable"
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_missing_api_key_never_leaks_secret(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter = OpenAIProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert exc.value.error.code == "provider_api_key_missing"
    assert "test-key" not in exc.value.error.message
