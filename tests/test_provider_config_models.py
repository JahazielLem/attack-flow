import pytest
from pydantic import ValidationError

from pathlib import Path

from attack_flow_api.config import ProviderConfig, ProvidersConfig, load_providers_config


def test_provider_config_model_validates_canonical_fields() -> None:
    config = ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini", "gpt-4.1"],
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        timeout_seconds=30,
        connect_timeout_seconds=5,
        read_timeout_seconds=20,
        retry_max_attempts=3,
        retry_base_delay_ms=200,
        retry_max_delay_ms=2000,
    )

    assert config.provider_id == "default-openai"
    assert config.provider_type == "openai"
    assert config.default_model == "gpt-4.1-mini"
    assert config.allowed_models == ["gpt-4.1-mini", "gpt-4.1"]
    assert config.timeout_seconds == 30
    assert config.retry_max_attempts == 3


def test_provider_config_model_accepts_anthropic_and_gemini_fields() -> None:
    anthropic = ProviderConfig(
        provider_id="anthropic-primary",
        provider_type="anthropic",
        enabled=True,
        api_key_env="ANTHROPIC_API_KEY",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-3-5-haiku-latest",
        allowed_models=["claude-3-5-haiku-latest"],
        timeout_seconds=30,
        retry_max_attempts=2,
    )
    gemini = ProviderConfig(
        provider_id="gemini-primary",
        provider_type="gemini",
        enabled=True,
        api_key_env="GEMINI_API_KEY",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        default_model="gemini-1.5-flash",
        allowed_models=["gemini-1.5-flash"],
        timeout_seconds=30,
        retry_max_attempts=2,
    )

    assert anthropic.provider_type == "anthropic"
    assert anthropic.api_key_env == "ANTHROPIC_API_KEY"
    assert gemini.provider_type == "gemini"
    assert gemini.api_key_env == "GEMINI_API_KEY"


def test_provider_config_model_rejects_invalid_provider_type() -> None:
    with pytest.raises(ValidationError):
        ProviderConfig(
            provider_id="bad-provider",
            provider_type="unsupported",  # type: ignore[arg-type]
        )


def test_public_provider_metadata_excludes_secret_fields() -> None:
    config = ProviderConfig(
        provider_id="azure-primary",
        provider_type="azure_openai",
        enabled=True,
        api_key_env="AZURE_OPENAI_KEY",
        azure_api_key_env="AZURE_OPENAI_KEY",
        azure_ad_token_env="AZURE_AD_TOKEN",
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini"],
        base_url="https://example.openai.azure.com",
        api_version="2024-10-21",
    )

    public = config.to_public_metadata()
    payload = public.model_dump()

    assert payload["provider_id"] == "azure-primary"
    assert payload["provider_type"] == "azure_openai"
    assert payload["default_model"] == "gpt-4.1-mini"
    assert payload["allowed_models"] == ["gpt-4.1-mini"]
    assert "api_key_env" not in payload
    assert "azure_api_key_env" not in payload
    assert "azure_ad_token_env" not in payload
    assert "provider_config" not in payload


def test_public_provider_metadata_supports_gemini_without_secret_fields() -> None:
    config = ProviderConfig(
        provider_id="gemini-primary",
        provider_type="gemini",
        enabled=True,
        api_key_env="GEMINI_API_KEY",
        default_model="gemini-1.5-flash",
        allowed_models=["gemini-1.5-flash"],
        base_url="https://generativelanguage.googleapis.com/v1beta",
    )

    payload = config.to_public_metadata().model_dump()

    assert payload["provider_id"] == "gemini-primary"
    assert payload["provider_type"] == "gemini"
    assert payload["default_model"] == "gemini-1.5-flash"
    assert payload["base_url"] == "https://generativelanguage.googleapis.com/v1beta"
    assert "api_key_env" not in payload


def test_providers_config_lookup_and_lists() -> None:
    providers = ProvidersConfig(
        providers=[
            ProviderConfig(provider_id="p1", provider_type="openai", enabled=True),
            ProviderConfig(provider_id="p2", provider_type="anthropic", enabled=False),
        ]
    )

    assert providers.get_provider_by_id("p1") is not None
    assert providers.get_provider_by_id("missing") is None
    assert [item.provider_id for item in providers.list_enabled_providers()] == ["p1"]
    assert [item.provider_id for item in providers.list_public_metadata()] == ["p1", "p2"]


def test_get_openai_provider_by_id_returns_only_openai_provider() -> None:
    providers = ProvidersConfig(
        providers=[
            ProviderConfig(provider_id="p1", provider_type="openai", enabled=True),
            ProviderConfig(provider_id="p2", provider_type="azure_openai", enabled=True),
            ProviderConfig(provider_id="p3", provider_type="anthropic", enabled=True),
        ]
    )

    assert providers.get_openai_provider_by_id("p1") is not None
    assert providers.get_openai_provider_by_id("p2") is not None
    assert providers.get_openai_provider_by_id("p3") is None
    assert providers.get_openai_provider_by_id("missing") is None


def test_validate_openai_provider_config_reports_usable_and_error_states() -> None:
    providers = ProvidersConfig(
        providers=[
            ProviderConfig(
                provider_id="usable",
                provider_type="openai",
                enabled=True,
                api_key_env="OPENAI_API_KEY",
                default_model="gpt-4.1-mini",
            ),
            ProviderConfig(
                provider_id="invalid",
                provider_type="openai",
                enabled=False,
                api_key_env="",
                allowed_models=[],
                base_url="   ",
            ),
            ProviderConfig(
                provider_id="azure-usable",
                provider_type="azure_openai",
                enabled=True,
                azure_api_key_env="AZURE_OPENAI_KEY",
                default_model="gpt-4.1-mini",
                base_url="https://example.openai.azure.com",
                api_version="2024-10-21",
            ),
            ProviderConfig(
                provider_id="azure-invalid",
                provider_type="azure_openai",
                enabled=False,
                allowed_models=[],
                base_url="   ",
                api_version="   ",
            ),
        ]
    )

    assert providers.validate_openai_provider_config("usable") == []
    assert providers.validate_openai_provider_config("azure-usable") == []
    assert providers.validate_openai_provider_config("missing") == ["provider_not_found_or_not_openai"]
    assert providers.validate_openai_provider_config("invalid") == [
        "provider_disabled",
        "api_key_env_missing",
        "model_configuration_missing",
        "base_url_invalid",
    ]
    assert providers.validate_openai_provider_config("azure-invalid") == [
        "provider_disabled",
        "base_url_missing",
        "api_version_missing",
        "api_key_env_missing",
        "model_configuration_missing",
        "base_url_invalid",
    ]


def test_validate_provider_config_reports_anthropic_and_gemini_states() -> None:
    providers = ProvidersConfig(
        providers=[
            ProviderConfig(
                provider_id="anthropic-usable",
                provider_type="anthropic",
                enabled=True,
                api_key_env="ANTHROPIC_API_KEY",
                default_model="claude-3-5-haiku-latest",
            ),
            ProviderConfig(
                provider_id="gemini-usable",
                provider_type="gemini",
                enabled=True,
                api_key_env="GEMINI_API_KEY",
                default_model="gemini-1.5-flash",
            ),
            ProviderConfig(
                provider_id="gemini-invalid",
                provider_type="gemini",
                enabled=False,
                api_key_env="",
                allowed_models=[],
                base_url="   ",
            ),
        ]
    )

    assert providers.validate_provider_config("anthropic-usable") == []
    assert providers.validate_provider_config("gemini-usable") == []
    assert providers.validate_provider_config("missing") == ["provider_not_found"]
    assert providers.validate_provider_config("gemini-invalid") == [
        "provider_disabled",
        "api_key_env_missing",
        "model_configuration_missing",
        "base_url_invalid",
    ]


def test_load_providers_config_raises_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_providers_config(tmp_path / "missing-providers.yml")


def test_load_providers_config_rejects_non_mapping_root(tmp_path: Path) -> None:
    config_path = tmp_path / "providers.yml"
    config_path.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        load_providers_config(config_path)

    assert str(exc.value) == "Provider config YAML root must be a mapping"
