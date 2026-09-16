from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


ProviderType = Literal["openai", "azure_openai", "anthropic", "gemini", "openai_compatible"]


class ProviderConfig(BaseModel):
    provider_id: str
    provider_type: ProviderType
    enabled: bool = True
    default_model: str | None = None
    allowed_models: list[str] = Field(default_factory=list)

    # Common provider connection/config fields (non-secret values only)
    base_url: str | None = None
    api_version: str | None = None
    organization: str | None = None
    project: str | None = None

    # Secret references (environment variable names only)
    api_key_env: str | None = None
    azure_api_key_env: str | None = None
    azure_ad_token_env: str | None = None

    # Provider-specific extras for extensibility
    provider_config: dict[str, str] = Field(default_factory=dict)

    # Runtime request behavior settings (non-secret)
    timeout_seconds: float | None = Field(default=None, gt=0)
    connect_timeout_seconds: float | None = Field(default=None, gt=0)
    read_timeout_seconds: float | None = Field(default=None, gt=0)
    retry_max_attempts: int | None = Field(default=None, ge=1)
    retry_base_delay_ms: int | None = Field(default=None, ge=0)
    retry_max_delay_ms: int | None = Field(default=None, ge=0)

    def to_public_metadata(self) -> "ProviderPublicMetadata":
        return ProviderPublicMetadata(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            enabled=self.enabled,
            default_model=self.default_model,
            allowed_models=self.allowed_models,
            base_url=self.base_url,
            api_version=self.api_version,
            organization=self.organization,
            project=self.project,
        )


class ProviderPublicMetadata(BaseModel):
    provider_id: str
    provider_type: ProviderType
    enabled: bool
    default_model: str | None = None
    allowed_models: list[str] = Field(default_factory=list)
    base_url: str | None = None
    api_version: str | None = None
    organization: str | None = None
    project: str | None = None


class ProvidersConfig(BaseModel):
    providers: list[ProviderConfig] = Field(default_factory=list)

    def get_provider_by_id(self, provider_id: str) -> ProviderConfig | None:
        normalized = provider_id.strip()
        if not normalized:
            return None
        for provider in self.providers:
            if provider.provider_id == normalized:
                return provider
        return None

    def list_enabled_providers(self) -> list[ProviderConfig]:
        return [provider for provider in self.providers if provider.enabled]

    def list_public_metadata(self) -> list[ProviderPublicMetadata]:
        return [provider.to_public_metadata() for provider in self.providers]

    def get_openai_provider_by_id(self, provider_id: str) -> ProviderConfig | None:
        provider = self.get_provider_by_id(provider_id)
        if provider is None:
            return None
        if provider.provider_type not in {"openai", "azure_openai"}:
            return None
        return provider

    def get_provider_by_id_and_type(
        self,
        provider_id: str,
        provider_types: set[ProviderType],
    ) -> ProviderConfig | None:
        provider = self.get_provider_by_id(provider_id)
        if provider is None:
            return None
        if provider.provider_type not in provider_types:
            return None
        return provider

    def validate_provider_config(self, provider_id: str) -> list[str]:
        provider = self.get_provider_by_id(provider_id)
        if provider is None:
            return ["provider_not_found"]

        errors: list[str] = []
        if not provider.enabled:
            errors.append("provider_disabled")
        if provider.provider_type == "azure_openai":
            if provider.base_url is None or not provider.base_url.strip():
                errors.append("base_url_missing")
            if provider.api_version is None or not provider.api_version.strip():
                errors.append("api_version_missing")
            if all(
                not (env_var and env_var.strip())
                for env_var in (
                    provider.azure_api_key_env,
                    provider.azure_ad_token_env,
                    provider.api_key_env,
                )
            ):
                errors.append("api_key_env_missing")
        elif provider.api_key_env is None or not provider.api_key_env.strip():
            errors.append("api_key_env_missing")
        if provider.default_model is None and not provider.allowed_models:
            errors.append("model_configuration_missing")
        if provider.base_url is not None and not provider.base_url.strip():
            errors.append("base_url_invalid")
        return errors

    def validate_openai_provider_config(self, provider_id: str) -> list[str]:
        provider = self.get_openai_provider_by_id(provider_id)
        if provider is None:
            return ["provider_not_found_or_not_openai"]
        return self.validate_provider_config(provider_id)


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    app_name: str = Field(default="attack-flow-api", validation_alias="APP_NAME")
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    api_host: str = Field(default="127.0.0.1", validation_alias="API_HOST")
    api_port: int = Field(default=8000, validation_alias="API_PORT")
    api_prefix: str = Field(default="/api/v1", validation_alias="API_PREFIX")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    cors_enabled: bool = Field(default=False, validation_alias="CORS_ENABLED")
    cors_allow_origins: str = Field(default="", validation_alias="CORS_ALLOW_ORIGINS")
    cors_allow_credentials: bool = Field(
        default=False, validation_alias="CORS_ALLOW_CREDENTIALS"
    )
    cors_allow_methods: str = Field(default="*", validation_alias="CORS_ALLOW_METHODS")
    cors_allow_headers: str = Field(default="*", validation_alias="CORS_ALLOW_HEADERS")
    data_dir: Path = Field(default=Path("data"), validation_alias="DATA_DIR")
    sqlite_path: Path = Field(
        default=Path("data/attack-flow.db"), validation_alias="SQLITE_PATH"
    )
    upload_dir: Path = Field(default=Path("data/uploads"), validation_alias="UPLOAD_DIR")
    artifact_dir: Path = Field(
        default=Path("data/artifacts"), validation_alias="ARTIFACT_DIR"
    )
    file_storage_strict_mode: bool = Field(
        default=True, validation_alias="FILE_STORAGE_STRICT_MODE"
    )
    file_storage_max_bytes: int | None = Field(
        default=None, validation_alias="FILE_STORAGE_MAX_BYTES"
    )
    upload_max_bytes: int = Field(default=10_000_000, validation_alias="UPLOAD_MAX_BYTES")
    upload_allowed_file_classes: str = Field(
        default="pdf,plaintext,stix_json",
        validation_alias="UPLOAD_ALLOWED_FILE_CLASSES",
    )
    upload_allowed_mime_types: str = Field(
        default="application/pdf,text/plain,application/json",
        validation_alias="UPLOAD_ALLOWED_MIME_TYPES",
    )
    stix_max_object_count: int = Field(default=50000, validation_alias="STIX_MAX_OBJECT_COUNT")
    stix_max_structured_payload_bytes: int = Field(
        default=2_000_000,
        validation_alias="STIX_MAX_STRUCTURED_PAYLOAD_BYTES",
    )
    normalized_content_max_chars: int = Field(
        default=100_000,
        validation_alias="NORMALIZED_CONTENT_MAX_CHARS",
    )
    normalized_structured_max_bytes: int = Field(
        default=2_000_000,
        validation_alias="NORMALIZED_STRUCTURED_MAX_BYTES",
    )
    normalized_pipeline_version: str = Field(
        default="v1",
        validation_alias="NORMALIZED_PIPELINE_VERSION",
    )
    raw_text_max_chars: int = Field(default=200000, validation_alias="RAW_TEXT_MAX_CHARS")
    url_fetch_max_redirects: int = Field(default=5, validation_alias="URL_FETCH_MAX_REDIRECTS")
    url_fetch_connect_timeout_seconds: float = Field(
        default=5.0,
        validation_alias="URL_FETCH_CONNECT_TIMEOUT_SECONDS",
    )
    url_fetch_read_timeout_seconds: float = Field(
        default=10.0,
        validation_alias="URL_FETCH_READ_TIMEOUT_SECONDS",
    )
    url_fetch_max_response_bytes: int = Field(
        default=2_000_000,
        validation_alias="URL_FETCH_MAX_RESPONSE_BYTES",
    )
    url_fetch_allowed_schemes: str = Field(
        default="http,https",
        validation_alias="URL_FETCH_ALLOWED_SCHEMES",
    )
    url_fetch_block_private_destinations: bool = Field(
        default=True,
        validation_alias="URL_FETCH_BLOCK_PRIVATE_DESTINATIONS",
    )
    providers_config_path: Path = Field(
        default=Path("config/providers.yml"), validation_alias="PROVIDERS_CONFIG_PATH"
    )
    allow_runtime_provider_override: bool = Field(
        default=False, validation_alias="ALLOW_RUNTIME_PROVIDER_OVERRIDE"
    )
    allow_runtime_provider_types: str = Field(
        default="openai,openai_compatible,azure_openai,anthropic,gemini",
        validation_alias="ALLOW_RUNTIME_PROVIDER_TYPES",
    )
    allow_runtime_provider_extra_headers: bool = Field(
        default=False, validation_alias="ALLOW_RUNTIME_PROVIDER_EXTRA_HEADERS"
    )
    runtime_provider_timeout_seconds: float = Field(
        default=180.0,
        gt=0,
        validation_alias="RUNTIME_PROVIDER_TIMEOUT_SECONDS",
    )

    def allowed_runtime_provider_type_set(self) -> set[str]:
        return {item.strip() for item in self.allow_runtime_provider_types.split(",") if item.strip()}


def load_settings() -> AppSettings:
    return AppSettings()


def load_providers_config(config_path: Path) -> ProvidersConfig:
    if not config_path.exists():
        raise FileNotFoundError(f"Provider config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as config_file:
        raw_data = yaml.safe_load(config_file)

    if raw_data is None:
        raw_data = {}
    if not isinstance(raw_data, dict):
        raise ValueError("Provider config YAML root must be a mapping")

    try:
        return ProvidersConfig.model_validate(raw_data)
    except ValidationError as error:
        raise ValueError("Provider config validation failed") from error


def resolve_runtime_paths(settings: AppSettings) -> dict[str, Path]:
    return {
        "data_dir": settings.data_dir,
        "sqlite_path": settings.sqlite_path,
        "upload_dir": settings.upload_dir,
        "artifact_dir": settings.artifact_dir,
    }


def ensure_runtime_directories(runtime_paths: dict[str, Path]) -> None:
    runtime_paths["data_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["upload_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["artifact_dir"].mkdir(parents=True, exist_ok=True)
    runtime_paths["sqlite_path"].parent.mkdir(parents=True, exist_ok=True)
