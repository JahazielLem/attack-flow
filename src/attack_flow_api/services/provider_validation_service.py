import time
from dataclasses import dataclass, field

from attack_flow_api.providers.contracts import ProviderValidationRequest, RuntimeProviderOverride
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.registry import (
    ProviderDisabledError,
    ProviderNotFoundError,
    ProviderRegistry,
    RuntimeProviderExtraHeadersNotAllowedError,
    RuntimeProviderOverrideDisabledError,
    RuntimeProviderTypeNotAllowedError,
)


@dataclass(frozen=True, slots=True)
class ProviderValidationServiceResult:
    valid: bool
    provider_id: str
    provider_type: str | None
    model: str | None
    latency_ms: int
    error_code: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    retryable: bool | None = None
    status_code: int | None = None
    error_details: dict[str, str] = field(default_factory=dict)


class ProviderValidationService:
    def __init__(self, provider_registry: ProviderRegistry):
        self.provider_registry = provider_registry

    def validate_provider(self, provider_id: str, model: str | None = None) -> ProviderValidationServiceResult:
        started = time.perf_counter()
        provider_type: str | None = None

        try:
            provider_config = self.provider_registry.get_provider_config(provider_id)
            provider_type = provider_config.provider_type
            adapter = self.provider_registry.resolve_adapter(provider_id)
            result = adapter.validate(
                request=self._build_validation_request(
                    provider_id=provider_id,
                    provider_type=provider_type,
                    model=model,
                )
            )
            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
            return ProviderValidationServiceResult(
                valid=bool(result.is_valid),
                provider_id=result.provider_id,
                provider_type=result.provider_type,
                model=result.checked_model,
                latency_ms=latency_ms,
            )
        except ProviderNotFoundError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="provider_not_found",
                error_category="configuration_error",
                error_message="provider not found",
                retryable=False,
            )
        except ProviderDisabledError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="provider_disabled",
                error_category="configuration_error",
                error_message="provider is disabled",
                retryable=False,
            )
        except ProviderAdapterInvocationError as exc:
            normalized_error = exc.error
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type or normalized_error.provider_type,
                started=started,
                error_code=normalized_error.code,
                error_category=normalized_error.category.value,
                error_message=normalized_error.message,
                retryable=normalized_error.retryable,
                status_code=normalized_error.status_code,
                error_details=normalized_error.details,
            )

    def validate_runtime_provider(
        self,
        *,
        runtime_override: RuntimeProviderOverride,
        allow_runtime_provider_override: bool,
        allowed_provider_types: set[str],
        allow_extra_headers: bool = False,
    ) -> ProviderValidationServiceResult:
        started = time.perf_counter()
        provider_id = f"runtime-{runtime_override.provider_type}"
        provider_type: str | None = runtime_override.provider_type

        try:
            adapter = self.provider_registry.resolve_runtime_adapter(
                runtime_override=runtime_override,
                allow_runtime_provider_override=allow_runtime_provider_override,
                allowed_provider_types=allowed_provider_types,
                allow_extra_headers=allow_extra_headers,
            )
            result = adapter.validate(
                request=self._build_validation_request(
                    provider_id=adapter.provider_id,
                    provider_type=adapter.provider_type,
                    model=runtime_override.deployment or runtime_override.model,
                )
            )
            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
            return ProviderValidationServiceResult(
                valid=bool(result.is_valid),
                provider_id=result.provider_id,
                provider_type=result.provider_type,
                model=result.checked_model,
                latency_ms=latency_ms,
            )
        except RuntimeProviderOverrideDisabledError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="runtime_provider_override_disabled",
                error_category="configuration_error",
                error_message="runtime provider override is disabled",
                retryable=False,
            )
        except RuntimeProviderTypeNotAllowedError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="runtime_provider_type_not_allowed",
                error_category="configuration_error",
                error_message="runtime provider type is not allowed",
                retryable=False,
            )
        except RuntimeProviderExtraHeadersNotAllowedError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="runtime_provider_extra_headers_not_allowed",
                error_category="configuration_error",
                error_message="runtime provider extra headers are disabled",
                retryable=False,
            )
        except ProviderAdapterInvocationError as exc:
            normalized_error = exc.error
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type or normalized_error.provider_type,
                started=started,
                error_code=normalized_error.code,
                error_category=normalized_error.category.value,
                error_message=normalized_error.message,
                retryable=normalized_error.retryable,
                status_code=normalized_error.status_code,
                error_details=normalized_error.details,
            )

    def _build_validation_request(
        self, *, provider_id: str, provider_type: str, model: str | None
    ) -> ProviderValidationRequest:
        return ProviderValidationRequest(
            provider_id=provider_id,
            provider_type=provider_type,
            model=model,
        )

    def _failure(
        self,
        *,
        provider_id: str,
        provider_type: str | None,
        started: float,
        error_code: str,
        error_category: str,
        error_message: str,
        retryable: bool,
        status_code: int | None = None,
        error_details: dict[str, str] | None = None,
    ) -> ProviderValidationServiceResult:
        latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
        return ProviderValidationServiceResult(
            valid=False,
            provider_id=provider_id,
            provider_type=provider_type,
            model=None,
            latency_ms=latency_ms,
            error_code=error_code,
            error_category=error_category,
            error_message=error_message,
            retryable=retryable,
            status_code=status_code,
            error_details=error_details or {},
        )
