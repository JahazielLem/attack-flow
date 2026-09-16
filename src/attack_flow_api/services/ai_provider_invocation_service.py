import json
import logging
import time
from dataclasses import dataclass

from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import StructuredGenerationRequest, StructuredResponseFormat
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.ai_orchestration_planner import ProviderOrchestrationInput
from attack_flow_api.services.ai_prompt_templates import PromptTemplateBundle


@dataclass(frozen=True, slots=True)
class ProviderInvocationResult:
    provider_invoked: bool
    provider_id: str | None
    model_used: str | None
    deterministic_input_sufficient: bool
    prompt_text: str | None = None
    output_json: dict[str, object] | None = None
    output_text: str | None = None
    error_code: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    retryable: bool | None = None


class AIProviderInvocationService:
    def __init__(self, provider_registry: ProviderRegistry):
        self.provider_registry = provider_registry
        self._logger = logging.getLogger("attack_flow_api.provider_invocation")

    def invoke_if_needed(
        self,
        *,
        packaged_input: ProviderOrchestrationInput,
        prompt_bundle: PromptTemplateBundle,
        requested_provider_id: str | None,
        requested_model: str | None = None,
    ) -> ProviderInvocationResult:
        effective_provider_id = requested_provider_id
        if effective_provider_id is None or not effective_provider_id.strip():
            effective_provider_id = self.provider_registry.get_default_enabled_provider_id()

        plan = self.provider_registry.plan_optional_invocation(
            requested_provider_id=effective_provider_id,
            deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
        )

        self._logger.info(
            "provider invocation planned requested_provider_id=%s effective_provider_id=%s mode=%s adapter_resolved=%s",
            requested_provider_id,
            effective_provider_id,
            plan.mode.value,
            plan.adapter is not None,
        )

        if plan.adapter is None:
            return ProviderInvocationResult(
                provider_invoked=False,
                provider_id=plan.provider_id,
                model_used=None,
                deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
                prompt_text=None,
            )

        provider_config = self.provider_registry.get_provider_config(plan.provider_id or "")

        selected_model = requested_model
        if selected_model is None:
            selected_model = provider_config.default_model or (
                provider_config.allowed_models[0] if provider_config.allowed_models else None
            )

        max_attempts = provider_config.retry_max_attempts if provider_config.retry_max_attempts is not None else 3
        base_delay_ms = provider_config.retry_base_delay_ms if provider_config.retry_base_delay_ms is not None else 200
        max_delay_ms = provider_config.retry_max_delay_ms if provider_config.retry_max_delay_ms is not None else 2000

        generation_request = StructuredGenerationRequest(
            provider_id=plan.provider_id or "",
            provider_type=plan.provider_type or "",
            model=selected_model or "",
            prompt=self._compose_provider_prompt(prompt_bundle),
            response_format=StructuredResponseFormat.JSON_OBJECT,
            timeout_seconds=provider_config.timeout_seconds or 30.0,
        )

        self._logger.debug(
            "provider invocation prompt provider_id=%s model=%s\n%s",
            plan.provider_id,
            selected_model,
            generation_request.prompt,
        )

        for attempt in range(1, max_attempts + 1):
            try:
                response = plan.adapter.generate_structured(generation_request)
                return ProviderInvocationResult(
                    provider_invoked=True,
                    provider_id=response.provider_id,
                    model_used=response.model,
                    deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
                    prompt_text=generation_request.prompt,
                    output_json=response.output_json,
                    output_text=response.output_text,
                )
            except ProviderAdapterInvocationError as exc:
                normalized_error = exc.error
                is_last_attempt = attempt >= max_attempts
                if normalized_error.retryable and not is_last_attempt:
                    delay_seconds = min(base_delay_ms * (2 ** (attempt - 1)), max_delay_ms) / 1000.0
                    self._logger.info(
                        "provider invocation retrying provider_id=%s model=%s attempt=%s delay_seconds=%.3f error_code=%s",
                        plan.provider_id,
                        selected_model,
                        attempt,
                        delay_seconds,
                        normalized_error.code,
                    )
                    time.sleep(delay_seconds)
                    continue

                return ProviderInvocationResult(
                    provider_invoked=True,
                    provider_id=plan.provider_id,
                    model_used=selected_model,
                    deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
                    prompt_text=generation_request.prompt,
                    error_code=normalized_error.code,
                    error_category=normalized_error.category.value,
                    error_message=normalized_error.message,
                    retryable=normalized_error.retryable,
                )

    def _compose_provider_prompt(self, prompt_bundle: PromptTemplateBundle) -> str:
        schema_json = json.dumps(prompt_bundle.output_schema, indent=2, sort_keys=True)
        return (
            f"SYSTEM_INSTRUCTION:\n{prompt_bundle.system_instruction}\n\n"
            f"USER_PROMPT:\n{prompt_bundle.user_prompt}\n\n"
            f"OUTPUT_SCHEMA:\n{schema_json}\n"
        )
