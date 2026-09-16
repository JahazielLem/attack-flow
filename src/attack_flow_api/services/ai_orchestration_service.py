import json
import hashlib
from dataclasses import dataclass

from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_output_validation_service import (
    ExtractionOutputValidationResult,
    parse_validate_and_repair_extraction_output,
)
from attack_flow_api.services.ai_prompt_templates import (
    build_empty_extraction_reprompt_bundle,
    build_prompt_template_bundle,
)
from attack_flow_api.services.ai_provider_invocation_service import AIProviderInvocationService
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.filesystem import LocalFileStorage
from attack_flow_api.storage.repositories import ArtifactCreate


@dataclass(frozen=True, slots=True)
class AIOrchestrationExecutionResult:
    succeeded: bool
    provider_invoked: bool
    provider_id: str | None
    model_used: str | None
    extraction_mode: str
    extraction_payload_json: str
    extraction_validation_state: str
    repair_attempted: bool
    provenance_classification: str
    authors_json: str
    external_references_json: str
    error_code: str | None = None
    error_message: str | None = None


class AIOrchestrationService:
    def __init__(
        self,
        *,
        persistence_service: PersistenceService,
        provider_invocation_service: AIProviderInvocationService,
        file_storage: LocalFileStorage | None = None,
    ):
        self.persistence_service = persistence_service
        self.provider_invocation_service = provider_invocation_service
        self.file_storage = file_storage

    def run_for_job(
        self,
        *,
        job_id: str,
        requested_provider_id: str | None,
        requested_model: str | None,
    ) -> AIOrchestrationExecutionResult:
        normalized_package = self.persistence_service.resolve_normalized_package_for_job(job_id)
        if normalized_package is None:
            return AIOrchestrationExecutionResult(
                succeeded=False,
                provider_invoked=False,
                provider_id=requested_provider_id,
                model_used=requested_model,
                extraction_mode="full_extraction",
                extraction_payload_json="{}",
                extraction_validation_state="invalid",
                repair_attempted=False,
                provenance_classification="unknown",
                authors_json="[]",
                external_references_json="[]",
                error_code="normalized_package_missing",
                error_message="canonical normalized package is not available",
            )

        packaged_input = build_provider_orchestration_input(normalized_package)
        prompt_bundle = build_prompt_template_bundle(packaged_input)

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="ai_extraction_input_prepared",
                source_component="orchestration",
                message="ai extraction input prepared",
                details={
                    "mode": packaged_input.mode.value,
                    "source_type": packaged_input.source_type,
                    "deterministic_input_sufficient": packaged_input.deterministic_input_sufficient,
                    "normalized_char_count": len(packaged_input.normalized_text),
                    "normalized_excerpt": _build_excerpt(packaged_input.normalized_text),
                    "attack_ref_count": len(packaged_input.deterministic_attack_refs),
                    "entity_count": len(packaged_input.deterministic_entities),
                    "relationship_count": len(packaged_input.deterministic_relationships),
                },
            )

        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="provider_invocation_started",
                source_component="orchestration",
                message="provider invocation started",
                details={
                    "requested_provider_id": requested_provider_id,
                    "requested_model": requested_model,
                    "deterministic_input_sufficient": packaged_input.deterministic_input_sufficient,
                },
            )

        invocation_result = self.provider_invocation_service.invoke_if_needed(
            packaged_input=packaged_input,
            prompt_bundle=prompt_bundle,
            requested_provider_id=requested_provider_id,
            requested_model=requested_model,
        )
        _capture_ai_trace(
            self=self,
            job_id=job_id,
            packaged_input=packaged_input,
            prompt_bundle=prompt_bundle,
            invocation_result=invocation_result,
            label="initial",
        )

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            if not invocation_result.provider_invoked:
                self.persistence_service.record_job_event(
                    job=job,
                    event_type="provider_invocation_skipped",
                    source_component="orchestration",
                    message="provider invocation skipped",
                    details={
                        "requested_provider_id": requested_provider_id,
                        "requested_model": requested_model,
                        "deterministic_input_sufficient": invocation_result.deterministic_input_sufficient,
                    },
                )
            self.persistence_service.record_job_event(
                job=job,
                event_type="provider_invocation_completed",
                source_component="orchestration",
                message="provider invocation completed",
                details={
                    "provider_invoked": invocation_result.provider_invoked,
                    "provider_id": invocation_result.provider_id,
                    "model_used": invocation_result.model_used,
                    "deterministic_input_sufficient": invocation_result.deterministic_input_sufficient,
                    "error_code": invocation_result.error_code,
                    "error_category": invocation_result.error_category,
                    "retryable": invocation_result.retryable,
                },
            )

        validated = parse_validate_and_repair_extraction_output(
            invocation_result=invocation_result,
            packaged_input=packaged_input,
        )

        if _should_retry_empty_full_extraction(packaged_input, invocation_result, validated):
            retry_bundle = build_empty_extraction_reprompt_bundle(
                packaged_input,
                source_cues=_extract_source_cues(packaged_input.normalized_text),
            )
            retry_result = self.provider_invocation_service.invoke_if_needed(
                packaged_input=packaged_input,
                prompt_bundle=retry_bundle,
                requested_provider_id=requested_provider_id,
                requested_model=requested_model,
            )
            _capture_ai_trace(
                self=self,
                job_id=job_id,
                packaged_input=packaged_input,
                prompt_bundle=retry_bundle,
                invocation_result=retry_result,
                label="retry",
            )
            retry_validated = parse_validate_and_repair_extraction_output(
                invocation_result=retry_result,
                packaged_input=packaged_input,
            )
            if retry_validated.valid and retry_validated.extraction_result is not None:
                invocation_result = retry_result
                validated = retry_validated
                if job is not None:
                    self.persistence_service.record_job_event(
                        job=job,
                        event_type="provider_invocation_reprompted",
                        source_component="orchestration",
                        message="provider invocation re-prompted",
                        details={
                            "requested_provider_id": requested_provider_id,
                            "requested_model": requested_model,
                            "source_cues": _extract_source_cues(packaged_input.normalized_text),
                        },
                    )
                    self.persistence_service.record_job_event(
                        job=job,
                        event_type="provider_invocation_reprompt_completed",
                        source_component="orchestration",
                        message="provider invocation re-prompt completed",
                        details={
                            "provider_invoked": retry_result.provider_invoked,
                            "provider_id": retry_result.provider_id,
                            "model_used": retry_result.model_used,
                            "error_code": retry_result.error_code,
                            "error_category": retry_result.error_category,
                            "retryable": retry_result.retryable,
                        },
                    )

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="structured_extraction_validated",
                source_component="orchestration",
                message="structured extraction validated",
                details={
                    "valid": validated.valid,
                    "repair_attempted": validated.repair_attempted,
                    "error_code": validated.error_code,
                    "error_message": validated.error_message,
                },
            )

            result_excerpt: str | None = None
            result_top_level_keys: list[str] = []
            if validated.extraction_result is not None:
                result_payload = validated.extraction_result.model_dump(mode="json")
                result_excerpt = _build_excerpt(result_payload)
                result_top_level_keys = sorted(result_payload.keys())
            elif invocation_result.output_text is not None:
                result_excerpt = _build_excerpt(invocation_result.output_text)
            elif invocation_result.output_json is not None:
                result_excerpt = _build_excerpt(invocation_result.output_json)

            self.persistence_service.record_job_event(
                job=job,
                event_type="ai_extraction_result",
                source_component="orchestration",
                message="ai extraction result",
                details={
                    "provider_invoked": invocation_result.provider_invoked,
                    "provider_id": invocation_result.provider_id,
                    "model_used": invocation_result.model_used,
                    "validation_state": validated.extraction_result.validation_state.value
                    if validated.extraction_result is not None
                    else "invalid",
                    "repair_attempted": validated.repair_attempted,
                    "error_code": validated.error_code,
                    "error_message": validated.error_message,
                    "result_excerpt": result_excerpt,
                    "top_level_keys": result_top_level_keys,
                },
            )

        return _to_execution_result(
            invocation_result=invocation_result,
            validated=validated,
            packaged_input=packaged_input,
        )


def _to_execution_result(
    *,
    invocation_result,
    validated: ExtractionOutputValidationResult,
    packaged_input,
) -> AIOrchestrationExecutionResult:
    metadata = packaged_input.metadata
    authors = _as_str_list(metadata.get("authors"))
    external_references = _as_str_list(metadata.get("external_references"))

    if not validated.valid or validated.extraction_result is None:
        return AIOrchestrationExecutionResult(
            succeeded=False,
            provider_invoked=invocation_result.provider_invoked,
            provider_id=invocation_result.provider_id,
            model_used=invocation_result.model_used,
            extraction_mode=packaged_input.mode.value,
            extraction_payload_json="{}",
            extraction_validation_state="invalid",
            repair_attempted=validated.repair_attempted,
            provenance_classification=packaged_input.source_type,
            authors_json=_to_json_list(authors),
            external_references_json=_to_json_list(external_references),
            error_code=validated.error_code,
            error_message=validated.error_message,
        )

    return AIOrchestrationExecutionResult(
        succeeded=True,
        provider_invoked=invocation_result.provider_invoked,
        provider_id=invocation_result.provider_id,
        model_used=invocation_result.model_used,
        extraction_mode=packaged_input.mode.value,
        extraction_payload_json=json.dumps(validated.extraction_result.model_dump(mode="json")),
        extraction_validation_state=validated.extraction_result.validation_state.value,
        repair_attempted=validated.extraction_result.repair_attempted,
        provenance_classification=packaged_input.source_type,
        authors_json=_to_json_list(authors),
        external_references_json=_to_json_list(external_references),
    )


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if candidate:
            out.append(candidate)
    return out


def _to_json_list(values: list[str]) -> str:
    return json.dumps(values)


def _build_excerpt(value: object, *, limit: int = 220) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)

    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def _trace_payload(
    *,
    job_id: str,
    packaged_input,
    prompt_bundle,
    invocation_result,
    label: str,
) -> dict[str, object]:
    return {
        "job_id": job_id,
        "label": label,
        "mode": packaged_input.mode.value,
        "source_type": packaged_input.source_type,
        "provider_id": invocation_result.provider_id,
        "model_used": invocation_result.model_used,
        "prompt": invocation_result.prompt_text or prompt_bundle.user_prompt,
        "system_instruction": prompt_bundle.system_instruction,
        "output_text": invocation_result.output_text,
        "output_json": invocation_result.output_json,
        "error_code": invocation_result.error_code,
        "error_category": invocation_result.error_category,
        "error_message": invocation_result.error_message,
        "retryable": invocation_result.retryable,
    }


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _trace_artifact_metadata(*, payload: dict[str, object], file_size_bytes: int, sha256: str) -> str:
    prompt = payload.get("prompt")
    output_text = payload.get("output_text")
    output_json = payload.get("output_json")
    metadata = {
        "kind": "ai_trace",
        "label": payload.get("label"),
        "mode": payload.get("mode"),
        "source_type": payload.get("source_type"),
        "provider_id": payload.get("provider_id"),
        "model_used": payload.get("model_used"),
        "prompt_length": len(prompt) if isinstance(prompt, str) else None,
        "output_text_length": len(output_text) if isinstance(output_text, str) else None,
        "output_json_keys": sorted(output_json.keys()) if isinstance(output_json, dict) else None,
        "file_size_bytes": file_size_bytes,
        "sha256": sha256,
    }
    return json.dumps(metadata, sort_keys=True)


def _trace_artifact_details(*, artifact_path: str, artifact_id: str, label: str, file_size_bytes: int) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": "ai_trace",
        "label": label,
        "path": artifact_path,
        "size_bytes": file_size_bytes,
    }


def _capture_ai_trace(
    self,
    *,
    job_id: str,
    packaged_input,
    prompt_bundle,
    invocation_result,
    label: str,
) -> None:
    if self.file_storage is None or not invocation_result.provider_invoked:
        return

    payload = _trace_payload(
        job_id=job_id,
        packaged_input=packaged_input,
        prompt_bundle=prompt_bundle,
        invocation_result=invocation_result,
        label=label,
    )
    serialized = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8")
    trace_file = self.file_storage.write_artifact(serialized, extension="json")
    sha256 = _sha256_hex(serialized + label.encode("utf-8"))
    artifact = self.persistence_service.create_artifact(
        ArtifactCreate(
            id=f"ai-trace-{job_id}-{label}-{sha256[:12]}",
            job_id=job_id,
            type="ai_trace",
            path=trace_file.relative_path,
            sha256=sha256,
            size_bytes=trace_file.size_bytes,
            metadata_json=_trace_artifact_metadata(payload=payload, file_size_bytes=trace_file.size_bytes, sha256=sha256),
        )
    )
    job = self.persistence_service.get_job(job_id)
    if job is not None:
        self.persistence_service.record_job_event(
            job=job,
            event_type="ai_trace_captured",
            source_component="orchestration",
            message="ai trace captured",
            details=_trace_artifact_details(
                artifact_path=artifact.path,
                artifact_id=artifact.id,
                label=label,
                file_size_bytes=trace_file.size_bytes,
            ),
        )


def _should_retry_empty_full_extraction(
    packaged_input,
    invocation_result,
    validated: ExtractionOutputValidationResult,
) -> bool:
    if packaged_input.mode.value != "full_extraction":
        return False
    if not invocation_result.provider_invoked:
        return False
    if not validated.valid or validated.extraction_result is None:
        return False
    return len(validated.extraction_result.attack_actions) == 0


def _extract_source_cues(normalized_text: str, *, limit: int = 6) -> list[str]:
    cues: list[str] = []
    for line in normalized_text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if len(candidate) > 90:
            continue
        lowered = candidate.lower()
        if any(keyword in lowered for keyword in ("phase", "persistence", "lateral movement", "reconnaissance", "command", "control", "c2", "credential", "mimikatz", "powershell", "scheduled task")):
            cues.append(candidate)
        if len(cues) >= limit:
            break
    return cues
