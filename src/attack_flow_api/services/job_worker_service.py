import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from attack_flow_api.config import AppSettings
from attack_flow_api.providers.contracts import RuntimeProviderOverride
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.ai_orchestration_service import AIOrchestrationService
from attack_flow_api.services.ai_provider_invocation_service import AIProviderInvocationService
from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult
from attack_flow_api.services.afb_fusion_assembler import build_fused_output_candidate_from_sources
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.canonical_flow_conversion_service import build_canonical_flow_output
from attack_flow_api.services.canonical_flow_validation_service import validate_canonical_flow_output
from attack_flow_api.services.export_finalization_service import ExportFinalizationService
from attack_flow_api.services.file_classification import FileRoutingResult, classify_file_for_routing
from attack_flow_api.services.normalized_package_assembler import (
    build_narrative_normalized_update,
    build_structured_stix_normalized_update,
)
from attack_flow_api.services.stix_attack_refs import extract_explicit_attack_refs
from attack_flow_api.services.stix_bundle_inventory import build_stix_bundle_inventory_and_narrative
from attack_flow_api.services.stix_entities import extract_stix_entities
from attack_flow_api.services.stix_extraction_package import build_stix_extraction_package
from attack_flow_api.services.html_extraction import extract_readable_text_from_html
from attack_flow_api.services.pdf_extraction import PdfExtractionError, extract_pdf_text_content
from attack_flow_api.services.plaintext_extraction import (
    PlaintextExtractionError,
    extract_plaintext_content,
)
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.services.canonical_flow_contracts import CanonicalFlowOutput
from attack_flow_api.services.afb_export_contracts import (
    AfbExportArtifactMetadata,
    assemble_afb_export_bundle,
)
from attack_flow_api.services.stix_export_contracts import (
    StixExportArtifactMetadata,
    assemble_stix_export_bundle,
)
from attack_flow_api.services.stix_json_validation import (
    parse_stix_json_object,
    StixJsonValidationError,
    validate_stix_json_bundle_shape,
)
from attack_flow_api.services.stix_relationships import extract_stix_relationships
from attack_flow_api.services.url_fetch import UrlFetchError, fetch_url_bounded
from attack_flow_api.storage.filesystem import LocalFileStorage
from attack_flow_api.storage.models import InputSource
from attack_flow_api.storage.repositories import (
    InputSourceFetchUpdate,
    InputSourceFileUpdate,
    JobExtractionUpdate,
    JobUpdate,
    InputSourceStixUpdate,
)


class JobWorkerService:
    def __init__(
        self,
        persistence_service: PersistenceService,
        settings: AppSettings,
        file_storage: LocalFileStorage,
        provider_registry: ProviderRegistry,
        poll_interval_seconds: float = 1.0,
    ):
        self.persistence_service = persistence_service
        self.settings = settings
        self.file_storage = file_storage
        self.provider_registry = provider_registry
        self.poll_interval_seconds = poll_interval_seconds
        self.worker_id = f"worker-{uuid4()}"
        self._shutdown_event = asyncio.Event()
        self._wake_event = asyncio.Event()
        self._logger = logging.getLogger("attack_flow_api.worker")
        self._forced_failure_job_ids: set[str] = set()
        self._runtime_provider_overrides: dict[str, RuntimeProviderOverride] = {}
        self._url_job_context: dict[str, _UrlJobContext] = {}
        self._file_job_context: dict[str, _FileJobContext] = {}
        self._allowed_url_schemes = {
            item.strip().lower()
            for item in self.settings.url_fetch_allowed_schemes.split(",")
            if item.strip()
        }
        self._stage_progress = {
            "fetching": 10,
            "extracting": 25,
            "normalizing": 40,
            "ai_extraction": 60,
            "flow_building": 80,
            "exporting": 95,
        }
        self._processing_stages = (
            "extracting",
            "normalizing",
            "ai_extraction",
            "flow_building",
        )
        self._stix_extraction_failed_code = "stix_extraction_failed"
        self._stix_extraction_failed_message = "failed to extract structured stix content"
        self._provider_invocation_service = AIProviderInvocationService(provider_registry)
        self._ai_orchestration_service = AIOrchestrationService(
            persistence_service=persistence_service,
            provider_invocation_service=self._provider_invocation_service,
            file_storage=file_storage,
        )
        self._export_finalization_service = ExportFinalizationService(
            file_storage=file_storage,
            persistence_service=persistence_service,
        )

    async def run(self) -> None:
        self._logger.info("job worker started", extra={"worker_id": self.worker_id})
        try:
            while not self._shutdown_event.is_set():
                claimed_job = self.persistence_service.claim_next_queued_job(self.worker_id)
                if claimed_job is not None:
                    self._logger.info(
                        "queued job claimed",
                        extra={
                            "worker_id": self.worker_id,
                            "job_id": claimed_job.id,
                            "status": claimed_job.status,
                            "stage": claimed_job.stage,
                        },
                    )
                    await self._process_claimed_job(claimed_job.id)
                    continue

                try:
                    await asyncio.wait_for(self._wake_event.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    pass
                finally:
                    self._wake_event.clear()
        except asyncio.CancelledError:
            self._logger.info("job worker cancelled", extra={"worker_id": self.worker_id})
            raise
        finally:
            self._logger.info("job worker stopped", extra={"worker_id": self.worker_id})

    def stop(self) -> None:
        self._shutdown_event.set()
        self._wake_event.set()

    def notify_new_job(self) -> None:
        self._wake_event.set()

    def set_runtime_provider_override(self, job_id: str, runtime_override: RuntimeProviderOverride) -> None:
        self._runtime_provider_overrides[job_id] = runtime_override

    def force_failure_for_job(self, job_id: str) -> None:
        self._forced_failure_job_ids.add(job_id)

    def _record_job_event(self, job_id: str, *, event_type: str, message: str, details: dict[str, object]) -> None:
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return
        self.persistence_service.record_job_event(
            job=job,
            event_type=event_type,
            source_component="worker",
            message=message,
            details=details,
        )

    async def _process_claimed_job(self, job_id: str) -> None:
        try:
            for stage in self._processing_stages:
                self._advance_stage(job_id, stage)
                await self._run_stage_hook(job_id, stage)

            self.persistence_service.mark_job_completed(job_id)
            self._logger.info(
                "job lifecycle completed",
                extra={"worker_id": self.worker_id, "job_id": job_id, "status": "completed"},
            )
        except (_UrlJobProcessingError, _FileJobProcessingError) as exc:
            self.persistence_service.mark_job_failed(
                job_id,
                error_code=exc.job_error_code,
                error_message=exc.job_error_message,
            )
            self._logger.warning(
                "job lifecycle failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_code": exc.job_error_code,
                },
            )
        except _AIExtractionJobProcessingError as exc:
            self.persistence_service.mark_job_failed(
                job_id,
                error_code=exc.job_error_code,
                error_message=exc.job_error_message,
            )
            self._logger.warning(
                "job lifecycle failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_code": exc.job_error_code,
                },
            )
        except _STIXExportJobProcessingError as exc:
            self.persistence_service.mark_job_failed(
                job_id,
                error_code=exc.job_error_code,
                error_message=exc.job_error_message,
            )
            self._logger.warning(
                "job lifecycle failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_code": exc.job_error_code,
                },
            )
        except _AFBExportJobProcessingError as exc:
            self.persistence_service.mark_job_failed(
                job_id,
                error_code=exc.job_error_code,
                error_message=exc.job_error_message,
            )
            self._logger.warning(
                "job lifecycle failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_code": exc.job_error_code,
                },
            )
        except _ExportJobProcessingError as exc:
            self.persistence_service.mark_job_failed(
                job_id,
                error_code=exc.job_error_code,
                error_message=exc.job_error_message,
            )
            self._logger.warning(
                "job lifecycle failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_code": exc.job_error_code,
                },
            )
        except Exception as exc:  # pragma: no cover
            self.persistence_service.mark_job_failed(
                job_id,
                error_code="worker_processing_error",
                error_message=str(exc),
            )
            self._logger.exception(
                "job lifecycle failed",
                extra={"worker_id": self.worker_id, "job_id": job_id},
            )
        finally:
            self._url_job_context.pop(job_id, None)
            self._file_job_context.pop(job_id, None)
            self._runtime_provider_overrides.pop(job_id, None)

    def _advance_stage(self, job_id: str, stage: str) -> None:
        self.persistence_service.update_job_lifecycle(
            job_id,
            status=stage,
            stage=stage,
            progress_percent=self._stage_progress.get(stage),
            worker_id=self.worker_id,
        )

    async def _run_stage_hook(self, job_id: str, stage: str) -> None:
        if job_id in self._forced_failure_job_ids:
            self._forced_failure_job_ids.remove(job_id)
            raise RuntimeError("Forced worker failure for testing")

        job = self.persistence_service.get_job(job_id)
        if job is None or job.input_source_id is None:
            await asyncio.sleep(0)
            return

        input_source = self.persistence_service.get_input_source(job.input_source_id)
        if input_source is None:
            await asyncio.sleep(0)
            return

        if stage == "flow_building":
            self._run_canonical_flow_building(job_id)
            await asyncio.sleep(0)
            return

        if input_source.type == "url":
            await self._run_url_stage(job_id, stage, input_source)
            await asyncio.sleep(0)
            return

        if input_source.type == "file":
            await self._run_file_stage(job_id, stage, input_source)
            await asyncio.sleep(0)
            return

        if input_source.type == "text" and stage == "normalizing":
            self._persist_narrative_normalized_package(job_id, input_source.id)
            await asyncio.sleep(0)
            return

        normalized_text = None
        if stage == "ai_extraction":
            normalized_text = self.persistence_service.resolve_canonical_text_for_job(job_id)
            await asyncio.to_thread(self._run_ai_extraction_orchestration, job_id)
        _ = (job_id, stage, normalized_text)
        await asyncio.sleep(0)

    def _run_canonical_flow_building(self, job_id: str) -> None:
        # All requested exports are attempted, but the job only succeeds if every attempted
        # export validates and finalizes successfully.
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return

        if job.canonical_flow_json:
            canonical_flow = CanonicalFlowOutput.model_validate_json(job.canonical_flow_json)
            validation = validate_canonical_flow_output(canonical_flow)
            if not validation.valid:
                self._logger.warning(
                    "canonical flow validation failed",
                    extra={
                        "worker_id": self.worker_id,
                        "job_id": job_id,
                        "error_count": len(validation.errors),
                    },
                )
            self._advance_stage(job_id, "exporting")
            self._run_exports_with_all_or_nothing_policy(job_id, canonical_flow=canonical_flow)
            return

        fused_output: FusedOutputCandidate | None = None
        extraction_output: AfbExtractionResult | None = None

        if job.fusion_result_json:
            fused_output = FusedOutputCandidate.model_validate_json(job.fusion_result_json)
        elif job.extraction_result_json:
            extraction_output = AfbExtractionResult.model_validate_json(job.extraction_result_json)
        else:
            return

        canonical_flow = build_canonical_flow_output(fused_output=fused_output, extraction_output=extraction_output)
        if canonical_flow is None:
            return

        validation = validate_canonical_flow_output(canonical_flow)
        persisted_canonical_flow = canonical_flow.model_copy(
            update={
                "validation_state": "valid" if validation.valid else "invalid",
                "validation_errors": list(validation.errors),
            }
        )
        self.persistence_service.persist_canonical_flow_output(job_id, persisted_canonical_flow)
        if not validation.valid:
            self._logger.warning(
                "canonical flow validation failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_count": len(validation.errors),
                },
            )

        self._advance_stage(job_id, "exporting")
        self._run_exports_with_all_or_nothing_policy(job_id, canonical_flow=persisted_canonical_flow)

    def _run_exports_with_all_or_nothing_policy(self, job_id: str, *, canonical_flow: CanonicalFlowOutput) -> None:
        export_errors: list[_ExportJobProcessingError] = []

        try:
            self._run_stix_export(job_id, canonical_flow=canonical_flow)
        except _STIXExportJobProcessingError as exc:
            export_errors.append(
                _ExportJobProcessingError(job_error_code=exc.job_error_code, job_error_message=exc.job_error_message)
            )

        try:
            self._run_afb_export(job_id, canonical_flow=canonical_flow)
        except _AFBExportJobProcessingError as exc:
            export_errors.append(
                _ExportJobProcessingError(job_error_code=exc.job_error_code, job_error_message=exc.job_error_message)
            )

        if export_errors:
            failed_export_codes = ", ".join(error.job_error_code for error in export_errors)
            failed_export_messages = "; ".join(error.job_error_message for error in export_errors)
            raise _ExportJobProcessingError(
                job_error_code="export_validation_failed",
                job_error_message=(
                    "one or more exports failed validation: "
                    f"{failed_export_codes}; {failed_export_messages}"
                ),
            )

    def _run_stix_export(self, job_id: str, *, canonical_flow: CanonicalFlowOutput | None = None) -> None:
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return

        if canonical_flow is None:
            if not job.canonical_flow_json:
                raise _STIXExportJobProcessingError(
                    job_error_code="stix_export_missing_canonical_flow",
                    job_error_message="canonical flow is required for stix export",
                )
            canonical_flow = CanonicalFlowOutput.model_validate_json(job.canonical_flow_json)

        if canonical_flow is None:
            raise _STIXExportJobProcessingError(
                job_error_code="stix_export_missing_canonical_flow",
                job_error_message="canonical flow is required for stix export",
            )

        canonical_validation = validate_canonical_flow_output(canonical_flow)
        if not canonical_validation.valid:
            self._logger.warning(
                "canonical flow validation failed",
                extra={
                    "worker_id": self.worker_id,
                    "job_id": job_id,
                    "error_count": len(canonical_validation.errors),
                },
            )

        bundle = assemble_stix_export_bundle(canonical_flow)
        self._finalize_export_artifact(
            job=job,
            job_id=job_id,
            artifact_type="stix",
            bundle_id=bundle.metadata.id,
            object_count=bundle.metadata.object_count,
            finalization_result=self._export_finalization_service.finalize_stix_export(
                job_id=job_id,
                bundle=bundle,
            ),
        )

    def _run_afb_export(self, job_id: str, *, canonical_flow: CanonicalFlowOutput | None = None) -> None:
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return

        if canonical_flow is None:
            if not job.canonical_flow_json:
                raise _AFBExportJobProcessingError(
                    job_error_code="afb_export_missing_canonical_flow",
                    job_error_message="canonical flow is required for afb export",
                )
            canonical_flow = CanonicalFlowOutput.model_validate_json(job.canonical_flow_json)

        if canonical_flow is None:
            raise _AFBExportJobProcessingError(
                job_error_code="afb_export_missing_canonical_flow",
                job_error_message="canonical flow is required for afb export",
            )

        afb_bundle = assemble_afb_export_bundle(canonical_flow)
        self._finalize_export_artifact(
            job=job,
            job_id=job_id,
            artifact_type="afb",
            bundle_id=afb_bundle.metadata.bundle_id,
            object_count=afb_bundle.metadata.object_count,
            schema_version=afb_bundle.metadata.schema_version,
            finalization_result=self._export_finalization_service.finalize_afb_export(
                job_id=job_id,
                bundle=afb_bundle,
            ),
        )

    def _finalize_export_artifact(
        self,
        *,
        job,
        job_id: str,
        artifact_type: str,
        bundle_id: str | None,
        object_count: int | None,
        finalization_result,
        schema_version: str | None = None,
    ) -> None:
        if not finalization_result.valid:
            self._record_export_validation_failure(
                job=job,
                artifact_type=artifact_type,
                bundle_id=bundle_id,
                object_count=object_count,
                validation_errors=[error.model_dump(mode="json") for error in finalization_result.validation_errors],
                error_code=finalization_result.error_code,
                error_message=finalization_result.error_message,
                schema_version=schema_version,
            )
            raise self._build_export_processing_error(
                artifact_type=artifact_type,
                job_error_code=finalization_result.error_code or "export_validation_failed",
                job_error_message=finalization_result.error_message or "one or more exports failed validation",
            )

        artifact = self.persistence_service.list_artifacts(job_id=job_id, artifact_type=artifact_type)[-1]
        if artifact_type == "stix":
            self.persistence_service.record_stix_export_completed(
                job=job,
                artifact=artifact,
                bundle_id=bundle_id or "",
                object_count=object_count or 0,
                exported_at=finalization_result.created_at.isoformat().replace("+00:00", "Z")
                if finalization_result.created_at is not None
                else "",
            )
            return

        self.persistence_service.record_afb_export_completed(
            job=job,
            artifact=artifact,
            bundle_id=bundle_id or "",
            object_count=object_count or 0,
            exported_at=finalization_result.created_at.isoformat().replace("+00:00", "Z")
            if finalization_result.created_at is not None
            else "",
            schema_version=schema_version,
        )

    def _record_export_validation_failure(
        self,
        *,
        job,
        artifact_type: str,
        bundle_id: str | None,
        object_count: int | None,
        validation_errors: list[dict[str, object]],
        error_code: str | None,
        error_message: str | None,
        schema_version: str | None = None,
    ) -> None:
        if artifact_type == "stix":
            self.persistence_service.record_stix_export_failed(
                job=job,
                bundle_id=bundle_id,
                object_count=object_count,
                validation_errors=validation_errors,
                error_code=error_code,
                error_message=error_message,
            )
            return

        self.persistence_service.record_afb_export_failed(
            job=job,
            bundle_id=bundle_id,
            object_count=object_count,
            validation_errors=validation_errors,
            schema_version=schema_version,
            error_code=error_code,
            error_message=error_message,
        )

    def _build_export_processing_error(
        self,
        *,
        artifact_type: str,
        job_error_code: str,
        job_error_message: str,
    ):
        if artifact_type == "stix":
            return _STIXExportJobProcessingError(
                job_error_code=job_error_code,
                job_error_message=job_error_message,
            )

        return _AFBExportJobProcessingError(
            job_error_code=job_error_code,
            job_error_message=job_error_message,
        )

    async def _run_url_stage(self, job_id: str, stage: str, input_source: InputSource) -> None:
        if input_source.source_url is None:
            raise _UrlJobProcessingError(
                job_error_code="url_input_invalid",
                job_error_message="url input source is missing source_url",
            )

        if stage == "extracting":
            await self._fetch_url_content(job_id, input_source.id, input_source.source_url)
            return

        if stage == "normalizing":
            context = self._require_url_context(job_id)
            content_type = context.content_type or ""
            if "html" not in content_type.lower():
                self.persistence_service.update_input_source_fetch(
                    input_source.id,
                    payload=InputSourceFetchUpdate(
                        fetch_error_code="unsupported_content_type",
                        fetch_error_message=f"unsupported content type: {content_type or 'unknown'}",
                    ),
                )
                raise _UrlJobProcessingError(
                    job_error_code="url_unsupported_content_type",
                    job_error_message=f"unsupported content type: {content_type or 'unknown'}",
                )
            extracted = extract_readable_text_from_html(context.body.decode("utf-8", errors="replace"))
            self._record_job_event(
                job_id,
                event_type="text_normalized",
                message="text normalized",
                details={
                    "input_source_id": input_source.id,
                    "source_type": input_source.type,
                    "normalized_char_count": extracted.normalized_char_count,
                    "normalization_version": extracted.normalization_version,
                },
            )
            self.persistence_service.update_input_source_fetch(
                input_source.id,
                payload=InputSourceFetchUpdate(
                    raw_text=extracted.raw_extracted_text,
                    normalized_text=extracted.normalized_text,
                    normalized_char_count=extracted.normalized_char_count,
                    normalization_version=extracted.normalization_version,
                    content_text=extracted.normalized_text,
                ),
            )
            self._persist_narrative_normalized_package(job_id, input_source.id)
            return

        if stage == "ai_extraction":
            _ = self.persistence_service.resolve_canonical_text_for_job(job_id)
            await asyncio.to_thread(self._run_ai_extraction_orchestration, job_id)

    async def _fetch_url_content(self, job_id: str, input_source_id: str, source_url: str) -> None:
        job = self.persistence_service.get_job(job_id)
        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="url_validation_started",
                source_component="worker",
                message="url validation started",
                details={"source_url": source_url, "allowed_schemes": sorted(self._allowed_url_schemes)},
            )
            self.persistence_service.record_job_event(
                job=job,
                event_type="url_fetch_started",
                source_component="worker",
                message="url fetch started",
                details={"source_url": source_url},
            )
        try:
            fetched = fetch_url_bounded(
                source_url,
                allowed_schemes=self._allowed_url_schemes,
                block_private_destinations=self.settings.url_fetch_block_private_destinations,
                connect_timeout_seconds=self.settings.url_fetch_connect_timeout_seconds,
                read_timeout_seconds=self.settings.url_fetch_read_timeout_seconds,
                max_redirects=self.settings.url_fetch_max_redirects,
                max_response_bytes=self.settings.url_fetch_max_response_bytes,
            )
        except UrlFetchError as exc:
            self.persistence_service.update_input_source_fetch(
                input_source_id,
                payload=InputSourceFetchUpdate(
                    fetch_error_code=exc.code,
                    fetch_error_message=exc.message,
                ),
            )
            raise _UrlJobProcessingError(
                job_error_code=_map_url_fetch_error_to_job_error(exc.code),
                job_error_message=exc.message,
            ) from exc

        self.persistence_service.update_input_source_fetch(
            input_source_id,
            payload=InputSourceFetchUpdate(
                fetch_final_url=fetched.final_url,
                fetch_status_code=fetched.status_code,
                fetch_content_type=fetched.content_type,
                fetch_size_bytes=fetched.size_bytes,
                fetch_error_code=None,
                fetch_error_message=None,
            ),
        )
        self._record_job_event(
            job_id,
            event_type="url_fetch_completed",
            message="url fetch completed",
            details={
                "source_url": source_url,
                "final_url": fetched.final_url,
                "status_code": fetched.status_code,
                "content_type": fetched.content_type,
                "size_bytes": fetched.size_bytes,
            },
        )
        self._url_job_context[job_id] = _UrlJobContext(
            content_type=fetched.content_type,
            body=fetched.body,
        )

    async def _run_file_stage(self, job_id: str, stage: str, input_source: InputSource) -> None:
        if input_source.storage_path is None:
            raise _FileJobProcessingError(
                job_error_code="file_input_invalid",
                job_error_message="file input source is missing storage_path",
            )

        if stage == "extracting":
            await self._extract_file_content(job_id, input_source)
            return

        if stage == "normalizing":
            context = self._require_file_context(job_id)
            update = InputSourceFileUpdate(
                file_class=context.routing.file_class,
                stix_json_kind=context.routing.stix_json_kind,
                stix_json_valid=context.stix_json_valid,
                raw_text=context.raw_text,
                normalized_text=context.normalized_text,
                normalized_char_count=context.normalized_char_count,
                normalization_version=context.normalization_version,
                content_text=context.normalized_text,
            )
            self.persistence_service.update_input_source_file(input_source.id, update)
            if context.routing.file_class in {"plaintext", "pdf"}:
                self._persist_narrative_normalized_package(job_id, input_source.id)
            if context.stix_update is not None:
                self.persistence_service.update_input_source_stix(input_source.id, context.stix_update)
                self._persist_structured_stix_normalized_package(job_id, input_source.id)
            return

        if stage == "ai_extraction":
            _ = self.persistence_service.resolve_canonical_text_for_job(job_id)
            await asyncio.to_thread(self._run_ai_extraction_orchestration, job_id)

    def _run_ai_extraction_orchestration(self, job_id: str) -> None:
        job = self.persistence_service.get_job(job_id)
        if job is None:
            return

        requested_provider_id = job.provider_id
        requested_model = job.model
        runtime_override = self._runtime_provider_overrides.get(job_id)
        registered_runtime_provider_id = None
        try:
            if runtime_override is not None:
                registered_runtime_provider_id = self.provider_registry.register_runtime_provider(
                    runtime_override=runtime_override,
                    allow_runtime_provider_override=self.settings.allow_runtime_provider_override,
                    allowed_provider_types=self.settings.allowed_runtime_provider_type_set(),
                    allow_extra_headers=self.settings.allow_runtime_provider_extra_headers,
                    timeout_seconds=self.settings.runtime_provider_timeout_seconds,
                )
                requested_provider_id = registered_runtime_provider_id

            execution = self._ai_orchestration_service.run_for_job(
                job_id=job_id,
                requested_provider_id=requested_provider_id,
                requested_model=requested_model,
            )
        finally:
            if registered_runtime_provider_id is not None:
                self.provider_registry.unregister_runtime_provider(registered_runtime_provider_id)

        self.persistence_service.update_job_extraction(
            job_id,
            JobExtractionUpdate(
                extraction_mode=execution.extraction_mode,
                provider_invoked=execution.provider_invoked,
                provider_id=execution.provider_id,
                model=execution.model_used,
                extraction_result_json=execution.extraction_payload_json,
                extraction_validation_state=execution.extraction_validation_state,
                extraction_repair_attempted=execution.repair_attempted,
                extraction_provenance_classification=execution.provenance_classification,
                extraction_authors_json=execution.authors_json,
                extraction_external_references_json=execution.external_references_json,
            ),
        )

        if execution.succeeded:
            normalized_package = self.persistence_service.resolve_normalized_package_for_job(job_id) or {}
            extraction_result = AfbExtractionResult.model_validate_json(execution.extraction_payload_json)
            fused_candidate = build_fused_output_candidate_from_sources(
                normalized_package=normalized_package,
                extraction_result=extraction_result,
            )
            self.persistence_service.persist_fused_output_candidate(job_id, fused_candidate)
            self.persistence_service.update_job(
                job_id,
                JobUpdate(
                    result_json=fused_candidate.model_dump_json(),
                    provider_id=execution.provider_id,
                    model=execution.model_used,
                ),
            )
            return

        raise _AIExtractionJobProcessingError(
            job_error_code=execution.error_code or "worker_processing_error",
            job_error_message=execution.error_message or execution.error_code or "ai extraction failed",
        )

    async def _extract_file_content(self, job_id: str, input_source: InputSource) -> None:
        try:
            file_bytes = self.file_storage.read_bytes(input_source.storage_path or "")
        except (FileNotFoundError, ValueError) as exc:
            self._fail_file_job(
                input_source.id,
                file_class=None,
                stix_json_valid=None,
                job_error_code="file_read_failed",
                job_error_message="unable to read stored upload",
            )
            raise _FileJobProcessingError(
                job_error_code="file_read_failed",
                job_error_message="unable to read stored upload",
            ) from exc

        self._record_job_event(
            job_id,
            event_type="file_validated",
            message="file validated",
            details={
                "input_source_id": input_source.id,
                "storage_path": input_source.storage_path,
                "size_bytes": len(file_bytes),
            },
        )

        routing = classify_file_for_routing(
            original_filename=input_source.original_name,
            declared_mime_type=input_source.mime_type,
            detected_mime_type=input_source.detected_mime_type,
            file_bytes=file_bytes,
        )
        self._record_job_event(
            job_id,
            event_type="file_classified",
            message="file classified",
            details={
                "input_source_id": input_source.id,
            "file_class": routing.file_class,
            "detected_mime_type": input_source.detected_mime_type,
            "is_supported": routing.is_supported,
            "unsupported_reason": routing.unsupported_reason,
        },
    )

        if not routing.is_supported:
            if routing.unsupported_reason == "json_not_stix_bundle_shape":
                try:
                    _ = validate_stix_json_bundle_shape(file_bytes)
                except StixJsonValidationError as exc:
                    self.persistence_service.update_input_source_stix(
                        input_source.id,
                        InputSourceStixUpdate(
                            stix_json_kind="bundle",
                            stix_json_valid=False,
                            stix_parse_error_code=exc.code,
                            stix_parse_error_message=exc.message,
                        ),
                    )
                    self._fail_file_job(
                        input_source.id,
                        file_class="stix_json",
                        stix_json_valid=False,
                        job_error_code=exc.code,
                        job_error_message=exc.message,
                    )
                    raise _FileJobProcessingError(
                        job_error_code=exc.code,
                        job_error_message=exc.message,
                    ) from exc
            reason = routing.unsupported_reason or "unsupported"
            self._fail_file_job(
                input_source.id,
                file_class="unsupported",
                stix_json_valid=None,
                job_error_code="unsupported_file_class",
                job_error_message=f"unsupported file class: {reason}",
            )
            raise _FileJobProcessingError(
                job_error_code="unsupported_file_class",
                job_error_message=f"unsupported file class: {reason}",
            )

        if routing.file_class == "plaintext":
            try:
                extracted = extract_plaintext_content(file_bytes)
            except PlaintextExtractionError as exc:
                self._fail_file_job(
                    input_source.id,
                    file_class="plaintext",
                    stix_json_valid=None,
                    job_error_code=exc.code,
                    job_error_message=exc.message,
                )
                raise _FileJobProcessingError(job_error_code=exc.code, job_error_message=exc.message) from exc
            self._file_job_context[job_id] = _FileJobContext(
                routing=routing,
                stix_json_valid=None,
                raw_text=extracted.extracted_text,
                normalized_text=extracted.normalized_text,
                normalized_char_count=extracted.normalized_char_count,
                normalization_version=extracted.normalization_version,
            )
            self._record_job_event(
                job_id,
                event_type="text_normalized",
                message="text normalized",
                details={
                    "input_source_id": input_source.id,
                    "source_type": input_source.type,
                    "normalized_char_count": extracted.normalized_char_count,
                    "normalization_version": extracted.normalization_version,
                },
            )
            return

        if routing.file_class == "pdf":
            try:
                extracted = extract_pdf_text_content(file_bytes)
            except PdfExtractionError as exc:
                self._fail_file_job(
                    input_source.id,
                    file_class="pdf",
                    stix_json_valid=None,
                    job_error_code=exc.code,
                    job_error_message=exc.message,
                )
                raise _FileJobProcessingError(job_error_code=exc.code, job_error_message=exc.message) from exc
            self._file_job_context[job_id] = _FileJobContext(
                routing=routing,
                stix_json_valid=None,
                raw_text=extracted.extracted_text,
                normalized_text=extracted.normalized_text,
                normalized_char_count=extracted.normalized_char_count,
                normalization_version=extracted.normalization_version,
            )
            self._record_job_event(
                job_id,
                event_type="text_normalized",
                message="text normalized",
                details={
                    "input_source_id": input_source.id,
                    "source_type": input_source.type,
                    "normalized_char_count": extracted.normalized_char_count,
                    "normalization_version": extracted.normalization_version,
                },
            )
            return

        if routing.file_class == "stix_json":
            try:
                stix_validation = validate_stix_json_bundle_shape(file_bytes)
                parsed_bundle = parse_stix_json_object(file_bytes)
            except StixJsonValidationError as exc:
                self._fail_stix_job(
                    input_source_id=input_source.id,
                    stix_json_kind="bundle",
                    stix_json_valid=False,
                    stix_parse_error_code=exc.code,
                    stix_parse_error_message=exc.message,
                    job_error_code=exc.code,
                    job_error_message=exc.message,
                )
                raise _FileJobProcessingError(job_error_code=exc.code, job_error_message=exc.message) from exc

            try:
                inventory = build_stix_bundle_inventory_and_narrative(parsed_bundle)
                attack_refs = extract_explicit_attack_refs(parsed_bundle)
                entities = extract_stix_entities(parsed_bundle)
                relationships = extract_stix_relationships(parsed_bundle)
                extraction_package = build_stix_extraction_package(
                    validation=stix_validation,
                    inventory=inventory,
                    attack_refs=attack_refs,
                    entities=entities,
                    relationships=relationships,
                )
            except Exception as exc:
                self._fail_stix_job(
                    input_source_id=input_source.id,
                    stix_json_kind=stix_validation.stix_json_kind,
                    stix_json_valid=False,
                    stix_bundle_id=stix_validation.bundle_id,
                    stix_spec_version=stix_validation.spec_version,
                    stix_parse_error_code=self._stix_extraction_failed_code,
                    stix_parse_error_message=self._stix_extraction_failed_message,
                    job_error_code=self._stix_extraction_failed_code,
                    job_error_message=self._stix_extraction_failed_message,
                )
                raise _FileJobProcessingError(
                    job_error_code=self._stix_extraction_failed_code,
                    job_error_message=self._stix_extraction_failed_message,
                ) from exc
            self._file_job_context[job_id] = _FileJobContext(
                routing=routing,
                stix_json_valid=stix_validation.stix_json_valid,
                raw_text=inventory.narrative_raw_text,
                normalized_text=inventory.narrative_normalized_text,
                normalized_char_count=inventory.narrative_normalized_char_count,
                normalization_version=inventory.narrative_normalization_version,
                stix_update=InputSourceStixUpdate(
                    stix_json_kind=stix_validation.stix_json_kind,
                    stix_json_valid=stix_validation.stix_json_valid,
                    stix_bundle_id=stix_validation.bundle_id,
                    stix_spec_version=stix_validation.spec_version,
                    stix_source_type="stix_bundle",
                    stix_object_count=inventory.object_count,
                    stix_relationship_count=len(relationships),
                    stix_attack_ref_count=len(attack_refs),
                    stix_summary_json=json.dumps(
                        {
                            "bundle_metadata": extraction_package.bundle_metadata,
                            "inventory": extraction_package.inventory,
                            "narrative": extraction_package.narrative,
                        }
                    ),
                    stix_entities_json=json.dumps(extraction_package.entities),
                    stix_relationships_json=json.dumps(extraction_package.relationships),
                    stix_attack_refs_json=json.dumps(extraction_package.attack_refs),
                    stix_provenance_json=json.dumps(extraction_package.provenance),
                ),
            )
            self._record_job_event(
                job_id,
                event_type="stix_parsed",
                message="stix parsed",
                details={
                    "input_source_id": input_source.id,
                    "stix_json_kind": stix_validation.stix_json_kind,
                    "stix_json_valid": stix_validation.stix_json_valid,
                    "bundle_id": stix_validation.bundle_id,
                    "spec_version": stix_validation.spec_version,
                    "object_count": inventory.object_count,
                    "relationship_count": len(relationships),
                    "attack_ref_count": len(attack_refs),
                },
            )
            if inventory.narrative_normalized_text is not None:
                self._record_job_event(
                    job_id,
                    event_type="text_normalized",
                    message="text normalized",
                    details={
                        "input_source_id": input_source.id,
                        "source_type": input_source.type,
                        "normalized_char_count": inventory.narrative_normalized_char_count,
                        "normalization_version": inventory.narrative_normalization_version,
                    },
                )
            return

        raise _FileJobProcessingError(
            job_error_code="unsupported_file_class",
            job_error_message=f"unsupported file class: {routing.file_class}",
        )

    def _require_url_context(self, job_id: str) -> "_UrlJobContext":
        context = self._url_job_context.get(job_id)
        if context is None:
            raise _UrlJobProcessingError(
                job_error_code="url_fetch_context_missing",
                job_error_message="url fetch context missing for normalization",
            )
        return context

    def _require_file_context(self, job_id: str) -> "_FileJobContext":
        context = self._file_job_context.get(job_id)
        if context is None:
            raise _FileJobProcessingError(
                job_error_code="file_extract_context_missing",
                job_error_message="file extraction context missing for normalization",
            )
        return context

    def _fail_file_job(
        self,
        input_source_id: str,
        *,
        file_class: str | None,
        stix_json_valid: bool | None,
        job_error_code: str,
        job_error_message: str,
    ) -> None:
        self.persistence_service.update_input_source_file(
            input_source_id,
            InputSourceFileUpdate(
                file_class=file_class,
                stix_json_valid=stix_json_valid,
                ingestion_error_code=job_error_code,
                ingestion_error_message=job_error_message,
            ),
        )

    def _fail_stix_job(
        self,
        *,
        input_source_id: str,
        stix_json_kind: str,
        stix_json_valid: bool,
        stix_parse_error_code: str,
        stix_parse_error_message: str,
        job_error_code: str,
        job_error_message: str,
        stix_bundle_id: str | None = None,
        stix_spec_version: str | None = None,
    ) -> None:
        self.persistence_service.update_input_source_stix(
            input_source_id,
            InputSourceStixUpdate(
                stix_json_kind=stix_json_kind,
                stix_json_valid=stix_json_valid,
                stix_bundle_id=stix_bundle_id,
                stix_spec_version=stix_spec_version,
                stix_parse_error_code=stix_parse_error_code,
                stix_parse_error_message=stix_parse_error_message,
            ),
        )
        self._fail_file_job(
            input_source_id,
            file_class="stix_json",
            stix_json_valid=stix_json_valid,
            job_error_code=job_error_code,
            job_error_message=job_error_message,
        )

    def _persist_narrative_normalized_package(self, job_id: str, input_source_id: str) -> None:
        input_source = self.persistence_service.get_input_source(input_source_id)
        if input_source is None:
            return
        update = build_narrative_normalized_update(
            input_source,
            pipeline_version=self.settings.normalized_pipeline_version,
            content_budget_chars=self.settings.normalized_content_max_chars,
        )
        if update is None:
            return
        self.persistence_service.update_input_source_normalized(input_source_id, update)
        self._record_job_event(
            job_id,
            event_type="normalized_package_created",
            message="normalized package created",
            details={
                "normalized_source_type": update.normalized_source_type,
                "pipeline_version": update.normalized_pipeline_version,
                "content_budget_chars": update.normalized_content_budget_chars,
            },
        )

    def _persist_structured_stix_normalized_package(self, job_id: str, input_source_id: str) -> None:
        input_source = self.persistence_service.get_input_source(input_source_id)
        if input_source is None:
            return
        update = build_structured_stix_normalized_update(
            input_source,
            pipeline_version=self.settings.normalized_pipeline_version,
            content_budget_chars=self.settings.normalized_content_max_chars,
        )
        if update is None:
            return
        self.persistence_service.update_input_source_normalized(input_source_id, update)
        self._record_job_event(
            job_id,
            event_type="normalized_package_created",
            message="normalized package created",
            details={
                "normalized_source_type": update.normalized_source_type,
                "pipeline_version": update.normalized_pipeline_version,
                "content_budget_chars": update.normalized_content_budget_chars,
            },
        )


class _UrlJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


class _FileJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


class _AIExtractionJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


class _STIXExportJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


class _AFBExportJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


class _ExportJobProcessingError(RuntimeError):
    def __init__(self, *, job_error_code: str, job_error_message: str):
        super().__init__(job_error_message)
        self.job_error_code = job_error_code
        self.job_error_message = job_error_message


@dataclass(frozen=True, slots=True)
class _UrlJobContext:
    content_type: str | None
    body: bytes


@dataclass(frozen=True, slots=True)
class _FileJobContext:
    routing: FileRoutingResult
    stix_json_valid: bool | None
    raw_text: str | None
    normalized_text: str | None
    normalized_char_count: int | None
    normalization_version: str | None
    stix_update: InputSourceStixUpdate | None = None


def _map_url_fetch_error_to_job_error(fetch_error_code: str) -> str:
    return {
        "invalid_url": "url_validation_failed",
        "invalid_url_scheme": "url_validation_failed",
        "dns_resolution_failed": "url_destination_unsafe",
        "unsafe_destination": "url_destination_unsafe",
        "fetch_timeout": "url_fetch_timeout",
        "redirect_limit_exceeded": "url_redirect_limit_exceeded",
        "invalid_redirect": "url_redirect_invalid",
        "response_too_large": "url_response_too_large",
        "fetch_failed": "url_fetch_failed",
    }.get(fetch_error_code, "url_fetch_failed")
