import sqlite3
from pathlib import Path


SCHEMA_VERSION = 14


def create_connection(sqlite_path: Path) -> sqlite3.Connection:
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(sqlite_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(sqlite_path: Path) -> None:
    with create_connection(sqlite_path) as connection:
        _create_schema_migrations_table(connection)
        current_version = _get_schema_version(connection)
        if current_version < SCHEMA_VERSION:
            _apply_schema(connection)
        _set_schema_version(connection, SCHEMA_VERSION)


def _create_schema_migrations_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        """
    )


def _get_schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    if row is None or row["version"] is None:
        return 0
    return int(row["version"])


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES (?)", (version,))


def _apply_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS input_sources (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            original_name TEXT,
            source_url TEXT,
            fetch_final_url TEXT,
            fetch_status_code INTEGER,
            fetch_content_type TEXT,
            fetch_size_bytes INTEGER,
            fetch_error_code TEXT,
            fetch_error_message TEXT,
            content_text TEXT,
            raw_text TEXT,
            normalized_text TEXT,
            normalized_char_count INTEGER,
            was_truncated INTEGER,
            normalization_version TEXT,
            storage_path TEXT,
            metadata_json TEXT,
            options_json TEXT,
            mime_type TEXT,
            size_bytes INTEGER,
            sha256 TEXT,
            title TEXT,
            case_id TEXT,
            source_name TEXT,
            stored_filename TEXT,
            detected_mime_type TEXT,
            file_class TEXT,
            stix_json_kind TEXT,
            stix_json_valid INTEGER,
            stix_bundle_id TEXT,
            stix_spec_version TEXT,
            stix_source_type TEXT,
            stix_object_count INTEGER,
            stix_relationship_count INTEGER,
            stix_attack_ref_count INTEGER,
            stix_summary_json TEXT,
            stix_entities_json TEXT,
            stix_relationships_json TEXT,
            stix_attack_refs_json TEXT,
            stix_provenance_json TEXT,
            stix_parse_error_code TEXT,
            stix_parse_error_message TEXT,
            normalized_source_type TEXT,
            normalized_package_json TEXT,
            normalized_stats_json TEXT,
            normalized_content_chars INTEGER,
            normalized_content_was_truncated INTEGER,
            normalized_content_budget_chars INTEGER,
            normalized_pipeline_version TEXT,
            ingestion_error_code TEXT,
            ingestion_error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            provider_id TEXT,
            model TEXT,
            input_source_id TEXT,
            result_json TEXT,
            fusion_result_json TEXT,
            fusion_validation_state TEXT,
            fusion_provenance_json TEXT,
            fusion_conflicts_json TEXT,
            fusion_attack_refs_json TEXT,
            fusion_entities_json TEXT,
            fusion_relationships_json TEXT,
            canonical_flow_json TEXT,
            canonical_flow_validation_state TEXT,
            canonical_flow_provenance_json TEXT,
            canonical_flow_conflicts_json TEXT,
            canonical_flow_validation_errors_json TEXT,
            extraction_mode TEXT,
            provider_invoked INTEGER,
            extraction_result_json TEXT,
            extraction_validation_state TEXT,
            extraction_repair_attempted INTEGER,
            extraction_provenance_classification TEXT,
            extraction_authors_json TEXT,
            extraction_external_references_json TEXT,
            progress_percent INTEGER,
            started_at TEXT,
            last_heartbeat_at TEXT,
            worker_id TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            completed_at TEXT,
            error_code TEXT,
            error_message TEXT,
            request_id TEXT,
            FOREIGN KEY (input_source_id) REFERENCES input_sources(id)
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            type TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT,
            size_bytes INTEGER,
            metadata_json TEXT,
            validation_state TEXT,
            validation_errors_json TEXT,
            export_status TEXT,
            error_code TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY (job_id) REFERENCES jobs(id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            job_id TEXT,
            sequence INTEGER,
            request_id TEXT,
            event_type TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            metadata_json TEXT,
            status TEXT,
            stage TEXT,
            source_component TEXT,
            message TEXT,
            details_json TEXT,
            redacted INTEGER,
            FOREIGN KEY (job_id) REFERENCES jobs(id)
        );
        """
    )
