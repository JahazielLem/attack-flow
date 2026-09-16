# Self-Hosting Deployment (API and UI)

This project supports separate deployment of the API and UI.

- Default model: deploy API and UI independently.
- Optional model: use a same-origin reverse proxy (`deploy/nginx/ui-api-proxy.conf`).
- Optional bundled proxy stack: `docker-compose.proxy.yml`.

## Configuration Example

Copy `.env.example` to `.env` and update values for your environment.

```bash
cp .env.example .env
```

Key variables:

- `API_BIND_PORT`: host port for API container (`docker-compose.api.yml`)
- `UI_BIND_PORT`: host port for UI container (`docker-compose.ui.yml`)
- `VITE_API_BASE_URL`: API base URL for separate-origin/local UI deployments
- `VITE_API_BASE_URL_PROXY`: API base path for bundled proxy deployment
- `DATA_DIR`, `SQLITE_PATH`, `UPLOAD_DIR`, `ARTIFACT_DIR`: backend persistence paths
- `RUNTIME_PROVIDER_TIMEOUT_SECONDS`: per-attempt timeout for request-supplied providers (default `180`)

Proxy certificate support:

- Place corporate root CA certificates in `certs/` as `.crt` files.
- `Dockerfile.api` copies `certs/` into the image and imports those certificates during build.
- Rebuild the API image after changing certificates.

## Provider Configuration and Metadata

Provider configuration is loaded from `PROVIDERS_CONFIG_PATH` into a registry-backed abstraction layer.

- Providers are configured by `provider_id` and `provider_type` (for example `openai`, `azure_openai`, `anthropic`, `gemini`, `openai_compatible`).
- Runtime provider access is registry-driven by `provider_id`, not hardcoded to a vendor client.
- Public provider metadata is intentionally separate from secret-bearing configuration.
  - `/api/v1/providers` exposes safe metadata only.
  - Secret-bearing fields are internal and must not be returned in API responses.
- Provider invocation can be explicitly skipped when deterministic structured input is sufficient.

Keep provider secrets in environment variables or your secret manager. Do not store secret values in repository config files.

## Provider Validation API

Provider validation is available through the API:

- `POST /api/v1/providers/validate` validates a configured provider by `provider_id`.
- Configured provider validation runs through the provider abstraction/registry layer for `openai`, `azure_openai`, `anthropic`, and `gemini`.
- Runtime provider override validation is supported for `openai`, `openai_compatible`, `azure_openai`, `anthropic`, and `gemini` when runtime overrides are enabled.
- Provider validation supports practical runtime controls:
  - model selection from request/default/allowed models,
  - bounded timeout behavior,
  - bounded retry/backoff for transient failures.
- Validation output is normalized and safe for API clients:
  - includes result/status metadata and `request_id`,
  - does not expose provider secrets or secret-bearing config fields.
- Gemini support uses one simple API-key-based endpoint mode for this version. Vertex-specific or enterprise authentication flows are not included.

## Orchestration Behavior

Orchestration runs in the worker pipeline (`ai_extraction` stage) using canonical normalized input.

- Canonical normalized package data is the orchestration source input.
- Orchestration modes:
  - `full_extraction` for narrative-heavy inputs,
  - `enrichment` for deterministic structured STIX/OpenCTI-derived inputs.
- Deterministic findings are preserved in intermediate output:
  - explicit ATT&CK refs,
  - entities,
  - relationships,
  - provenance.
- Provider invocation is optional when deterministic input is sufficient.
- Output is constrained to an AFB v2-compatible intermediate extraction shape.
- Validation enforces practical safety/grounding constraints:
  - only explicitly grounded ATT&CK techniques,
  - steps may remain unmapped to ATT&CK,
  - action descriptions must be verbatim source excerpts,
  - operators limited to `AND`/`OR`,
  - conditions limited to `true`/`false`,
  - authors and external references remain list-valued metadata.
- Malformed provider output may receive one bounded repair attempt before failing cleanly.

This stage intentionally does not produce final flow graph/export artifacts.

## Canonical Flow Behavior

This adds the internal canonical flow model used after orchestration/extraction.

- Fused output is converted into one canonical internal flow model.
- Direct extraction output may be used as fallback only if it is passed into the canonical converter.
- The canonical model preserves actions, conditions, operators, assets/attachments, ATT&CK refs, evidence, confidence, provenance, authors, external references, and conflict metadata when present.
- Only explicit source-grounded ATT&CK techniques are allowed.
- Steps without ATT&CK mappings are allowed.
- Only `AND`/`OR` operators and `true`/`false` conditions are allowed.
- Descriptions remain verbatim source excerpts.
- Source-grounded attachment semantics are enforced.

This is an internal worker-stage model and does not change the public API surface.

## STIX Export Behavior

This exports the canonical constrained flow model as a STIX 2.1 bundle after canonical flow persistence.

- Attack Flow extension objects are used where appropriate.
- Only explicit ATT&CK techniques from source are exported as technique mappings.
- Steps without ATT&CK mappings are allowed.
- Descriptions remain verbatim source excerpts.
- Only `AND`/`OR` operators and `true`/`false` conditions are exported.
- Source-grounded attachment semantics are preserved.
- Valid STIX artifacts are persisted and retrievable through `GET /api/v1/jobs/{job_id}/artifacts/stix`.
- Invalid exports fail clearly and are not exposed as successful artifacts.

## AFB Export Behavior

This exports the canonical constrained flow model to a pinned Attack Flow v2-compatible AFB artifact.

- Canonical flow metadata is mapped into the pinned `attack-flow` root object.
- Only explicit ATT&CK techniques from source are exported as technique mappings.
- Steps without ATT&CK mappings are allowed.
- Descriptions remain verbatim source excerpts.
- Only `AND`/`OR` operators and `true`/`false` conditions are exported.
- Source-grounded attachment semantics are preserved.
- Valid AFB artifacts are persisted and retrievable through `GET /api/v1/jobs/{job_id}/artifacts/afb`.
- Invalid exports fail clearly and are not exposed as successful artifacts.

Practical limitation:

- The export target is intentionally pinned to the local Attack Flow v2 schema and extension definition.

## Shared Export Finalization

- Exporters validate output before success is finalized.
- Artifact metadata is persisted consistently for valid STIX/AFB exports.
- Invalid or incomplete artifacts are suppressed from download endpoints.
- Export validation failures are visible through existing job status/result/audit surfaces where practical.
- The partial failure policy is all-or-nothing at the job level: all requested exports are attempted, but the job fails if any export is invalid.

## Audit Trail

Jobs emit structured audit events across the lifecycle, and the API exposes a debug-oriented retrieval endpoint:

- `GET /api/v1/jobs/{job_id}/audit`
- Returns the current job snapshot plus ordered audit events.
- Intended for support/debug workflows rather than end-user reporting.
- Secrets and unsafe raw content are redacted or suppressed by default.
- Useful fields remain available, such as status/stage transitions, provider IDs, model names, counts, file classifications, and error codes.

Practical limitation:

- Audit history is kept intentionally conservative and does not surface raw incident text or provider payloads by default.

## Start API Independently

Container run:

```bash
docker build -f Dockerfile.api -t attack-flow-api:local .
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v attack_flow_api_data:/var/lib/attack-flow/data \
  attack-flow-api:local
```

On macOS with Docker Desktop, a host bind mount (for example `$(pwd)/data:/var/lib/attack-flow/data`) requires that directory to be shared under Docker Desktop file sharing settings.

Compose (API-only):

```bash
docker compose -f docker-compose.api.yml up --build
```

## Start UI Independently

Container run:

```bash
docker build -f Dockerfile.ui \
  --build-arg AFB_BASE_URL=/ \
  --build-arg VITE_API_BASE_URL=http://localhost:8000/api/v1 \
  -t attack-flow-ui:local .
docker run --rm -p 8080:80 attack-flow-ui:local
```

Compose (UI-only):

```bash
docker compose -f docker-compose.ui.yml up --build
```

## Optional Bundled Proxy Stack

This is optional convenience only. Separate API and UI deployment remains the default model.

```bash
docker compose -f docker-compose.proxy.yml up --build
```

This stack includes:

- `attack-flow-api`
- `attack-flow-ui`
- `attack-flow-proxy` (nginx)

The proxy forwards:

- `/` -> UI container
- `/api/` -> API container

## How UI Reaches API

The UI API target is configured with `VITE_API_BASE_URL` at build time.

Recommended defaults by deployment model:

- Separate UI/API origins: `VITE_API_BASE_URL=http://localhost:8000/api/v1` (or `https://api.example.com/api/v1`)
- Bundled proxy stack: `VITE_API_BASE_URL_PROXY=/api/v1`

Examples:

- Local: `http://localhost:8000/api/v1`
- Separate host: `https://api.example.com/api/v1`
- Same-origin proxy path: `https://ui.example.com/api/v1`

## Backend Persistence

API persistence is volume-backed in `docker-compose.api.yml`:

- Docker named volume: `attack_flow_api_data`
- Container mount: `/var/lib/attack-flow/data`

SQLite DB and stored files survive restarts as long as the volume is retained.

## Local-Only / Internal Use

- Bind ports to private interfaces or trusted networks when possible.
- Keep `.env` local and do not commit it.
- Use least-privilege network access between UI and API.

## Internet-Exposed Use

- Terminate TLS at your edge/load balancer/reverse proxy.
- Restrict inbound access with firewall rules.
- Rotate provider credentials and keep secrets out of images and source control.

## Separate-Origin UI/API and CORS Guidance

If UI and API are hosted on different origins (scheme/host/port), browser calls require CORS to allow the UI origin.

- Current deployment package does not automatically configure CORS policy for you.
- Recommended options:
  1. Deploy with same-origin proxying (optional `deploy/nginx/ui-api-proxy.conf`), or
  2. Configure API CORS policy to explicitly allow your UI origin(s) in your deployment environment.

API CORS runtime environment variables:

- `CORS_ENABLED=true`
- `CORS_ALLOW_ORIGINS=https://ui.example.com` (comma-separated for multiple origins)
- `CORS_ALLOW_CREDENTIALS=false`
- `CORS_ALLOW_METHODS=*`
- `CORS_ALLOW_HEADERS=*`

Avoid wildcard CORS for internet-facing deployments unless you fully understand the risk.

## Troubleshooting

### Docker network not found when starting compose

If you see an error like `failed to set up container networking` or `network ... not found`, clean stale compose resources and recreate the stack:

```bash
docker compose -f docker-compose.proxy.yml down --remove-orphans
docker compose -f docker-compose.proxy.yml up --build -d
```

If the issue persists, prune unused networks and retry:

```bash
docker network prune -f
docker compose -f docker-compose.proxy.yml up --build -d
```

You can verify running services with:

```bash
docker compose -f docker-compose.proxy.yml ps
```

### Docker Desktop mount denied (macOS)

If you see an error like `mounts denied` and `path ... is not shared from the host`, Docker Desktop does not have access to that host directory.

Options:

1. Use a Docker named volume instead of a host bind mount (recommended):

```bash
docker run --rm -p 8000:8000 --env-file .env \
  -v attack_flow_api_data:/var/lib/attack-flow/data \
  attack-flow-api:local
```

2. Or add the host path in Docker Desktop:

- Docker Desktop -> Settings (Preferences) -> Resources -> File Sharing
- Add your repository path (for example `/Users/<you>/code/ctid/flow-viz-4`)
- Retry the same `docker run` or compose command
