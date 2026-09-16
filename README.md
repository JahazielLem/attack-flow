[![build](https://github.com/JahazielLem/attack-flow/actions/workflows/build.yml/badge.svg)](https://github.com/JahazielLem/attack-flow/actions/workflows/build.yml)

# Attack Flow Builder: SPARTA and Space Shield by Kevin Leon

This repository is a maintained fork of [center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) with SPARTA and ESA Space Shield support integrated with upstream Attack Flow 4.0.0.

The goal of this fork is to keep pace with upstream Attack Flow changes while adding space security capabilities that are safe to regenerate during future updates instead of relying on manual patches.

## Key Features

- Upstream Attack Flow 4.0.0 merged into this fork, including visualizations, mitigation/detection nodes and optional AI flow generation.
- SPARTA integration using the [official STIX download](https://sparta.aerospace.org/download/STIX?f=latest).
- ESA Space Shield integration using the [official STIX bundle](https://spaceshield.esa.int/stix/space-attack.json).
- Both frameworks are available in TTP selection, framework filters and the searchable TTP wiki.
- Full SPARTA and Space Shield tactic, technique, and sub-technique support.
- Action TTP autocompletion for tactic, technique, and sub-technique combinations.
- Export and import support for `subtechnique_id` and `subtechnique_ref` in `attack-action`.
- Home screen framework versions and documentation links sourced from the generated data.
- A dedicated blue `countermeasure` card mapped to STIX `course-of-action`.
- Red `action` cards for easier visual distinction.
- Catppuccin theme support and Catppuccin-based default styling.
- Customized splash screen and branding for the space framework builder.
- Custom STIX observables for:
  - `x-sigmf-capture`
  - `x-raw-iq-capture`

## Framework Data

| Framework | Bundled version | Documentation | STIX source |
| --- | --- | --- | --- |
| SPARTA | 4.0.1 | [User guide](https://sparta.aerospace.org/resources/user-guide) · [Versions](https://sparta.aerospace.org/resources/versions) | [Official latest bundle](https://sparta.aerospace.org/download/STIX?f=latest) |
| ESA Space Shield | 0.3 (STIX collection, 2025-06-24) | [Space Shield documentation and matrix](https://spaceshield.esa.int/) | [Official bundle](https://spaceshield.esa.int/stix/space-attack.json) |

Versions above identify the framework datasets, not the STIX specification. Source regeneration retrieves current official datasets, rebuilds enumerations, metadata and wiki entries, and:

- Extracts dataset versions from the source metadata.
- Synthesizes SPARTA tactics from `kill_chain_phases` when the STIX bundle does not ship standalone tactic objects.
- Preserves tactics, techniques, sub-techniques and mitigation relationships.
- Namespaces Space Shield IDs as `SSH.*` internally to avoid collisions with ATT&CK IDs while retaining the original STIX object references.
- Excludes non-matrix `SV-*` threat reference objects from offensive matrix autocompletion.

To regenerate all source enumerations, including SPARTA and Space Shield:

```bash
cd src/attack_flow_builder
npm run update-sources
```

## Custom Observables

This fork adds two custom observables intended for RF and signal-capture workflows:

### `x-sigmf-capture`

Fields:

- `name`
- `file_name`
- `frequency_hz`
- `sample_rate_hz`
- `modulation`
- `capture_date`
- `description`

### `x-raw-iq-capture`

Fields:

- `name`
- `file_name`
- `frequency_hz`
- `sample_rate_hz`
- `modulation`
- `capture_date`
- `description`

These observables are available in the builder UI and round-trip through STIX export/import.

## Local Development

### Requirements

- Python 3.12
- [Poetry](https://python-poetry.org/)
- Node.js 24.18 or newer in the 24.x series
- npm
- [Graphviz](https://graphviz.org/) for `make docs-examples`

### Install Dependencies

```bash
poetry install --with api,docs
cd src/attack_flow_builder
npm ci
```

### Run the Builder Locally

```bash
cd src/attack_flow_builder
npm run dev
```

### Build the Builder

```bash
cd src/attack_flow_builder
npm run build
```

### Run with Docker

The release workflow builds multi-architecture images for `linux/amd64` and `linux/arm64`. To build and run this checkout locally:

```bash
docker build -t attack-flow-space-frameworks:local .
docker run --rm --name AttackFlowBuilder -p 8080:80 attack-flow-space-frameworks:local
```

For local development, Docker Compose builds this fork from the local checkout and tags it as `ghcr.io/jahaziellem/attack-flow:v4.0.0-space-frameworks` (a local tag until published):

```bash
docker compose up --build
```

### Run Builder Quality Checks

These commands mirror the Attack Flow Builder GitHub Actions checks:

```bash
cd src/attack_flow_builder
npm run lint
npm run test:unit
npm run build
```

### Run Python Quality Checks

These commands cover the Python-side GitHub Actions checks:

```bash
poetry run black --check src/attack_flow/
poetry run make test-ci
```

### Build the Documentation Site

`make docs-examples` requires Graphviz's `dot` binary to be installed locally.

```bash
poetry run make docs-schema
poetry run make validate
poetry run make docs-examples
poetry run make docs-matrix
poetry run make docs
```

## GitHub Actions Compatibility

The workflow in `.github/workflows/build.yml` has been updated to work correctly in a forked repository by:

- Using the current repository name for GitHub Pages base paths.
- Generating PR flow links from the active repository instead of hardcoded upstream paths.
- Building docs with repository-relative Pages URLs.

This makes the fork safer to push, test, and publish with GitHub Actions without re-editing workflow URLs after every upstream sync.

## Upstream 4.0 Resources

- [Self-hosting the optional API and UI](docs/deployment-self-hosting.md)
- [API runtime and provider configuration](src/attack_flow_api/README.md)
- [Generation guide](docs/generation.rst)
- [Synchronization notes](docs/fork-sync-2026-09.md)

## Upstream Project

The original Attack Flow project is maintained by the MITRE Center for Threat-Informed Defense:

- Fork documentation: [Attack Flow Builder SPARTA Documentation](https://jahaziellem.github.io/attack-flow/)
- Upstream repository: [center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow)
- Project documentation: [Attack Flow Documentation](https://center-for-threat-informed-defense.github.io/attack-flow/)

## License

Copyright 2021 MITRE.

Licensed under the Apache License, Version 2.0.

This project makes use of MITRE ATT&CK.
