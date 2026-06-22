[![build](https://github.com/JahazielLem/attack-flow/actions/workflows/build.yml/badge.svg)](https://github.com/JahazielLem/attack-flow/actions/workflows/build.yml)

# Attack Flow Builder SPARTA by PWNSAT

This repository is a maintained fork of [center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) with a production-ready SPARTA integration layered on top of the latest upstream codebase.

The goal of this fork is to keep pace with upstream Attack Flow changes while adding SPARTA-specific capabilities that are safe to regenerate during future updates instead of relying on manual patches.

## Key Features

- Upstream Attack Flow updates rebased into this fork.
- SPARTA framework integration using the maintained STIX source from [JahazielLem/attack-stix-data](https://github.com/JahazielLem/attack-stix-data).
- Automatic resolution of the latest `sparta-attack-*.json` bundle during source regeneration.
- Full SPARTA tactic, technique, and sub-technique support.
- Action TTP autocompletion for tactic, technique, and sub-technique combinations.
- Export and import support for `subtechnique_id` and `subtechnique_ref` in `attack-action`.
- Splash screen SPARTA version display sourced from the generated SPARTA bundle metadata.
- A dedicated blue `countermeasure` card mapped to STIX `course-of-action`.
- Red `action` cards for easier visual distinction.
- Catppuccin theme support and Catppuccin-based default styling.
- Customized splash screen and branding for the SPARTA-enabled builder.
- Custom STIX observables for:
  - `x-sigmf-capture`
  - `x-raw-iq-capture`

## SPARTA Data Handling

SPARTA data is generated from the latest versioned bundle published in the `sparta-attack` directory of the STIX source repository. During regeneration, the builder:

- Detects the newest available SPARTA bundle version.
- Synthesizes SPARTA tactics from `kill_chain_phases` when the STIX bundle does not ship standalone tactic objects.
- Preserves SPARTA sub-techniques and their relationships.
- Excludes non-matrix `SV-*` threat reference objects from offensive matrix autocompletion.

To regenerate all source enumerations, including SPARTA:

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
- Node.js 20
- npm
- [Graphviz](https://graphviz.org/) for `make docs-examples`

### Install Dependencies

```bash
poetry install
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

The fork publishes a multi-architecture image for `linux/amd64` and `linux/arm64`, so Apple Silicon and other ARM hosts should not need to force an amd64 platform.

```bash
docker pull ghcr.io/jahaziellem/attack-flow:v3.2.1-sparta
docker run --rm --name AttackFlowBuilder -p 8080:80 ghcr.io/jahaziellem/attack-flow:v3.2.1-sparta
```

For local development, Docker Compose builds this fork from the local checkout and tags it with the same release image name:

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

## Upstream Project

The original Attack Flow project is maintained by the MITRE Center for Threat-Informed Defense:

- Fork documentation: [Attack Flow Builder SPARTA Documentation](https://jahaziellem.github.io/attack-flow/)
- Upstream repository: [center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow)
- Project documentation: [Attack Flow Documentation](https://center-for-threat-informed-defense.github.io/attack-flow/)

## License

Copyright 2021 MITRE.

Licensed under the Apache License, Version 2.0.

This project makes use of MITRE ATT&CK.
