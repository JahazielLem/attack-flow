# Fork synchronization — 16 September 2026

The fork started at `3a32b074` (Attack Flow Builder 3.2.1) with a clean working
tree matching `origin/main`. Upstream `center-for-threat-informed-defense/attack-flow`
was 180 commits ahead, with 52 commits unique to the fork. This integration merges
upstream `0bd4a2d45dceacce499d7e94b85f7966e70f5399` (Attack Flow 4.0) on branch
`codex/sync-upstream-space-frameworks`, preserving the fork's history.

## Integration decisions

- Keep upstream 4.0's visualizations, AI flow generation, TIE recommendations,
  defensive objects, tagging, classification markings, API and dependency updates.
- Retain the Kevin Leon branding, TTP wiki, Catppuccin theme, blue countermeasure card,
  `x-sigmf-capture` and `x-raw-iq-capture` observables, and separate subtechnique fields.
- Preserve subtechniques in the ordinary technique selector for existing flows and
  upstream recommendations. The dedicated subtechnique selector still resolves its
  parent technique and tactic. Defensive recommendations follow the selected
  subtechnique. Cloning preserves the specialized TTP editor.
- Preserve fractional RF values on import/export. STIX object references identify the
  correct framework when external IDs overlap.
- Use current official STIX sources, replacing the SPARTA mirror dependency. The
  old `attack/` generator is superseded by the upstream `sources/` pipeline.
- Retain the fork's GitHub Pages links and multi-architecture Docker release workflow.
  Both frontend Dockerfiles use Node 24.18 to match upstream dependency requirements.
  The new Docker tag is local until a release is explicitly published.

## Framework snapshots

| Source | Version | Tactics | Parent techniques | Subtechniques | Mitigations |
| --- | --- | ---: | ---: | ---: | ---: |
| [SPARTA](https://sparta.aerospace.org/resources/versions) | 4.0.1 | 9 | 93 | 133 | 268 |
| [ESA Space Shield](https://spaceshield.esa.int/) | STIX collection 0.3 | 14 | 61 | 107 | 86 |

SPARTA comes from <https://sparta.aerospace.org/download/STIX?f=latest>.
Space Shield comes from <https://spaceshield.esa.int/stix/space-attack.json>.
Its collection version is 0.3, with collection metadata dated 2025-06-24; individual
objects have more recent modification dates. This is distinct from the STIX 2.1
standard and the bundle's ATT&CK schema version.

ATT&CK was refreshed to 19.2 across Enterprise, ICS and Mobile. ATLAS, D3FEND and F3
were regenerated from their official current endpoints; F3's collection is 1.1.
Generated catalogs record source URLs and collection versions where provided.

Space Shield IDs use `SSH.*` internally to avoid collisions with ATT&CK tactics.
SPARTA's embedded D3FEND countermeasures use `SPA.D3-*` to avoid overwriting the
standalone D3FEND technique references. Original STIX IDs and reference URLs remain
attached to all these catalog entries. SPARTA's synthetic tactic IDs remain stable
for existing flows, and `SV-*` threat reference objects stay outside the matrix.

Run all updates with `npm run update-sources` in `src/attack_flow_builder`, or use
`npm run update-sparta` and `npm run update-space-shield` individually. Generated
catalogs and wiki files are committed; normal builds do not require framework downloads.

## Validation

- Frontend: 292 tests passing across 55 suites, including ingestion, autocomplete,
  STIX round trips, RF observables, cloning and home screen documentation links.
- Type checking, production build and CLI build pass. ESLint has no errors and
  retains seven upstream optional-prop warnings. Vite reports large bundle warnings.
- All 42 corpus flows export to STIX and pass validation, including Kevin Leon; the
  standalone schema example also passes.
- Python formatting passes. The Python suite reports 518 passed and 21 failed on
  Windows. All 21 failures reproduce against a pristine copy of upstream at the
  same commit: Windows path separators, open temporary-file locking, symlink
  privileges and SVG fixture line endings. They are not introduced by this merge.
- Sphinx documentation builds. Browser checks confirm framework version links,
  Space Shield wiki search/results and both frameworks enabled on new flows.

No remote push, website deployment or container release is performed by this local
synchronization.
