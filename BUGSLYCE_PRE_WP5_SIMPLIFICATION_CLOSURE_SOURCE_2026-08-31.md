# BugSlyce PRE-WP5 Simplification Closure Source

**Date:** 2026-08-31
**Package:** PRE-WP5-SIMPLIFY-01
**Status:** ACCEPTED / CLOSED

## Repository baseline

Accepted implementation commit:

`0e9c8d2e08eb4e96611b54af119701276c148bc8`

Subject:

`Collapse reconnaissance to single workflow`

Parent:

`97ccc43c27a2129f032ad9c7a743ebfc670b5f7f`

Immutable public tag remains:

`v1.3.0 -> fc8f0febc809efd0540173b63af87945c500d028`

## Accepted product decision

BugSlyce now exposes one normal operator reconnaissance workflow:

`Reconnaissance`

The normal workflow executes the existing internal:

`deep-bounded`

pipeline.

Quick and Standard are no longer executable normal project reconnaissance
modes.

The operator no longer chooses a reconnaissance depth/profile when running
the normal project pipeline.

Historical/internal profile identities may remain where useful for cheap
read compatibility, specialist internals, historical records or existing
artefact contracts.

Historical Quick or Standard project-pipeline execution/resume must not
remain available as a back door.

## Explicitly retained internal contracts

The simplification did not redesign the accepted Deep/WP4 architecture.

Retained contracts include:

- `deep-bounded` persisted/internal workflow identity
- `deep-bounded-core` root content profile behaviour
- existing Deep model/class/artefact terminology where internal
- 15-step normal pipeline topology
- stages 010D and 011D
- WP4 native bounded discovery
- WP4B exactly-one recursive feedback pass
- recursive depth exactly 1
- recursive total candidate budget 800
- recursive per-origin budget 100
- zero new negative baselines during recursive feedback
- sitemap > JS request_call > JS route_configuration > HTML priority
- scope and materialised-origin enforcement
- redirect destinations never authorise themselves
- terminal HTTP 429 behaviour
- shared runtime HTTP enforcement state
- exact timing provenance
- native content-discovery resume recognition
- report/export/evidence-pack integration
- policy and scope requirements
- Manual Setup Only as a distinct non-recon operation

## Explicitly not removed in this package

This package did not perform unrelated cleanup of:

- direct lower-level content-plan/content-run commands
- lower-level Nmap profiles
- Gobuster compatibility/runtime-less branches
- bundled tiny/standard resources used by lower-level or historical paths
- internal Deep classes or artefact names
- historical release documentation

Gobuster cleanup remains a separate future concern and was not used to widen
the boundary of this package.

## Validation

### Mint

Final full repository suite:

`4350 passed in 311.97s`

Additional gates:

- compileall: passed
- `git diff --check`: passed
- approved RED owner SHA-256:
  `2a154cc765b0bd673765d6d973c7f2c67d4d3662dad3b9240ee5df9ed7385c75`

### Kali

Exact accepted commit pulled by fast-forward.

Focused owner gate:

`310 passed in 116.74s`

Additional gates:

- compileall: passed
- `git diff --check`: passed
- approved RED owner SHA-256 unchanged
- worktree clean

Kali identity at verification:

`HEAD = origin/main = 0e9c8d2e08eb4e96611b54af119701276c148bc8`

## Stale-test reconciliation

The first full-suite gate after implementation produced 49 failures.

Classification:

- 38 stale executable-mode invariants
- 1 current Deep invariant requiring adaptation
- 10 historical resume/composition cases requiring refusal or Deep adaptation
- 0 unexpected production regressions

The reconciliation changed tests only.

No production files were changed during the stale-test reconciliation.

No tests were deleted during that reconciliation.

Important snapshot-integrity, corruption, canonical-path, reuse,
source-control provenance and Stage 010 failure-truthfulness contracts were
preserved.

## WP5 starting point

WP5 remains NOT STARTED.

Its objective is application/service graph and operator composition, not
simply collecting more URLs.

The accepted starting product surface is now one normal Reconnaissance
workflow, which should simplify WP5 composition and operator-facing
presentation.

The frozen Whatnot and Deriv field evidence remain the principal WP5 field
oracles.

Do not treat documentation-derived WebSocket information as observed
WebSocket behaviour, and do not authorise WebSocket interaction merely
because documentation describes it.

BugSlyce v1 remains reconnaissance and triage only. Exploitation and active
vulnerability testing remain outside scope.
