# BugSlyce Post-Field-Validation Implementation Decisions

**Date:** 28 August 2026
**Baseline implementation source:** `BUGSLYCE_POST_FIELD_VALIDATION_IMPLEMENTATION_SOURCE_2026-08-28.md`
**Decision status:** approved development-planning refinement
**Baseline commit before this addendum:** `b4c80e526c98ff9ae250c4a302d01ff939622aa7`

## 1. Purpose

This addendum records implementation decisions made after Work Package 0 source-ownership inspection.

It does not rewrite or invalidate the evidence and classifications in the baseline implementation source.

Where this addendum changes package placement or implementation strategy, this addendum takes precedence for subsequent development.

## 2. Gobuster and STRICT-HTTPS-SNI

`STRICT-HTTPS-SNI` remains a reproduced BugSlyce v1.3 collection-reliability defect.

The reproduced v1.3 strict Gobuster path:

- preserves the authorised logical hostname in an HTTP `Host` header;
- resolves and selects an authorised IPv4 peer;
- substitutes that selected IPv4 peer into the HTTPS request URL;
- therefore loses the logical hostname at the TLS/SNI layer.

Work Package 0 source inspection also established that BugSlyce's native internal HTTP transport already models these concepts correctly:

- logical HTTP/TLS hostname;
- selected network peer;
- fail-closed programme-scope validation.

The internal peer-bound transport connects to the selected approved peer while preserving the logical hostname for HTTP and TLS semantics.

### Decision

Do not implement a Gobuster-specific SNI compatibility repair as part of Work Package 1.

BugSlyce-native bounded content discovery will supersede Gobuster execution for the bounty-first content-discovery workflow.

The practical `STRICT-HTTPS-SNI` defect will be closed through the native-discovery work package when the normal bounty-first workflow no longer depends on the defective Gobuster HTTPS transport path and the native path demonstrably preserves logical hostname/SNI separately from selected peer identity.

Gobuster must not remain represented as a trusted primary bounty content-discovery engine while its reproduced HTTPS/SNI limitation remains.

## 3. Gobuster compatibility posture

Do not remove historical Gobuster evidence support merely because native execution supersedes it.

Preserve, where practical:

- parsing of existing Gobuster artefacts;
- historical evidence-pack compatibility;
- deterministic ingestion of previously collected Gobuster results.

During development and acceptance, Gobuster and ffuf may be used as optional manual or controlled comparison engines.

They must not own BugSlyce's production trust-boundary semantics for:

- scope;
- hostname/SNI identity;
- peer selection;
- required researcher-identification headers;
- pacing;
- concurrency;
- redirect policy;
- evidence provenance.

After native discovery has passed controlled and field acceptance, dead Gobuster execution infrastructure may be reviewed separately for retirement.

## 4. Revised Work Package 1

Work Package 0 inspection showed that the remaining immediate correctness defects occupy two materially different seams.

### WP1A - external execution diagnostic retention

Included field issue:

- `FIELD-001-DIAG-01` / cross-case external collector diagnostic loss.

Required result:

- preserve exit status;
- preserve bounded, redacted actionable subprocess diagnostics;
- carry diagnostic provenance through project execution metadata;
- make useful failure context available to operator-facing output and evidence-pack export where appropriate;
- do not expose configured secret header values or other redacted execution data;
- do not create unbounded diagnostic artefacts.

This must be generic external-process evidence handling rather than a Gobuster-only fix.

### WP1B - retained redirect evidence handoff

Included field issue:

- `FIELD-002-REDIRECT-HANDOFF-01`.

Required result:

- retained redirect status and `Location` evidence must survive into deterministic redirect analysis;
- existing root/earlier HTTP evidence must not disappear merely because it was not recollected by a later Deep collector;
- operator composition must be able to represent observed redirect relationships;
- no redirect destination inherits authorisation;
- no additional network request is implied by offline redirect analysis;
- followed, refused, unresolved and observed-only relationships must remain distinguishable where the evidence supports those states.

WP1A and WP1B should be implemented as separate coherent sub-packages unless subsequent RED-contract work proves a genuinely shared persistence seam.

## 5. Native discovery acceptance requirements

The later native bounded-discovery package must retain BugSlyce's existing safety properties and demonstrate:

- logical hostname preserved for HTTP and TLS/SNI;
- selected peer identity retained separately;
- fail-closed programme scope;
- required identification headers;
- explicit pacing and concurrency;
- explicit request and recursion budgets;
- deterministic stopping conditions;
- bounded negative-response and wildcard-response calibration;
- redirect decisions governed by frozen programme scope;
- no authorisation inheritance through redirects;
- useful collection diagnostics;
- evidence provenance and raw artefact retention;
- compatibility with later bounded recursive feedback.

Native discovery should own these semantics directly rather than trying to coerce an external brute-force engine into BugSlyce's trust model.

## 6. Evidence classification remains unchanged

This decision changes implementation strategy, not historical evidence classification.

`STRICT-HTTPS-SNI` remains recorded as a reproduced v1.3 defect.

It is not reclassified as a false positive or withdrawn merely because the defective execution path is planned for supersession.
