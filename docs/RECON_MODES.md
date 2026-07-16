# Recon Modes

BugSlyce has four operator-facing modes. Mode names describe evidence depth;
they do not grant permission to run recon.

## Current Modes

| Mode | Profile | Status | Purpose |
| --- | --- | --- | --- |
| Manual Setup Only | none | available | Create project metadata and `scope.md` without recon. |
| Quick Recon | `lab-safe-tiny` | available | Fast first-pass bounded collection. |
| Standard Recon | `standard-bounded` | available | Bounded collection plus offline interpretation. |
| Deep Recon | `deep-bounded` | available | Bounded same-origin Deep collection plus offline review orchestration. |

## Global Safety Boundaries

BugSlyce project workflows are for authorised targets only. The generated
`scope.md` template is not authorisation.

Project workflows remain bounded and non-exploitative:

- no UDP pipeline phase;
- no NSE scripts;
- no brute force;
- no exploitation;
- no password spraying;
- no credential stuffing;
- no authentication testing;
- no form submission;
- no browser automation;
- no JavaScript execution;
- no parameter replay, guessing or mutation;
- no unrestricted or recursive crawling;
- no vulnerability confirmation.

BugSlyce reports static evidence for manual review. A review lead is not proof
of vulnerability, exploitability or impact.

## Quick Recon

Quick Recon uses `lab-safe-tiny`. It is the fastest executable collection mode
and uses the bundled `lab-root-tiny` resource. It is suitable for initial lab
or CTF triage where the operator wants a compact local evidence pack quickly.

Quick readiness requires:

- Python and core BugSlyce readiness;
- `nmap`;
- `curl`;
- `gobuster`;
- bundled `lab-root-tiny`.

## Standard Recon

Standard Recon uses `standard-bounded`. It runs the bounded collection workflow
and adds offline interpretation of already collected artefacts. Standard uses
the bundled `standard-bounded-core` resource.

Standard interpretation may include human triage context, manual review leads,
investigation threads, route/source review and readable evidence cards. It does
not increase collection merely because interpretation is deeper.

Standard readiness requires:

- Python and core BugSlyce readiness;
- `nmap`;
- `curl`;
- `gobuster`;
- bundled `standard-bounded-core`.

## Deep Recon

Deep Recon uses `deep-bounded`. It is available through the canonical project
pipeline. It runs existing bounded collection stages, then performs bounded
same-origin Deep source/route collection, shallow same-origin follow-up and
offline orchestration of Deep review stages.

Deep includes:

- source/route collection;
- HTTP fingerprint review;
- redirect and authentication-flow review;
- response-similarity review;
- static HTML route extraction;
- static JavaScript route extraction without JavaScript execution;
- shallow same-origin route follow-up;
- HTML form inventory without submitting forms;
- parameter-name inventory without values;
- compact Deep runbook guidance;
- explicit Deep evidence artefacts.

Deep external references may be retained as offline reference evidence where a
model supports that distinction, but they must not become executable requests.
Executable Deep planning is same-origin and scope-conscious.

Deep readiness requires:

- Python and core BugSlyce readiness;
- `nmap`;
- `curl`;
- `gobuster`;
- bundled `standard-bounded-core`.

## Resume Contract

Completed Quick, Standard and Deep projects may reuse verified existing
outputs. A completed Deep resume is a no-op apart from local validation and
preserves canonical artefacts.

Interrupted Deep network stages fail closed. Full response bodies and the
shallow-follow-up result are deliberately not persisted in a form that can
reproduce every offline Deep analysis. BugSlyce therefore refuses ambiguous
partial Deep resume rather than silently repeating bounded network collection.
Use a clean project for an explicit Deep rerun.

## Evidence and Reports

Reports, status files, runbooks, pipeline metadata and evidence packs are local
artefacts. They may contain target evidence. Handle them according to the
engagement rules.

BugSlyce does not claim:

- confirmed vulnerabilities;
- attack paths;
- exploitability;
- credential validity;
- absence of risk.

Manual validation remains required. Reported context is not proof of vulnerability.
