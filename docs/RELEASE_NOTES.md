# Release Notes

## 1.2.0

BugSlyce `1.2.0` is the v1.2 reliability and production bug-bounty runtime
release.

Before final promotion, the v1.2 runtime completed source-level acceptance in
controlled authorised labs and under current authorised bug-bounty programme
constraints. An untagged `1.2.0rc1` candidate wheel also completed isolated
Mint and Kali exact-wheel acceptance and a packaged Deep authorised-lab run.

### Strict bug-bounty project runtime

- Added private engagement-policy configuration for programme-specific
  automation permission, aggregate HTTP rate, concurrency, TCP discovery,
  Nmap service/version permission and traffic identification.
- Added default-deny programme scope with explicit include/exclude rules for
  hostnames, HTTP URL/path namespaces and IPv4 destinations.
- Standard and Deep bug-bounty pipelines now require successful strict policy,
  programme-scope and target preflight before live collection.
- Added policy-aware internal HTTP, curl, Gobuster and Nmap planning and
  enforcement, including HTTP-only bug-bounty project support.
- Integrated the interactive bug-bounty launcher flow from policy setup through
  programme scope to the final Standard or Deep run decision.

### Deep reliability and evidence

- Added native Deep metadata hand-off so metadata requests are collected by the
  bounded metadata collector instead of being silently treated as complete.
- Added bounded sitemap metadata collection and same-origin sitemap route
  references without persisting or following the full XML body.
- Tightened response-family evidence, canonical ranked-lead presentation,
  distinctive access-boundary and confirmed listing evidence.
- Reduced repeated-family prominence and improved supporting evidence in the
  HTML Operator Report.
- Improved completed-project guidance, partial-evidence handling and project
  status/next-step behaviour.

### Safety boundary

BugSlyce remains reconnaissance and evidence-led triage only. Exploitation,
credential attacks, form submission, authentication testing, recursive
uncontrolled discovery and arbitrary command execution remain outside the v1
scope. Review leads remain observations requiring operator validation, not
confirmed vulnerability claims.

## 1.1.1

BugSlyce `1.1.1` is a documentation-only safety advisory release. It does
not change live reconnaissance behaviour.

Controlled local traffic capture of BugSlyce `1.1.0` identified the
following production bug bounty readiness gaps:

- Standard Recon peaked at 154 requests per second.
- Deep Recon peaked at 450 requests per second.
- Programme-required researcher-identification headers cannot currently be
  applied consistently across every HTTP request path.

The measured rates came from a controlled local capture server and may vary
by environment. They nevertheless demonstrate that the current release does
not provide suitably conservative production traffic pacing.

Until pacing and identification-header support are implemented and
verified:

- Do not use Standard or Deep Recon against production bug bounty targets.
- Do not use any live mode where programme-required traffic identification
  cannot be honoured.
- Continue using BugSlyce only in CTFs and controlled authorised labs.

No production target was involved in discovering these issues.


## 1.1.0

BugSlyce `1.1.0` adds a self-contained offline HTML evidence report and
improves presentation of existing deterministic evidence and review models.

- Added self-contained HTML evidence reports generated locally from existing
  extracted evidence-pack directories without network requests.
- Preserved the complete existing Operator Summary assembled from structured
  Deep artefacts, with explicit partial-input notices for older or incomplete
  packs.
- Presented existing structured Deep interpretations as searchable records,
  without adding collection, ranking or vulnerability conclusions.
- Consolidated exact matching URL strings for presentation while preserving
  every underlying status, redirect, source and evidence ID.
- Separated assessed-origin URLs, external references and unclassified values
  using the existing strict HTTP-origin contract.
- Added expandable evidence collections, concise artefact paths and
  human-readable display labels while retaining original structured values.

HTML report generation remains local-first and presentation-only. Review leads
are observations requiring operator validation, and BugSlyce remains outside
exploitation and active vulnerability testing.

## 1.0.0

BugSlyce `1.0.0` technical acceptance is complete. The exact same wheel was
accepted through isolated temporary pipx acceptance on Mint and Kali and is
approved to tag and publish. This repository state has not yet created the final tag, GitHub
release or PyPI publication.

The accepted v1 scope provides bounded Manual Setup Only, Quick, Standard and
Deep workflows, local evidence artefacts, reports, runbooks and portable,
self-validating evidence packs. BugSlyce remains outside exploitation and
active vulnerability testing; its reports preserve observed evidence and
manual-review leads rather than confirmed vulnerability claims.

## 1.0.0rc2

BugSlyce `1.0.0rc2` is a historical v1 release candidate prepared at commit
`113494f3c727c4543ca87e9be37b64c8c1858dbe`. Its exact wheel,
`bugslyce-1.0.0rc2-py3-none-any.whl`, SHA-256
`24ecc358ed6b4e3db9213e7142637fade953b30744fb11fa613c050f1ae6a441`,
passed temporary pipx acceptance on Mint and Kali. Since `1.0.0rc1`, Deep
content discovery uses a distinct bundled `deep-bounded-core` resource; the
tagged `1.0.0rc1` release candidate used `standard-bounded-core` for both
Standard and Deep.

## 1.0.0rc1

BugSlyce `1.0.0rc1` is the first v1 release candidate. It was tagged as
`v1.0.0rc1`, was not published as a package and was not the final `1.0.0`
release.

### Release State

BugSlyce `1.0.0rc1` completed Mint and Kali acceptance on 2026-07-16. Manual
Setup Only, Quick Recon, Standard Recon and Deep Recon were validated. Quick,
Standard and Deep were smoke-tested against an authorised private lab target.
Completed Deep resume, canonical hash stability and evidence-pack containment
were verified.

This candidate was tagged as `v1.0.0rc1`. No package was published.

### Operator Workflow

- Interactive launcher for new projects, resume, project listing and doctor.
- Project scaffolding with `bugslyce_project.json` and an operator-reviewed
  `scope.md`.
- Manual Setup Only for metadata and scope preparation without recon.
- Quick Recon using `lab-safe-tiny`.
- Standard Recon using `standard-bounded`.
- Deep Recon using `deep-bounded`.
- Project status, operator runbook, report generation and evidence-pack ZIP
  export.
- Conservative resume: completed runs may reuse verified artefacts; ambiguous
  state fails closed.

### Readiness

- Python `3.11` or newer is required.
- `bugslyce doctor` is passive and local.
- Executable recon modes require `nmap`, `curl` and `gobuster`.
- Bundled `lab-root-tiny` gates Quick Recon.
- Bundled `standard-bounded-core` gates Standard and Deep Recon.
- Mode readiness is profile-specific.
- Doctor exit code `0` means all executable recon modes are ready; exit code
  `2` means one or more requirements are blocked.

### Safety

- Live project pipelines require explicit confirmation.
- Project targets must match reviewed scope.
- External commands use fixed argv construction and reject ASCII control
  characters.
- No shell execution, `os.system` or `subprocess.Popen` is used by live recon.
- Deep collection is same-origin and bounded.
- Cross-origin references may be retained as offline evidence but are not
  fetched as executable requests.
- Project paths, package resources, symlinks and evidence-pack entries are
  contained by explicit validation.
- Evidence packs use an allowlist and explicit artefact references.
- Partial Deep network state is refused on resume because the full in-memory
  bodies required for offline analysis are deliberately not persisted.

### Outputs

Completed project workflows may produce:

- `report.md`
- `recon_status.md`
- `recon_status.json`
- `runbook.md`
- `project_pipeline.md`
- `project_pipeline.json`
- raw evidence artefacts referenced by `recon_manifest.json`
- an adjacent evidence ZIP

Deep Recon also retains:

- `deep_source_route_collection.md`
- `deep_source_route_collection.json`
- `deep_recon_review.md`
- `deep_recon_runbook.md`
- `deep_recon_orchestration.json`

### Known Limitations

- BugSlyce is Linux-focused.
- It has been directly validated on Kali Linux and Linux Mint.
- Ubuntu and other Debian-derived Linux systems are expected to work when the
  required Python version and external tools are available, but they are not
  currently part of the directly validated host set.
- Native Windows and macOS operation is not claimed.
- Source installation is the documented route for this release candidate; do
  not assume PyPI publication.
- BugSlyce does not exploit, authenticate, brute force, submit forms, execute
  JavaScript, mutate parameters or perform unrestricted recursive crawling.
- Standard Recon uses bounded collection plus offline interpretation.
- Deep Recon uses bounded same-origin collection plus offline orchestration.
- Partial Deep resume is intentionally refused.
- Local evidence packs are not encrypted and are not automatically redacted.
- Absence of evidence is not proof of safety.
- Manual validation remains necessary.
