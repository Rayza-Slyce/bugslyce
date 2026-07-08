# BugSlyce v0.3.0 Release Checklist

## Purpose

This checklist is for manually reviewing whether the repository is ready to
tag as `v0.3.0`.

It does not create a release, create a Git tag, publish a package, or upload
anything. It is an operator checklist only.

Suggested release title:

`BugSlyce v0.3.0 - Standard Operator Workflow`

Release summary:

Adds Standard Recon operator workflow improvements: Investigation Threads,
Standard Investigation Workflow in `runbook.md`, project engagement context,
engagement-aware Standard wording, and Offline Route/Source Review. Quick
Recon remains unchanged. Standard still reuses the bounded 12-step collection
pipeline and does not increase scan volume. Deep Recon remains unavailable.

## Current Release Scope

BugSlyce v0.3.0 - Standard Operator Workflow includes:

- Local readiness checks with `bugslyce doctor`.
- Project scaffolding with a starter scope template.
- Project engagement context metadata:
  - Unknown / not specified.
  - CTF / learning lab.
  - Bug bounty.
  - Internal authorised assessment.
- Project inventory with `bugslyce project list`.
- Quick Recon with `lab-safe-tiny`.
- Standard Recon v1 with `standard-bounded`.
- Standard Recon v1 reusing the same bounded 12-step collection path as Quick.
- Standard Recon v1 adding offline `## Manual Review Leads` to `report.md`.
- Standard Investigation Threads.
- Standard Investigation Workflow in `runbook.md`.
- Engagement-aware Standard wording.
- Standard Offline Route/Source Review.
- route/source review noise reduction for common HTML/default-page paths.
- Standard Manual Review Lead noise reduction for local robots storage paths
  and synthetic hidden HTML wrappers.
- Standard robots lead consolidation for unusual User-Agent values with
  hash-shaped or encoded-looking artefacts.
- Deep Recon remaining planned and unavailable.
- Conservative pipeline resume with `--resume`.
- Deterministic Operator Summary and local report generation.
- Project runbook generation.
- Recon status and next-step advice.
- Evidence pack export.
- Deterministic parsing of saved raw evidence and recon manifests.

## Safety Boundaries To Reconfirm

- [ ] Authorised targets only wording is present.
- [ ] Scope review is required before recon.
- [ ] `--confirm` is required for live pipeline execution.
- [ ] No NSE scripts.
- [ ] No UDP scans.
- [ ] No brute force.
- [ ] No exploitation.
- [ ] No recursive discovery.
- [ ] No larger Standard scan volume compared with Quick.
- [ ] No route fetching from Offline Route/Source Review.
- [ ] No crawling.
- [ ] No browser automation.
- [ ] No JavaScript execution.
- [ ] No online decoders.
- [ ] No hash cracking.
- [ ] No form submission.
- [ ] No authentication testing.
- [ ] No arbitrary user-supplied command flags.
- [ ] No LLM calls in the deterministic MVP pipeline.
- [ ] Evidence remains local unless the operator shares it manually.

## Test Checklist

Run local checks before tagging:

```bash
.venv/bin/pytest
.venv/bin/pytest tests/test_readme.py tests/test_recon_modes_doc.py tests/test_packaging.py tests/test_recon_modes.py
git diff --check
.venv/bin/bugslyce doctor
.venv/bin/bugslyce --version
.venv/bin/bugslyce wizard
.venv/bin/bugslyce project run --help
```

- [ ] Full test suite passes.
- [ ] Focused release/documentation tests pass.
- [ ] `git diff --check` passes.
- [ ] Safety grep shows no new unsafe runtime behaviour.
- [ ] Doctor reports ready on Kali or the intended operator environment.
- [ ] Version output is correct.
- [ ] Wizard renders correctly.
- [ ] Project run help shows `--confirm` and `--resume`.

## Documentation Checklist

- [ ] README explains install.
- [ ] README explains quick start.
- [ ] README explains safety model.
- [ ] README explains outputs.
- [ ] README explains limitations.
- [ ] README release checkpoint references v0.3.0.
- [ ] Recon modes documentation describes Standard operator workflow.
- [ ] Demo walkthrough exists.
- [ ] Demo walkthrough uses example IPs only.
- [ ] No real THM/VPN IPs are included in public docs.
- [ ] No private evidence or screenshots are committed.

## Live Smoke Checklist

Use an authorised lab only.

Suggested manual flow:

```bash
bugslyce doctor

bugslyce project scaffold \
  --name example-lab \
  --target TARGET \
  --projects-dir bugslyce-output

bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm

bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile standard-bounded \
  --confirm

bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm \
  --resume
```

- [ ] Fresh pipeline completes.
- [ ] Quick report omits `## Manual Review Leads`.
- [ ] Standard report includes `## Manual Review Leads`.
- [ ] Standard report includes `## Investigation Threads`.
- [ ] Standard report includes `## Offline Route/Source Review`.
- [ ] Standard runbook includes `## Standard Investigation Workflow`.
- [ ] Standard profile is recorded as `standard-bounded`.
- [ ] Standard visible pipeline remains 12 steps.
- [ ] Standard does not increase scan volume over Quick.
- [ ] Engagement context wizard accepts numeric and common text choices.
- [ ] Engagement-aware Standard wording appears for the selected context.
- [ ] Offline Route/Source Review filters default-page noise while preserving
  useful route references.
- [ ] Deep Recon remains unavailable.
- [ ] Deep Recon still requires separate profile-bounds, implementation, test,
  and smoke-test gates before any future enablement.
- [ ] Deep planned pipeline skeleton remains static, gated, and non-executable.
- [ ] Deep planned output taxonomy remains static, gated, and non-executable.
- [ ] Deep scope/safety preflight contract remains static, gated, and
  non-executable.
- [ ] Deep readiness summary renderer remains static, gated, and
  non-executable.
- [ ] `bugslyce recon deep-readiness` remains stdout-only, static, and
  non-executable.
- [ ] `bugslyce recon deep-readiness --json` remains stdout-only, static, and
  non-executable.
- [ ] Deep eligibility evaluator remains pure, internal, and non-executable.
- [ ] `bugslyce recon deep-eligibility` remains stdout-only, fail-closed, and
  non-executable.
- [ ] Deep common metadata request planner remains pure, internal, and
  non-executable.
- [ ] `bugslyce recon deep-metadata-plan` remains stdout-only, planning-only,
  and non-executable.
- [ ] Deep metadata project-state adapter remains pure, internal, and
  non-executable.
- [ ] Deep metadata review model remains offline, deterministic, and
  non-executable.
- [ ] `bugslyce recon deep-metadata-review --input-dir` remains read-only,
  stdout-only, and non-executable.
- [ ] Deep metadata coverage summary remains offline, internal, and
  non-executable.
- [ ] `bugslyce recon deep-metadata-coverage --input-dir` remains read-only,
  stdout-only, and non-executable.
- [ ] Deep metadata coverage preview summarises duplicate-origin planner
  skips without noisy per-URL rows.
- [ ] Deep source/route coverage summary remains offline, internal, and
  non-executable.
- [ ] `bugslyce recon deep-source-route-coverage --input-dir` remains
  read-only, stdout-only, and non-executable.
- [ ] Deep source/route coverage preview keeps bare static directories in
  static/directory context and compacts long rendered evidence lists.
- [ ] Deep preview bundle model remains internal, offline, bounded, and
  non-executable.
- [ ] `bugslyce recon deep-preview --input-dir` remains read-only,
  stdout-only, and non-executable.
- [ ] Deep preview groups low-priority metadata coverage gaps without hiding
  coverage counts.
- [ ] Deep collection policy model remains offline, restrictive, internal, and
  non-executable.
- [ ] Standard report includes the Human Triage Brief and readable evidence
  cards before raw wide evidence tables.
- [ ] Standard Human Triage promotes useful local robots metadata body values
  without claiming credentials or correlating unrelated evidence.
- [ ] Standard auth-surface discovery uses the small fixed
  `standard-bounded-core` route set, preserves `lab-root-tiny` general routes,
  and performs no form submission, authentication testing, credential use,
  brute force, recursive crawling, or extension fuzzing beyond explicitly
  listed paths.
- [ ] Workflow provenance reports `standard-bounded-core` accurately when the
  combined Standard content profile produced the gobuster artefact.
- [ ] Standard reports treat ordinary login form fields as auth-route context,
  not confirmed credentials or standalone credential discovery.
- [ ] Deep collection request planner remains offline, internal, policy-gated,
  and non-executable.
- [ ] Deep metadata collector core remains metadata-only, fetcher-injected,
  non-CLI, and does not write artefacts.
- [ ] Deep HTTP fetcher remains bounded, standard-library only, non-CLI, and
  does not write artefacts or follow redirects automatically.
- [ ] `bugslyce recon deep-metadata-collect --input-dir` remains stdout-only,
  metadata-only, policy-gated, and does not enable Deep Recon full mode.
- [ ] `bugslyce recon deep-metadata-collect --write-artifacts` writes only
  `deep_metadata_collection.md` and `deep_metadata_collection.json`, without
  storing full response bodies.
- [ ] Deep metadata collection review remains offline, no-file-output, and
  summarises repeated bodies and skipped requests without finding claims.
- [ ] `bugslyce recon deep-metadata-collection-review --input-dir` reads only
  `deep_metadata_collection.json`, writes no artefacts, and makes no HTTP
  requests.
- [ ] `report.md` is generated.
- [ ] `runbook.md` is generated.
- [ ] `project_pipeline.md` and `project_pipeline.json` are generated.
- [ ] `recon_status.md` and `recon_status.json` are generated.
- [ ] Evidence ZIP is generated.
- [ ] Resume skips existing phases safely.
- [ ] Normal rerun without `--resume` refuses existing evidence.

## Repository Hygiene Checklist

- [ ] `git status` is clean.
- [ ] No raw target evidence is staged.
- [ ] No `bugslyce-output/` evidence folders are staged.
- [ ] No ZIP evidence packs are staged.
- [ ] No `.venv/`, `__pycache__/`, or cache files are staged.
- [ ] No secrets, API keys, tokens, or credentials are present.
- [ ] Version in `pyproject.toml` is reviewed.
- [ ] Licence section is reviewed.

## Manual Tagging Notes

A Git tag marks a specific commit as a named version snapshot.

For `v0.3.0`, after every checklist item passes, the operator may manually
run:

```bash
git tag v0.3.0
git push origin v0.3.0
```

Do not tag until the checklist is complete. Do not tag a dirty working tree.
Do not tag if private evidence is committed. Creating a GitHub release is
optional and should be done manually.

## Not Included In v0.3.0

- No authenticated testing.
- No vulnerability confirmation.
- No exploit automation.
- No Deep Recon.
- No deep crawling.
- No recursive discovery or larger Standard scan volume.
- No route fetching from Offline Route/Source Review.
- No browser automation or JavaScript execution.
- No online decoders or hash cracking.
- No brute force, authentication testing, or form submission.
- No cloud sync.
- No automatic reporting to third parties.
- No LLM analysis in the default deterministic pipeline.
