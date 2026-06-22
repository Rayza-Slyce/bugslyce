# BugSlyce v0.2.0 Release Checklist

## Purpose

This checklist is for manually reviewing whether the repository is ready to
tag as `v0.2.0`.

It does not create a release, create a Git tag, publish a package, or upload
anything. It is an operator checklist only.

## Current Release Scope

The v0.2.0 checkpoint includes:

- Local readiness checks with `bugslyce doctor`.
- Project scaffolding with a starter scope template.
- Project inventory with `bugslyce project list`.
- Quick Recon with `lab-safe-tiny`.
- Standard Recon v1 with `standard-bounded`.
- Standard Recon v1 reusing the same bounded 12-step collection path as Quick.
- Standard Recon v1 adding offline `## Manual Review Leads` to `report.md`.
- Standard Manual Review Lead noise reduction for local robots storage paths
  and synthetic hidden HTML wrappers.
- Standard robots lead consolidation for unusual User-Agent values with
  hash-shaped or encoded-looking artefacts.
- Context-neutral Standard review wording suitable for CTF/lab and bug bounty
  use.
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
- [ ] No form submission.
- [ ] No authentication testing.
- [ ] No arbitrary user-supplied command flags.
- [ ] No LLM calls in the deterministic MVP pipeline.
- [ ] Evidence remains local unless the operator shares it manually.

## Test Checklist

Run local checks before tagging:

```bash
.venv/bin/pytest
.venv/bin/bugslyce doctor
.venv/bin/bugslyce --version
.venv/bin/bugslyce wizard
.venv/bin/bugslyce project run --help
```

- [ ] Full test suite passes.
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
- [ ] Standard profile is recorded as `standard-bounded`.
- [ ] Standard does not increase scan volume over Quick.
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

For `v0.2.0`, after every checklist item passes, the operator may manually
run:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Do not tag until the checklist is complete. Do not tag a dirty working tree.
Do not tag if private evidence is committed. Creating a GitHub release is
optional and should be done manually.

## Not Included In v0.2.0

- No authenticated testing.
- No vulnerability confirmation.
- No exploit automation.
- No Deep Recon.
- No deep crawling.
- No recursive discovery or larger Standard scan volume.
- No brute force, authentication testing, or form submission.
- No cloud sync.
- No automatic reporting to third parties.
- No LLM analysis in the default deterministic pipeline.
