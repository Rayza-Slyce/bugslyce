# BugSlyce

[![Tests](https://github.com/Rayza-Slyce/bugslyce/actions/workflows/tests.yml/badge.svg)](https://github.com/Rayza-Slyce/bugslyce/actions/workflows/tests.yml)

BugSlyce is a local-first, evidence-led recon triage tool for authorised labs,
CTFs and scoped assessments. It runs bounded project workflows, preserves local
artefacts, builds operator reports and helps prioritise manual review.

BugSlyce is not an exploitation framework, vulnerability scanner or automated
pentesting platform. Its reports describe observed evidence and review leads;
BugSlyce does not claim confirmed vulnerabilities.

Current package version: `1.0.0rc1`. This is the first BugSlyce v1 release
candidate, not the final `1.0.0` release. It has not been tagged or published
from this development phase.

## Authorised Use

Use BugSlyce only against systems you own or are explicitly authorised to
assess. The generated `scope.md` template is a local safety aid, not proof of
authorisation. Always review scope and programme rules before running recon.

## Supported Host Expectations

BugSlyce is intended for Linux operator workstations. It has been developed and
validated on Kali Linux and Linux Mint. Other Debian-derived Linux systems,
including Ubuntu, are expected to work when the required Python version and
external tools are available, but they are not currently part of the directly
validated host set. Native Windows and macOS operation is not currently
claimed.

## What BugSlyce Provides

- Local project scaffolding and scope templates.
- Passive doctor/readiness checks.
- Bounded Quick, Standard and Deep Recon project workflows.
- Deterministic reports, runbooks, status files and pipeline metadata.
- Local evidence-pack ZIP export.
- Conservative resume behaviour for completed or clearly reusable work.
- Offline interpretation that keeps raw evidence separate from conclusions.

## Operator Modes

| Mode | Profile | Purpose |
| --- | --- | --- |
| Manual Setup Only | none | Create project metadata and `scope.md` without running recon. |
| Quick Recon | `lab-safe-tiny` | Fast first-pass bounded collection using the bundled `lab-root-tiny` wordlist. |
| Standard Recon | `standard-bounded` | Bounded collection plus offline interpretation using `standard-bounded-core`. |
| Deep Recon | `deep-bounded` | Bounded same-origin Deep collection and offline review orchestration using `standard-bounded-core`. |

## Minimal Install

For a source install on a Debian-derived workstation:

```bash
git clone https://github.com/Rayza-Slyce/bugslyce.git
cd bugslyce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

BugSlyce also requires local external tools for executable recon:

```bash
sudo apt update
sudo apt install git python3 python3-venv nmap curl gobuster
```

Run the doctor before recon:

```bash
bugslyce doctor
```

If your virtual environment is not active, use:

```bash
./.venv/bin/bugslyce doctor
```

Detailed setup instructions are in [docs/INSTALLATION.md](docs/INSTALLATION.md).

## First Launch

Most operators should start with the guided launcher:

```bash
bugslyce
```

The launcher can create a project, ask for engagement context, choose a mode,
show the exact command that will run and require an exact `YES` confirmation
before live recon starts.

## Output Overview

A completed project commonly contains:

- `bugslyce_project.json`: project metadata.
- `scope.md`: operator-reviewed scope template.
- `recon_manifest.json`: collected evidence manifest.
- `report.md`: evidence-led report and review leads.
- `recon_status.md` and `recon_status.json`: current progress and next-step context.
- `runbook.md`: operator guide for the local project.
- `project_pipeline.md` and `project_pipeline.json`: pipeline step history.
- an adjacent evidence-pack ZIP.

Deep Recon additionally retains:

- `deep_source_route_collection.md`
- `deep_source_route_collection.json`
- `deep_recon_review.md`
- `deep_recon_runbook.md`
- `deep_recon_orchestration.json`

The evidence pack may contain target identifiers, service banners, headers,
HTML and discovered paths. Store and share it carefully. It is not proof that a
vulnerability exists.

## Resume Summary

Completed Quick, Standard and Deep projects may be resumed as verified reuse.
A completed Deep resume is a no-op apart from local validation and leaves
canonical artefacts unchanged. Partial Deep network state fails closed because
the complete in-memory response bodies required for offline Deep analysis are
not persisted. Use a clean project for an explicit Deep rerun after an unsafe
partial state.

Interactive resume preview is read-only. Declining resume changes no canonical
project files.

## More Documentation

- [Installation](docs/INSTALLATION.md)
- [Operator Guide](docs/OPERATOR_GUIDE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Recon mode details](docs/RECON_MODES.md)
- [Release notes](docs/RELEASE_NOTES.md)
- [Release acceptance](docs/RELEASE_ACCEPTANCE.md)

## Development and Testing Status

The package version is `1.0.0rc1`. The deterministic test suite mocks live
execution and should not contact targets. Local development checks include:

```bash
python -m pytest
bugslyce doctor
bugslyce --help
```

## Licence

BugSlyce is released under the MIT Licence. See [LICENSE](LICENSE).
