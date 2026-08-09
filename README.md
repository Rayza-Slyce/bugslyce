# BugSlyce

[![Tests](https://github.com/Rayza-Slyce/bugslyce/actions/workflows/tests.yml/badge.svg)](https://github.com/Rayza-Slyce/bugslyce/actions/workflows/tests.yml)

BugSlyce is a local-first, evidence-led recon triage tool for authorised labs,
CTFs and scoped assessments. It runs bounded project workflows, preserves local
artefacts, builds operator reports and helps prioritise manual review.

BugSlyce is not an exploitation framework, vulnerability scanner or automated
pentesting platform. Its reports describe observed evidence and review leads;
BugSlyce does not claim confirmed vulnerabilities.

## Production bug bounty preflight

BugSlyce `1.2.0` introduces the v1.2 strict bug-bounty runtime.
Standard and Deep bug-bounty project execution uses policy-aware traffic
controls and default-deny programme-scope enforcement.

Historical controlled testing of `1.1.1` against a local HTTP capture server
found that Standard Recon peaked at **154 requests per second** and Deep Recon
peaked at **450 requests per second**. That release also could not consistently
apply programme-required researcher-identification headers across every HTTP
request path. The strict v1.2 project runtime replaces those unsafe paths.

**Standard and Deep bug-bounty project execution requires a ready private
engagement policy, default-deny programme scope, an authorised target and
compatible strict local tools. Unsupported direct and modular live commands
remain blocked.**

BugSlyce remains suitable for CTFs and controlled authorised labs. No
production target was involved in discovering these issues.

BugSlyce contains central internal HTTP enforcement and policy-aware
external-tool planning and enforcement. Curl shares
aggregate pacing and traffic identity with internal HTTP. Compatible Gobuster
plans use one thread, a conservative delay and the configured identity. Strict
bug bounty Nmap plans perform bounded TCP port-state discovery and, only when
explicitly permitted, service/version enrichment over observed open ports; incompatible
required curl or Nmap capability blocks preflight, while incompatible optional
Gobuster is omitted rather than weakened.

Standard and Deep project pipelines may run only after strict preflight. Save
or update private policy configuration without running recon:

```bash
bugslyce project policy --project ./bugslyce_project.json --configure
```

No platform preset supersedes current programme rules. CTFs and controlled
authorised labs remain supported live-testing contexts. Standard and Deep
bug-bounty project execution is supported only when the current programme
policy, default-deny programme scope and strict preflight all permit it.

Current package version: `1.2.0`.

The v1.2 runtime completed source-level, isolated-package, cross-host and
packaged authorised-lab acceptance before final promotion.

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
| Deep Recon | `deep-bounded` | Bounded same-origin Deep collection and offline review orchestration using `deep-bounded-core`. |

## Install from PyPI

Install BugSlyce as an isolated command-line application with `pipx`:

```bash
sudo apt update
sudo apt install pipx nmap curl gobuster
pipx ensurepath
pipx install bugslyce
```

Open a new terminal if `pipx ensurepath` asks you to refresh your shell, then
run the doctor before recon:

```bash
bugslyce doctor
```

Upgrade an existing pipx installation with:

```bash
pipx upgrade bugslyce
```

## Source Install

For a source install on a Debian-derived workstation:

```bash
sudo apt update
sudo apt install git python3 python3-venv nmap curl gobuster
git clone https://github.com/Rayza-Slyce/bugslyce.git
cd bugslyce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
bugslyce doctor
```

If the virtual environment is not active, use:

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

![BugSlyce interactive launcher](https://raw.githubusercontent.com/Rayza-Slyce/bugslyce/main/docs/images/bugslyce-interactive-menu.png)

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

## Offline HTML Evidence Report

Convert an existing local extracted evidence-pack directory into one
self-contained HTML report for offline review:

```bash
bugslyce report html \
  --input-dir ./path/to/extracted-evidence-pack \
  --output ./bugslyce-evidence-report.html
```

The input is an existing local evidence-pack directory, not a target. The
command reads existing local collection artefacts, writes only the requested
HTML output, makes no network requests and performs no additional
reconnaissance or testing. The self-contained report opens in a normal browser
and presents existing Operator Summary reasoning, Deep interpretations, route
provenance, HTTP evidence, manual review leads, collection-confidence
boundaries and searchable evidence records. Review leads are observations, not
confirmed vulnerabilities.

The screenshot below is from an authorised lab example and contains authorised
lab-scoped evidence.

![Self-contained BugSlyce HTML evidence report from an authorised lab example](https://raw.githubusercontent.com/Rayza-Slyce/bugslyce/main/docs/images/bugslyce-html-evidence-report.png)

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

The package version is `1.2.0`. The deterministic test suite mocks live
execution and should not contact targets. Local development checks include:

```bash
python -m pytest
bugslyce doctor
bugslyce --help
```

## Licence

BugSlyce is released under the MIT Licence. See [LICENSE](LICENSE).
