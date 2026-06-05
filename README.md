# BugSlyce

BugSlyce is a local-first, CLI-first bug bounty recon triage assistant for authorised testing workflows. It ingests existing recon outputs, organises assets and endpoints, links evidence, generates deterministic manual-review candidates, and writes a careful Markdown report plus a JSON project export.

The current MVP is deterministic Python only. It does not make network requests, run scanners, call LLMs, or confirm security issues.

## What BugSlyce Is

- A local Python CLI for organising already-collected, authorised recon outputs.
- A deterministic parser and triage assistant for hosts, HTTP metadata, URLs, notes, evidence, and grouped manual-review leads.
- A report generator that uses careful language and keeps human validation at the centre.
- A portfolio-safe project using fake demo data under `examples/demo_recon/`.

## What BugSlyce Is Not

- Not a live recon tool.
- Not a scanner runner.
- Not an exploitation framework.
- Not a brute force, bypass, fuzzing, or attack automation tool.
- Not an LLM agent yet.
- Not a replacement for manual validation, programme scope review, or responsible disclosure judgement.

## Current MVP Status

Implemented:

- Parsers for MVP input files.
- In-memory `ProjectState` assembly with assets, HTTP services, endpoints, evidence IDs, warnings, and deterministic tags.
- Grouped deterministic triage candidates.
- Deterministic `report.md` generation.
- Deterministic `project_state.json` export.
- Thin CLI command: `bugslyce run <input_dir> --output <output_dir>`.

Candidates are manual review leads, not confirmed findings. They are evidence-backed prompts for careful manual validation.

## Local Development Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Running The Demo

```bash
bugslyce run ./examples/demo_recon/basic_saas --output ./bugslyce-output/demo-basic-saas
```

Fallback module command:

```bash
python -m bugslyce.cli run ./examples/demo_recon/basic_saas --output ./bugslyce-output/demo-basic-saas
```

Expected outputs:

- `report.md`
- `project_state.json`

## Current Inputs

BugSlyce currently looks for these files in an input directory:

- `scope.md`
- `subdomains.txt`
- `httpx.jsonl`
- `urls.txt`
- `notes.md`

Missing optional files are handled with warnings rather than stopping the run.

## Safety Boundaries

BugSlyce is for authorised testing only. Use it only with programmes, assets, and data you are explicitly permitted to assess.

Do not commit raw recon files, private outputs, screenshots, Burp exports, HAR files, API keys, tokens, customer data, or sensitive material.

These paths are gitignored by default:

- `bugslyce-output/`
- `private_recon/`
- `raw-recon/`
- `.env`

The demo data in this repository is fictional and sanitised. Domains such as `example-bounty.test` are not real targets.

## Current Non-Goals

- No live recon.
- No scanning.
- No LLM calls yet.
- No config flow yet.
- No assisted recon.
- No vulnerability confirmation.
- No exploit generation or active testing logic.

## Deterministic Python First, LLM Later

No-LLM mode works as the current default. Future LLM support, if added, should remain optional, conservative, and controlled. Raw recon should not be sent to any provider by default.
