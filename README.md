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

## Current MVP Workflow

```bash
bugslyce run ./examples/demo_recon/basic_saas --output ./bugslyce-output/demo-basic-saas
```

BugSlyce currently ingests recon files; it does not gather recon itself yet. Automated recon is planned later, but it is not part of the current MVP.

For private local use, keep real/private recon under `private_recon/`, `raw-recon/`, or another gitignored path. Write generated outputs under `bugslyce-output/`.

Do not commit real targets, API keys, screenshots, Burp files, HAR files, or raw private outputs.

## Candidate Language

Candidates are manual review leads, not confirmed findings. Evidence IDs show why something was included in the queue.

Priority means manual attention priority, not severity. A `kill_switch` priority means low signal or stop-unless-new-evidence, not proof of safety.

## Local Config

BugSlyce defaults to no-LLM mode:

```text
BUGSLYCE_LLM_PROVIDER=none
```

Current config commands are a local foundation for future provider support:

```bash
bugslyce config show
bugslyce config init
bugslyce config forget-key
bugslyce config reset
```

No LLM calls exist yet. These commands only read and write local `.env` settings for future use.

`.env` is local and gitignored. API keys must never be committed. If you choose to store a key with `bugslyce config init`, it is stored in the project `.env` file. This is local storage, not perfect security; anyone with access to this machine or project folder may be able to read it.

## No-LLM Provider Abstraction

BugSlyce includes a minimal provider interface for future optional LLM support. Provider `none` is the default and keeps the current deterministic behaviour unchanged.

No external LLM calls are implemented yet. Future providers should receive a minimised triage context, not raw recon files by default. The minimised context contains counts, candidate summaries, capped endpoint lists, capped evidence summaries, language rules, and a privacy note.

`bugslyce run` currently uses provider `none` and prints that deterministic report mode is active. Future provider names such as `gemini`, `openai`, `anthropic`, and `ollama` are recognised as configuration values but are not implemented yet. If a future provider is configured, reset to no-LLM mode with:

```bash
bugslyce config reset
```

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
- Config commands exist only as a local foundation for future providers.
- No assisted recon.
- No vulnerability confirmation.
- No exploit generation or active testing logic.

## Known Limitations

- Does not run recon yet.
- Does not parse Burp exports, nuclei output, or screenshots yet.
- Scope matching is simple.
- Report output is deterministic and may still need human judgement.
- No LLM provider calls are implemented yet.
- No confirmed vulnerability claims.

## Roadmap

- v0.1: deterministic recon-output triage.
- v0.2: private lab/IP support.
- v0.3: recon planning model, no execution yet.
- v0.4: controlled lab-safe recon execution.
- v0.5: passive/bug-bounty-safe recon profiles.
- v0.6: optional LLM report enhancement from minimised context.

LLMs are optional and are not required for the deterministic engine.

## Deterministic Python First, LLM Later

No-LLM mode works as the current default. Future LLM support, if added, should remain optional, conservative, and controlled. Raw recon should not be sent to any provider by default.
