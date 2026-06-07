# BugSlyce

BugSlyce is a local-first, scope-aware recon pack generator and triage assistant for authorised security testing. It currently ingests existing recon outputs, organises assets and endpoints, links evidence, generates deterministic manual-review candidates, and writes a careful Markdown recon pack plus a JSON project export.

The current MVP is deterministic Python only. It does not make network requests, run scanners, call LLMs, or confirm security issues.

## What BugSlyce Is

- A local Python CLI for organising already-collected, authorised recon outputs.
- An evidence-first parser and triage assistant for hosts, HTTP metadata, URLs, structured evidence, and grouped manual-review leads.
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
- Deterministic recon-pack generation in `report.md`.
- Deterministic `project_state.json` export.
- Thin CLI command: `bugslyce run <input_dir> --output <output_dir>`.

Candidates are manual review leads, not confirmed findings. They are evidence-backed prompts for careful manual validation.

## Evidence-first Direction

BugSlyce is moving toward an evidence-first recon pack generator. The intended future workflow is:

1. Accept an authorised target and explicit scope.
2. Run controlled, profile-based recon.
3. Save raw outputs locally.
4. Parse structured recon evidence.
5. Generate a Markdown and JSON recon pack.
6. Optionally let a user-selected LLM summarise minimised structured evidence.
7. Leave validation and judgement to the operator.

The current version still ingests files and does not execute recon. Future automated recon will be scope-aware, profile-based, and locally saved.

`notes.md` remains optional operator context but is deprecated as a triage driver. Note bullets do not create individual manual-review candidates.

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

## Recon Plan Mode

BugSlyce can preview future recon activity without executing commands:

```bash
bugslyce recon plan \
  --target 10.10.10.10 \
  --scope ./private_recon/example/scope.md \
  --profile lab-full \
  --output ./private_recon/example
```

This writes:

- `recon_plan.json`
- `recon_plan.md`

Plan mode only documents proposed steps, command previews, expected artifacts, safety notes, and future `recon_manifest.json` entries. It does not execute nmap, curl, gobuster, ffuf, or any other network command.

Supported profiles:

- `lab-full`: broad planning for an explicitly authorised private lab, including full TCP discovery, service checks, HTTP metadata, bounded content discovery, and limited reviewed recursion.
- `bug-bounty-standard`: scope-first and conservative, with bounded service discovery, low-rate HTTP checks, and no aggressive fuzzing by default.
- `passive-only`: offline import and recon-pack assembly planning with no live command previews.

Active profiles require the target string to appear in the supplied scope file. `passive-only` can still create a plan when it does not, but records a warning because no live recon is planned.

Actual recon execution is planned for a later phase. `recon_manifest.json` remains the bridge between that future controlled executor and the current evidence-first recon pack generator.

### Recon Execution Dry Run

A generated plan can be loaded and reviewed through the dry-run executor scaffold:

```bash
bugslyce recon execute \
  --plan ./private_recon/example/recon_plan.json \
  --dry-run
```

This writes:

- `recon_execution_preview.json`
- `recon_execution_preview.md`

The preview validates the plan, lists each planned step, counts non-empty command previews, and shows expected artifacts and confirmation requirements. It does not run commands.

The `--dry-run` flag is required. Live recon execution is not implemented yet, and running `bugslyce recon execute` without that flag fails safely. Dry-run mode is the safety bridge between the current planning model and any future controlled executor.

### Recon Safety Preflight

Run local safety and readiness checks against a generated plan:

```bash
bugslyce recon preflight \
  --plan ./private_recon/example/recon_plan.json
```

Preflight writes:

- `recon_preflight.json`
- `recon_preflight.md`

It checks:

- BugSlyce plan provenance and structure.
- Literal target alignment with the recorded scope file.
- Expected local tool availability using PATH lookup only.
- Whether the planned output directory uses a safer local recon path.
- Command previews for configured high-risk tokens that are outside current product boundaries.

Preflight does not run commands or contact targets. Missing required tools fail active profiles, while `passive-only` requires no external recon tools. Warnings do not fail preflight, but any failed check produces a non-zero CLI exit code.

This is a required safety layer before any future controlled live execution is introduced.

### Passive-only Execution

BugSlyce can complete a local execution pipeline for a `passive-only` plan:

```bash
bugslyce recon execute \
  --plan ./private_recon/example/recon_plan.json \
  --passive-only \
  --input-dir ./private_recon/example/artifacts
```

The optional `--input-dir` selects an existing local artifact directory. Without it, BugSlyce uses the plan output directory as the input directory.

Passive-only execution:

1. Loads and validates `recon_plan.json`.
2. Requires the plan profile to be `passive-only`.
3. Runs and writes recon preflight results.
4. Parses existing local recon artifacts through the deterministic project assembly pipeline.
5. Writes `report.md`, `project_state.json`, `recon_execution.json`, and `recon_execution.md`.

It does not run network commands or execute command-preview strings. Plans using `lab-full` or `bug-bounty-standard` remain blocked because live command execution is not implemented.

This local packaging and analysis path is the safe bridge between planning/preflight and any future controlled live recon executor.

### Structured Command Foundation

BugSlyce models future recon activity as structured argument lists rather than shell command strings. For example:

```text
["nmap", "-p-", "--min-rate", "5000", "-oN", "/safe/output/nmap-allports.txt", "10.10.10.10"]
```

The current command builder can create non-executable templates for planned nmap, curl, and gobuster steps. Unknown ports, URLs, rates, and wordlists remain explicit placeholders, and those commands are marked as not ready for execution.

Command validation currently checks:

- The tool is allowlisted.
- `argv` is a list of strings and starts with the declared tool.
- Shell metacharacters and configured high-risk tokens are absent.
- Output files remain inside the planned output directory.
- Timeouts are positive and bounded.
- No unresolved placeholders remain.

The current runner is simulated only. It validates a `ReconCommand` and returns a simulated result with `executed=false`; it does not start processes or create network output. Live execution remains unimplemented.

Any future live runner must retain structured argv, allowlisted tools, bounded timeouts, output-file enforcement, preflight checks, explicit operator confirmation, and no shell interpretation.

## Safe Private Lab Workflow

For authorised private lab data, keep inputs in a gitignored folder:

```bash
mkdir -p private_recon/thm-lab-name
cd private_recon/thm-lab-name
touch scope.md subdomains.txt httpx.jsonl urls.txt notes.md
```

Then run BugSlyce from the repository root:

```bash
bugslyce run ./private_recon/thm-lab-name --output ./bugslyce-output/thm-lab-name
```

`private_recon/` and `bugslyce-output/` are gitignored. Do not commit real lab outputs. BugSlyce does not run scans yet; it only ingests files you provide. Candidates are manual review leads, not confirmed findings.

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

No external LLM calls are implemented yet. Future providers should receive minimised structured evidence, not raw recon files by default. LLMs remain optional and are not required for the deterministic recon-pack engine.

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

## Raw Recon Artifact Support

BugSlyce can also ingest selected saved raw recon artifacts:

- nmap normal output in files matching `nmap*.txt`
- gobuster output in files matching `gobuster-*.txt`
- saved curl response headers in files matching `curl-headers-*.txt`
- robots files matching `robots-*.txt`
- saved HTML files matching `*.html`

These parsers extract structured port services, HTTP services, discovered paths, headers, robots directives, page titles, links and sources, comments, hidden elements, forms, inputs, keyword hits, and conservative encoded-looking artifacts.

BugSlyce also supports `recon_manifest.json` for explicit raw artifact context. The manifest records the target and maps each saved artifact to its parser type plus optional URL, base URL, host, port, protocol, description, and tags. Manifest metadata takes precedence over filename hints.

Filename hints remain available as a backwards-compatible fallback for manually collected data without a manifest. Artifact paths declared in a manifest are constrained to the input directory; unknown types, missing files, and unsafe paths are skipped with warnings.

Future controlled recon execution is expected to write `recon_manifest.json` while saving outputs locally. BugSlyce still does not run recon. Raw artifact parsing is the bridge between manual recon today and a future planner/executor model for controlled, scope-aware recon. Parser and candidate logic is behaviour-driven and must not be treated as target-specific.

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
- Notes are optional context and do not drive the manual-review queue.
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
