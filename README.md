# BugSlyce

BugSlyce is a local-first, scope-aware recon pack generator and triage assistant for authorised security testing. It currently ingests existing recon outputs, organises assets and endpoints, links evidence, generates deterministic manual-review candidates, and writes a careful Markdown recon pack plus a JSON project export.

When reading `scope.md`, BugSlyce separates target-like entries such as IP addresses, networks, hostnames, wildcard domains, and HTTP URLs from policy or activity restrictions. Restriction text remains scope context and is not added to the asset inventory or manual review queue.

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
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
python -m pip install -e ".[dev]"
bugslyce --version
bugslyce wizard
```

The editable install exposes the `bugslyce` console command while keeping the
source tree live for development. Calling `.venv/bin/bugslyce` directly
remains supported when the virtual environment is not activated. The bundled
`bugslyce/wordlists/lab-root-tiny.txt` file is included as package data.

## Running Tests

```bash
pytest
```

## Local Sanity Check

After installation, these commands verify the local CLI surfaces without
starting recon:

```bash
pytest
bugslyce --help
bugslyce wizard
bugslyce project --help
bugslyce recon --help
```

## Local Readiness Check

```bash
bugslyce doctor
```

Doctor checks the local Python runtime, BugSlyce package resources, virtual
environment status, command availability for `nmap`, `curl`, and `gobuster`,
and the bundled and system content-discovery wordlists. It uses import,
filesystem, and `PATH` inspection only. It does not execute those tools, run
recon, create files, or make network requests.

Missing `gobuster` or the larger dirbuster wordlist limits content-discovery
profiles but does not make the rest of BugSlyce unusable. Unsupported Python
or a missing bundled `lab-root-tiny` resource is reported as not ready.

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

The Markdown recon pack starts with a deterministic **Operator Summary**. It
ranks a small set of evidence-backed review leads, separates low-signal items
and likely rabbit holes, and records current evidence coverage. Summary items
cite evidence IDs and use manual-review language rather than vulnerability
claims. The summary does not replace or remove the full candidate, structured
artifact, and raw evidence sections below it, which remain available for
auditability.

Encoded-looking HTML artifacts are also classified deterministically as
`likely_signal`, `possible_signal`, or `likely_noise`. Classification uses
value shape and conservative source context to separate review candidates from
documentation, DTD, default-page, static-resource, and low-diversity noise.
BugSlyce does not decode or interpret these values automatically, and the
classification does not claim a vulnerability or establish meaning. Original
artifact rows and evidence IDs remain in the report for auditability.

## Current MVP Workflow

```bash
bugslyce run ./examples/demo_recon/basic_saas --output ./bugslyce-output/demo-basic-saas
```

BugSlyce currently ingests recon files; it does not gather recon itself yet. Automated recon is planned later, but it is not part of the current MVP.

For private local use, keep real/private recon under `private_recon/`, `raw-recon/`, or another gitignored path. Write generated outputs under `bugslyce-output/`.

Do not commit real targets, API keys, screenshots, Burp files, HAR files, or raw private outputs.

## Guided Starting Point

`bugslyce wizard` is a safe, preview-only entrypoint for new or returning
operators:

```bash
bugslyce wizard
```

It explains the local project workflow and prints templates for project
creation, project status, next-step previews, report review, and evidence-pack
export. It does not require a project file, create files, execute recon, or
make network requests. Operators must review programme scope and manually run
any suggested command.

This command is groundwork for a future interactive guided mode. It does not
prompt for targets or execute suggested actions.

Guided mode includes a lightweight boxed BugSlyce wordmark with the
`by Rayza Slyce` credit. The local-first tagline remains in the guidance below
the wordmark. This branding is display-only: it is not added to recon
commands, reports, status output, exports, project guidance, or
machine-readable files.

## Project Sessions

BugSlyce projects are small local JSON session files that remember a target,
scope file, recon output directory, and conservative default profiles:

### Project Scaffold

```bash
bugslyce project scaffold \
  --name authorised-lab \
  --target 10.10.10.10 \
  --projects-dir ./bugslyce-output
```

This creates `bugslyce-output/authorised-lab/scope.md` and
`bugslyce-output/authorised-lab/bugslyce_project.json`. The scope file is a
conservative starter template, not proof of authorisation. Review and edit it
to match the actual programme or lab scope before running recon.

Scaffolding performs no recon or network requests. Existing non-scaffold
files, reports, manifests, and raw evidence are never overwritten. `--force`
can replace only the two BugSlyce-owned scaffold files in an otherwise clean
project directory.

### Project Inventory

```bash
bugslyce project list --projects-dir ./bugslyce-output
```

Project inventory checks only immediate child directories containing
`bugslyce_project.json`. It shows each target, creation time, recon-pack
presence, and project path in deterministic name order. Malformed project
files are reported without preventing valid projects from being listed.

The inventory is read-only: it creates no files, runs no recon, and makes no
network requests. It is useful when resuming work or switching between local
lab targets.

### Project Runbook

```bash
bugslyce project runbook \
  --project ./bugslyce-output/authorised-lab/bugslyce_project.json
```

This writes `runbook.md` into the saved project output directory. The runbook
summarises project paths, local recon status, the current safe next action,
command previews, scope reminders, and evidence-pack export guidance.

Runbook generation uses local project metadata and evidence only. It performs
no recon, executes no suggested command, and makes no network requests. The
generated file can be safely regenerated when resuming a project later.

### Safe Project Pipeline

```bash
bugslyce project run \
  --project ./bugslyce-output/authorised-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm
```

The `lab-safe-tiny` pipeline runs the existing approved full-TCP discovery,
service scan, HTTP metadata, evidence-derived path follow-up, tiny root
content discovery, content-result follow-up, selective body fetch, status,
runbook, and evidence export phases in order. It requires explicit
confirmation, stops on the first required failure, and writes
`project_pipeline.json` and `project_pipeline.md`.

This first pipeline version expects a fresh scaffolded project. It refuses an
existing recon manifest, content-plan directory, or evidence-pack ZIP rather
than mixing old and new evidence. It does not add NSE scripts, UDP scans,
brute force, exploitation, recursion, form submission, authentication
testing, arbitrary flags, arbitrary wordlists, or arbitrary commands.

### Project Init

```bash
bugslyce project init \
  --name authorised-lab \
  --target 10.10.10.10 \
  --scope ./private_recon/authorised-lab/scope.md \
  --output-dir ./bugslyce-output/authorised-lab
```

This creates `bugslyce_project.json` inside the output directory. Project
names are restricted to letters, numbers, dash, and underscore. Targets must
be one plain IP address or hostname. Existing project files are not
overwritten unless `--force` is supplied.

Saved details can be reviewed without inspecting recon evidence:

```bash
bugslyce project show \
  --project ./bugslyce-output/authorised-lab/bugslyce_project.json
```

Project status lets an operator resume work without remembering separate
target, scope, and output paths:

```bash
bugslyce project status \
  --project ./bugslyce-output/authorised-lab/bugslyce_project.json
```

When a recon manifest exists, project status reuses the local recon status
advisor and the saved scope file. If recon has not started, it reports that no
pack exists and suggests a first safe planning or scoped discovery action.

For a guided copy/paste preview of the next bounded action:

```bash
bugslyce project next \
  --project ./bugslyce-output/authorised-lab/bugslyce_project.json
```

`project next` reads the saved project, local recon manifest, parsed evidence,
and status signals. It prints the recommended next safe action and an exact
command preview using the saved target, scope, and output paths. Live command
previews retain `--confirm`. Content discovery execution is suggested only
when an expected project-derived plan has BugSlyce planner provenance,
matching target/profile, and matching recon input directory.

When no automated follow-up appears pending, guidance switches to manual
review of `report.md` and an optional evidence-pack export. If
`lab-root-tiny` completed without `lab-root-light`, it can also preview the
optional broader planning command. Suggested commands never add recursion,
arbitrary wordlists, brute force, exploitation, NSE scripts, UDP scanning,
form submission, or external LLM uploads.

The guided command does not create plan directories, update recon status
files, mutate evidence, execute a command, or make a network request.
Operators must review scope and manually run any preview they choose. This is
the deterministic foundation for a future interactive wizard, not an
interactive wizard itself.

Project management performs no live recon, subprocess execution, or network
requests. Project files are local JSON only and do not store API keys,
credentials, provider tokens, or other secrets. This session layer is
groundwork for a future guided wizard mode rather than a database.

## Timestamp Provenance

BugSlyce writes operator-facing metadata timestamps in UTC ISO-8601 format
with seconds precision and a trailing `Z`, for example
`2026-06-14T13:45:12Z`.

New project files include `created_at`. Recon status files include
`generated_at` and `source_input_dir`. Evidence export manifests include
`exported_at`, and reports display the generation time already recorded in
`project_state.json`. Structured command results use the same UTC formatting
for their existing start/end timestamp fields.

ZIP entry timestamps deliberately remain fixed at `1980-01-01T00:00:00` so
archive layout metadata stays deterministic. The real export time is stored
inside `bugslyce_export_manifest.json` and the export README instead. Tests
inject fixed clocks and do not depend on wall-clock time.

Older project, manifest, status, and recon files without these timestamp
fields remain supported. Timestamps record local metadata provenance only;
they do not prove when a security condition began or establish a
vulnerability.

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

The simulated runner remains available for command-flow tests and previews. Isolated live runners exist only for the scoped curl-header command and the two fixed nmap discovery profiles described below.

Any future live runner must retain structured argv, allowlisted tools, bounded timeouts, output-file enforcement, preflight checks, explicit operator confirmation, and no shell interpretation.

### Nmap Command Planning

BugSlyce models three approved future nmap profiles without executing them:

- `lab-tcp-top`: SYN discovery across nmap's top 1000 TCP ports.
- `lab-tcp-full`: full TCP discovery with a fixed planned rate.
- `lab-service-scan`: service/version detection for an explicit validated port list.

Create a non-executing command plan with:

```bash
bugslyce recon nmap-plan \
  --target 10.10.10.10 \
  --scope ./private_recon/example/scope.md \
  --profile lab-tcp-top \
  --output ./bugslyce-output/nmap-plan
```

The command writes `nmap_command_plan.json` and `nmap_command_plan.md` without executing nmap. Planning also models `lab-service-scan`; the narrow live form is documented below and can use only ports derived from saved BugSlyce discovery output. Validation rejects arbitrary arguments, NSE scripts including `-sC`, `-A`, OS detection, UDP scans, decoys or spoofing, `-T5`, multiple targets, shell metacharacters, and output paths outside the selected directory.

### Scoped Nmap TCP Discovery

BugSlyce has two narrowly restricted live nmap discovery profiles:

- `lab-tcp-top`: one top-1000 TCP discovery command.
- `lab-tcp-full`: one full TCP discovery command using the fixed planned rate.

```bash
bugslyce recon nmap-discover \
  --target 10.10.10.10 \
  --scope ./private_recon/example/scope.md \
  --profile lab-tcp-top \
  --output ./private_recon/example \
  --confirm
```

Use `--profile lab-tcp-full` to write `nmap-allports.txt`. Both profiles require explicit confirmation, one exactly listed target-like in-scope entry, a bounded process timeout, and their fixed output filename inside the selected directory.

The discovery validator rejects arbitrary nmap arguments, NSE scripts, service-detection flags, UDP scans, `-A`, `-O`, `-T5`, decoys or spoofing, multiple targets, and shell metacharacters. The workflow writes raw nmap output, `recon_manifest.json`, the recon pack, and execution metadata.

### Scoped Nmap Service Detection

BugSlyce can run one narrow service/version command against TCP ports already recorded as open by a prior BugSlyce nmap discovery run:

```bash
bugslyce recon nmap-services \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --confirm
```

The command prefers `nmap-allports.txt` and falls back to `nmap-top1000.txt`. It derives, sorts, and deduplicates open TCP ports from that file; there is no CLI option for manually supplying ports. The target comes from the existing manifest or discovery output and must be explicitly listed in scope.

The live runner accepts only `nmap -sV -Pn -p <derived-ports> -oN nmap-services-all.txt <target>`. It rejects NSE scripts including `-sC`, UDP scans, arbitrary flags or ports, `-A`, `-O`, `-T5`, decoys or spoofing, multiple targets, shell metacharacters, and output paths outside the existing directory. It preserves the discovery artifact in `recon_manifest.json`, adds the service artifact, and rebuilds the recon pack.

### Scoped HTTP Metadata Collection

BugSlyce can collect bounded metadata from HTTP services already identified by saved nmap service evidence:

```bash
bugslyce recon http-metadata \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --confirm
```

For at most 10 discovered HTTP services, the command collects response headers, `/robots.txt`, and the root homepage HTML. Origins are derived from structured nmap evidence; the CLI accepts no URL or port arguments. Requests use fixed curl argv shapes, a 10-second timeout, no redirect-following option, no request body, and only HEAD or GET behavior.

The command requires an exact scope match and writes only inside the existing BugSlyce directory. It preserves nmap artifacts, appends HTTP artifacts to `recon_manifest.json`, and rebuilds the recon pack. It does not perform content discovery, brute force, exploitation, form submission, or arbitrary URL requests. Live gobuster/content discovery remains unimplemented.

### Discovered-Path Follow-up

BugSlyce can perform bounded header checks for same-origin paths that already
exist in collected HTML or robots evidence:

```bash
bugslyce recon path-followup \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --confirm
```

This command does not accept URLs, paths, or wordlists. It derives concrete
relative paths from saved same-origin links, sources, and robots rules,
deduplicates them, and checks at most 20 URLs. Root, anchors, external URLs,
`robots.txt`, and path traversal forms are excluded. Each approved URL receives
one fixed, bounded curl HEAD request with no redirect-following option or
request body.

The command requires an exact scope match and preserves prior manifest
artifacts while rebuilding the recon pack. It does not run gobuster, ffuf,
wordlists, recursive crawling, content discovery, brute force, exploitation,
or form submission. General wordlist-based content discovery remains
unimplemented.

### Content Discovery Planning

BugSlyce can create a reviewed, non-executing root content discovery plan for
HTTP origins already present in structured recon evidence:

```bash
bugslyce recon content-plan \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --profile lab-root-light \
  --output ./bugslyce-output/example-content-plan
```

Two profiles are available:

- `lab-root-tiny` uses BugSlyce's bundled small generic wordlist, five threads,
  and a shorter timeout. It is a first-live proving profile for checking the
  execution, parsing, manifest, and report pipeline. It is not thorough recon.
- `lab-root-light` keeps the broader system wordlist path, ten threads, and a
  longer bounded timeout for later lab use.

Both profiles plan at most five discovered HTTP service roots. They produce
`content_discovery_plan.json` and `content_discovery_plan.md` with structured
gobuster argv previews, deterministic future artifact names, moderate-risk
labels, scope requirements, and future confirmation requirements.

Planning does not run gobuster, ffuf, feroxbuster, dirsearch, curl, or any
wordlist. The referenced default wordlist is a future execution prerequisite;
planning only warns when it is absent. The profile proposes no recursion,
extensions, arbitrary paths, or user-supplied flags. Live content discovery
is available only through an approved saved plan.

### Controlled Root Content Discovery

BugSlyce can execute the fixed root-discovery steps in an existing plan:

```bash
bugslyce recon content-run \
  --plan ./bugslyce-output/example-content-plan/content_discovery_plan.json \
  --scope ./private_recon/example/scope.md \
  --confirm
```

Execution supports only `lab-root-tiny` and `lab-root-light` plans and the
exact structured gobuster argv lists written by BugSlyce. The target must
still be explicitly in scope, the profile-specific approved local wordlist
must exist, each origin must remain in current structured HTTP evidence, and
all output filenames must remain inside the planned directory. Results are
copied into the original recon directory, added to `recon_manifest.json`, and
used to rebuild the recon pack.

If gobuster starts but exceeds its timeout, BugSlyce records that the command
started and timed out. A non-empty partial output file is preserved, marked as
partial in the manifest, and used to rebuild the recon pack before the command
returns a non-zero status. A timeout before useful output does not create a
gobuster artifact. Larger and more thorough discovery remains future
profile-based work.

The command accepts no URL, path, wordlist, thread, extension, header, cookie,
authentication, proxy, or arbitrary gobuster options. It does not use
recursion, ffuf, feroxbuster, dirsearch, form submission, credential brute
force, or exploitation.

`lab-root-tiny` remains the short smoke/proving profile. `lab-root-light` uses
the broader approved system wordlist and may take substantially longer. For a
multi-origin plan, an operator can narrow execution to one existing immutable
plan step:

```bash
bugslyce recon content-run \
  --plan ./bugslyce-output/content-plan/content_discovery_plan.json \
  --scope ./private_recon/example/scope.md \
  --step-id CONTENT-STEP-002 \
  --confirm
```

The selector cannot add an origin or alter the planned URL, wordlist, flags,
threads, or output path. Without `--step-id`, all approved plan steps run in
order. If a later step times out, completed earlier outputs remain imported;
non-empty partial timeout output is also preserved and labelled. Execution
metadata records selected step/origin, completed and partial imports, and the
exact timed-out step/origin.

The latest completed live phase writes generic metadata to
`recon_execution.json` and `recon_execution.md` in the recon directory.
Content discovery also keeps `recon_execution_content_run.json` and
`recon_execution_content_run.md`, plus the existing plan-directory
`content_discovery_execution.*` files.

Longer content discovery runs print simple status blocks before and after each
approved step, including step ID, origin, progress count, timeout, elapsed
time, and artifact or timeout state. This is deliberately not a streaming
progress bar: BugSlyce retains the validated `subprocess.run` execution model
and does not stream process output.

### Content-Result Follow-up

BugSlyce can perform bounded HEAD checks for selected paths already present in
gobuster-derived `discovered_path` evidence:

```bash
bugslyce recon content-followup \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --confirm
```

Selection is dynamic and target-independent. Response status, directory or
extensionless shape, redirects, static-file suffixes, prior low-signal tags,
and generic application-oriented path segments affect ranking. No particular
path is required. Selection is capped at 20 URLs total and 10 per HTTP origin.

The command excludes external origins, duplicates, traversal forms, root,
already collected robots/homepage equivalents, known dead paths, and URLs
already checked by an earlier content follow-up. It accepts no URL or path
arguments and runs no wordlists, gobuster, ffuf, recursion, brute force,
exploitation, or form submission.

Follow-up phases are idempotent. When valid evidence exists but every current
candidate is already processed, excluded, duplicate, static, non-HTML,
403/404, or otherwise low signal, `content-followup` and `body-fetch` exit
cleanly with status 0 and state that no request was executed. Missing inputs,
malformed manifests, and scope failures remain errors. A clean no-op does not
replace the metadata for the latest phase that actually executed requests.

### Recon Status And Next Steps

BugSlyce can inspect an existing local recon directory without running recon:

```bash
bugslyce recon status \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md
```

The command reports the manifest target, detected phases, artifact counts,
latest and phase-specific execution metadata, and deterministic next-step
advice. The optional scope file adds an exact target-alignment status; an
out-of-scope result is reported as a warning and never triggers activity.

`recon status` writes repeatable `recon_status.json` and `recon_status.md`
files. It does not replace the recon pack, project state, or execution
metadata. It performs no subprocess execution or network requests. Advice is
based only on saved local evidence and remains conservative: it can recommend
the next bounded BugSlyce phase, optional broader planned root discovery, or
manual review when no eligible automated follow-up appears pending.

Status and recon pack reports also include a clean workflow/provenance
summary. The raw manifest profile remains available for compatibility, while
repeated add-on phases are displayed as base discovery, enrichment, content
discovery profiles, and follow-up phases. `lab-root-tiny` and
`lab-root-light` runs are shown separately instead of repeating an ambiguous
`plus-content-discovery` suffix.

BugSlyce preserves every raw discovered-path evidence row, including repeated
observations from different discovery profiles. Human-facing summaries report
raw path rows, unique URL strings, and duplicate rows retained for
auditability. This is reporting and provenance cleanup only; evidence IDs and
raw path tables are not deduplicated or removed.

This is useful when resuming an authorised lab after a VPN target expires,
checking what completed before a timeout, or deciding whether a fresh run is
needed. Absence of evidence is not proof of safety, and manual validation
remains required.

### Evidence Pack Export

BugSlyce can create a portable ZIP from an existing local recon directory:

```bash
bugslyce recon export \
  --input-dir ./private_recon/example \
  --output ./bugslyce-output/example-evidence-pack.zip
```

The export includes the recon report, project state, recon manifest, status
files when present, latest and phase-specific execution metadata, scope, and
every local raw artifact referenced by `recon_manifest.json`. It also includes
`bugslyce_export_manifest.json` and `BUGSLYCE_EXPORT_README.md`. Missing
manifest-referenced artifacts are recorded in the export manifest.

Exports use an explicit file allowlist and reject traversal or references
outside the input directory. Unrelated files and directories such as `.git`,
`.venv`, `__pycache__`, and `.pytest_cache` are not included. Existing ZIP
files are not overwritten unless `--force` is supplied.

Evidence-pack export performs no live recon, subprocess execution, network
requests, or LLM calls. The ZIP may contain sensitive target IPs, URLs,
headers, HTML, service banners, and discovered paths. Review it before sharing
and do not distribute it publicly unless authorised. Raw artifacts are
preserved for auditability, and the archive does not claim confirmed
vulnerabilities.

### Selective Body Fetch

BugSlyce can fetch saved HTML/application bodies for high-signal paths that
were already selected and checked by `recon content-followup`:

```bash
bugslyce recon body-fetch \
  --input-dir ./private_recon/example \
  --scope ./private_recon/example/scope.md \
  --confirm
```

Selection is evidence-driven and target-independent. Phase 30 only considers
prior content-followup header artifacts with status 200, then ranks likely
HTML/application paths using generic path shape and segment signals. It
excludes roots, robots, homepage-equivalent index pages, 401/403/404
responses, static/archive suffixes, external origins, traversal forms,
duplicates, and URLs whose body was already saved. Selection is capped at 10
URLs total and 5 per origin.

The command accepts no URL or path arguments. It uses a fixed bounded curl GET
shape with no redirects, request body, headers, cookies, authentication, or
proxy options. It runs no crawling, wordlists, gobuster, ffuf, recursion,
brute force, exploitation, or form submission. Saved HTML is parsed by the
existing metadata pipeline for titles, links, comments, hidden elements,
forms, inputs, keywords, and encoded-looking artifacts.

### Scoped Curl Header Request

BugSlyce has one narrowly scoped live command:

```bash
bugslyce recon curl-headers \
  --url http://10.10.10.10/ \
  --scope ./private_recon/example/scope.md \
  --output ./private_recon/example \
  --confirm
```

This command:

- Requires explicit `--confirm`.
- Accepts one explicit `http://` or `https://` URL.
- Requires the exact URL host to appear in the supplied scope file.
- Runs one curl response-header request using a structured argv list.
- Uses a bounded timeout, enforced by both curl and the local process runner.
- Writes only inside the selected output directory.
- Saves the raw headers, `recon_manifest.json`, recon-pack outputs, and execution metadata.

The live runner accepts only the approved curl header argv shape. It does not use shell interpretation, does not send request bodies, and does not run POST, PUT, DELETE, brute force, exploitation, recursive discovery, or content discovery. NSE-based nmap scanning and live gobuster execution remain unimplemented.

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

When a valid manifest is present, it is the primary input description. Legacy files such as `subdomains.txt`, `httpx.jsonl`, `urls.txt`, and `notes.md` are still parsed when present, but are not required and do not generate missing-file warnings. Missing, unsupported, malformed, or unsafe manifest-listed artifacts still generate warnings.

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
