# BugSlyce

BugSlyce is a local-first recon triage assistant for authorised labs and
bug bounty-style recon. It runs a bounded, scope-aware evidence collection
workflow, preserves raw artefacts, builds a BugSlyce Recon Pack, and
prioritises evidence-backed leads for manual review.

BugSlyce does not claim confirmed vulnerabilities. Its candidates and
priorities describe where an operator may want to look next, not exploit
severity or proof of impact.

Current version: `0.1.0`

## Safety Model

BugSlyce is intended only for targets you are authorised to assess.

The live MVP workflow enforces these boundaries:

- A local scope file is required.
- The project target must match a target-like in-scope entry.
- Live project pipelines require explicit `--confirm`.
- The only one-command pipeline profile is `lab-safe-tiny`.
- Live phases use fixed, validated command shapes and bounded timeouts.
- Evidence and generated reports remain local.
- No NSE scripts.
- No UDP scans.
- No brute force.
- No exploitation.
- No recursive discovery.
- No form submission.
- No authentication testing.
- No arbitrary user-supplied command flags, paths, URLs, or wordlists in the
  pipeline.
- No LLM calls in the deterministic MVP pipeline.

Scope matching is a safety control, not a substitute for reading the actual
programme or lab rules. Review the generated `scope.md` before every live run.

## Install

For local development:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
bugslyce --version
```

Install development dependencies with:

```bash
python -m pip install -e ".[dev]"
```

The editable install exposes the `bugslyce` console command. During
development, `.venv/bin/bugslyce` remains available without activating the
virtual environment. The bundled `lab-root-tiny` wordlist is installed as
package data.

## Quick Start

For a new user in an interactive terminal, start with:

```bash
bugslyce
```

The interactive launcher can run doctor/readiness checks, scaffold a project,
choose **Quick Recon** or **Manual Setup Only**, confirm authorisation, and
optionally run the MVP pipeline. Quick Recon maps to the current
`lab-safe-tiny` pipeline. **Standard Recon** and **Deep Recon** are planned
future modes and are not available yet. Recon mode names do not make activity
automatically safe; authorisation and scope still matter. Manual Setup Only
creates local project files and prints the next safe command preview without
running recon.

Interactive mode defaults to `~/bugslyce-output` so project output is
predictable regardless of the current working directory. Direct CLI commands
still use the paths you provide.

Advanced users and automation can use the direct commands below.

Check local readiness:

```bash
bugslyce doctor
```

Create a local project and starter scope:

```bash
bugslyce project scaffold \
  --name example-lab \
  --target 10.10.10.10 \
  --projects-dir bugslyce-output
```

Edit and review:

```text
bugslyce-output/example-lab/scope.md
```

Run the approved MVP pipeline only after confirming authorisation and scope:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm
```

Review the evidence-backed Operator Summary:

```bash
less bugslyce-output/example-lab/report.md
```

Ask BugSlyce what local action is appropriate next:

```bash
bugslyce project next \
  --project bugslyce-output/example-lab/bugslyce_project.json
```

`project next` prints command previews only. It does not execute them.

See [docs/DEMO_WALKTHROUGH.md](docs/DEMO_WALKTHROUGH.md) for a complete
fictional-target MVP walkthrough from readiness checks through review, resume,
and evidence handling.

## Pipeline Workflow

The fixed `lab-safe-tiny` pipeline runs these approved stages in order:

1. Validate the project, scope, and local readiness.
2. Run full TCP discovery with the fixed `lab-tcp-full` profile.
3. Run service/version detection on discovered open TCP ports.
4. Collect bounded HTTP headers, `robots.txt`, and homepage HTML.
5. Follow same-origin paths already present in collected evidence.
6. Create a non-executing `lab-root-tiny` content plan.
7. Execute that exact approved tiny root-discovery plan.
8. Follow selected paths found by content discovery.
9. Fetch bodies only for eligible high-signal HTML/application paths.
10. Generate local recon status.
11. Generate the project runbook.
12. Export a portable evidence pack.

The pipeline stops on a required failure. Content follow-up and body fetch may
complete as clean no-ops when no eligible new work remains.

After a successful run:

```bash
less bugslyce-output/example-lab/report.md
bugslyce project status \
  --project bugslyce-output/example-lab/bugslyce_project.json
bugslyce project next \
  --project bugslyce-output/example-lab/bugslyce_project.json
```

## Resume Workflow

Fresh runs omit `--resume` and refuse an existing recon manifest, tiny plan
directory, or evidence ZIP.

To continue an interrupted or partially completed project:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm \
  --resume
```

Resume is conservative:

- It revalidates local readiness, target, and scope.
- It reuses only a coherent prefix of clearly completed phases.
- It validates manifest artefact paths inside the project directory.
- It validates tiny-plan target, profile, scope, input, and output provenance.
- It refuses mixed-target, missing-artefact, path-escape, or otherwise
  ambiguous state.
- It regenerates status and runbook output.
- It does not overwrite an existing evidence ZIP.
- It skips an existing ZIP only when completed pipeline metadata verifies the
  prior export.

`project_pipeline.md` and `project_pipeline.json` record completed,
`skipped_existing`, no-op, failed, and pending stages.

## Outputs

A completed project may contain:

- `report.md`: the human-readable BugSlyce Recon Pack and Operator Summary.
- `project_state.json`: structured parsed assets, services, paths, evidence,
  and candidates.
- `recon_manifest.json`: target and raw artefact provenance.
- `recon_status.md` and `recon_status.json`: detected phases, coverage, latest
  execution, and deterministic next-step advice.
- `runbook.md`: project paths, scope reminders, current status, and safe
  command previews.
- `project_pipeline.md` and `project_pipeline.json`: pipeline timing, step
  status, reused evidence, failures, and final output paths.
- `recon_execution.md` and `recon_execution.json`: latest live phase metadata.
- Phase-specific execution metadata where applicable.
- Raw nmap, curl, HTML, robots, and gobuster artefacts referenced by the
  manifest.
- `bugslyce-output/example-lab-evidence-pack.zip`: portable evidence archive.

The evidence pack contains an export manifest and safety README. It may
contain target IPs, URLs, response headers, HTML, service banners, and
discovered paths. Review it before sharing.

ZIP entry timestamps remain fixed for reproducible packaging. Real UTC export
time is stored inside the archive metadata.

## Operator Summary

`report.md` starts with a deterministic Operator Summary:

- **Review First** ranks the most useful evidence-backed leads.
- **Low-Signal / Avoid Rabbit Holes** identifies dead paths, static assets,
  default-page noise, and other context that should not be over-weighted.
- **Current Coverage** records what the recon pack has and has not observed.
- Evidence IDs link summary statements to the detailed raw and structured
  evidence below.

Encoded-looking artefacts are classified conservatively as `likely_signal`,
`possible_signal`, or `likely_noise`. BugSlyce does not decode them
automatically or claim what they mean.

Manual review candidates are leads, not confirmed vulnerabilities. Priority
means manual attention priority, not exploit severity. Manual validation is
required before reporting any issue.

## Project Commands

### Guided Entry Point

```bash
bugslyce wizard
```

Prints a safe local workflow guide. It runs no recon and makes no network
requests.

### Readiness

```bash
bugslyce doctor
```

Checks Python, package resources, virtual environment state, local tool paths,
and wordlists using import, filesystem, and `PATH` inspection only. It does
not execute `nmap`, `curl`, or `gobuster`.

### Project Management

```bash
bugslyce project scaffold --help
bugslyce project init --help
bugslyce project list --help
bugslyce project show --help
bugslyce project status --help
bugslyce project next --help
bugslyce project runbook --help
bugslyce project run --help
```

- `scaffold` creates a project directory, starter `scope.md`, and
  `bugslyce_project.json`.
- `init` records an existing scope and output directory.
- `list` inventories immediate-child local projects.
- `show` displays saved project metadata.
- `status` inspects local recon progress without live activity.
- `next` prints the next safe command preview without executing it.
- `runbook` writes a local, human-readable project guide.
- `run` executes the confirmed fixed-profile pipeline.

Project metadata is local JSON. It should not contain credentials, API keys,
tokens, or other secrets.

## Recon Commands

Most operators should begin with `project scaffold`, `project run`, and
`project next`. Lower-level recon commands remain available for debugging,
reviewed manual operation, and phase-specific recovery:

```text
bugslyce recon plan
bugslyce recon execute --dry-run
bugslyce recon preflight
bugslyce recon nmap-plan
bugslyce recon nmap-discover
bugslyce recon nmap-services
bugslyce recon http-metadata
bugslyce recon path-followup
bugslyce recon content-plan
bugslyce recon content-run
bugslyce recon content-followup
bugslyce recon body-fetch
bugslyce recon status
bugslyce recon export
```

There is also a narrow legacy `recon curl-headers` command for one explicitly
scoped URL. It is not used to introduce arbitrary URLs into the project
pipeline.

Live lower-level commands retain their own confirmation, scope, structured
argument, timeout, output-path, and provenance checks. Use each command's
`--help` before manual operation.

### Content Discovery Profiles

- `lab-root-tiny` uses the bundled small generic wordlist. It is the approved
  proving profile used by `lab-safe-tiny`.
- `lab-root-light` uses the expected local dirbuster small wordlist and is a
  broader optional root-only profile.

`lab-root-light` is not part of the one-command MVP pipeline. It should be
planned explicitly and, for larger multi-origin runs, executed one immutable
planned step at a time.

### Evidence Pack Export

```bash
bugslyce recon export \
  --input-dir bugslyce-output/example-lab \
  --output bugslyce-output/example-lab-evidence-pack.zip
```

Export reads local files only. It does not run recon or make network requests.
It includes allowlisted reports, status, execution metadata, scope, and
manifest-referenced raw artefacts. Paths outside the input directory and
traversal references are rejected.

## Existing Evidence Import

The original deterministic import command remains available:

```bash
bugslyce run INPUT_DIR --output OUTPUT_DIR
```

BugSlyce can parse selected saved nmap normal output, gobuster output, curl
headers, robots files, HTML, `httpx.jsonl`, URL lists, subdomain lists, and
`recon_manifest.json`. This mode performs local parsing and report generation;
it does not run live recon.

When present, `recon_manifest.json` provides the primary target and artefact
context. Raw evidence remains available for auditability even when repeated
discovery profiles observe the same path. Human-facing status and provenance
summaries distinguish raw discovered-path rows from unique URL strings.

## Current MVP Limitations

- `lab-safe-tiny` is intentionally conservative and is not thorough recon.
- `lab-root-light` is optional and manually planned; it is not part of the
  default project pipeline.
- Resume may refuse evidence when completion or provenance is ambiguous.
- There is no deep crawler or recursive discovery.
- There is no authenticated testing.
- There is no vulnerability confirmation or exploitation workflow.
- There is no brute force, form submission, NSE, or UDP pipeline phase.
- There is no LLM analysis in the default deterministic workflow.
- There is no cloud sync or evidence upload.
- Scope matching uses simple target-like exact host and supported suffix or
  wildcard forms. It does not replace human programme-scope review.
- Status and candidate ranking are deterministic heuristics, not proof that a
  target is safe or vulnerable.
- BugSlyce assists evidence collection and triage; it does not replace manual
  validation or responsible disclosure judgement.

## Local Data Safety

Real targets and evidence should remain in gitignored locations such as
`private_recon/` and `bugslyce-output/`.

Do not commit:

- Real target identifiers or private programme scope.
- Raw recon output, screenshots, Burp files, or HAR files.
- Export ZIPs.
- API keys, credentials, cookies, tokens, or `.env` secrets.

Absence of evidence is not proof of safety.

## Development Sanity Checks

These checks do not start live recon:

```bash
.venv/bin/pytest
.venv/bin/bugslyce doctor
.venv/bin/bugslyce wizard
.venv/bin/bugslyce project run --help
.venv/bin/bugslyce recon --help
```

The test suite mocks live process execution and must not contact targets.

## MVP Release Checkpoint

- Current version: `0.1.0`
- Main MVP pipeline: `lab-safe-tiny`
- Release tag: not yet created
- Package publishing: not performed

Recommended checks before creating a release tag:

1. Run the full test suite.
2. Run `bugslyce doctor` on the intended operator environment.
3. Run one authorised lab smoke with a fresh scaffolded project.
4. Review `report.md`, pipeline metadata, runbook, status, and export contents.
5. Review this README for command and safety accuracy.

See [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) before tagging
`v0.1.0`.

This repository is at an MVP checkpoint. No release has been tagged or
published by this documentation phase.

## License

See `LICENSE` for the project license.
