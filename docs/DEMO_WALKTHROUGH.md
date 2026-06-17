# BugSlyce Demo Walkthrough

## Purpose

This walkthrough demonstrates the intended local-first BugSlyce MVP flow
against a fictional authorised lab-style target.

The example target `10.10.10.10` is a placeholder. Replace it only with a
target you are explicitly authorised to assess. Review the actual programme
or lab scope before running recon; this document does not grant
authorisation.

## Interactive Mode

The easiest MVP path in an interactive terminal is:

```bash
bugslyce
```

The launcher presents:

- **Quick Recon**: maps to the current `lab-safe-tiny` pipeline for a
  fast, bounded first pass with the tiny bundled wordlist.
- **Manual Setup Only**: creates the project and scope template, then prints
  the next safe command preview without running recon.
- **Standard Recon** and **Deep Recon**: planned future modes that are not
  available yet.

The launcher still requires exact `YES` confirmation before creating a
project or running live recon. Recon mode names do not make activity
automatically safe; authorisation and scope still matter. Non-interactive
shells should use the direct commands below.

Interactive mode defaults to `~/bugslyce-output` so project output is
predictable regardless of the current working directory. Direct CLI commands
still use the paths you provide.

## 1. Check Local Readiness

From the BugSlyce repository or an activated editable-install environment:

```bash
bugslyce doctor
```

Doctor checks local prerequisites using Python imports, filesystem access, and
`PATH` lookup:

- Supported Python version.
- Virtual environment status.
- `nmap`, `curl`, and `gobuster` availability.
- Bundled `lab-root-tiny` wordlist access.
- Optional dirbuster small wordlist availability for broader
  `lab-root-light` discovery.

Doctor does not execute those tools, run recon, or contact a target. Missing
optional broader-discovery resources do not prevent the rest of BugSlyce from
working.

## 2. Scaffold A Project

Create a local project directory:

```bash
bugslyce project scaffold \
  --name example-lab \
  --target 10.10.10.10 \
  --projects-dir bugslyce-output
```

This creates:

```text
bugslyce-output/example-lab/
├── bugslyce_project.json
└── scope.md
```

`bugslyce_project.json` records the local project target, scope path, output
directory, and default profiles. `scope.md` is a conservative starter
template, not proof of authorisation.

Open `scope.md`, compare it with the actual authorised rules, and edit it
before running any live command.

## 3. Preview The Next Safe Action

Ask BugSlyce to inspect the local project:

```bash
bugslyce project next \
  --project bugslyce-output/example-lab/bugslyce_project.json
```

For a fresh project, the preview should recommend the approved starting
discovery action. Suggested commands are previews only. `project next` does
not execute recon or make network requests.

## 4. Run The Safe MVP Pipeline

After reviewing scope, run the fixed MVP pipeline with explicit confirmation:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm
```

`lab-safe-tiny` runs the approved bounded chain:

1. Local readiness, project, target, and scope validation.
2. Full TCP discovery using the fixed `lab-tcp-full` profile.
3. Service/version detection on discovered open TCP ports.
4. HTTP metadata collection for discovered HTTP services.
5. Same-origin follow-up for paths already found in HTTP evidence.
6. Non-executing `lab-root-tiny` content planning.
7. Exact approved tiny root content discovery.
8. Dynamic follow-up of eligible content-discovery results.
9. Selective body fetch for eligible HTML/application paths.
10. Recon status generation.
11. Project runbook generation.
12. Evidence-pack export.

The pipeline does not add:

- NSE scripts.
- UDP scans.
- Brute force.
- Exploitation.
- Recursive discovery.
- Form submission.
- Authentication testing.
- Arbitrary commands, flags, URLs, paths, or wordlists.

The pipeline stops after a required failure. Follow-up stages may report a
clean no-op when all current evidence is already processed or excluded by
safety and signal rules.

## 5. Review Outputs

Review the main report:

```bash
less bugslyce-output/example-lab/report.md
```

`report.md` contains the Operator Summary, evidence-backed manual review
leads, low-signal guidance, structured evidence, and raw artefact references.

Review the generated project runbook:

```bash
less bugslyce-output/example-lab/runbook.md
```

`runbook.md` records project paths, scope reminders, current status, suggested
next commands, and export guidance.

Review the pipeline record:

```bash
less bugslyce-output/example-lab/project_pipeline.md
```

`project_pipeline.md` records timing, completed and skipped stages, no-op or
failed stages, reused evidence, and final output paths.

Other important local outputs include:

- `project_state.json`
- `recon_manifest.json`
- `recon_status.md`
- `recon_status.json`
- `project_pipeline.json`
- Raw nmap, curl, HTML, robots, and content-discovery artefacts
- `bugslyce-output/example-lab-evidence-pack.zip`

## 6. Resume Safely If Interrupted

If an authorised lab or VPN session is interrupted, run the same project with
`--resume`:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm \
  --resume
```

Resume revalidates the target, scope, local readiness, manifest artefact
paths, and tiny content-plan provenance. It reuses only clearly completed
phases in a coherent order.

Ambiguous, mixed-target, missing-artefact, or path-escape state is refused
instead of guessed. Existing evidence is not deleted. Existing export ZIPs
are not overwritten; a ZIP is skipped only when prior completed pipeline
metadata verifies it. Recon status and the project runbook are regenerated.

Fresh projects should omit `--resume`.

## 7. Export And Share Carefully

The pipeline creates:

```text
bugslyce-output/example-lab-evidence-pack.zip
```

The archive can contain sensitive target IPs, URLs, service banners, response
headers, HTML, discovered paths, scope text, and execution metadata.

Keep evidence local unless an approved reporting channel requires it. Do not
upload or share an evidence pack publicly without authorisation and manual
review.

For a manual local export from an existing recon directory:

```bash
bugslyce recon export \
  --input-dir bugslyce-output/example-lab \
  --output bugslyce-output/example-lab-evidence-pack.zip
```

Export performs no live recon or network requests.

## 8. What To Do After The Report

The Operator Summary is a triage aid:

- **Review First** lists evidence-backed leads that deserve manual attention.
- **Low-Signal / Avoid Rabbit Holes** identifies dead paths, static assets,
  default content, and likely parser or documentation noise.
- Evidence IDs link summary statements to the detailed report and saved raw
  artefacts.

These are not confirmed vulnerabilities. Priority means manual attention
priority, not exploit severity. Review the surrounding evidence and perform
manual validation before claiming or reporting any finding.

Check the current local recommendation:

```bash
bugslyce project status \
  --project bugslyce-output/example-lab/bugslyce_project.json

bugslyce project next \
  --project bugslyce-output/example-lab/bugslyce_project.json
```

Both commands inspect local files and do not run recon.

## 9. Clean-Up

List local projects:

```bash
bugslyce project list --projects-dir bugslyce-output
```

BugSlyce does not automatically delete projects or evidence. The operator may
archive or remove local project directories and evidence ZIPs manually after
meeting the programme's retention and handling requirements.

Keep real target evidence out of version control. The repository ignores
`bugslyce-output/`, private recon directories, and ZIP archives by default.
