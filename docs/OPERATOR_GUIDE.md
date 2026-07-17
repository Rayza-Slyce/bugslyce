# Operator Guide

This guide follows the normal BugSlyce workflow from authorisation and project
creation through recon, review, resume and evidence handling.

## 1. Authorisation and Scope

Use BugSlyce only for systems you own or are explicitly authorised to assess.
The generated `scope.md` file is a local template and safety check; it is not
authorisation.

Before typing `YES` to run recon, verify:

- the target is the intended engagement target;
- `scope.md` matches the allowed programme or lab scope;
- the selected mode fits the engagement rules;
- programme rules do not prohibit any planned activity.

BugSlyce safety controls do not replace external rules.

## 2. Interactive Launcher

Start the launcher with:

```bash
bugslyce
```

The main menu is:

```text
1. Start a new project
2. Resume an existing project
3. List projects
4. Run doctor/readiness check
5. Exit
```

For a new project, the launcher prompts for:

- project name;
- target hostname or IP address;
- projects directory;
- engagement context;
- recon mode;
- exact `YES` confirmation before live recon;
- whether to run the pipeline immediately.

The launcher prints command previews for direct CLI use. It does not treat a
mode choice as authorisation.

## 3. Operator Modes

### Manual Setup Only

Manual Setup Only creates local project metadata and `scope.md`. It performs no
recon and remains usable when live-recon dependencies are missing, provided core
application readiness passes.

Use it when you want to review scope before any collection.

### Quick Recon

Quick Recon uses profile `lab-safe-tiny`. It performs bounded first-pass
collection and uses the bundled `lab-root-tiny` content resource. It is useful
for initial lab or CTF triage where the operator wants local evidence and
review leads quickly.

### Standard Recon

Standard Recon uses profile `standard-bounded`. It runs the bounded collection
workflow and adds offline interpretation of already collected evidence,
including manual review leads and investigation guidance. It uses the bundled
`standard-bounded-core` resource.

Standard interpretation does not turn leads into confirmed findings.

### Deep Recon

Deep Recon uses profile `deep-bounded`. It adds bounded same-origin Deep
collection, shallow follow-up and offline orchestration over existing Deep
review stages. It uses the bundled `deep-bounded-core` resource and remains
manual-review oriented.

Deep Recon:

- keeps executable requests same-origin and scope-conscious;
- retains external absolute references as offline evidence where supported
  rather than fetching them;
- does not submit forms;
- does not execute JavaScript;
- does not replay, guess or mutate parameter values;
- does not perform recursive or unrestricted crawling.

Deep projects retain these fixed Deep artefacts:

```text
deep_source_route_collection.md
deep_source_route_collection.json
deep_recon_review.md
deep_recon_runbook.md
deep_recon_orchestration.json
```

## 4. Choosing a Mode

| Mode | Best use | Collection scope | Interpretation depth | Bundled resource | Resume implication |
| --- | --- | --- | --- | --- | --- |
| Manual Setup Only | Scope review before recon | none | none | none | no live phase to resume |
| Quick Recon | Fast first pass | bounded base workflow | core report/status/runbook | `lab-root-tiny` | completed runs can be reused |
| Standard Recon | Evidence review after bounded collection | bounded base workflow | Standard offline interpretation | `standard-bounded-core` | completed runs can be reused |
| Deep Recon | Same-origin detailed manual review | bounded base plus Deep collection | Deep offline orchestration | `deep-bounded-core` | completed runs reuse safely; partial Deep state fails closed |

Deep is not always the right choice. Use the narrowest mode that fits the
engagement and the question you need to answer.

## 5. Creating a Project

Interactive creation:

```bash
bugslyce
```

Direct CLI creation:

```bash
bugslyce project scaffold \
  --name example-lab \
  --target target.example.test \
  --projects-dir bugslyce-output \
  --engagement-context ctf_lab
```

The direct command creates:

```text
bugslyce-output/example-lab/bugslyce_project.json
bugslyce-output/example-lab/scope.md
```

Use documentation or lab targets in examples. Do not run live recon against a
real system unless you are authorised.

## 6. Scope Review

Open and review:

```text
scope.md
```

The project target must match the intended scope. Current project workflows do
not add UDP, NSE scripts, brute force, exploitation, recursive discovery, form
submission or authentication testing. These exclusions do not override stricter
programme rules.

## 7. Running Recon

Run the doctor first:

```bash
bugslyce doctor
```

Then run a confirmed project pipeline:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm
```

Supported project profiles:

```text
lab-safe-tiny
standard-bounded
deep-bounded
```

The pipeline validates readiness, target and scope before live collection. If a
required tool or bundled resource is missing for the selected profile, it fails
before live phases start.

## 8. Progress and Completion

Pipeline statuses include:

| Status | Meaning |
| --- | --- |
| `completed` | The step completed successfully. |
| `skipped_existing` | Verified existing output was reused. |
| `noop` | The step had no eligible work and this was expected. |
| `failed` | The step failed and later phases were not run. |
| `pending` | The step did not run. |

A no-op is not necessarily an error. For example, a follow-up step may have no
eligible new paths.

## 9. Resume Behaviour

The launcher and CLI expect the project JSON path, not just the project directory:

```text
bugslyce-output/example-lab/bugslyce_project.json
```

CLI resume pattern:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile deep-bounded \
  --confirm \
  --resume
```

Completed Quick, Standard and Deep runs may safely reuse verified existing
evidence. A completed Deep resume is a verified no-op apart from local
validation; it preserves canonical report, status, runbook, pipeline metadata
and evidence-pack files.

Partial Deep state fails closed. The full in-memory response bodies and
shallow-follow-up result required for complete offline Deep analysis are not
persisted, so BugSlyce will not silently repeat Deep network stages during
resume. Start a clean Deep project for an explicit rerun after an unsafe
partial state.

Interactive resume preview is read-only. If you decline the resume prompt, no
canonical project artefacts are rewritten.

## 10. Generated Files

| File | Purpose |
| --- | --- |
| `bugslyce_project.json` | Project metadata and local paths. |
| `scope.md` | Operator-reviewed scope template. |
| `recon_manifest.json` | Evidence manifest for collected local artefacts. |
| `report.md` | Human-readable evidence report and manual review leads. |
| `recon_status.md` | Current progress and safe next-step summary. |
| `recon_status.json` | Machine-readable status. |
| `runbook.md` | Local operator guide and command previews. |
| `project_pipeline.md` | Human-readable pipeline history. |
| `project_pipeline.json` | Machine-readable pipeline history. |
| content-plan directories | Deterministic content-discovery plans and execution metadata. |
| raw evidence files | nmap, HTTP, path, content and body artefacts supporting review. |
| evidence-pack ZIP | Portable package of selected local evidence and summaries. |

`report.md` helps with review. `recon_status.md` explains progress.
`runbook.md` helps navigate safe next actions. Pipeline metadata records how
the outputs were created. Raw evidence remains the audit trail.

## 11. Evidence Packs

Project pipelines generate an adjacent evidence ZIP after successful output
steps. The pack contains a manifest, safety notes, reports, status, scope,
pipeline metadata and selected raw evidence.

Evidence packs may contain sensitive target data such as IP addresses, URLs,
headers, service banners, HTML and discovered paths. Store them carefully and
do not share them publicly without review. The ZIP is not encrypted and is not
redacted.

An evidence pack is not encrypted and is not redacted. It is not proof that a
vulnerability exists. Manual validation is required before reporting any issue.

## 12. Reading Results

Read results from evidence to conclusion:

1. Start with `report.md` and its Operator Summary.
2. Review Manual Review Leads before lower-priority context.
3. Compare any lead with raw artefacts.
4. Use `runbook.md` and `recon_status.md` as navigation aids.
5. Treat inferred routes, forms and parameter names as static review context,
   not confirmed vulnerabilities.

Absence of evidence is not proof of safety.

## 13. Direct CLI Reference

Common operator commands:

```bash
bugslyce --help
bugslyce doctor
bugslyce project scaffold --help
bugslyce project run --help
bugslyce project status --help
bugslyce project next --help
bugslyce recon --help
```

Lower-level `bugslyce recon ...` commands are available for reviewed manual
operation and diagnostics. Read each command's `--help` before use.

## 14. Safe Shutdown and Reruns

Interrupting a live pipeline may leave partial local output. Preserve evidence
before deleting a project. Use a new project directory for a clean rerun rather
than casually overwriting completed evidence.

Do not assume partial Deep output is resumable. Completed Deep projects can be
verified and reused; interrupted Deep network stages are refused for safety.
