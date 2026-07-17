# Troubleshooting

This guide is organised by symptom. None of these checks require running recon
against a target.

## `bugslyce: command not found`

Activate the virtual environment used for installation:

```bash
source .venv/bin/activate
bugslyce --help
```

Or call the installed script directly:

```bash
./.venv/bin/bugslyce --help
./.venv/bin/bugslyce doctor
```

If the command is still missing, reinstall from the repository root:

```bash
python -m pip install .
```

## Doctor Exit Code `2`

Exit code `2` means the doctor found a blocked requirement. It is not a
traceback or a scan failure.

Read these sections in the doctor output:

- External tools;
- Bundled resources;
- Mode readiness;
- Recommended fixes.

Manual Setup Only may still be ready when Quick, Standard or Deep Recon is
blocked.

## `gobuster` Missing

`gobuster` is required by Quick, Standard and Deep Recon.

On Debian-derived systems:

```bash
sudo apt update
sudo apt install gobuster
```

On other Linux distributions, install the equivalent package or place an
executable `gobuster` on `PATH`. Then rerun:

```bash
bugslyce doctor
```

## Tool Path Found But Blocked

The doctor rejects unsafe or unusable tool paths, including:

- a directory with the tool name;
- a file that is not executable;
- a path that is not safely invokable;
- a `PATH` ordering problem that resolves the wrong file.

Fix the local executable or `PATH`, then run `bugslyce doctor` again. The
doctor does not run the tool while checking it.

## Bundled Resource Blocked

BugSlyce installs its v1 bundled resources inside the Python package:

- `lab-root-tiny`;
- `standard-bounded-core`;
- `deep-bounded-core`.

If one is missing, reinstall BugSlyce:

```bash
python -m pip install .
bugslyce doctor
```

Do not manually substitute arbitrary wordlists into package paths. If you need
a custom workflow, keep it separate from the fixed project pipeline.

## Wrong Project Path On Resume

The resume command expects the project JSON file, not just the directory.

Incorrect:

```bash
bugslyce project run --project bugslyce-output/example-lab --profile lab-safe-tiny --confirm --resume
```

Correct:

```bash
bugslyce project run \
  --project bugslyce-output/example-lab/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm \
  --resume
```

## Scope Mismatch Or Target Rejected

BugSlyce validates that the project target and scope align before live project
pipelines run. If validation fails:

1. Open `bugslyce_project.json` and confirm the target.
2. Open `scope.md` and confirm the in-scope entries.
3. Confirm the engagement rules allow the selected mode.

Do not bypass scope checks to make a command run.

## Output Directory Already Contains Evidence

Fresh project runs refuse existing recon manifests, content-plan directories
or evidence ZIP collisions. This protects prior evidence.

Use `--resume` only when you intend to reuse a compatible project state. For a
clean rerun, create a new project or preserve and move the old output first.

## Partial Deep Resume Refused

This is intentional. Deep offline analysis requires full in-memory response
bodies and shallow-follow-up results that are not persisted completely. If a
Deep network stage was interrupted or ambiguous, BugSlyce fails closed rather
than silently repeating bounded network collection.

Use a clean project for an explicit Deep rerun.

## Completed Resume Skips Everything

A completed resume may report local validation as completed and the reusable
phases as `skipped_existing`. That means BugSlyce verified existing canonical
artefacts and did not rerun live collection.

For a completed Deep project, the no-op resume preserves report, status,
runbook, pipeline metadata and evidence ZIP bytes.

## Doctor Says Manual Setup Ready But Recon Blocked

Manual Setup Only needs core application readiness. Executable recon also needs
`nmap`, `curl`, `gobuster` and the selected mode's bundled resource.

This state is normal on a new machine. You can create and review project scope
before installing recon tools.

## Permission Errors

Check:

- the projects directory is writable;
- the virtual environment is writable by your user;
- external tool files are executable;
- the evidence ZIP destination is not locked by another process.

Avoid running the whole application with `sudo` as a routine fix. Prefer using
a project directory owned by your normal user.

## Empty Or Unexpected Report

Check:

```bash
bugslyce project status --project /path/to/bugslyce_project.json
```

Then inspect:

- `project_pipeline.md` for failed, pending, no-op or skipped phases;
- `recon_status.md` for detected evidence phases;
- raw artefacts referenced by `recon_manifest.json`;
- `scope.md` and the project target.

A no-op phase can be expected when no eligible follow-up work exists.

## Evidence ZIP Handling

The evidence pack is normally written adjacent to the project output directory.
It may contain sensitive target evidence and is not encrypted or redacted.

Review the ZIP before sharing it. Do not publish target evidence, credentials,
cookies, tokens or private programme data.

## Getting Diagnostic Information

Safe local commands:

```bash
bugslyce doctor
bugslyce --help
bugslyce project status --project /path/to/bugslyce_project.json
bugslyce project next --project /path/to/bugslyce_project.json
```

When asking for help, share command output and metadata only after removing
target evidence and private scope details.
