# Release Acceptance

This guide is the current acceptance procedure for BugSlyce `1.0.0rc2`. The
completed public record below documents the earlier `1.0.0rc1` acceptance.

Do not run live recon against any system unless you own it or are explicitly
authorised to assess it. A generated `scope.md` is a local safety aid, not
authorisation.

## Completed Public Release Record

| Field | Result |
| --- | --- |
| Acceptance date | 2026-07-16 |
| Accepted source commit | `e4c8fba` |
| Package version | `1.0.0rc1` |
| Mint validation | passed |
| Kali clean installation | passed |
| Doctor readiness | passed |
| Manual Setup Only | passed |
| Quick | passed |
| Standard | passed |
| Deep | passed |
| Completed Deep no-op resume | passed |
| Canonical Deep hash stability | passed |
| Evidence-pack review | passed |
| Repository cleanliness | passed |
| Target description | authorised private lab/CTF target, identifier withheld |
| Release outcome | GO for tagging `v1.0.0rc1` |

The `v1.0.0rc1` tag was subsequently created. No package was published, and
`1.0.0rc1` was not final `1.0.0`.

## Part 1: Local Package Acceptance

Run these checks from a clean source checkout without contacting a target. A
pipx implementation may bootstrap its own temporary packaging environment;
record that separately from BugSlyce target contact.

### 1. Checkout Verification

```bash
git status --short
git log -1 --oneline
```

The working tree should be clean before release acceptance starts.

### 2. Version Consistency

```bash
python - <<'PY'
import bugslyce
print(bugslyce.__version__)
PY
python -m bugslyce.cli --version
```

Both commands must report `1.0.0rc2`; the CLI form must print
`bugslyce 1.0.0rc2`.

### 3. Test Groups

```bash
PYTHON=python3
[ -x .venv/bin/python ] && PYTHON=.venv/bin/python
[ -x venv/bin/python ] && PYTHON=venv/bin/python

"$PYTHON" -m pytest -q tests/test_release_candidate.py
"$PYTHON" -m pytest -q tests/test_release_safety.py
"$PYTHON" -m pytest -q \
  tests/test_cli.py \
  tests/test_interactive.py \
  tests/test_doctor.py \
  tests/test_project_pipeline.py \
  tests/test_project_session.py
"$PYTHON" -m pytest -q \
  tests/test_deep_collection_policy.py \
  tests/test_deep_collection_request_plan.py \
  tests/test_deep_source_route_collector.py \
  tests/test_deep_http_fetcher.py \
  tests/test_deep_shallow_route_followup.py
"$PYTHON" -m pytest -q \
  tests/test_documentation.py \
  tests/test_readme.py \
  tests/test_recon_modes_doc.py
"$PYTHON" -m pytest -q
```

### 4. Static Safety Searches

```bash
grep -RInE \
  'shell=True|os\.system|subprocess\.Popen|eval\(|exec\(|pickle\.loads|yaml\.load' \
  bugslyce tests || true

grep -RInE \
  'hydra|sqlmap|masscan|nuclei|credential stuffing|password spraying|form submission|JavaScript execution' \
  bugslyce README.md docs tests || true
```

Review matches. Deny-list constants, safety prose and tests are not executable
offensive integrations.

### 5. Package Build Attempt

Use a temporary directory outside the repository:

```bash
TMP_BUILD=$(mktemp -d)
python -m build --no-isolation --outdir "$TMP_BUILD"
```

If `build` is unavailable, try a local wheel build:

```bash
TMP_BUILD=$(mktemp -d)
python -m pip wheel --no-deps --no-build-isolation --wheel-dir "$TMP_BUILD" .
```

Do not install build requirements from the network during acceptance.

### 6. Temporary Clean Installation

When a local artefact is produced:

```bash
TMP_VENV=$(mktemp -d)
python -m venv "$TMP_VENV/venv"
"$TMP_VENV/venv/bin/python" -m pip install --no-index --find-links "$TMP_BUILD" bugslyce
"$TMP_VENV/venv/bin/python" -m pip check
"$TMP_VENV/venv/bin/bugslyce" --version
"$TMP_VENV/venv/bin/bugslyce" --help
"$TMP_VENV/venv/bin/bugslyce" doctor
```

Doctor may exit `2` on a host missing `nmap`, `curl` or `gobuster`; that is a
readiness result, not a package import failure.

### 7. Package Resource Verification

Verify the installed package has all bundled wordlists:

```bash
"$TMP_VENV/venv/bin/python" - <<'PY'
import importlib.resources

base = importlib.resources.files("bugslyce").joinpath("wordlists")
for name in (
    "lab-root-tiny.txt",
    "standard-auth-core.txt",
    "standard-bounded-core.txt",
    "deep-bounded-core.txt",
):
    path = base.joinpath(name)
    print(name, path.is_file(), len(path.read_text(encoding="utf-8")))
PY
```

All four files must exist and be non-empty.

### 8. Exact-Wheel Temporary pipx Acceptance

Mint and Kali must install the same exact local wheel. Record its filename and
SHA-256 before either installation, then verify exact-wheel SHA-256 equality between Mint and Kali.

```bash
WHEEL=/absolute/path/to/bugslyce-1.0.0rc2-py3-none-any.whl
sha256sum "$WHEEL"
PIPX_HOME=$(mktemp -d)
PIPX_BIN_DIR=$(mktemp -d)
export PIPX_HOME PIPX_BIN_DIR
pipx install --pip-args="--no-deps" "$WHEEL"
"$PIPX_BIN_DIR/bugslyce" --version
"$PIPX_BIN_DIR/bugslyce" --help
```

Verify the installed command and module path are outside the source checkout,
and record the installed distribution version. Use the temporary pipx
environment's Python to repeat the four-file resource check above.

Run `bugslyce doctor`. Exit `0` is expected on a fully ready host. Exit `2` is acceptable only when the output clearly attributes it to missing external tooling and confirms the package, core components and bundled resources are otherwise ready.

pipx bootstrap network activity, if any, is packaging bootstrap only. Record
it separately from BugSlyce target contact. The BugSlyce package itself must be
the exact verified local wheel and installed with `--no-deps`; no BugSlyce
target contact is permitted during this acceptance.

### 9. CLI and Doctor Verification

```bash
bugslyce --help
bugslyce --version
bugslyce project run --help
bugslyce doctor
```

Expected version: `bugslyce 1.0.0rc2`.

### 10. Markdown Link Validation

```bash
python -m pytest -q tests/test_documentation.py tests/test_readme.py
```

### 11. Clean Tree and Diff Checks

```bash
git diff --check
git status --short
```

## Part 2: Authorised Kali Smoke Acceptance

Set private local variables. Do not use a random public target.

```bash
export BUGSLYCE_SMOKE_TARGET='AUTHORISED_TARGET'
export BUGSLYCE_SMOKE_ROOT="$HOME/bugslyce-rc-smoke"
```

The target must be owned by the operator or explicitly authorised. Review each
generated `scope.md` before typing `YES`.

### Manual Setup Only

Create a project through the launcher or CLI and choose Manual Setup Only.
Verify:

- `bugslyce_project.json` exists.
- `scope.md` exists and was reviewed.
- no `recon_manifest.json` exists.
- no live-tool outputs exist.
- no evidence ZIP is falsely created.

### Quick

Run an authorised project with profile `lab-safe-tiny`.
Verify:

- core project outputs are present;
- `recon_manifest.json` is present;
- `report.md`, `recon_status.md`, `runbook.md` and pipeline metadata are
  present;
- the adjacent evidence ZIP exists.

### Standard

Run an authorised project with profile `standard-bounded`.
Verify:

- bounded collection completed;
- Standard offline interpretation sections are present;
- no Deep-only artefacts are present.

### Deep

Run an authorised project with profile `deep-bounded`.
Verify the five retained Deep artefacts:

- `deep_source_route_collection.md`
- `deep_source_route_collection.json`
- `deep_recon_review.md`
- `deep_recon_runbook.md`
- `deep_recon_orchestration.json`

### Completed Deep Resume

Hash canonical artefacts before resume:

```bash
cd "$BUGSLYCE_SMOKE_ROOT/deep-project"
sha256sum \
  bugslyce_project.json \
  scope.md \
  report.md \
  recon_status.md \
  recon_status.json \
  runbook.md \
  project_pipeline.md \
  project_pipeline.json \
  deep_source_route_collection.md \
  deep_source_route_collection.json \
  deep_recon_review.md \
  deep_recon_runbook.md \
  deep_recon_orchestration.json \
  > before.sha256
```

Run completed resume with the documented command for the project file. Then
hash the same files again:

```bash
sha256sum \
  bugslyce_project.json \
  scope.md \
  report.md \
  recon_status.md \
  recon_status.json \
  runbook.md \
  project_pipeline.md \
  project_pipeline.json \
  deep_source_route_collection.md \
  deep_source_route_collection.json \
  deep_recon_review.md \
  deep_recon_runbook.md \
  deep_recon_orchestration.json \
  > after.sha256
diff -u before.sha256 after.sha256
```

Acceptance requires no live recon rerun, a verified no-op resume and identical
canonical artefact hashes.

Partial Deep state must fail closed. Do not repeat uncertain bounded Deep
network collection in the same project; use a clean project for an explicit
rerun.

### Evidence Pack

Verify:

- the ZIP exists in the documented adjacent location;
- archive entries contain no absolute paths;
- archive entries contain no `..` traversal paths;
- only intended project material is present;
- Deep artefacts are present for Deep projects;
- no `.env`, SSH key or unrelated neighbouring file appears;
- the ZIP is not treated as encrypted or redacted.

### Acceptance Record

Keep private target details out of commits and public tickets.

| Date | Commit | Package version | Kali version | Python version | Private target identifier | Mode | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  | `1.0.0rc2` |  |  |  |  |  |  |
