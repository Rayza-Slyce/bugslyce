# Release Checklist

This checklist prepares BugSlyce `1.0.0rc1` for release-candidate acceptance.
It does not create a Git tag, publish a package or upload artefacts.

Current decision: **GO for v1.0.0rc1 tagging**.

All local and Kali release-candidate blockers have passed for accepted source
commit `e4c8fba`. The final documentation-only acceptance-record commit will
follow that tested source commit so the public record can be tagged
truthfully. The Git tag has not yet been created, nothing has been published,
and this remains release candidate `1.0.0rc1`, not final `1.0.0`.

## A. Source Integrity

- [x] Working tree is clean.
- [x] Expected base commit is recorded.
- [x] `pyproject.toml`, `bugslyce.__version__` and `bugslyce --version` all
      report `1.0.0rc1`.
- [x] No stale current-version references remain.
- [x] No generated target evidence is tracked.
- [x] No secrets, `.env` files, provider configuration or private project
      directories are tracked.
- [x] No temporary build output is committed.

## B. Static Safety

- [x] No `shell=True`.
- [x] No `os.system`.
- [x] No `subprocess.Popen`.
- [x] No unsafe deserialisation such as `pickle.loads` or `yaml.load`.
- [x] No offensive-tool integration is executable.
- [x] No brute force, exploitation, form submission, authentication testing,
      browser automation or JavaScript execution is introduced.
- [x] No unexpected HTTP methods are introduced.
- [x] Quick remains `lab-safe-tiny`.
- [x] Standard remains `standard-bounded`.
- [x] Deep remains `deep-bounded`.
- [x] Request counts, response-size caps, redirect limits and Deep bounds are
      unchanged.

## C. Test Matrix

Run from the repository root:

- [x] Documentation tests pass.
- [x] Full suite passes.

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
"$PYTHON" -m compileall -q bugslyce
git diff --check
```

## D. Packaging

- [x] Build a local wheel or source distribution where local tooling permits.
- [x] Create a clean temporary virtual environment.
- [x] Install only the built local artefact, without dependency downloads.
- [x] Run `python -m pip check`.
- [x] Import `bugslyce`.
- [x] Verify `bugslyce --version` prints `bugslyce 1.0.0rc1`.
- [x] Run `bugslyce doctor`.
- [x] Confirm bundled wordlists are present and non-empty:
      `lab-root-tiny.txt` and `standard-bounded-core.txt`.
- [x] Confirm documentation files are present in the source repository.
- [x] Confirm no unrelated files are installed as package data.

## E. Kali Acceptance

- [x] Clean source pull or clean clone.
- [x] Fresh virtual environment.
- [x] Local source installation.
- [x] `bugslyce doctor` exits `0`.
- [x] `bugslyce --help` and `bugslyce --version` work.
- [x] Manual Setup Only smoke passes.
- [x] Authorised Quick smoke passes with `lab-safe-tiny`.
- [x] Authorised Standard smoke passes with `standard-bounded`.
- [x] Authorised Deep smoke passes with `deep-bounded`.
- [x] Completed Deep resume is a verified no-op.
- [x] Canonical Deep artefact hashes remain stable after completed resume.
- [x] Evidence ZIP contents are reviewed.
- [x] Working tree remains clean after acceptance.

## F. Release Decision

Allowed outcomes:

- **GO**: all local checks and Kali acceptance pass.
- **GO WITH DOCUMENTED LIMITATION**: all release blockers pass, with an
  explicitly documented non-blocking limitation.
- **NO-GO**: any release blocker remains.

Release blockers include:

- Version mismatch.
- Test-suite failure.
- Missing required bundled resources.
- Doctor failure on the Kali acceptance host after dependencies are installed.
- Live recon outside documented scope or origin policy.
- Shell execution or arbitrary command-flag injection.
- Evidence-pack path escape or unrelated local-data inclusion.
- Partial Deep resume being treated as safe.

## Current Status

### Locally Completed

- Version alignment is expected to be validated by tests.
- Source audit and static safety checks are expected to run locally.
- Unit, integration and documentation checks are expected to run locally.
- Source package-data configuration is expected to be validated locally.

### Kali Acceptance Completed

- Fresh clean installation passed.
- Doctor exit `0` passed.
- Manual Setup Only smoke passed.
- Quick Recon smoke passed.
- Standard Recon smoke passed.
- Deep Recon smoke passed.
- Completed Deep no-op and hash stability passed.
- Evidence ZIP content review passed.

### Still Not Performed

- Git tag creation.
- Package publication.
- GitHub release creation.
- Final `1.0.0` release.
