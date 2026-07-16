# Release Checklist

This checklist prepares BugSlyce `1.0.0rc1` for release-candidate acceptance.
It does not create a Git tag, publish a package or upload artefacts.

Current decision: **NO-GO pending Kali acceptance**.

## A. Source Integrity

- [ ] Working tree is clean.
- [ ] Expected base commit is recorded.
- [ ] `pyproject.toml`, `bugslyce.__version__` and `bugslyce --version` all
      report `1.0.0rc1`.
- [ ] No stale current-version references remain.
- [ ] No generated target evidence is tracked.
- [ ] No secrets, `.env` files, provider configuration or private project
      directories are tracked.
- [ ] No temporary build output is committed.

## B. Static Safety

- [ ] No `shell=True`.
- [ ] No `os.system`.
- [ ] No `subprocess.Popen`.
- [ ] No unsafe deserialisation such as `pickle.loads` or `yaml.load`.
- [ ] No offensive-tool integration is executable.
- [ ] No brute force, exploitation, form submission, authentication testing,
      browser automation or JavaScript execution is introduced.
- [ ] No unexpected HTTP methods are introduced.
- [ ] Quick remains `lab-safe-tiny`.
- [ ] Standard remains `standard-bounded`.
- [ ] Deep remains `deep-bounded`.
- [ ] Request counts, response-size caps, redirect limits and Deep bounds are
      unchanged.

## C. Test Matrix

Run from the repository root:

- [ ] Documentation tests pass.
- [ ] Full suite passes.

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

- [ ] Build a local wheel or source distribution where local tooling permits.
- [ ] Create a clean temporary virtual environment.
- [ ] Install only the built local artefact, without dependency downloads.
- [ ] Run `python -m pip check`.
- [ ] Import `bugslyce`.
- [ ] Verify `bugslyce --version` prints `bugslyce 1.0.0rc1`.
- [ ] Run `bugslyce doctor`.
- [ ] Confirm bundled wordlists are present and non-empty:
      `lab-root-tiny.txt` and `standard-bounded-core.txt`.
- [ ] Confirm documentation files are present in the source repository.
- [ ] Confirm no unrelated files are installed as package data.

## E. Kali Acceptance

- [ ] Clean source pull or clean clone.
- [ ] Fresh virtual environment.
- [ ] Local source installation.
- [ ] `bugslyce doctor` exits `0`.
- [ ] `bugslyce --help` and `bugslyce --version` work.
- [ ] Manual Setup Only smoke passes.
- [ ] Authorised Quick smoke passes with `lab-safe-tiny`.
- [ ] Authorised Standard smoke passes with `standard-bounded`.
- [ ] Authorised Deep smoke passes with `deep-bounded`.
- [ ] Completed Deep resume is a verified no-op.
- [ ] Canonical Deep artefact hashes remain stable after completed resume.
- [ ] Evidence ZIP contents are reviewed.
- [ ] Working tree remains clean after acceptance.

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

### Pending Kali Acceptance

- Fresh clean installation.
- Doctor exit `0`.
- Manual Setup Only smoke.
- Quick Recon smoke.
- Standard Recon smoke.
- Deep Recon smoke.
- Completed Deep no-op and hash stability.
- Evidence ZIP content review.
