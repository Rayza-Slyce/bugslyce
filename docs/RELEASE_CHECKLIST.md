# Release Checklist

This checklist prepares BugSlyce `1.0.0rc2` for release-candidate acceptance.
It does not create a Git tag, publish a package or upload artefacts.

Current decision: **rc2 package build and exact-wheel temporary pipx acceptance completed on Mint and Kali; final v1 release remains pending**.

The earlier `1.0.0rc1` acceptance covered source commit `e4c8fba`, and that
release candidate was subsequently tagged as `v1.0.0rc1`. No package was
published. The current checkout remains pre-release `1.0.0rc2`, not final
`1.0.0`.

## A. Source Integrity

- [x] Working tree is clean.
- [x] Expected base commit is recorded.
- [x] `pyproject.toml`, `bugslyce.__version__` and `bugslyce --version` all
      report `1.0.0rc2`.
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
- [x] Verify `bugslyce --version` prints `bugslyce 1.0.0rc2`.
- [x] Run `bugslyce doctor`.
- [x] Confirm bundled wordlists are present and non-empty:
      `lab-root-tiny.txt`, `standard-auth-core.txt`,
      `standard-bounded-core.txt` and `deep-bounded-core.txt`.
- [x] Confirm documentation files are present in the source repository.
- [x] Confirm no unrelated files are installed as package data.

## E. Historical rc1 Acceptance

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

### Current rc2 completed checks

- rc2 package/version alignment, local build, wheel and source-distribution
  inspection, source-distribution wheel rebuild and temporary-venv acceptance
  completed on Mint.
- Exact accepted wheel: `bugslyce-1.0.0rc2-py3-none-any.whl`.
- Exact accepted wheel SHA-256:
  `24ecc358ed6b4e3db9213e7142637fade953b30744fb11fa613c050f1ae6a441`.
- Mint temporary pipx acceptance: completed with pipx 1.4.3. The installed
  command and module resolved inside the temporary pipx environment; help and
  launcher exit were `0`. Doctor exit `2` was caused by missing `gobuster`, an
  external-tool readiness result; package, core components and all four
  bundled wordlists were ready.
- Kali temporary pipx acceptance: completed with pipx 1.8.0 and Python 3.13.11.
  The same exact wheel SHA-256 was installed; command and module
  resolved inside the temporary pipx environment; help, launcher and doctor
  exits were `0`; all four bundled wordlists were ready.
- Mint's shared-pip bootstrap upgrade failed under `PIP_NO_INDEX=1`, but pipx
  continued and installed the exact local wheel successfully. Kali permitted
  network access only for pipx's temporary packaging bootstrap. Neither
  acceptance involved BugSlyce target contact; BugSlyce used the verified local
  wheel with dependencies disabled.

### Historical rc1 acceptance

- Fresh clean installation passed.
- Doctor exit `0` passed.
- Manual Setup Only smoke passed.
- Quick Recon smoke passed.
- Standard Recon smoke passed.
- Deep Recon smoke passed.
- Completed Deep no-op and hash stability passed.
- Evidence ZIP content review passed.

### Still pending for rc2

- Commit and push the rc2 release-hardening changes.
- Final clean build from the committed rc2 release state.
- Final `1.0.0` release decision and version bump.
- Final release tag.
- GitHub release.
- PyPI publication.
