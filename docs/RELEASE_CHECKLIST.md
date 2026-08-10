# Release Checklist

This checklist tracks BugSlyce `1.2.1` safety-patch release acceptance.
It does not create a Git tag, publish a package or upload artefacts.

Current decision: **The `1.2.1` source/runtime safety correction is accepted;
release packaging and promotion checks are still required.**

Accepted safety-fix commit:
`6b3e0d3d34b2f19c0a7f088a0ba1658644011a05`.

### Completed `1.2.1` source/runtime acceptance

- [x] Special-purpose and multicast resolved IPv4 peers require explicit
      IPv4/CIDR programme authority.
- [x] Strict Gobuster pins the programme-approved IPv4 peer and preserves the
      logical HTTP Host authority.
- [x] Controlled local Kali execution reproduced the original DNS hand-off
      defect and subsequently confirmed the corrected peer binding.
- [x] Focused safety-critical validation passed: `875 passed`.
- [x] Full Mint and Kali source validation passed: `3,274 passed`.
- [x] `compileall` and `git diff --check` passed.
- [x] Safety-fix commit was pushed and independently verified on Kali.

### Still required for `1.2.1`

- [x] Align package/runtime/release-facing metadata to `1.2.1`.
- [x] Pass focused release/documentation validation and the full suite.
- [ ] Build the final `1.2.1` wheel and source distribution from reviewed
      committed source.
- [ ] Verify package metadata, archive safety, RECORD and bundled resources.
- [ ] Verify the exact same wheel through isolated Mint and Kali installation.
- [ ] Create and push annotated tag `v1.2.1`.
- [ ] Publish and verify PyPI `1.2.1` and GitHub `v1.2.1`.

## Historical `1.2.0` release acceptance

Historical decision: **BugSlyce `1.2.0` release acceptance is complete.**

Historical source baseline before `1.2.0` release-metadata preparation:
`0372bd9ff616d0ce604408a1ddc5c5a516ae874b`.

### Completed source/runtime acceptance

- [x] Standard bug-bounty project flow passed under strict engagement policy
      and default-deny programme scope.
- [x] Deep bug-bounty project flow passed under the same strict runtime.
- [x] Interactive policy -> programme scope -> Standard/Deep run hand-off passed.
- [x] Prohibited TCP discovery and Nmap service/version stages remained
      policy-driven no-ops.
- [x] Deep metadata delegation completed with no uncollected delegated metadata
      requests in final acceptance.
- [x] Out-of-scope external destinations were refused by programme-scope
      enforcement.
- [x] Sitemap metadata collection and evidence-pack integrity were verified.
- [x] Pre-release runtime baseline full suite passed: `3,178 passed`.

### Still required for final `1.2.0`

- [x] Focused release/documentation validation passed after candidate-version
      alignment: `255 passed`.
- [x] Full suite passed after candidate-version alignment: `3,178 passed`;
      compileall and `git diff --check` also passed.
- [x] Untagged `1.2.0rc1` wheel and source distribution built and inspected.
- [x] `1.2.0rc1` wheel/sdist metadata, members, RECORD and path safety passed.
- [x] `1.2.0rc1` isolated Mint installation passed.
- [x] The exact same `1.2.0rc1` wheel passed temporary pipx acceptance on Mint
      and Kali.
- [x] Packaged `1.2.0rc1` Deep authorised-lab acceptance passed.
- [x] Final `1.2.0` wheel and source distribution built from the reviewed state.
- [x] Final wheel/sdist metadata and archive safety checks passed.
- [x] Final exact wheel passed isolated/package verification on Mint and Kali.
- [x] Final release commit and annotated `v1.2.0` tag were created and pushed.
- [x] PyPI `1.2.0` release and GitHub `v1.2.0` release were verified publicly.

### 1.2.0 release record

Release source commit:
`11bc5207a0dcccad2da898c14d5f984738adfeff`

Annotated release tag:
`v1.2.0`

Final wheel:

`bugslyce-1.2.0-py3-none-any.whl`

SHA-256:

`33d0c36bccff80959db5fce74ddcf373e16c75b18521ef5d957718050ffb2f2e`

Final source distribution:

`bugslyce-1.2.0.tar.gz`

SHA-256:

`c30bf8fec28818c3d5ba125d742bcc28dc2052ba3c0312f76895661c89996d45`

The untagged `1.2.0rc1` candidate was used for packaged cross-host and
authorised-lab acceptance before final promotion. No public rc1 tag or package
release was required.

The completed `1.1.0`, `1.0.0`, `1.0.0rc2` and `1.0.0rc1` records below are
historical evidence and must not be rewritten as current `1.2.0` results.

## Historical 1.1.0 - A. Source Integrity

- [x] Working tree is clean.
- [x] Expected base commit is recorded.
- [x] `pyproject.toml`, `bugslyce.__version__` and `bugslyce --version` all
      report `1.1.0`.
- [x] No stale current-version references remain.
- [x] No raw or private evidence pack is tracked.
- [x] No generated HTML evidence report is tracked.
- [x] No unapproved target artefact is tracked.
- [x] No private credentials, secrets or private engagement material is tracked.
- [x] The sole intentional lab-derived documentation artefact added for 1.1.0
      is `docs/images/bugslyce-html-evidence-report.png`, an approved
      authorised-lab screenshot with SHA-256
      `6ca7366d4faaedba817248727107693e12b3917555664bf86594022f1673957c`.
- [x] No temporary build output is committed.

## Historical 1.1.0 - B. Static Safety

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

## Historical 1.1.0 - C. Test Matrix

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

## Historical 1.1.0 - D. Packaging

- [x] Build a local wheel or source distribution where local tooling permits.
- [x] Create a clean temporary virtual environment.
- [x] Install only the built local artefact, without dependency downloads.
- [x] Run `python -m pip check`.
- [x] Import `bugslyce`.
- [x] Verify `bugslyce --version` prints `bugslyce 1.1.0`.
- [x] Run `bugslyce doctor`.
- [x] Confirm bundled wordlists are present and non-empty:
      `lab-root-tiny.txt`, `standard-auth-core.txt`,
      `standard-bounded-core.txt` and `deep-bounded-core.txt`.
- [x] Confirm documentation files are present in the source repository.
- [x] Confirm no unrelated files are installed as package data.

## Historical 1.1.0 - E. Earlier rc1 Acceptance

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

## Historical 1.1.0 - F. Release Decision

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

## Historical Release Status

### 1.1.0 release record

- Accepted release commit: `a7f37b3235c27fad0d4f2f9ed2ccf29f4f86380c`.
- Annotated tag: `v1.1.0`, created and pushed to GitHub.
- GitHub release published: <https://github.com/Rayza-Slyce/bugslyce/releases/tag/v1.1.0>.
  It contains `bugslyce-1.1.0-py3-none-any.whl`, `bugslyce-1.1.0.tar.gz` and
  `SHA256SUMS`.
- PyPI publication: completed.
- Published wheel: `bugslyce-1.1.0-py3-none-any.whl` (SHA-256
  `8765dcfeeb9fa9f43de154f54d13049c46d7fa7c241cb8e9b759da620a1c6a87`).
- Published source distribution: `bugslyce-1.1.0.tar.gz` (SHA-256
  `bec36c61f618f5ed2a85e1b38b01bc515965495efc5d91354eb3bbe04849c477`).
- Kali pipx upgraded BugSlyce from `1.0.0` to `1.1.0` successfully.
  Post-publication verification used the environment
  `/home/rayza/.local/share/pipx/venvs/bugslyce`; installed package metadata
  reports `1.1.0`, no runtime dependencies are installed, and the published
  package imports from pipx site-packages.
- `v1.1.0` remains permanently attached to release commit
  `a7f37b3235c27fad0d4f2f9ed2ccf29f4f86380c`. Any later checklist-record
  commit belongs to `main` and is not part of the tagged release artefacts.
- Pre-release development baseline: `ed1f6f7becf0014ba41d64d2f4dc1799e4353724`.
- Current version aligned to `1.1.0` in package metadata, runtime metadata and
  release-facing documentation.
- User-facing scope: self-contained offline HTML evidence reports and bounded
  presentation improvements over existing deterministic evidence and review
  models.
- No reconnaissance, collection, ranking, evidence or vulnerability semantics
  changed for the release.
- Focused documentation/release tests: `42 passed`; affected release,
  packaging, CLI, HTML and report tests: `311 passed`; full suite: `2,015 passed`.
- Pre-publication local build completed: `bugslyce-1.1.0-py3-none-any.whl` (438,399 bytes;
  133 members; SHA-256
  `d0c53f369b8305f4c4448b234bf4d8cd606e6096dd7481059394ad4bfdf76b5d`)
  and `bugslyce-1.1.0.tar.gz` (659,345 bytes; 241 members; SHA-256
  `fe2116dea824fd720669a05b2c5e8d3e622e4c384183700156f2ed43beb191ff`).
- The fresh source-distribution rebuild produced a 133-member wheel (SHA-256
  `4269347ca7d92ada28c189b6aba6bfaae7b9a77ad7cdc45a8b69a85848d6fc4e`).
- Wheel and source-distribution metadata report `1.1.0`; wheel RECORD,
  path-safety, duplicate-member and distribution-hygiene checks passed.
- Temporary-venv installation from the local wheel with `--no-index --no-deps`
  passed outside the checkout. CLI version/help, HTML-report help, imports,
  package metadata and all four bundled wordlists passed.
- Offline RecruitX HTML acceptance passed with unchanged input hashes, seven
  existing Operator Summary items, complete structured Deep inputs, route
  counts `47` assessed / `2` external / `0` unclassified and no network
  requests.
- Approved HTML-report screenshot SHA-256:
  `6ca7366d4faaedba817248727107693e12b3917555664bf86594022f1673957c`.

### Historical rc2 release-candidate acceptance

- rc2 baseline commit: `113494f3c727c4543ca87e9be37b64c8c1858dbe`.
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

### Historical 1.0.0 final technical acceptance

- Accepted source commit: `32bfd20f78cda81e22241bb73836038defac0504`.
- Committed-build evidence bundle SHA-256:
  `7ef3d9ffd6385b70adf33a31935e3248f8ba70a3cbd917a62c5787256f7668c2`.
- Exact accepted wheel: `bugslyce-1.0.0-py3-none-any.whl`.
- Exact accepted wheel SHA-256:
  `e29346eda47bd37d166612bee775e231a48b79749696a1a66aaeb7e499860f63`.
- The accepted committed-tree build used `SOURCE_DATE_EPOCH=1784728149`.
- Full suite: `1,983 passed`; compileall, wheel RECORD and distribution hygiene
  checks passed. The wheel has 131 members and the source distribution has 238.
- Checkout and source-distribution-built wheels were semantically identical;
  temporary-venv installation outside the checkout, help and safe launcher
  exit all passed.
- Mint final-wheel temporary pipx acceptance: completed with pipx 1.4.3 and
  Python 3.12.3. Mint acceptance bundle SHA-256:
  `40f487df5eb676b49e8509485be99e289067a0ae0bbb222d72bd60b822f68820`.
  The isolated command and module resolved from temporary pipx paths; installed
  version, help and launcher exits were `1.0.0`, `0` and `0`. Doctor exit `2`
  occurred because Gobuster was absent; package and resources were otherwise
  ready. The exact local wheel was installed with dependencies disabled and no
  BugSlyce target contact occurred.
- Kali same-wheel temporary pipx acceptance: completed with pipx 1.8.0 and
  Python 3.13.11. Kali acceptance bundle SHA-256:
  `23e68a4ca031dd7585118d6f93232a4658149f65c65d985a16106c69222013af`.
  The isolated command and module resolved from temporary pipx paths; installed
  version, help and launcher exits were `1.0.0`, `0` and `0`; doctor exit `0`
  confirmed full local readiness.
  The exact same local wheel was installed with dependencies disabled and no
  BugSlyce target contact occurred.
- Final runtime resources verified on both systems: `lab-root-tiny.txt` (25),
  `standard-auth-core.txt` (15), `standard-bounded-core.txt` (220) and
  `deep-bounded-core.txt` (1,753).
- Technical GO: GO to tag and publish.
