# Release Checklist

This checklist is for maintainers preparing a future BugSlyce release. It does
not create a release, create a Git tag, publish a package or upload artefacts.

The current package version is `0.3.0`. Do not claim a v1.0.0 release until the
project version, release process and distribution artefacts have been updated
deliberately.

## Documentation

- [ ] README describes the current package version and implemented workflows.
- [ ] Current profiles are documented: `lab-safe-tiny`, `standard-bounded`,
      `deep-bounded`.
- [ ] Current mode names are documented: Quick Recon, Standard Recon and Deep
      Recon.
- [ ] [Installation](INSTALLATION.md) matches the current dependencies.
- [ ] [Operator Guide](OPERATOR_GUIDE.md) matches the current CLI and launcher.
- [ ] [Troubleshooting](TROUBLESHOOTING.md) covers common readiness and resume
      failures.
- [ ] [Recon Modes](RECON_MODES.md) matches the mode registry.

## Safety Boundaries

- [ ] Authorised-use wording is present.
- [ ] Scope review is required before live recon.
- [ ] `--confirm` is required for project pipeline execution.
- [ ] No UDP pipeline phase is documented as available.
- [ ] No NSE scripts are documented as available.
- [ ] No brute force, exploitation, form submission, authentication testing,
      browser automation or JavaScript execution is documented as available.
- [ ] Reports are described as manual review context, not confirmed findings.

## Readiness

- [ ] Python minimum version remains documented as `3.11`.
- [ ] Required external tools are documented: `nmap`, `curl`, `gobuster`.
- [ ] Bundled resources are documented: `lab-root-tiny`,
      `standard-bounded-core`.
- [ ] `bugslyce doctor` is documented as passive and local.
- [ ] Doctor exit codes are documented.

## Validation

- [ ] Documentation tests pass.
- [ ] CLI, interactive and doctor tests pass.
- [ ] Pipeline and project-session tests pass.
- [ ] Full suite passes.
- [ ] `git diff --check` passes.
- [ ] Local no-network package installation validates bundled resources.

## Release Actions

Release tagging and package publication are intentionally not described here as
a command recipe. Perform them only through the project's approved release
process.
