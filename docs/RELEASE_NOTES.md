# Release Notes

BugSlyce currently reports package version `0.3.0`.

These notes describe the current repository state for operators and reviewers.
They do not create a release, publish a package or claim a v1.0.0 release.

## Current Implemented Workflows

- Manual Setup Only.
- Quick Recon with `lab-safe-tiny`.
- Standard Recon with `standard-bounded`.
- Deep Recon with `deep-bounded`.

The executable recon workflows remain bounded, scope-conscious and
non-exploitative. They do not submit forms, execute JavaScript, brute force,
perform authentication testing, mutate parameters or claim confirmed
vulnerabilities.

## Operator Documentation

Use the current public documentation set:

- [Installation](INSTALLATION.md)
- [Operator Guide](OPERATOR_GUIDE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Recon Modes](RECON_MODES.md)

## Version Boundary

The implemented workflows are v1 release-candidate functionality inside the
current `0.3.0` package. Do not tag or publish a new release from this file
alone.
