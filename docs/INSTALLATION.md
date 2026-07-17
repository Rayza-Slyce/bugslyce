# Installation

This guide installs BugSlyce from source and verifies local readiness without
running recon.

## Supported Environment

BugSlyce is intended for Linux operator workstations.

| Host | Status |
| --- | --- |
| Kali Linux | Directly validated operator environment. |
| Linux Mint | Directly validated Debian-derived environment. |
| Ubuntu and other Debian-derived Linux systems | Expected to work when the required Python version and external tools are available, but not currently part of the directly validated host set. |
| Other Linux distributions | Untested; may work when equivalent packages are available. |
| Windows and macOS | Native operation is not currently claimed. |

## Requirements

Core application readiness requires:

- Python `3.11` or newer.
- Minimum supported Python: 3.11.
- The BugSlyce Python package importable in the active environment.
- The `bugslyce` command surface available.
- Package-local bundled resources resolvable.

Executable recon readiness also requires:

| Requirement | Blocks |
| --- | --- |
| `nmap` | Quick, Standard and Deep Recon |
| `curl` | Quick, Standard and Deep Recon |
| `gobuster` | Quick, Standard and Deep Recon |
| bundled `lab-root-tiny` wordlist | Quick Recon |
| bundled `standard-bounded-core` wordlist | Standard Recon |
| bundled `deep-bounded-core` wordlist | Deep Recon |

Manual Setup Only is governed by core readiness. It can create project metadata
and `scope.md` even when live-recon tools are missing.

The legacy dirbuster small wordlist is optional for older manual planning
contexts. It is not required for the executable v1 project workflows.

## Debian, Kali and Mint Example

On common Debian-derived systems, install the local tools with:

```bash
sudo apt update
sudo apt install git python3 python3-venv nmap curl gobuster
```

Package names and repositories differ on other distributions. Use the
equivalent packages for your platform.

## Source Installation

Install BugSlyce in a virtual environment:

```bash
git clone https://github.com/Rayza-Slyce/bugslyce.git
cd bugslyce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Verify the command:

```bash
bugslyce --help
bugslyce doctor
```

If `bugslyce` is not found, the virtual environment is probably not active.
Either activate it again or call the script by path:

```bash
./.venv/bin/bugslyce doctor
```

For development, install the test dependency group explicitly:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## Upgrade From Source

Use a conservative fast-forward source update:

```bash
git pull --ff-only
source .venv/bin/activate
python -m pip install .
bugslyce doctor
```

Do not use destructive reset commands unless you understand the local changes
you are discarding.

## Uninstall

Remove the Python package from the active environment:

```bash
python -m pip uninstall bugslyce
```

This does not delete project directories, output directories or evidence packs.
Remove those manually only after preserving any evidence you need.

## Readiness Verification

Run:

```bash
bugslyce doctor
```

The doctor is passive. It does not scan, contact a target, make network
requests, install packages or run `nmap`, `curl` or `gobuster`.

Readiness terms:

| Term | Meaning |
| --- | --- |
| Core ready | Local BugSlyce project and inspection features are usable. |
| Recon ready | All executable v1 recon modes have their required tools and bundled resources. |
| Overall ready | Core readiness and recon readiness are both ready. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All executable v1 recon modes are ready. |
| `2` | One or more executable recon requirements are blocked. |

Exit code `2` is not a crash. Read the External tools, Bundled resources and
Mode readiness sections to see exactly what to fix.

## Local Package Validation

These checks confirm the local package without running a target scan:

```bash
bugslyce --help
bugslyce doctor
```

If the bundled wordlists are installed correctly, the doctor lists
`lab-root-tiny`, `standard-bounded-core` and `deep-bounded-core` under
Bundled resources. The installed package data files are
`lab-root-tiny.txt`, `standard-bounded-core.txt` and
`deep-bounded-core.txt`.
