# BugSlyce

**BugSlyce** is a local-first recon triage assistant for authorised labs, CTFs, and bug bounty work.

It helps you go from:

```text
I have an in-scope target.
```

to:

```text
Here is the evidence.
Here is what looks worth reviewing first.
Here is what is probably noise.
```

BugSlyce is not an autopwn tool. It does not claim confirmed vulnerabilities, exploit targets, brute force credentials, submit forms, or run arbitrary commands. It collects bounded recon evidence, keeps it local, and turns it into a structured review pack.

Current release: **v0.1.0**

---

## What BugSlyce Does

BugSlyce creates a local project for a target, runs a controlled recon pipeline, and generates a readable evidence pack.

The current MVP can:

* launch with a simple interactive menu using `bugslyce`
* create a scoped project
* validate IPv4 addresses, hostnames, and simple `http://` / `https://` URLs
* run a bounded **Quick Recon** pipeline
* collect TCP, service, and HTTP evidence
* perform small, controlled content discovery
* preserve raw artefacts for review
* generate a human-readable report
* produce a project runbook
* export a portable evidence ZIP
* highlight credential-like comments or sensitive artefacts for manual review
* separate useful review leads from low-signal rabbit holes

Everything stays local unless you choose to share it.

---

## What BugSlyce Does Not Do

BugSlyce v0.1.0 does **not** run:

* exploitation
* brute force
* credential attacks
* authentication testing
* form submission
* UDP scans
* NSE scripts
* recursive crawling
* arbitrary user-supplied commands
* LLM analysis
* cloud upload or sync

Candidates in the report are **manual review leads**, not confirmed findings.

---

## Install

Recommended install from the public GitHub repository:

```bash
pipx install git+https://github.com/Rayza-Slyce/bugslyce.git
bugslyce
```

If you do not have `pipx` installed:

```bash
sudo apt install pipx
pipx ensurepath
```

Then restart your terminal and run:

```bash
bugslyce
```

For contributors or local development:

```bash
git clone git@github.com:Rayza-Slyce/bugslyce.git
cd bugslyce
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
bugslyce
```

---

## First Run

Start BugSlyce with:

```bash
bugslyce
```

You will see the interactive launcher:

```text
1. Start a new project
2. Resume an existing project
3. List projects
4. Run doctor/readiness check
5. Exit
```

For a new target, choose:

```text
Start a new project
```

BugSlyce will ask for:

* project name
* target IP, hostname, or simple URL
* output directory
* recon mode
* authorisation confirmation

By default, projects are stored in:

```text
~/bugslyce-output
```

That keeps your recon output away from the source code repository.

---

## Recon Modes

### Quick Recon

Available in v0.1.0.

Quick Recon is the current MVP pipeline. It is designed for a fast, bounded first look at an authorised target.

It performs:

* project and scope validation
* full TCP discovery using the approved lab profile
* service/version detection on discovered TCP ports
* HTTP metadata collection
* same-origin path follow-up where evidence supports it
* tiny root content discovery using the bundled wordlist
* selected content follow-up
* selected body fetch for useful application pages
* status generation
* runbook generation
* evidence pack export

Quick Recon is intentionally conservative. It is enough to produce useful evidence and review leads, not enough to replace manual testing.

### Manual Setup Only

Available in v0.1.0.

Manual Setup Only creates the project and starter scope file without running recon. Use this when you want to inspect or edit the scope before any live activity.

### Standard Recon

Planned for a future release.

Standard Recon is intended to add broader but still controlled recon coverage.

### Deep Recon

Planned for a future release.

Deep Recon is intended to add richer analysis, stronger artefact grouping, CMS review leads, and optional evidence review workflows.

---

## Target Input

BugSlyce accepts:

```text
10.10.10.10
example.com
sub.example.com
https://example.com
http://10.10.10.10
```

Simple URLs are normalised to the target host.

For example:

```text
https://example.com
```

becomes:

```text
example.com
```

BugSlyce rejects malformed or ambiguous input such as:

```text
10.10.10
https://example.com/admin
https://example.com?x=1
https://user:pass@example.com
ftp://example.com
```

URL path seeding is not supported in v0.1.0.

---

## Output

A completed Quick Recon project can include:

```text
report.md
project_state.json
recon_manifest.json
recon_status.md
recon_status.json
runbook.md
project_pipeline.md
project_pipeline.json
recon_execution.md
recon_execution.json
raw nmap/curl/HTML/robots/gobuster artefacts
evidence-pack.zip
```

The most important file is:

```text
report.md
```

It starts with an **Operator Summary**.

The Operator Summary is split into:

* **Review First** — evidence-backed leads worth looking at manually
* **Low-Signal / Avoid Rabbit Holes** — areas that are probably not worth over-prioritising
* **Current Coverage** — what the recon pack did and did not observe

Evidence IDs link the summary back to the raw and structured artefacts.

---

## Example Review Lead

BugSlyce may produce a lead like this:

```text
Credential-like artefact review in homepage HTML

Why:
Parsed HTML evidence contains a comment referencing credential-like context
and related sensitive keyword hits.

Next:
Review the saved HTML/source context manually.
Do not submit forms, brute force, or treat any value as valid without
explicit authorisation and manual validation.
```

That is not a confirmed vulnerability.

It means:

```text
This looks worth reviewing first.
```

not:

```text
This is exploitable.
```

---

## Evidence Pack Export

Quick Recon automatically exports an evidence pack when the pipeline completes.

You can also export one manually:

```bash
bugslyce recon export \
  --input-dir ~/bugslyce-output/example-project \
  --output ~/bugslyce-output/example-project-evidence-pack.zip \
  --force
```

The evidence pack may contain target IPs, URLs, service banners, response headers, HTML, discovered paths, and other sensitive recon material.

Review it before sharing.

---

## Safety Model

BugSlyce is intended only for targets you are authorised to assess.

The MVP safety model includes:

* local scope file required
* explicit confirmation before live recon
* fixed command shapes
* bounded timeouts
* validated target input
* local evidence storage
* no arbitrary user command flags in the pipeline
* no exploitation or brute force
* no authentication testing
* no LLM calls in the deterministic workflow

Scope matching is a safety control, not a substitute for reading the actual lab, CTF, or programme rules.

Always confirm authorisation before running recon.

---

## Local Data Safety

Do not commit private recon data.

Keep real target material in ignored locations such as:

```text
~/bugslyce-output
private_recon/
```

Do not commit:

* raw recon output
* screenshots
* Burp files
* HAR files
* exported evidence ZIPs
* API keys
* cookies
* tokens
* `.env` secrets
* private programme scope

Absence of evidence is not proof of safety.

---

## Useful Commands

Most users should start with:

```bash
bugslyce
```

Check local readiness:

```bash
bugslyce doctor
```

List local BugSlyce projects:

```bash
bugslyce project list --projects-dir ~/bugslyce-output
```

Preview the next action for a project:

```bash
bugslyce project next \
  --project ~/bugslyce-output/example-project/bugslyce_project.json
```

Resume an interrupted Quick Recon project:

```bash
bugslyce project run \
  --project ~/bugslyce-output/example-project/bugslyce_project.json \
  --profile lab-safe-tiny \
  --confirm \
  --resume
```

Advanced and phase-specific commands are available under:

```bash
bugslyce project --help
bugslyce recon --help
```

---

## Development Checks

For development:

```bash
python -m pip install -e ".[dev]"
pytest
bugslyce doctor
bugslyce --help
```

The test suite should not contact live targets.

---

## Current Limitations

BugSlyce v0.1.0 is an MVP.

Current limitations:

* only Quick Recon is implemented
* Standard Recon and Deep Recon are not available yet
* no authenticated testing
* no deep crawler
* no CMS-specific CVE research leads yet
* no LLM evidence review yet
* no vulnerability confirmation
* no exploit workflow
* simple URLs are normalised to host targets only
* ranking is deterministic heuristic triage, not proof of risk

BugSlyce assists evidence collection and prioritisation. It does not replace manual validation or responsible disclosure judgement.

---

## Roadmap

Planned future work includes:

* Standard Recon mode
* Deep Recon mode
* richer CMS and framework fingerprinting
* known CVE research leads for detected technologies
* optional local or API-based LLM evidence review
* improved report formatting
* more tested lab/CTF examples
* stable evidence pack format for wider use

Optional LLM review should remain advisory. It should suggest manual next steps from local evidence, not run commands or claim confirmed findings.

---
## Licence

BugSlyce is released under the MIT Licence.

See [LICENSE](LICENSE) for details.


