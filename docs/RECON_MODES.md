# BugSlyce Recon Modes

This document is the design contract for BugSlyce recon modes. It describes
the intended meaning of each mode, the safety boundaries that apply to all
modes, and the roadmap for future work.

Phase 61 is documentation only. It does not implement Standard Recon, Deep
Recon, CTF/lab context handling, local evidence mode, vulnerability
intelligence, LLM review, or any new scanning behaviour.

## Core Mode Principle

Recon mode names describe depth, time, and evidence coverage. They do not
describe permission.

- All modes require authorisation and strict scope.
- Quick Recon means fast first-pass signal finding.
- Standard Recon means broader bounded evidence collection and better artefact
  interpretation.
- Deep Recon means slower evidence expansion, correlation, and review
  preparation.
- None of the modes mean "safe to run anywhere".
- Deep Recon must not simply mean "run big wordlists".
- BugSlyce should guide manual review, not automatically prove or exploit
  vulnerabilities.

Authorisation, scope, and operator judgement remain mandatory regardless of
mode.

## Quick Recon

Quick Recon is the implemented current mode.

- Purpose: fast first-pass recon that finds useful review leads while keeping
  execution bounded and predictable.
- Current internal profile name: `lab-safe-tiny`.
- The internal profile name must not be interpreted as permission. It is an
  implementation identifier, not an authorisation statement.

Quick Recon may include:

- Project, scope, and readiness validation.
- TCP port discovery.
- Service/version detection.
- Basic HTTP metadata collection.
- Header, `robots.txt`, and homepage HTML collection.
- Evidence-derived same-origin path follow-up.
- Tiny root content discovery.
- Selected discovered path follow-up.
- Selective body fetch for eligible high-signal HTML/application paths.
- Local report, runbook, status, pipeline metadata, and evidence pack
  generation.

Quick Recon must not:

- Run NSE scripts.
- Run UDP scans.
- Brute force.
- Exploit.
- Submit forms.
- Test authentication.
- Run recursive discovery by default.
- Accept arbitrary command flags, URLs, paths, or wordlists.
- Upload evidence.
- Call an LLM by default.
- Make unsupported vulnerability claims.

Expected artefacts include:

- `report.md`
- `runbook.md`
- `recon_status.md` and `recon_status.json`
- `project_state.json`
- `project_pipeline.md` and `project_pipeline.json`
- `recon_manifest.json`
- Raw evidence where applicable.
- Evidence pack ZIP.

## Standard Recon

Standard Recon is planned and unavailable until implemented.

Proposed internal profile name: `standard-bounded`.

Standard Recon is the normal broader workflow for authorised manual review. It
should collect richer evidence than Quick Recon while remaining bounded,
deterministic, and non-exploitative.

Standard Recon may eventually include modest bounded additions such as:

- Broader handling of discovered HTTP/HTTPS services.
- Richer redirect, header, cookie, title, content-type, and status capture.
- `sitemap.xml` where relevant.
- `security.txt` and `.well-known/security.txt` where relevant.
- TLS/certificate metadata.
- DNS context for domain targets.
- A slightly larger bounded root discovery profile.
- Improved endpoint classification.
- Hash-looking artefact detection.
- Encoding and transform candidate detection.
- Specialised `robots.txt` analysis.
- Hidden HTML/source artefact analysis.
- Better evidence context windows.
- Cautious same-origin linked asset metadata collection.

Endpoint classification examples include:

- login
- admin
- API
- upload
- download
- export
- import
- callback
- redirect
- debug
- status/health
- object-reference-style parameters

Standard Recon must not become:

- Recursive crawling by default.
- Aggressive fuzzing.
- Authentication testing.
- Exploit validation.
- Broad uncontrolled discovery.
- Online hash lookup.
- Automatic hash cracking.
- Automatic steganography extraction.
- Automatic form submission.

## Deep Recon

Deep Recon is planned and unavailable until designed and implemented in later
phases.

Proposed internal profile name: `deep-correlation`.

Deep Recon means slower evidence expansion and correlation. It does not mean
aggressive scanning.

Deep Recon may eventually include:

- Richer endpoint clustering.
- Parameter clustering.
- Technology-aware surface mapping.
- Static asset review with strict limits.
- Same-origin JavaScript route extraction with no JavaScript execution.
- Source map detection.
- Stronger correlation between services, endpoints, parameters,
  technologies, notes, and raw evidence.
- Evidence graph / derived lead chains.
- Stronger report/runbook reasoning.
- Known-vulnerability review queues.
- Optional local-only transformation analysis.
- Optional same-origin small asset review where appropriate.

Deep Recon must not become:

- Autopwn.
- Exploit automation.
- Recursive crawling by default.
- Credential testing.
- CVE validation.
- Payload submission.
- Protection bypass.
- "Run a huge wordlist" mode.

## Lessons From Authorised CTF/Lab Use

Authorised CTF/lab work showed that BugSlyce was already useful at surfacing
services, high-port web servers, robots files, hidden HTML content,
encoded-looking artefacts, and candidate clues.

The main gap was not discovery. The main gap was interpretation, context, and
chaining.

Future improvements should be treated as design notes, not implemented
features:

- Hash-looking artefact detection with context weighting.
- Encoding and transform candidate detection.
- `robots.txt` specialised parsing.
- Hidden HTML/source artefact analysis.
- Same-origin linked asset metadata collection.
- Bounded nested discovery under high-signal directories.
- Candidate chaining / evidence graph.
- Better report separation between confirmed evidence, possible
  transformations, derived values, unresolved leads, rabbit holes, and
  suggested next manual actions.

Cautious example wording:

- "Possible hash candidate detected."
- "Encoded-looking value decoded into a path-like string. Manual review
  recommended."
- "Discovered directory contains enough signal to justify one bounded nested
  enumeration pass."
- "Unusual robots User-Agent value is also a possible hash and appears near
  flag-related wording."
- "Suspicious image asset found on high-signal page. Filename/context suggests
  possible hidden data. Consider manual steganography checks if this is an
  authorised CTF/lab."

Wording to avoid:

- "This is an MD5 hash."
- "Confirmed vulnerability."
- "Confirmed exploitability."
- "This target is vulnerable."
- "Exploit available."

## Engagement Context Separation

Recon mode and engagement context are separate concepts.

Recon mode describes depth and coverage:

- Quick
- Standard
- Deep

Engagement context describes how evidence is interpreted:

- Bug bounty / authorised external target.
- CTF/lab/TryHackMe.
- Post-access local evidence review.

CTF/lab-specific signals should not automatically pollute normal bug bounty
output.

CTF/lab-specific future checks may include:

- Flag-like string detection.
- ROT13/encoding of flag-shaped strings.
- Hidden page-source clue detection.
- Simple steganography suspicion.
- Puzzle-style wording detection.
- Room-answer candidate notes.

For bug bounty context, these checks should be reduced, disabled, or clearly
separated to avoid noisy and irrelevant output.

## Local Evidence Mode

Local evidence mode is a future post-access local evidence mode. It is not
part of normal network recon and is not implemented yet.

This mode may later allow the user to paste or import outputs from an
authorised lab shell, such as:

- `id`
- `sudo -l`
- `/etc/crontab`
- `/etc/cron.d`
- writable scripts
- SUID files
- PATH issues
- writable service files
- interesting home files
- unusual banners/MOTD
- writable web roots
- permissions on scripts executed by root

The output should be review leads, not exploitation.

It may eventually produce:

- confirmed evidence
- likely privilege escalation route
- what to validate next
- what not to overclaim
- safe manual proof suggestion

### Cron Misconfiguration Review Leads

Cron risk signals may include:

- Root runs a script on a schedule.
- The script is owned by a low-privileged user.
- The script is writable by a low-privileged user.
- The script lives in a web root or unusual writable location.
- The cron command uses relative paths.
- The cron command calls `bash`, `sh`, `python`, or similar.
- The script contents imply it runs as root.

Cautious wording:

"Root-executed cron script appears writable by the current user. This is a
likely privilege escalation review lead. Validate ownership and permissions
before modifying anything."

BugSlyce must not automatically modify files, deploy payloads, or attempt
privilege escalation.

## Global Forbidden Behaviours

BugSlyce must not automatically:

- exploit
- brute force
- attempt logins
- submit forms
- test authentication
- bypass protections
- run NSE scripts
- run UDP scans
- run recursive discovery by default
- execute arbitrary commands
- upload evidence anywhere
- call an LLM by default
- make unsupported vulnerability claims
- perform online hash lookups
- automatically crack hashes
- automatically extract steganographic content
- automatically modify local target files
- automatically attempt privilege escalation

Implementation guardrails:

- Do not add `shell=True`.
- Do not add `subprocess.Popen`.
- Do not add `os.system`.
- Do not add `pexpect`.
- Do not add arbitrary command execution.

## Expected Outputs

All modes should preserve a consistent local artefact model:

- report
- runbook
- recon status/state
- pipeline metadata
- evidence manifest
- raw evidence where applicable
- evidence pack/ZIP

Standard and Deep may add richer sections later, but should not create a
completely different operator experience.

Future richer report sections may include:

- confirmed evidence
- possible transformations
- derived values
- unresolved leads
- rabbit holes / low-signal leads
- suggested next manual action
- evidence chains
- review lead confidence
- what not to overclaim

## Vulnerability Intelligence Later

Vulnerability intelligence may later be used only as evidence enrichment and
review lead generation.

It must not be treated as proof of vulnerability.

Cautious wording:

- review candidate
- may warrant manual review
- potentially relevant advisory
- check applicability manually

Avoid wording that claims confirmed vulnerability or confirmed exploitability.

## Optional LLM Review Later

Optional LLM review may later help summarise, explain, group, or prioritise
local evidence.

It must be:

- optional
- off by default
- explicitly configured
- advisory only
- not the source of truth
- unable to override raw evidence
- unable to invent findings
- unable to make unsupported vulnerability claims

The deterministic BugSlyce evidence and artefacts remain primary.

## Roadmap

- Phase 61: recon mode design documentation.
- Phase 62: internal mode/profile registry while Standard/Deep remain
  unavailable.
- Phase 63A: artefact interpretation foundation for hash-looking candidates
  and context weighting.
- Phase 63B: encoding and transform candidate foundation for already-collected
  artefacts.
- Phase 63: Standard Recon v1 with modest bounded additions.
- Phase 64: controlled same-origin static JavaScript route extraction if still
  appropriate.
- Phase 65: report grouping, operator summary, review lead prioritisation, and
  evidence context improvements.
- Phase 66+: Deep Recon design and later implementation.
- Later: CTF/lab context separation.
- Later: post-access local evidence mode.
- Later: cron misconfiguration review leads.

## Phase 62 Registry Note

Phase 62 formalises the internal mode/profile registry as the source of truth
for mode IDs, display names, internal profile names, status, and availability.
Quick Recon remains the only available executable mode and continues to map to
`lab-safe-tiny`. Standard Recon and Deep Recon remain planned and unavailable.

## Phase 63A Artefact Interpretation Note

Phase 63A adds an offline artefact interpretation foundation for
hash-looking candidates and lightweight context weighting. It is intended to
support later Standard Recon, `robots.txt` parsing, hidden HTML/source
analysis, report grouping, and evidence chaining.

This phase does not enable Standard Recon, does not enable Deep Recon, and
does not change Quick Recon behaviour.

## Phase 63B Encoding/Transform Interpretation Note

Phase 63B adds an offline encoding and transform candidate foundation for
already-collected artefacts. It can recognise possible Base64, Base32, hex,
URL-encoded, binary ASCII, reversed-text, and ROT/Caesar-style candidates with
bounded local previews and lightweight context weighting.

This phase does not enable Standard Recon, does not enable Deep Recon, and
does not change Quick Recon behaviour. It does not add scanning, online
decoders, recursive decoding, report integration, or evidence-pack changes.
