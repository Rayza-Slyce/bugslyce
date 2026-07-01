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

Standard Recon v1 is available.

Internal profile name: `standard-bounded`.

Standard Recon is the normal broader workflow for authorised manual review. It
is intended to collect richer evidence than Quick Recon over time while
remaining bounded, deterministic, and non-exploitative. In v1, its runtime
value-add is offline interpretation of already-collected evidence, not
increased scan volume.

As of v0.3.0, Standard Recon still reuses the same bounded collection path as
Quick Recon and adds an offline operator workflow layer: Manual Review Leads,
Investigation Threads, Standard Investigation Workflow in `runbook.md`,
engagement-aware wording, and Offline Route/Source Review.

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

### Standard Recon v1 Wiring Plan

Standard Recon v1 is now available. The v1 product decision is that Standard
Recon initially improves interpretation of already-collected evidence, not
scan volume.

Standard Recon v1 should initially:

- Reuse the existing bounded evidence collection path.
- Collect no additional network evidence beyond what the current bounded
  pipeline already collects.
- Analyse only already-collected evidence.
- Convert collected robots, HTML, and text artefacts into `ArtefactSource`
  objects.
- Run the offline interpretation collector.
- Render `Manual Review Leads`.
- Pass the rendered section into the existing report seam.
- Keep `Manual Review Leads` separate from confirmed findings.
- Preserve cautious language throughout.
- Leave runbooks, evidence packs, and CLI output unchanged unless explicitly
  designed in a later phase.

Standard Recon v1 does not increase scan volume.

- It does not mean bigger wordlists.
- It does not mean recursive crawling.
- It does not add additional fetching, `sitemap.xml`, `security.txt`, static
  asset fetching, JavaScript extraction, or extra same-origin paths.
- It does not mean exploiting or validating vulnerabilities.
- It must not submit forms, attempt authentication, brute force, or fetch new
  paths because of interpretation leads.

The first value-add is better evidence interpretation.

The Standard Recon v1 report includes a clearly separated `## Manual Review
Leads` section after `## Operator Summary` and before `## Scope Summary`,
using the Phase 64B report seam. This section contains cautious review
prompts, not confirmed vulnerabilities.

Expected review-lead wording includes:

- Possible hash candidate detected.
- Possible encoded or transformed artefact detected.
- Robots directive contains possible encoded or hash-shaped artefacts.
- HTML comment contains clue-like wording.
- Treat this as a review lead, not proof of vulnerability.

Wording to avoid includes:

- Confirmed vulnerability.
- Confirmed exploitability.
- Confirmed credential.
- Confirmed secret.
- This is a flag.
- This is a password.
- Exploit this.
- Crack this.
- Attack this path.
- No vulnerabilities found.

Future implementation should map already-collected evidence into
`ArtefactSource` objects according to the existing artefact/evidence storage
architecture. Potential sources may include fetched `robots.txt`, homepage
HTML, selected high-signal HTML/application response bodies, selected
same-origin path follow-up bodies, and local notes or fetched text bodies if
already collected. Source mapping should avoid duplicating large response
bodies unnecessarily.

## Deep Recon

Deep Recon is planned and unavailable until designed and implemented in later
phases.

Planned internal profile name: `deep-bounded`.

### Deep Recon v1 Design Contract

Deep Recon v1 is a design target, not currently available runtime behaviour.
Deep Recon remains unavailable until separately implemented, tested, and
enabled.

Deep Recon means aggressive evidence discovery inside strict authorisation, scope, method, and rate limits.

It is a genuine step up from Standard Recon. It should dig much deeper into
the explicitly authorised attack surface while staying inside recon and triage
boundaries. Deep Recon may increase evidence discovery depth, request count,
correlation quality, and operator guidance. Deep Recon must not increase attack behaviour.

Mode relationship:

- Quick Recon: fast bounded collection.
- Standard Recon: Quick-style bounded collection plus offline operator
  workflow.
- Deep Recon: expanded bounded collection plus deeper source, route, service,
  parameter, metadata, and evidence correlation.

Deep Recon should be:

- Aggressive but bounded recon.
- Deeper evidence discovery than Standard.
- Expanded active collection using controlled GET/HEAD-style recon.
- Shallow same-origin discovery where explicitly bounded.
- Deeper offline correlation.
- Slower than Standard.
- Manual-review oriented.
- Suitable only for explicitly authorised targets.

Planned Deep Recon v1 default capabilities include:

- Larger bounded content discovery than Standard.
- Strict request, timeout, depth, redirect, and response-size limits.
- Bounded second-pass content discovery around strong-signal directories only.
- `robots.txt` expansion and safe follow-up.
- `sitemap.xml` discovery and parsing.
- `security.txt`, `humans.txt`, favicon, manifest, and common metadata
  checks.
- Broader same-origin HTTP review across discovered HTTP services.
- Shallow same-origin crawl from selected HTML pages.
- Selected HTML/body fetch with size limits.
- Same-origin JavaScript file discovery.
- Same-origin JavaScript/source file collection as text only.
- Static route extraction from collected JavaScript/source text.
- Static parameter inventory from URLs, HTML, and JavaScript/source text.
- HTML form inventory without submitting forms.
- Source map detection.
- Bounded source map collection only when directly referenced and
  same-origin.
- Backup/config/source exposure path checks using a tight allowlist and
  GET/HEAD only.
- Technology-specific discovery wordlists where conservative and bounded.
- Service-specific manual review queues.
- Deeper correlation across ports, services, headers, technologies, paths,
  routes, parameters, artefacts, candidates, manual leads, and investigation
  threads.
- Richer Deep report/runbook sections.
- Better evidence-pack organisation by service, route, and investigation
  thread.

Optional future Deep extensions may be designed later as explicit opt-in
capabilities only. They are not part of the immediate Deep Recon v1 default
contract unless separately designed, tested, and gated:

- Selected nuclei-style checks using a strict allowlist.
- Selected safe NSE scripts using a strict allowlist.
- UDP checks for explicitly authorised internal/lab contexts.
- Larger wordlists for explicitly authorised targets.
- External lookups when explicitly enabled.
- Local CTF/lab-only cracking helpers.
- LLM interpretation and guidance after deterministic Deep evidence exists.

BugSlyce v1 Deep Recon must not include:

- Exploitation.
- Automatic vulnerability confirmation.
- Brute forcing live services.
- Password spraying.
- Credential stuffing.
- Login attempts.
- Authentication testing.
- Session testing.
- Form submission.
- Destructive requests.
- Write actions.
- Payload injection.
- `sqlmap`.
- `hydra`.
- `masscan`.
- Uncontrolled crawling.
- Browser automation that interacts with applications.
- JavaScript execution.
- Arbitrary user-supplied command execution.
- Automatic reporting to third parties.

Proposed future Deep pipeline shape:

1. Environment and scope validation.
2. TCP/service discovery.
3. Service/version enrichment.
4. HTTP service matrix.
5. HTTP metadata collection.
6. Common metadata discovery.
7. Baseline content discovery.
8. Discovered-path follow-up.
9. Strong-signal directory selection.
10. Bounded second-pass content discovery.
11. Shallow same-origin crawl.
12. Selected HTML/body fetch.
13. Same-origin JavaScript/source discovery.
14. Same-origin JavaScript/source text collection.
15. Static route extraction.
16. Source map detection and bounded same-origin collection.
17. Parameter inventory.
18. HTML form inventory without submission.
19. Backup/config/source exposure checks with a tight allowlist.
20. Route/source/service correlation.
21. Deep investigation threads.
22. Deep manual review queue.
23. Deep report/runbook generation.
24. Evidence pack export.

This pipeline shape is a design target only. It is not currently available
runtime behaviour.

Phase 75A adds a code-level planned-pipeline skeleton for these 24 Deep steps.
The skeleton is static contract data only. It does not make `deep-bounded` executable, does not add runtime collection, does not add commands, and does not make Deep Recon available.

Phase 75B adds a code-level planned output and artefact taxonomy for future
Deep Recon outputs. The taxonomy is static contract data only. It does not create output files, does not write reports, does not create evidence packs, does not make `deep-bounded` executable, and does not make Deep Recon available.

Phase 76A adds a code-level scope and safety preflight contract for future
Deep Recon. The preflight contract defines planned gates for authorisation,
explicit scope, engagement context, Deep bounds, supported method classes,
local retention, and operator confirmation. It is static contract data only.
It does not inspect projects, does not read or write project files, does not
create outputs, does not make `deep-bounded` executable, and does not make
Deep Recon available.

Phase 76B adds a static Deep Recon readiness summary renderer. The renderer
combines the Deep profile contract, explicit bounds, planned pipeline, planned
outputs, and preflight gates into human-readable Markdown for maintainers. It
is static contract rendering only. It does not inspect projects, does not read
or write project files, does not create outputs, does not execute commands,
does not make `deep-bounded` executable, and does not make Deep Recon
available.

Phase 77A exposes the static Deep Recon readiness summary through the
informational command `bugslyce recon deep-readiness`. The command prints
static contract Markdown to stdout only. It does not run Deep Recon, does not
read or write project files, does not execute commands, does not create output
files, and does not change mode availability.

Phase 77B adds a machine-readable Deep Recon readiness snapshot. The
informational command `bugslyce recon deep-readiness --json` prints the static
contract snapshot as JSON to stdout only. JSON mode uses the same profile
contract, bounds, planned pipeline, planned outputs, preflight gates, and
validation status as the Markdown renderer. It does not run Deep Recon, does
not read or write project files, does not execute commands, does not create
output files, and does not change mode availability.

Phase 78A adds a pure internal Deep Recon eligibility evaluator. The evaluator
converts explicit operator-provided facts into a deterministic eligibility
decision for future Deep gating. It does not run Deep Recon, does not inspect
targets, does not read or write project files, does not execute commands, does
not create output files, does not expose a CLI command, and does not change
mode availability.

Phase 78B exposes the eligibility evaluator through the informational command
`bugslyce recon deep-eligibility`. The command is stdout-only, fails closed by
default, and uses explicit operator-provided facts plus static contract
validation. `bugslyce recon deep-eligibility --json` prints the same decision
as deterministic JSON. The command does not run Deep Recon, does not inspect
targets, does not read or write project files, does not execute commands, does
not create output files, and does not change mode availability.

Phase 79A adds a pure internal Deep common metadata request planner. It plans
a bounded deterministic queue for common metadata files from explicit
in-scope HTTP service URLs, including `robots.txt`, `sitemap.xml`,
`security.txt`, `.well-known/security.txt`, `humans.txt`,
`crossdomain.xml`, `clientaccesspolicy.xml`, and `favicon.ico`. It does not fetch URLs, does not make network requests, does not read or write project
files, does not execute commands, does not expose a CLI command, and does not
change mode availability.

Phase 79B exposes the metadata planner through the informational command
`bugslyce recon deep-metadata-plan`. The command is stdout-only, accepts
explicit service URLs only with repeatable `--service-url`, and prints a
planned common metadata request queue without fetching it. `bugslyce recon deep-metadata-plan --json` prints the same static plan as deterministic JSON.
The command does not make network requests, does not inspect targets, does
not read or write project files, does not execute commands, does not create
output files, and does not change mode availability.

Phase 79C adds a pure internal adapter from already-loaded BugSlyce
project-state HTTP service, endpoint, HTTP artefact, and discovered-path data
into Deep metadata planning services. It operates on in-memory project state
only. It does not read project files, does not inspect targets, does not fetch
URLs, does not make network requests, does not write files, does not execute
commands, does not expose a CLI command, and does not change mode
availability.

Proposed future Deep output sections include:

- Deep Evidence Expansion Summary.
- Deep HTTP Service Matrix.
- Deep Route/Source Correlation.
- Deep Parameter Inventory.
- Deep Form Inventory.
- Deep Service/Technology Correlation.
- Deep Investigation Threads.
- Deep Manual Review Queue.
- Deep Scope and Safety Summary.

Deep Recon must remain unavailable until all of these gates exist:

- Documented Deep profile contract.
- Code-level planned profile contract and explicit bounds model.
- Explicit Deep bounds for requests, timeouts, depth, redirects, and body
  size.
- Tests proving Quick remains unchanged.
- Tests proving Standard remains unchanged.
- Tests proving Deep has explicit bounds.
- Tests proving Deep unavailable state is intentional until enabled.
- Tests proving no exploit, authentication, or form-submission behaviour is
  introduced.
- Safety grep/checklist coverage.
- Authorised lab smoke checklist.
- Report/runbook tests for Deep output once implemented.

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
- Phase 63C: specialised offline `robots.txt` analyser foundation.
- Phase 63D: specialised offline HTML/source analyser foundation.
- Phase 63E: offline interpretation aggregation model for analyser outputs.
- Phase 64A: offline Markdown renderer for interpretation review leads.
- Phase 64B: report integration contract for future manual review sections.
- Phase 64C: offline interpretation collector for already-collected evidence.
- Phase 65A: Standard Recon v1 wiring design while Standard remained
  unavailable.
- Phase 65B: offline evidence-to-`ArtefactSource` mapper for already-collected
  project evidence.
- Phase 65C: offline Standard interpretation assembly helper for future
  Standard Recon wiring.
- Phase 65D: internal Standard interpretation report helper for future report
  wiring.
- Phase 66A: Standard Recon v1 available with the existing bounded collection
  path plus offline Manual Review Leads in `report.md`.
- Phase 66B: Standard Manual Review Lead source-mapping hardening to avoid
  local storage paths and synthetic mapper wrappers becoming review leads.
- Phase 67A: Standard Manual Review Lead consolidation for related detector
  outputs on the same artefact.
- Phase 69A: Standard Investigation Threads foundation for grouping related
  offline review signals into manual investigation paths.
- Later Standard Recon: modest bounded collection additions after the v1
  interpretation wiring is implemented and reviewed.
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
Quick Recon maps to `lab-safe-tiny`. Standard Recon maps to
`standard-bounded`. Deep Recon remains planned and unavailable.

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

## Phase 63C Robots Analysis Note

Phase 63C adds a specialised offline `robots.txt` analyser foundation for
already-collected robots content. It parses common directives, preserves line
context, and can surface cautious review leads for unusual user-agents,
high-signal disallowed paths, clue-like comments, unknown directives, and
possible hash-shaped or encoded artefacts by reusing the artefact analysis
foundation.

This phase does not fetch `robots.txt`, does not enable Standard Recon, does
not enable Deep Recon, and does not change Quick Recon behaviour. It does not
add report, runbook, CLI, or evidence-pack integration.

## Phase 63D HTML/Source Analysis Note

Phase 63D adds a specialised offline HTML/source analyser foundation for
already-collected HTML. It can recognise comments, hidden elements,
hidden-style attributes, suspicious IDs/classes/names, local references,
unusual local file references, clue-like inline text, and possible
hash-shaped or encoded artefacts by reusing the artefact analysis foundation.

This phase does not fetch pages or assets, does not execute JavaScript, does
not enable Standard Recon, does not enable Deep Recon, and does not change
Quick Recon behaviour. It does not add report, runbook, CLI, or evidence-pack
integration.

## Phase 63E Interpretation Aggregation Note

Phase 63E adds an offline interpretation aggregation model for
already-collected artefact, `robots.txt`, and HTML/source analysis results. It
normalises analyser-specific review leads into one deterministic structure for
future report and runbook integration.

This phase does not fetch pages, assets, or `robots.txt`, does not enable
Standard Recon, does not enable Deep Recon, and does not change Quick Recon
behaviour. It does not add report, runbook, CLI, or evidence-pack integration.

## Phase 64A Interpretation Markdown Rendering Note

Phase 64A adds an offline Markdown renderer for already-created
interpretation review leads. It provides a deterministic, cautious rendering
layer for future Standard Recon reporting while preserving review-lead wording
and bounded raw values/previews.

This phase does not enable Standard Recon, does not enable Deep Recon, does
not change Quick Recon behaviour, and does not integrate with current reports,
runbooks, CLI output, or evidence packs.

## Phase 64B Report Integration Contract Note

Phase 64B adds a report integration contract that can accept a pre-rendered
Manual Review Leads Markdown section and place it deterministically in the
report. This is a seam for future Standard Recon interpretation output; it
does not analyse evidence or create review leads itself.

This phase does not enable Standard Recon, does not enable Deep Recon, does
not change Quick Recon behaviour, and does not integrate live interpretation
analysis into current reports, runbooks, CLI output, or evidence packs.

## Phase 64C Interpretation Collection Note

Phase 64C adds an offline interpretation collector for already-collected
evidence sources. It classifies provided `ArtefactSource` inputs as generic
text, `robots.txt`, or HTML/source content, runs the appropriate offline
analysers, aggregates review leads, and can render a Manual Review Leads
Markdown section for future report integration.

This phase does not fetch pages, assets, or `robots.txt`, does not enable
Standard Recon, does not enable Deep Recon, and does not change Quick Recon
behaviour. It does not wire interpretation collection into current reports,
runbooks, CLI output, evidence packs, or the live project pipeline.

## Phase 65B Evidence-to-ArtefactSource Mapping Note

Phase 65B adds an offline mapper from existing BugSlyce project evidence into
`ArtefactSource` objects. It uses already-assembled in-memory project state,
including structured HTTP artefacts and operator note evidence, and preserves
available source IDs, URLs, local source paths, ports, services, field names,
and bounded text values for later offline interpretation.

This phase does not fetch files, pages, assets, or `robots.txt`, does not
enable Standard Recon, does not enable Deep Recon, and does not change Quick
Recon behaviour. It does not call the interpretation collector, does not pass
Manual Review Leads into current reports, and does not alter runbooks, CLI
output, evidence packs, or the live project pipeline.

## Phase 65C Standard Interpretation Assembly Note

Phase 65C adds an offline Standard interpretation assembly helper for future
Standard Recon use. It chains existing project-state evidence mapping with the
offline interpretation collector so already-collected project evidence can be
turned into sources, review leads, and optional Manual Review Leads Markdown.

This phase does not enable Standard Recon, does not enable Deep Recon, does
not change Quick Recon behaviour, and does not wire Manual Review Leads into
current reports. It does not modify the project pipeline, recon execution,
runbooks, CLI output, evidence packs, or the interactive launcher.

## Phase 65D Standard Interpretation Report Helper Note

Phase 65D adds an internal Standard interpretation report helper that renders
an in-memory report with Manual Review Leads by using already-collected
project evidence, the Standard interpretation assembly helper, and the
existing report seam.

This phase does not enable Standard Recon, does not enable Deep Recon, does
not change Quick Recon behaviour, and does not write report files. It does not
modify the live project pipeline, recon execution, CLI output, runbooks,
evidence packs, or the interactive launcher.

## Phase 66A Standard Recon v1 Availability Note

Phase 66A enables Standard Recon v1 with internal profile
`standard-bounded`. Standard v1 reuses the existing bounded collection path
used by Quick Recon and adds offline interpretation of already-collected
evidence into `report.md` through the `## Manual Review Leads` section.

This phase does not increase scan volume, does not add bigger wordlists, does
not add recursive crawling, does not fetch extra pages, assets,
`sitemap.xml`, `security.txt`, JavaScript, or extra paths, and does not add
form submission, authentication testing, brute force, exploitation, or
vulnerability validation. Quick Recon behaviour and Quick reports remain
unchanged. Deep Recon remains unavailable.

## Phase 66B Standard Manual Review Lead Noise Reduction Note

Phase 66B hardens Standard Manual Review Lead source mapping so local artefact
storage paths, such as saved `robots.txt` file paths, are not interpreted as
robots directives. It also avoids creating review leads from synthetic HTML
wrappers invented by the mapper for compact parsed artefacts.

This phase does not change Quick behaviour, does not change Standard scan
volume, does not change live recon collection, and does not make Deep Recon
available.

## Phase 67A Standard Lead Consolidation Note

Phase 67A consolidates related Standard Manual Review Lead detector outputs
for the same artefact. For example, a `robots.txt` User-Agent value that is
both unusual and hash-shaped is rendered as one stronger review lead instead
of duplicate-looking robots leads.

This improves report readability while preserving source context, raw values,
related artefact types, and safe manual validation guidance. It does not
change Quick behaviour, does not change Standard scan volume, does not change
live recon collection, and does not make Deep Recon available.

## Phase 69A Standard Investigation Threads Note

Phase 69A adds Standard Investigation Threads. These threads group related
offline review signals into practical manual investigation paths, such as
high-port HTTP application review, discovered hidden-path review, and encoded
or source artefact review.

This improves operator workflow without changing live recon collection. Quick
behaviour is unchanged, Standard scan volume is unchanged, and Deep Recon
remains unavailable.

Phase 69B polishes the default Investigation Threads ordering so Standard
reports start with broader HTTP service context, then discovered content, then
encoded/source artefact interpretation. This is report workflow ordering only:
Quick behaviour is unchanged, Standard scan volume is unchanged, live recon
collection is unchanged, and Deep Recon remains unavailable.

Phase 70A aligns Standard runbooks with Investigation Threads. Standard
runbooks can surface a concise `## Standard Investigation Workflow` section
derived from offline Investigation Threads so operators have a practical manual
workflow alongside the report. This is offline report/runbook alignment only:
Quick behaviour is unchanged, Standard scan volume is unchanged, live recon
collection is unchanged, and Deep Recon remains unavailable.

Phase 71A adds project-level engagement context metadata. Supported stored
values are `unknown`, `ctf_lab`, `bug_bounty`, and `internal_authorised`.
This prepares future Standard interpretation for context-aware wording while
leaving Quick collection, Standard scan volume, live recon collection, and Deep
availability unchanged.

Phase 71B makes Standard wording engagement-aware. The stored engagement
context changes interpretation language and operator guidance only; it does not
change Quick collection, increase Standard scan volume, change live recon
collection, alter candidate generation or Investigation Thread ordering, or
make Deep Recon available.

Phase 72A adds Standard offline route/source review. It analyses route-shaped
strings and path/source references already present in local evidence only. It
does not fetch referenced routes, crawl, increase Standard scan volume, alter
Quick collection, or make Deep Recon available.

Phase 72B reduces Offline Route/Source Review noise by filtering common
HTML/default-page source references such as document type paths, local
filesystem documentation paths, and stock media attribution paths. It still
analyses local evidence only, does not fetch routes, and does not increase
Standard scan volume.

## Phase 80A Standard Human Triage Brief Note

Phase 80A adds a Standard Human Triage Brief and readable evidence cards to
Standard report output. The brief is deterministic, evidence-backed, and
universal across targets; it is not tailored to a specific CTF room, lab, IP,
or application. It gives operators a compact start-here view using generic signals such as login/admin/auth surfaces,
robots and metadata clues, directory listings, unusual source comments, encoded-looking artefacts,
interesting HTTP status context, notable HTTP services, high-value non-HTTP
service context, and low-value static/library noise.

Readable evidence cards summarise high-value evidence as terminal-friendly
bullet blocks before the wider raw evidence tables. The raw evidence tables
remain available for auditability, and the JSON export remains the structured
source of truth.

This is report UX only. It does not add recon execution behaviour, does not
fetch URLs, does not execute commands, does not replace manual validation,
does not increase Standard scan volume, does not change Quick behaviour, and
does not make Deep Recon available.
