# BugSlyce Post-WP4 WP5 Handover Source

**Date:** 30 August 2026
**Current public release:** `1.3.0`
**Immutable release tag:** `v1.3.0`
**Immutable release tag target:** `fc8f0febc809efd0540173b63af87945c500d028`
**Current authoritative development commit:** `1947671e539a3450189a5efa94a58fa776343ec0`
**Current authoritative commit subject:** `Integrate recursive evidence feedback`
**Current phase:** WP4 closed across Mint and Kali; product simplification and WP5 planning next
**Public release posture:** do not publish another version merely because the current implementation round passes internal acceptance
**Next major implementation package:** WP5, application/service graph and operator composition

## 1. Purpose and supersession

This file supersedes `BUGSLYCE_POST_FIELD_VALIDATION_IMPLEMENTATION_SOURCE_2026-08-28.md` as the current working source of truth for BugSlyce development after WP4.

Do not delete, rewrite, rename or retrospectively correct earlier source files. They remain the historical record of:

- how BugSlyce reached public `1.3.0`;
- the CTF/lab acceptance period;
- the holdout programme;
- the final v1.3 report and persistence work;
- genuine bug-bounty Field Cases 001 and 002;
- the bounty-first product reorientation;
- the post-field-validation implementation plan;
- WP1 through WP4 design, RED/GREEN and acceptance decisions.

This source freezes what has actually been implemented and accepted through WP4, records the product simplification decision made at the WP4 boundary, and defines the starting point for WP5.

The overall product objective remains:

> **BugSlyce should automate as much as practical of disciplined, repeatable and authorised bug-bounty reconnaissance, retain trustworthy evidence and provenance, build an understandable model of the programme and application surface, and surface worthwhile investigation context for a human operator.**

BugSlyce remains local-first, evidence-led and recon-only.

## 2. Immutable public v1.3.0 disposition

BugSlyce `1.3.0` remains public, accepted and historically closed.

Tag:

`v1.3.0`

Tag target:

`fc8f0febc809efd0540173b63af87945c500d028`

The tag must never be moved, recreated or amended.

The post-field-validation development line does not rewrite the published `1.3.0` release record.

No new public release should be made merely because WP4, WP5 or WP6 internal acceptance passes. A future release must be earned through controlled validation and genuine authorised field evidence.

## 3. Current repository identity

Authoritative development commit:

`1947671e539a3450189a5efa94a58fa776343ec0`

Parent:

`ec0dd9e174918a54d1f159ae751749fdedaf3f69`

Subject:

`Integrate recursive evidence feedback`

WP4A accepted commit:

`ec0dd9e174918a54d1f159ae751749fdedaf3f69`

WP4A subject:

`Add native bounded content discovery`

At WP4 closure:

- Mint `HEAD == origin/main == 1947671e539a3450189a5efa94a58fa776343ec0`;
- Kali `HEAD == origin/main == 1947671e539a3450189a5efa94a58fa776343ec0`;
- `v1.3.0` remains at `fc8f0febc809efd0540173b63af87945c500d028`;
- Mint worktree was clean after commit/push;
- Kali worktree was clean after pull/verification.

## 4. Validation state at WP4 closure

Final Mint acceptance:

- focused WP4 gate: **178 passed in 37.76s**;
- full repository suite: **4,378 passed in 220.68s**;
- `compileall`: green;
- tracked whitespace check: green;
- untracked whitespace checks before commit: green;
- complete production diff reviewed before acceptance.

Final Kali verification:

- exact accepted commit pulled by fast-forward;
- focused WP4 gate: **178 passed in 34.76s**;
- `compileall`: green;
- accepted commit whitespace check: green;
- final worktree clean.

No live bug-bounty or lab field validation has yet been performed against the newly integrated post-WP4 build.

Internal acceptance is therefore complete, but field validation of the improved build remains future work under WP6.

## 5. Work-package status

Current status:

- WP0: CLOSED;
- WP1: CLOSED;
- WP2: CLOSED;
- WP3: CLOSED;
- WP4: CLOSED;
- WP5: NOT STARTED;
- WP6: NOT STARTED.

### 5.1 WP1 - transport and evidence-flow correctness

WP1 closed the reproduced transport/evidence-retention issues required before higher-level reasoning could be trusted.

Key accepted outcomes include:

- full external failure diagnostics retained as artefacts while bounded previews remain operator-safe;
- redirects retained as neutral evidence rather than silently lost between project-state and Deep analysis;
- redirect evidence does not grant authorisation;
- no fabricated fingerprints or network follow-up merely to reconcile models.

### 5.2 WP2 - semantic extraction hygiene

WP2 closed the semantic JavaScript extraction hygiene package.

Accepted semantic route-supporting contexts are deliberately narrow:

- `request_call`;
- `route_configuration`.

Ordinary lexical strings and framework serialised state do not become route authority merely because they contain URL-like text.

React Flight and modern framework state are handled conservatively enough to reduce lexical noise without converting framework data into collection authority.

### 5.3 WP3 - programme-first policy, scope and authorised fanout

WP3 closed the programme-first authority model.

Accepted principles include:

- programme policy is authority;
- relationships are evidence, not authority;
- redirect destinations never inherit authorisation;
- exact runtime materialisation is required before HTTP work is executable;
- wildcard authorisation does not make an unmaterialised child origin executable;
- qualified scheme/port scope is enforced;
- exclusions take precedence;
- the programme graph is canonical and deterministic;
- ProjectState provides evidence for graph reconstruction but does not widen policy.

WP3 established the authority foundation consumed by WP4.

### 5.4 WP4A - BugSlyce-native bounded discovery

WP4A replaced the critical content-discovery trust-boundary ownership with BugSlyce-native collection.

The accepted native implementation owns:

- logical hostname;
- TLS hostname/SNI;
- peer identity;
- required identification headers;
- User-Agent;
- pacing;
- concurrency;
- redirect policy;
- terminal HTTP 429 state;
- programme-scope checks;
- exact materialised origins;
- negative-response calibration;
- response fingerprints;
- typed evidence;
- bounded diagnostics;
- deterministic output publication.

The normal runtime-backed project pipeline no longer depends on Gobuster to own these semantics.

### 5.5 WP4B - deterministic recursive evidence feedback

WP4B added one bounded second-pass collection decision driven by retained semantic evidence.

The intended pattern is now:

**native root collection -> initial Deep evidence -> semantic candidate selection -> programme/scope re-enforcement -> one bounded second pass -> expanded Deep evidence -> offline analysis**

There is no open-ended crawler and no recursive network loop.

## 6. Accepted WP4 native discovery architecture

Canonical runtime-backed step 007 is now BugSlyce-native.

For a policy-aware `BugBountyProjectRuntime`, the project pipeline:

1. builds current `ProjectState`;
2. builds canonical `ProgrammeOrchestrationPlan`;
3. builds a `NativeContentDiscoveryPlan`;
4. executes it with `run_native_content_discovery()`;
5. registers native content-discovery artefacts;
6. retains the exact root plan, native result and programme orchestration in pipeline context;
7. supplies those exact typed objects to the Deep recursive-feedback phase.

The accepted runtime state relationship remains:

**one BugBountyProjectRuntime -> one aggregate mutable HTTP enforcement state -> multiple exact-origin InternalHTTPExecutor views**

Do not:

- mutate runtime approved origins to authorise evidence-derived destinations;
- call `bind_http_origins()` merely to widen the strict runtime for a discovered child;
- mutate project target;
- fabricate child runtimes;
- create an independent equivalent HTTP enforcement boundary for recursive collection.

Evidence can justify considering a destination. Evidence never authorises it.

## 7. Current native root request limits

The current code still contains the historical three pipeline profiles.

Temporary WP4 mappings are:

### Quick

- content profile: `lab-root-tiny`;
- maximum candidate requests per origin: **25**;
- total native candidate-request ceiling: **4,096**.

### Standard

- content profile: `standard-bounded-core`;
- maximum candidate requests per origin: **220**;
- total native candidate-request ceiling: **4,096**.

### Deep

- content profile: `deep-bounded-core`;
- maximum candidate requests per origin: **1,753**;
- total native candidate-request ceiling: **4,096**.

These mappings are now considered transitional rather than a long-term three-mode product contract.

## 8. Product simplification decision: remove Quick and Standard

At the WP4 closure boundary, the preferred product direction changed deliberately.

**Quick and Standard are planned for removal.**

The reason is operator value, not implementation convenience.

The practical operator goal is:

> **If BugSlyce is run against an authorised target, return the fullest useful bounded reconnaissance the tool can safely provide on the first run.**

The current Deep workflow is the only existing mode that materially serves that goal.

Quick is considered too shallow to justify a normal reconnaissance run.

Standard provides more than Quick but still does not provide enough distinct operator value to justify a separate public mode when the operator would choose Deep instead.

The original shallow/deep distinction was more useful before BugSlyce had mature controls for:

- programme policy;
- exact authorised origins;
- scheme/port-qualified scope;
- pacing;
- concurrency;
- explicit request budgets;
- deterministic stop conditions;
- redirect refusal;
- shared terminal HTTP 429 behaviour.

With those controls now in place, the preferred future product shape is:

**one normal BugSlyce reconnaissance workflow based on the current Deep pipeline**

The word `Deep` itself may eventually become unnecessary because it should represent the normal run, not an exceptional aggressive mode.

Do not remove Quick or Standard casually inside unrelated WP5 architecture work. Their removal should be a deliberate, bounded simplification step with owner tests and CLI/profile cleanup.

Do not create new Quick/Standard-specific abstractions or features in the meantime.

If field use later demonstrates a need for a lightweight operation, it should have a distinct purpose such as:

- configuration validation;
- readiness/proving;
- policy/scope validation;
- connectivity/identity verification.

It should not be presented as a shallow reconnaissance mode merely to preserve the old three-profile structure.

## 9. Gobuster and external content engines

Gobuster no longer owns the canonical runtime-backed step-007 workload.

Do not describe Gobuster as fully removed yet.

Legacy code remains, including some combination of:

- runtime-less pipeline compatibility;
- historical content-planning/execution paths;
- parser/import compatibility;
- comparator-oriented code;
- old progress plumbing.

This is acceptable at the WP4 closure boundary because the critical architecture no longer depends on Gobuster for policy, SNI, pacing, redirects or scope.

The eventual preferred direction is:

- BugSlyce works normally without Gobuster being required;
- legacy runtime-less Gobuster execution can be removed when the old modes/paths are simplified;
- Gobuster or ffuf may remain optional specialist comparators only if future field evidence demonstrates useful value.

Do not spend substantial engineering effort improving or preserving Gobuster solely for historical compatibility.

The reproduced Gobuster HTTPS/SNI issue does not need a dedicated repair if the operational dependency is removed instead.

## 10. Legacy evidence-pack policy

Legacy BugSlyce evidence-pack compatibility is now explicitly **low priority**.

The only known holder of old BugSlyce evidence packs is the current project operator, and the preferred response to revisiting an old target is generally a fresh run with the improved BugSlyce rather than engineering around historical pack formats.

Therefore:

- do not spend significant engineering time on migration/adapters solely to reopen historical packs;
- do not let old pack compatibility constrain new architecture;
- compatibility that survives naturally and cheaply is welcome;
- historical parsers do not need to be deleted merely because they are old;
- if a future simplification conflicts with legacy-pack compatibility, operator usefulness and current evidence quality take priority unless there is a separate justified need.

This is a product-priority decision, not an instruction to deliberately break working compatibility.

## 11. Recursive evidence feedback contract

WP4B is currently Deep-only.

Accepted fixed limits:

- maximum depth: **1**;
- maximum total recursive candidate requests: **800**;
- maximum recursive candidate requests per origin: **100**;
- recursive negative-response baseline requests: **0**.

Only these retained semantic evidence classes may feed the current second-pass planner:

1. sitemap-declared canonical URL;
2. semantic JavaScript `request_call`;
3. semantic JavaScript `route_configuration`;
4. HTML route reference.

Current deterministic source priority is:

1. sitemap;
2. JavaScript `request_call`;
3. JavaScript `route_configuration`;
4. HTML.

Canonical duplicates collapse before request-budget allocation.

Supporting evidence IDs are unioned, sorted and deduplicated.

Current stop reasons include:

- `already_collected`;
- `depth_exhausted`;
- `query_string_not_allowed`;
- `missing_evidence_provenance`;
- `evidence_not_retained`;
- `programme_scope_blocked`;
- `programme_scope_unknown`;
- `unmaterialised_origin`;
- `per_origin_limit_exceeded`;
- `total_request_limit_exceeded`.

Wildcard-authorised but unmaterialised child origins receive no request.

Query-string candidates are currently suppressed.

A redirect never grants authority to its destination.

The planner does not infer application conclusions merely from candidate presence.

## 12. Exact recursive execution and provenance

The recursive execution phase reconstructs the expected canonical plan from the exact typed inputs before making contact.

The accepted inputs include:

- runtime;
- ProjectState;
- ProgrammeOrchestrationPlan;
- exact NativeContentDiscoveryPlan;
- DeepMetadataCollectionResult;
- DeepHtmlRouteExtractionResult;
- DeepJavaScriptRouteExtractionResult.

The supplied/internal HTTP executor must share the same aggregate enforcement state and policy/resolver semantics as the runtime.

Each selected request is one bounded GET.

External application commands started by WP4B:

`0`

Typed HTTP 429 and transport failure behaviour propagates rather than being rewritten as successful or complete coverage.

## 13. Recursive response evidence retained

Each accepted recursive response retains:

- exact recursive request;
- status code;
- final URL;
- canonical headers;
- bounded body;
- body byte length;
- body SHA-256;
- exact measured HTTP elapsed time;
- evidence IDs.

The timing chain is explicitly preserved:

**InternalHTTPResponse.elapsed_seconds -> RecursiveEvidenceFeedbackCollectedResponse.elapsed_seconds -> DeepSourceRouteCollectedItem.elapsed_seconds**

No replacement `0.0`, rounding step or second clock is used to satisfy downstream models.

Recursive responses are adapted into the existing Deep source collection model.

The expanded Deep source collection is written using the existing Deep source collection artefacts.

Step 011D then performs offline orchestration against the expanded source collection.

A route learned from recursive content can therefore become useful offline evidence without being automatically requested again.

This is how the frozen Deriv-style `/docs/websocket` -> `/api/websocket` oracle is represented without creating a depth-two request.

## 14. Resume correction accepted during WP4 integration

The first WP4 integration GREEN exposed a real resume regression during actual source review.

Initial problem:

- native step 007 produced `content-discovery-internal-...` artefacts;
- resume detection still recognised only `gobuster-tiny-...` artefacts;
- a valid native step 007 could therefore appear absent;
- later step 008/009 artefacts could then make the existing state look like an incoherent pipeline prefix.

The issue was reproduced in a focused RED test before correction.

Accepted correction:

- current `content-discovery-internal-...` artefacts are recognised for step-007 resume detection;
- recognition remains constrained to recon-manifest artefacts already validated as existing files within the project output directory;
- old Gobuster recognition remains temporarily;
- phase-order validation was not weakened.

This correction exists for truthful resume behaviour of the current native pipeline. It is not a new commitment to historical Gobuster compatibility.

## 15. Field evidence that still drives the roadmap

The frozen cross-case synthesis remains:

`/home/rayza/bugslyce-output/field-validation-synthesis/field-001-002-synthesis.md`

SHA-256:

`8fa92c53a3ad2a0acb02abb5ca96c9adaac396cacac6efc52384bce6122530bc`

### 15.1 Whatnot

Field Case 001 demonstrated, among other things:

- modern bounty reconnaissance needs correct hostname/SNI semantics;
- manual JavaScript review materially expanded the application model;
- generic route/framework observations are less useful than semantic application relationships;
- edge/WAF behaviour can be path dependent;
- operator priorities should reflect investigation value rather than lexical novelty.

### 15.2 Deriv

Field Case 002 demonstrated, among other things:

- programme-wide scope and policy must be modelled before fanout;
- a wildcard does not automatically authorise the apex;
- required researcher-identification headers are trust-boundary inputs;
- redirects to unauthorised destinations must be refused;
- documentation can reveal high-value application/service topology;
- sitemap evidence can justify a bounded second collection decision;
- a single evidence-backed documentation GET materially expanded the service model;
- application understanding requires relationships between documentation, REST, authentication and realtime/WebSocket surfaces.

No WebSocket connection was attempted in the field case.

## 16. WP5 next: application/service graph and operator composition

WP5 is the next major production-development package.

Do not start WP5 by adding more collection merely because additional URLs are available.

WP5 should turn trustworthy deterministic evidence into a useful application/service model.

The core direction remains typed, provenance-aware relationships such as:

- origin -> redirects to -> origin;
- documentation -> describes -> service;
- service -> exposes -> route family;
- REST endpoint -> issues credential for -> WebSocket/realtime connection;
- authentication mechanism -> requires -> application identifier;
- authentication mechanism -> requires -> OAuth scope;
- sitemap -> declares -> route;
- JavaScript asset -> references -> service/route when semantic context supports it.

Operator-facing composition should organise evidence into meaningful surfaces such as:

- authentication/account;
- API/service;
- WebSocket/realtime;
- trading/commerce;
- seller/order;
- admin/operations;
- redirect/return-target;
- documentation/developer surface.

The goal is not a prettier URL list.

The goal is an operator-understandable model of what the application appears to consist of, how the surfaces relate, what evidence supports each relationship, what is direct documentation versus direct observation, and where inference begins.

## 17. WP5 evidence-language requirements

WP5 must preserve clear distinctions among:

- direct evidence;
- direct documentation;
- deterministic relationship derived from direct evidence;
- inference/hypothesis;
- operator recommendation;
- coverage limitation.

Do not collapse these into one generic finding type.

A documented API requirement is not the same as a directly observed runtime behaviour.

A route reference is not the same as a reachable vulnerability.

A service relationship is not authorisation for more collection.

A BugSlyce lead remains an investigation aid, not a confirmed vulnerability.

## 18. WP5 ranking/composition objective

WP5 should rank semantic architecture and investigation value above framework/lexical noise.

Examples of higher-value composition include:

- authentication/bootstrap flows;
- API family topology;
- application identifiers required by a service;
- documented OAuth scopes;
- REST-to-WebSocket bootstrap relationships;
- seller/order or trading/commerce route families;
- redirect/return-target relationships;
- developer/documentation surfaces describing live services.

Framework serialisation, generic chunk paths and ordinary lexical strings should not dominate merely because they are numerous.

Analysis Coverage should explain meaningful limits in what BugSlyce collected and understood, not only implementation-centric counters.

## 19. Frozen WP5 manual acceptance oracles

WP5 owns the Whatnot and Deriv operator-understanding oracles from the 28 August source.

### 19.1 Whatnot oracle

On frozen Whatnot evidence, the operator should gain materially better understanding of the application/service surface than from the current generic ranked route list.

The composition should prioritise application semantics and worthwhile investigation context over generic framework artefacts.

### 19.2 Deriv oracle

On frozen Deriv evidence, the operator should be able to understand relationships including the documented options/realtime surface rather than seeing unrelated strings and routes.

The frozen evidence includes direct documentation of concepts such as:

- API base `https://api.derivws.com`;
- authenticated REST bootstrap endpoint `/trading/v1/options/accounts/{accountId}/otp`;
- `Deriv-App-ID`;
- Bearer authentication;
- OAuth2 `trade` scope;
- short-lived single-use OTP bootstrap;
- authenticated WebSocket URL form;
- public unauthenticated WebSocket endpoint `wss://api.derivws.com/trading/v1/options/ws/public`.

These are documentation-derived facts from the authorised field evidence. They do not authorise WebSocket interaction or exploitation.

WP5 should represent such relationships truthfully and provenance-aware.

## 20. Quick/Standard removal relative to WP5

Quick/Standard removal is now a deliberate product simplification that should be addressed at or immediately before the start of WP5 implementation, not forgotten indefinitely.

The preferred sequence in the fresh thread is:

1. review this source;
2. inspect the current profile/CLI ownership and identify the smallest safe removal boundary;
3. decide whether Quick/Standard removal should be a short pre-WP5 cleanup package or the first bounded WP5-adjacent simplification;
4. reproduce/freeze any behaviour that must remain for the single normal run;
5. remove obsolete modes without expanding feature scope;
6. ensure the normal run retains current Deep capabilities and safety controls;
7. then begin the substantive WP5 application/service graph work.

Do not preserve Quick/Standard merely because tests or historical CLI names exist.

Do not turn their removal into a large compatibility project.

## 21. WP6 after WP5

WP6 remains acceptance, Kali verification and the second field cycle.

Expected sequence:

1. focused final owner gates on Mint;
2. full repository suite;
3. `compileall`;
4. `git diff --check`;
5. complete final diff review;
6. explicit approval before commit/push;
7. commit/push from Mint;
8. pull the exact approved commit on Kali;
9. verify runtime/repository identity;
10. run frozen/offline acceptance replay;
11. run controlled authorised labs;
12. run selected genuine authorised bounty field validation;
13. compare reliability, evidence quality, operator usefulness and experience against Field Cases 001 and 002;
14. classify new issues from field evidence before proposing further changes.

Do not publish a new public version merely because these internal gates pass.

The improved build must earn a release through field evidence.

## 22. Product boundary remains recon-only

BugSlyce v1 remains in scope for:

- authorised target reconnaissance;
- bounded service and HTTP collection;
- bounded native content discovery;
- deterministic semantic extraction;
- evidence retention and provenance;
- typed relationships;
- operator-prioritised investigation support;
- offline Markdown/HTML composition;
- evidence-pack export.

Outside BugSlyce v1:

- exploitation;
- active vulnerability testing;
- brute force;
- credential attacks;
- arbitrary form submission;
- payload delivery;
- vulnerability confirmation;
- post-exploitation;
- privilege escalation;
- WebSocket interaction merely because documentation mentions a WebSocket endpoint.

Collection evidence and application modelling must not silently broaden this boundary.

## 23. Evidence-led change control

Continue to classify observations as appropriate:

- direct evidence;
- inference;
- collection miss;
- reasoning/integration miss;
- attention/ranking miss;
- operator usability problem;
- reliability problem;
- possible product improvement;
- expected product boundary;
- comparator-only discovery;
- outside-v1 scope.

Do not suggest production code changes for a newly observed issue until it has been reproduced and classified.

Do not reopen previously closed issues merely because nearby code is being edited.

Do not add opportunistic features that are not justified by the active work package or field evidence.

## 24. Engineering workflow

### 24.1 Mint

Development occurs on Linux Mint.

Repository:

`~/projects/bugslyce`

Use Mint for:

- source inspection;
- RED/GREEN implementation;
- focused tests;
- owner/regression tests;
- full-suite acceptance;
- actual diff review;
- commits;
- pushes.

No live reconnaissance on Mint.

### 24.2 Approval and commit discipline

For substantive changes:

1. define the evidence-backed objective;
2. freeze/reproduce the RED contract where needed;
3. provide a focused Codex prompt only when Codex is useful;
4. run code/tests on Mint;
5. review the actual diff and test results;
6. obtain explicit approval before commit/push;
7. commit/push from Mint only after approval.

Codex is an implementation assistant, not the source of product direction.

### 24.3 Kali

Kali is used after approved commit/push for:

- pulling the exact accepted commit;
- verification;
- controlled labs;
- genuine authorised bounty field recon.

Repository:

`~/projects/bugslyce`

Kali SSH transfer address unless changed:

`192.168.122.43`

For large terminal output, redirect to a text file rather than requiring manual QTerminal selection.

## 25. Command-delivery rules

Operational guidance must continue to follow these rules:

- label command blocks **Mint** or **Kali** outside the block;
- number multiple command blocks;
- keep command blocks clean;
- never present a superseded runnable block and then reuse the same step number;
- if a block is superseded, mark it **DO NOT RUN**;
- do not use bare `exit` in interactive terminal guidance;
- do not use `set -e` or deliberate non-zero abort commands that can close an interactive terminal;
- prefer guards that print refusal and leave the shell alive;
- write potentially large output to a file;
- use UK English;
- spell `artefact`;
- avoid em dashes in project documents.

## 26. Model/Codex policy

Use the lowest model and reasoning tier sufficient for the work.

General guidance:

- documentation, handovers and deterministic small local work: do locally or use a lower tier;
- narrow deterministic correction: Terra High or lower when sufficient;
- ordinary coherent multi-file implementation: Sol Medium when sufficient;
- architecture, trust-boundary, persistence or scope redesign: Sol High;
- exceptional maximum reasoning only when the risk and complexity truly justify it.

Conserve Codex allowance.

Do not use Codex merely to restate project direction that is already known in the ChatGPT project context.

## 27. Deliberate deferrals and cleanup candidates

The following are not implemented merely because they are listed here:

- remove Quick mode;
- remove Standard mode;
- collapse the current Deep workflow into the normal/default BugSlyce run;
- consider a distinct validation/proving operation only if field need exists;
- remove the canonical need for the runtime-less Gobuster execution path;
- decide later whether Gobuster/ffuf remain useful optional specialist comparators;
- legacy evidence-pack migration/adapters remain low priority;
- recursive depth greater than 1 is deferred;
- query-string recursive collection is deferred;
- WebSocket interaction is deferred;
- broad passive/CT asset discovery remains deferred until deliberately revisited;
- browser/anti-bot assistance remains deferred;
- GUI/dashboard work remains deferred;
- AI-assisted interpretation remains optional and subordinate to deterministic evidence;
- generic resume persistence redesign is not required by current evidence;
- exploitation and active vulnerability testing remain excluded.

## 28. Immediate next task

Do not begin another field run yet.

Do not publish another version.

Start a fresh BugSlyce project conversation using this source as the current development contract.

The fresh thread should first:

1. confirm repository identity and WP1-WP4 closure;
2. confirm the Quick/Standard removal decision and legacy-pack priority;
3. inspect the smallest safe product boundary for collapsing to one normal reconnaissance workflow;
4. determine whether that simplification is best performed as a short pre-WP5 package or as the first bounded step adjacent to WP5;
5. then define the WP5 RED/ownership plan for application/service graph and operator composition.

Do not jump straight to a large WP5 Codex prompt before the fresh thread has reviewed this source and current ownership.

## 29. Fresh-thread handover prompt

Use the following as the starting context for the next ChatGPT project conversation:

> We are continuing BugSlyce, a local-first, evidence-led, recon-only authorised reconnaissance and triage tool. Read and treat `BUGSLYCE_POST_WP4_WP5_HANDOVER_SOURCE_2026-08-30.md` as the current source of truth. Earlier source files remain historical records and must not be rewritten. Current repo is `~/projects/bugslyce`. Authoritative `HEAD == origin/main == 1947671e539a3450189a5efa94a58fa776343ec0` (`Integrate recursive evidence feedback`), and immutable `v1.3.0` remains at `fc8f0febc809efd0540173b63af87945c500d028`. WP1, WP2, WP3 and WP4 are closed. WP4 final Mint acceptance was 178 focused tests plus 4,378 full-suite tests green; Kali pulled the exact commit and passed the 178-test focused gate, compileall and whitespace checks. WP5 has not started. WP6 follows WP5 and owns final acceptance plus the second authorised field cycle. WP4 established BugSlyce-native runtime-backed root discovery and one Deep-only deterministic depth-one recursive evidence pass. Gobuster no longer owns the canonical step-007 workload, although legacy/runtime-less code remains. Product direction has now simplified: Quick and Standard are planned for removal because the operator wants the fullest useful bounded reconnaissance on the first run; the current Deep workflow should become the single normal BugSlyce run. Legacy evidence-pack compatibility is low priority and should not consume substantial engineering effort. First review the source and current profile/CLI ownership, then decide the smallest safe boundary for removing/collapsing Quick and Standard before substantive WP5 work. WP5 objective is typed provenance-aware application/service relationships and operator composition that materially improves the frozen Whatnot and Deriv operator-understanding oracles, while preserving direct evidence versus documentation versus inference. Do not add exploitation or active vulnerability testing. Development is on Mint; review actual diffs/tests and obtain explicit approval before commit/push; Kali is for exact-commit verification and authorised live validation. Use UK English and spell `artefact`. Do not begin implementation until you have reviewed this source and proposed the next concrete, bounded planning step.

## 30. Current one-line status

**BugSlyce is internally accepted through WP4 at commit `1947671e539a3450189a5efa94a58fa776343ec0`; native bounded discovery and one deterministic evidence-led recursive pass are now integrated and verified on Mint and Kali, Quick/Standard are planned for removal in favour of one normal full reconnaissance workflow, and the next substantive product task is WP5 application/service graph and operator composition before a second controlled field-validation cycle.**
