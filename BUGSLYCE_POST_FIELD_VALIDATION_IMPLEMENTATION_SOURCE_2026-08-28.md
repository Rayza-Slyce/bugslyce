# BugSlyce Post-Field-Validation Implementation Source

**Date:** 28 August 2026
**Current public release:** `1.3.0`
**Immutable release tag:** `v1.3.0`
**Immutable release tag target:** `fc8f0febc809efd0540173b63af87945c500d028`
**Current phase:** evidence-backed bounty-first implementation planning and controlled development
**Development state:** Field Case 001 and Field Case 002 live reconnaissance closed; first improvement round authorised subject to the work-package gates in this source
**Public release posture:** do not publish another version merely because the first improvement round completes
**Long-term direction:** earn a genuinely useful bounty-first major release through implementation, Kali verification and further authorised field validation

## 1. Purpose and supersession

This file supersedes `BUGSLYCE_POST_V1_3_BOUNTY_FIRST_PRODUCT_DIRECTION_SOURCE_2026-08-27.md` as the current working source of truth for BugSlyce.

Do not delete or rewrite earlier source files. They remain the historical record of:

- how BugSlyce reached public `1.3.0`;
- the original CTF/lab-oriented acceptance model;
- the holdout series;
- the v1.3 report and persistence work;
- the first genuine bug-bounty field-validation methodology;
- the product reorientation that followed Field Case 001.

The field-validation phase that source described is now complete enough to authorise implementation.

The primary frozen cross-case synthesis is:

`/home/rayza/bugslyce-output/field-validation-synthesis/field-001-002-synthesis.md`

Frozen SHA-256:

`8fa92c53a3ad2a0acb02abb5ca96c9adaac396cacac6efc52384bce6122530bc`

That synthesis is the evidence contract for this improvement round. This source converts that evidence into a practical development sequence.

The project objective is now:

> **Build an improved BugSlyce that automates a materially useful portion of an experienced bug-bounty hunter's first one or two hours of authorised reconnaissance, while preserving BugSlyce's strongest properties: policy fidelity, fail-closed scope, deterministic evidence, provenance, bounded execution and operator-understandable reasoning.**

## 2. Immutable public v1.3.0 disposition

BugSlyce `1.3.0` remains public, accepted and closed.

Tag:

`v1.3.0`

Tag target:

`fc8f0febc809efd0540173b63af87945c500d028`

The tag must never be moved, recreated or amended.

Final release-record validation was:

- full pytest: **4,271 passed**;
- `compileall`: clean;
- `git diff --check`: clean;
- fresh authorised Blog and Skynet acceptance passed;
- public PyPI Kali acceptance passed.

Published artefacts remain:

Wheel:

`bugslyce-1.3.0-py3-none-any.whl`

SHA-256:

`36e5f4e37a6530fa94090f9b19f490ed0f0b255f09b7e47b37f40a6fd0b129d1`

Source distribution:

`bugslyce-1.3.0.tar.gz`

SHA-256:

`928f6e2f82a1340c146156663f036f8a3b1e99d36b100682a696b0829f327f50`

Field validation does not invalidate the release. It establishes that the public version is useful for CTF/lab and bounded host-oriented reconnaissance but is not yet a mature modern bounty reconnaissance product.

No cosmetic patch release should be created to hide that fact.

## 3. Product identity and current boundary

BugSlyce remains a **local-first, evidence-led authorised reconnaissance and triage tool**.

Current conceptual architecture:

**Programme policy and scope -> bounded collection -> typed evidence -> relationships -> coverage -> application model -> operator-facing investigation priorities**

The first improvement round remains reconnaissance-focused.

Still outside the current product boundary:

- exploitation;
- active vulnerability confirmation;
- arbitrary form submission;
- credential attacks;
- brute force;
- destructive testing;
- payload delivery;
- post-exploitation;
- privilege escalation;
- unapproved anti-bot or access-control circumvention.

A BugSlyce lead remains an investigation lead, not a confirmed vulnerability.

## 4. Why the product direction changed

BugSlyce evolved successfully through CTFs and labs. That made the old practical design centre approximately:

**single host -> ports/services -> HTTP -> content discovery -> static clues -> ranked leads**

That model worked well against many learning environments but underperformed on genuine modern bounty targets where useful reconnaissance depends more heavily on:

- programme-scale asset relationships;
- wildcard and exclusion rules;
- CDN/WAF/edge behaviour;
- hostname/SNI-sensitive HTTPS routing;
- modern JavaScript applications;
- Next.js and framework state;
- large route corpora;
- APIs and service origins;
- redirects and cross-origin relationships;
- authentication and OAuth surfaces;
- WebSocket relationships;
- iterative collection based on later discoveries.

The new primary acceptance question is therefore:

> **Would an experienced bounty hunter find BugSlyce materially useful during the first one or two hours of reconnaissance against a real authorised programme?**

Raw evidence count, raw URL count and CTF success are secondary measurements.

## 5. Closed field-validation cases

### 5.1 Field Case 001 - Whatnot

Field Case 001 used public BugSlyce `1.3.0` against the explicitly authorised Whatnot HackerOne programme, intentionally restricted to `www.whatnot.com` for the initial baseline.

The narrow scope later proved to be a methodological limitation for evaluating a bounty-first programme workflow, but it produced important transport, application-surface and operator-attention evidence.

Key direct outcomes included:

- Deep bounded collection completed enough to produce a report and evidence pack;
- strict Gobuster content discovery failed;
- direct controlled comparison showed hostname HTTPS transport worked while IP-targeted strict Gobuster transport failed TLS;
- ffuf completed the bounded workload that strict Gobuster could not;
- BugSlyce retained substantial application evidence but surfaced little of the useful application topology to the operator;
- manual JavaScript/source review materially expanded the application model;
- broad lexical route/GraphQL extraction produced false semantic candidates;
- path-dependent edge/WAF behaviour was observed;
- large-body bounds excluded some useful modern application responses.

The frozen manual Whatnot acceptance oracle includes materially understanding service relationships around:

- `/services/api`;
- `/services/auction`;
- `/services/graphql`;
- `/services/live`;
- login/register/authentication paths;
- GraphQL-related paths;
- a broad route map;
- account, order, seller, live and operational route families.

Exact reproduction of every manually discovered string is not required. Materially equivalent operator understanding is required.

### 5.2 Field Case 002 - Deriv

Field Case 002 used the Deriv HackerOne programme as a programme-first test rather than a single-host comparison.

The frozen programme evidence established:

- required header: `X-HackerOne-Research: rayza_slyce`;
- conservative BugSlyce pacing retained at 2 requests/second, concurrency 1 because v1.3 could not represent an operator-selected higher rate without mislabelling its provenance;
- important named assets including `app.deriv.com`, `smarttrader.deriv.com`, `cashier.deriv.com`, `oauth.deriv.com`, `api.deriv.com`, `derivws.com` and others;
- wildcard families including `*.deriv.com`, `*.deriv.cloud` and `*.derivws.com`;
- explicit exclusions retained from the programme;
- `*.deriv.com` does not automatically authorise the apex `deriv.com`.

Representative programme targets and discovered relationships produced the following evidence:

#### `app.deriv.com`

Both roots redirected to `https://deriv.com/`.

Because the apex was not positively authorised by the frozen programme scope used for automated reconnaissance, BugSlyce correctly failed closed and refused continuation.

#### `smarttrader.deriv.com`

Redirected to `https://dsmarttrader.deriv.com/`, which matched the programme wildcard.

BugSlyce v1.3 could not dynamically materialise that authorised child within the same programme graph, so the child had to be manually validated and materialised as a separate project.

The child then reproduced the strict HTTPS/SNI Gobuster defect.

#### `api.deriv.com`

Redirected to `https://developers.deriv.com/`.

The destination matched programme wildcard scope but again had to be manually validated and materialised as a separate project.

#### `developers.deriv.com`

This was a high-value modern application surface.

Direct retained evidence included:

- title `Deriv API`;
- Next.js application context;
- `/playground/`;
- `/ai-hub/`;
- `/app-builder/`;
- `/docs/`;
- `/comparison/`;
- a large sitemap;
- around 210 HTML routes in Deep orchestration;
- account/authentication/OAuth documentation;
- trading/options/payment-agent/wallet/market-data route families;
- WebSocket-related documentation routes.

BugSlyce's Operator Brief nevertheless prioritised a weak encoded/hidden HTML artefact thread instead of the substantive application architecture.

A later offline audit showed that sitemap-derived high-value routes did not feed back into a second bounded collection decision.

One manual bounded GET of the already-discovered route:

`https://developers.deriv.com/docs/options/websocket/`

returned direct documentation of:

- API base `https://api.derivws.com`;
- authenticated REST operation `POST /trading/v1/options/accounts/{accountId}/otp`;
- `Deriv-App-ID` requirement;
- Bearer authentication;
- OAuth2 scope `trade`;
- a short-lived single-use OTP bootstrap for WebSocket connection;
- documented authenticated WebSocket URL form;
- public unauthenticated WebSocket endpoint `wss://api.derivws.com/trading/v1/options/ws/public`.

No WebSocket connection was attempted.

#### `derivws.com`

HTTP behaviour was a redirector, not direct evidence of a WebSocket endpoint.

Root evidence contained 301 + Location relationships, while downstream Deep redirect analysis reported zero redirects. This reproduced the redirect handoff defect.

#### `api.derivws.com`

The documented API host returned a clean HTTP 404 at `/` and the same conventional 19-byte negative for generic metadata paths and synthetic negatives.

Its service role came from the documented application relationship, not from an interesting homepage.

This demonstrated that service relationships must survive even when a root looks empty.

#### `oauth.deriv.com`

Both HTTP and HTTPS roots redirected to `https://deriv.com/`.

BugSlyce correctly refused to follow the unapproved apex.

Again, downstream redirect analysis reported zero redirect observations despite retained 301 + Location evidence, and the Operator Brief reduced the result to a generic multiple-HTTP-services thread.

Field Case 002 live reconnaissance is closed.

## 6. Safety and evidence invariants that must not regress

The first improvement round is not allowed to trade away BugSlyce's strongest v1.3 properties.

The following are release invariants.

### 6.1 Fail-closed scope

BugSlyce must refuse collection where a destination is not positively authorised.

Authorisation does not travel with a redirect.

An in-scope origin redirecting to another origin does not make the destination authorised.

### 6.2 Programme identity requirements

Required researcher-identification headers must continue to be applied exactly where policy requires them.

### 6.3 Bounded execution

Request rate, concurrency, depth and request budgets must remain explicit and enforceable.

### 6.4 Evidence provenance

Direct observations, direct documentation, deterministic relationships and inference must remain distinguishable.

### 6.5 Artefact retention

Raw artefacts and machine-readable evidence must remain available for audit and evidence-pack export, including when later stages fail.

### 6.6 Failure truthfulness

A stage that cannot proceed safely must say so rather than fabricating coverage.

### 6.7 No protocol inference from names alone

Hostnames such as `oauth.*` or `*ws*` are hints, not direct evidence of protocol or application role.

## 7. Reproduced defect and limitation register

### 7.1 `STRICT-HTTPS-SNI`

**Status:** reproduced cross-case collection defect.

Strict HTTPS Gobuster transport substitutes selected IPv4 peer as the request authority and supplies Host separately, preserving HTTP virtual-host semantics but losing TLS hostname/SNI semantics.

Controlled comparisons on Whatnot and Deriv showed hostname HTTPS worked while the strict IP-targeted Gobuster request failed TLS handshake.

**Required result:** preserve logical hostname/SNI and peer identity as separate concepts.

### 7.2 External collector diagnostics loss

Relevant field identifiers include `FIELD-001-DIAG-01` and `FIELD-002-DIAG-01`.

**Status:** reproduced cross-case diagnostic defect.

Project/report output often retained only `gobuster exited with code 1`, while the underlying direct tool stderr contained the actionable TLS cause.

**Required result:** retain exit status, actionable stderr and relevant execution context without manual comparator reproduction.

### 7.3 `FIELD-002-REDIRECT-HANDOFF-01`

**Status:** reproduced analysis-integration defect.

Root evidence retained HTTP 301 + Location, but downstream redirect/auth-flow analysis reported zero redirects on multiple Deriv targets.

**Required result:** redirect relationships survive collection, persistence, semantic analysis and operator composition.

### 7.4 `FIELD-002-NEXT-ROUTE-01`

**Status:** reproduced route-extraction defect.

Next.js/React Flight serialised state was promoted into route candidates and apparent same-origin URLs.

**Required result:** classify framework/source context before treating strings as application routes.

### 7.5 `FIELD-001-JS-SEMANTICS-01`

**Status:** reproduced semantic-extraction defect.

Broad lexical/regex JavaScript analysis produced false route/GraphQL candidates from strings lacking application-endpoint semantics.

**Required result:** contextual/syntactic extraction strong enough to distinguish meaningful configuration/executable references from lexical noise.

### 7.6 `FIELD-002-SITEMAP-FEEDBACK-01`

**Status:** reproduced material collection/reasoning limitation.

BugSlyce discovered a high-value sitemap route corpus but did not feed later discoveries into a new bounded collection decision.

A single bounded follow-up to an already-known WebSocket documentation route materially expanded the operator's service model.

**Required result:** explicitly bounded recursive intelligence with scope, depth, pacing, provenance and request-budget controls.

### 7.7 `FIELD-ATTENTION-01`

Field-specific identifiers include `FIELD-001-ATTENTION-01` and `FIELD-002-ATTENTION-01`.

**Status:** reproduced cross-case operator-attention defect.

Generic multiple-service or encoded/hidden artefact threads repeatedly displaced more useful application topology.

**Required result:** application architecture and actionable relationships outrank generic lexical/framework oddities.

### 7.8 `FIELD-APP-SURFACE-01`

Field-specific identifiers include `FIELD-001-APP-SURFACE-01` and `FIELD-002-APP-SURFACE-01`.

**Status:** reproduced cross-case application-surface composition defect.

BugSlyce retained enough evidence for a useful application model but did not compose it into one.

**Required result:** coherent application/service surfaces with provenance and operator-relevant next steps.

## 8. Programme-scale architecture limitations supported by field evidence

These are not single-line bugs. They are current architecture limitations that materially harmed bounty usefulness.

### 8.1 `FIELD-002-POLICY-RATE-01`

BugSlyce cannot faithfully represent an operator-selected rate above the conservative built-in default without labelling it as programme-published.

Future policy provenance must distinguish:

- programme-published limit;
- operator-selected conservative limit;
- BugSlyce default limit.

### 8.2 `FIELD-002-SCOPE-MODEL-01`

The current model cannot faithfully represent port-constrained wildcard HTTP programme scope.

Future rules need combinations of:

- hostname exact/wildcard;
- protocol;
- port;
- path;
- include/exclude;
- eligibility/disposition where useful.

### 8.3 `FIELD-002-PROGRAMME-UX-01`

A real programme had to be manually decomposed into many isolated projects.

The long-term bounty workflow needs programme ingestion and programme-level work orchestration.

### 8.4 `FIELD-002-PROGRAMME-RELATION-01`

Authorised relationships became disconnected when programme assets were isolated into separate projects.

### 8.5 `FIELD-002-PROGRAMME-FANOUT-01`

The v1.3 runtime intentionally seeds only the selected target hostname.

That is safe for a single-target architecture but insufficient for a programme graph where authorised child assets are discovered during reconnaissance.

### 8.6 `FIELD-002-DYNAMIC-SCOPE-01`

BugSlyce can store wildcard and exact scope rules but does not currently validate an observed child against the programme and materialise an exact authorised runtime origin automatically.

The desired future transition is:

**observed/documented relationship -> evaluate include/exclude/protocol/port -> materialise exact authorised origin -> continue within remaining budget**

If validation fails or remains ambiguous, stop and explain why.

## 9. Watch items and deliberately deferred classifications

### 9.1 `FIELD-002-PROTOCOL-MODEL-01`

Explicit WebSocket topology was established from a manually fetched route that BugSlyce had discovered but had not itself collected.

It is therefore not yet proven how v1.3 handles explicit `wss://` evidence entering the normal pipeline.

Status: **WATCH**.

Do not manufacture a production defect until normal-pipeline reproduction exists.

### 9.2 Large-response handling

Field Case 001 showed useful modern application responses exceeding current body bounds.

Status: **review candidate**.

Do not simply raise limits without preserving memory, disk and evidence-budget safety.

### 9.3 Edge/challenge/browser assistance

Path-dependent Cloudflare/WAF behaviour and user-agent differences were observed.

Status: **future capability candidate**.

Do not implement anti-bot circumvention.

Browser-assisted collection may later be considered where programme-authorised and where it preserves evidence/scope controls.

### 9.4 Passive/CT asset discovery

Programme-scale passive discovery, including Certificate Transparency-derived assets, remains a serious bounty-first future candidate.

It is not required in the first implementation package unless source/design review shows it is necessary to satisfy the programme-graph foundation.

## 10. Acceptance oracles for the improved build

Tests are necessary but not sufficient.

The improved build must satisfy frozen replay and later authorised live acceptance.

### 10.1 Transport correctness oracle

- logical HTTPS hostname remains available for TLS/SNI;
- selected peer identity remains separately retained;
- strict content discovery no longer fails merely because the IP was substituted as TLS authority;
- failures retain actionable diagnostic cause.

### 10.2 Redirect oracle

A retained `301 + Location` must appear in downstream redirect analysis and human composition.

The operator must be able to distinguish:

- followed because authorised;
- refused because outside programme scope;
- unresolved because programme semantics are ambiguous.

### 10.3 Semantic extraction oracle

- Next.js/React Flight serialised state must not become fake routes;
- route/service candidates must retain source context;
- JavaScript lexical noise must not be promoted as meaningful GraphQL/API evidence without sufficient context.

### 10.4 Programme graph oracle

A programme-authorised child such as a wildcard-matching Deriv descendant must be evaluable against the frozen programme rules and materialisable as an exact runtime origin without manual creation of an unrelated project.

The same machinery must refuse a redirect to an unauthorised apex.

### 10.5 Recursive collection oracle

A high-value route discovered later through sitemap/JavaScript/metadata must be eligible for a bounded second-pass collection decision.

Every such request must record:

- why it was selected;
- discovery source;
- depth;
- remaining budget;
- scope decision;
- provenance.

### 10.6 Whatnot application-model oracle

The operator should receive a materially useful model of the important Whatnot application/service surface, including auth, GraphQL/API/service and major route-family relationships represented in the frozen manual review.

### 10.7 Deriv application-model oracle

The operator should receive a materially useful model including:

- developer/API documentation role;
- auth/OAuth family;
- WebSocket documentation/playground;
- trading/options/payment-agent/account/wallet route families;
- service relationships;
- redirect topology;
- the distinction between directly observed service behaviour and directly documented service relationships.

## 11. Development cadence: coherent work packages, not micro-fix churn

The project must remain disciplined without falling back into a cycle of one tiny fix, one tiny test run, one tiny commit, repeat.

The preferred unit of work is now a **coherent work package**.

A work package may contain several reproduced fixes or improvements when they:

- share a trust boundary or data flow;
- touch the same persistence/analysis seam;
- are easier to reason about together;
- can be covered by one combined RED/acceptance contract;
- can be reviewed as one coherent diff;
- do not make failure attribution unreasonably difficult.

The default package workflow is:

1. inspect actual source and current tests;
2. confirm all included field issues are reproduced/classified;
3. write or approve a combined RED/contract set for the package;
4. implement the package coherently;
5. run the combined focused package gate;
6. run relevant owner suites;
7. run the full suite once at the package boundary when warranted;
8. inspect the actual diff and test output;
9. commit/push only after approval.

Do **not** require a full regression suite after every small internal edit.

Do **not** require a separate commit for every field identifier.

Intermediate focused tests are appropriate when debugging a difficult seam, but they are not mandatory ceremony after every line change.

Conversely, do not bundle unrelated large trust-boundary changes solely to reduce the number of test runs.

If source inspection shows that a proposed package crosses unrelated owners or would make rollback/diagnosis unsafe, split it into two coherent sub-packages rather than many micro-stages.

## 12. Implementation sequence

### Work Package 0 - baseline, evidence fixtures and ownership map

**Purpose:** establish a trustworthy development baseline before code changes.

This package is primarily inspection and fixture planning, not production implementation.

Required work on Mint:

- verify current `HEAD`;
- verify `origin/main`;
- verify clean/dirty worktree;
- verify `v1.3.0` still points to `fc8f0febc809efd0540173b63af87945c500d028`;
- identify post-release documentation/bookkeeping commits on `main`;
- identify exact source owners for:
  - strict HTTPS/content-discovery transport;
  - external tool execution/diagnostics;
  - redirect persistence and Deep redirect analysis;
  - route/source extraction;
  - programme policy/scope;
  - project/runtime origin seeding;
  - content planning and follow-up;
  - application/operator composition;
- identify the smallest frozen evidence slices needed as deterministic regression fixtures;
- ensure the approved bounty-first plan/source is present in the repository before production Codex work begins.

No production edits should occur during the initial ownership map.

**Exit:** actual source seams are known, fixture strategy is agreed, and Work Package 1 can be scoped from real code rather than assumptions.

### Work Package 1 - transport and evidence-flow correctness bundle

**Primary included issues:**

- `STRICT-HTTPS-SNI`;
- external collector diagnostic loss;
- `FIELD-002-REDIRECT-HANDOFF-01`.

These belong together because they all concern whether HTTP collection and its execution/evidence semantics survive accurately through the pipeline.

Desired outcomes:

- preserve logical HTTPS hostname for TLS/SNI;
- retain selected peer identity separately;
- preserve scope and identification-header semantics;
- retain actionable collector stderr/exit diagnostics;
- make retained redirect evidence available to downstream redirect analysis and operator composition;
- preserve old evidence-pack compatibility where practical or provide deliberate migration handling if needed.

This package should normally use one combined RED contract and one combined focused acceptance gate rather than three isolated mini-fixes.

If source inspection proves redirect handoff is entirely separate from transport/tool execution, it may become a second coherent sub-package, but do not default to splitting every identifier.

**Model guidance:** GPT-5.6 Sol Medium is likely adequate if the seams are narrow; use Sol High if the change crosses substantial trust-boundary, persistence or execution architecture.

**Exit:** combined focused tests green, owner suites green, full suite green at package boundary, diff reviewed.

### Work Package 2 - semantic extraction hygiene bundle

**Primary included issues:**

- `FIELD-002-NEXT-ROUTE-01`;
- `FIELD-001-JS-SEMANTICS-01`;
- related source-context classification required to solve them honestly.

Desired architectural rule:

> **Classify where a candidate came from before deciding what that candidate means.**

Examples:

- HTML `href` -> route candidate;
- sitemap URL -> declared route;
- script `src` -> JavaScript/static asset;
- Next.js/React Flight payload -> framework state unless a more specific parser proves otherwise;
- explicit API URL -> service relationship candidate;
- explicit `wss://` -> WebSocket relationship candidate;
- arbitrary lexical string -> not automatically a route.

This package should reduce semantic false positives before the application graph begins trusting extracted relationships.

**Model guidance:** Sol Medium by default. Escalate only if the extraction architecture requires a broad parser redesign.

**Exit:** false-route regressions closed, existing legitimate extraction preserved, combined semantic-owner suites and full regression green.

### Work Package 3 - programme-first policy, scope and authorised fanout bundle

**Primary included issues:**

- `FIELD-002-POLICY-RATE-01`;
- `FIELD-002-SCOPE-MODEL-01`;
- `FIELD-002-PROGRAMME-UX-01`;
- `FIELD-002-PROGRAMME-RELATION-01`;
- `FIELD-002-PROGRAMME-FANOUT-01`;
- `FIELD-002-DYNAMIC-SCOPE-01`.

This is a deliberate architecture package.

Required capabilities should include a coherent foundation for:

- programme-level policy identity;
- rate provenance;
- exact/wildcard hostname rules;
- protocol and port constraints;
- include/exclude semantics;
- programme asset graph;
- observed/documented asset relationships;
- exact runtime materialisation after successful programme validation;
- explicit refusal when destination scope is not positively authorised.

The package may have internal implementation passes, but the acceptance boundary should be the coherent programme-first behaviour, not six independent cosmetic features.

Do not let programme scope become permissive by accident.

Do not make redirect destinations inherit authorisation.

**Model guidance:** Sol High is justified because this is architecture and trust-boundary heavy.

**Exit:** programme graph contract green, dynamic child materialisation green, unauthorised apex refusal green, policy/scope owner suites green, full regression green.

### Work Package 4 - BugSlyce-owned bounded discovery and recursive feedback bundle

This package combines two field-supported requirements that are strongly related:

1. BugSlyce must own the HTTP trust-boundary semantics of critical content discovery.
2. Later-discovered high-value evidence must be able to feed another bounded collection decision.

The intended direction is a native bounded discovery controller using BugSlyce-owned:

- logical hostname;
- TLS/SNI;
- peer identity;
- required headers;
- pacing;
- concurrency;
- redirect policy;
- negative-response calibration;
- response fingerprints;
- typed evidence;
- diagnostics;
- scope checks.

Gobuster/ffuf or other specialist engines may remain optional implementation engines or comparators, but they should not own trust-boundary semantics that BugSlyce itself must guarantee.

Recursive feedback should support a controlled pattern such as:

**root -> HTML/JS/metadata -> candidate classification -> bounded collection -> sitemap/API/service discovery -> re-ranking -> bounded second pass -> application model**

Explicit controls must include:

- maximum depth;
- total request budget;
- per-origin budget where appropriate;
- pacing/concurrency;
- programme-scope validation;
- discovery provenance;
- selection reason;
- deterministic stop conditions.

This package is substantial and may require two Codex implementation passes under one package acceptance contract if necessary. That is preferable to dozens of tiny commits.

**Model guidance:** Sol High for architecture/design and the first implementation pass. Narrow follow-up corrections can use lower settings.

**Exit:** native bounded discovery works against frozen replay and controlled labs, later sitemap/JS discoveries can trigger safe bounded second-pass collection, full suite green.

### Work Package 5 - application/service graph and operator composition bundle

Only after collection and semantic relationships are trustworthy should the product make stronger high-level claims.

Required capabilities should include typed, provenance-aware relationships such as:

- origin -> redirects to -> origin;
- documentation -> describes -> service;
- service -> exposes -> route family;
- REST endpoint -> issues credential for -> WebSocket connection;
- authentication mechanism -> requires -> application identifier;
- authentication mechanism -> requires -> OAuth scope;
- sitemap -> declares -> route;
- JavaScript asset -> references -> service/route where context supports it.

The operator-facing layer should compose these into useful surfaces such as:

- authentication/account;
- API/service;
- WebSocket/realtime;
- trading/commerce;
- seller/order;
- admin/operations;
- redirect/return-target;
- documentation/developer surface.

Operator priorities should rank application architecture and investigation value above generic framework oddities.

Analysis Coverage should explain meaningful coverage/limitations rather than presenting only implementation-centric counts.

This package owns the Whatnot and Deriv manual acceptance oracles.

**Model guidance:** Sol High for composition architecture; Sol Medium may be sufficient for later deterministic rendering/ranking work once the model is stable.

**Exit:** frozen replay produces materially improved Whatnot and Deriv operator understanding, report and composition owner suites green, full suite green.

### Work Package 6 - acceptance, Kali verification and second field cycle

After the first improvement round:

1. run focused package gates and final owner suites on Mint;
2. run full pytest;
3. run `compileall`;
4. run `git diff --check`;
5. inspect the complete final diff;
6. commit/push from Mint only after approval;
7. pull the exact approved commit on Kali;
8. verify distribution/runtime identity locally;
9. run frozen/offline acceptance fixtures;
10. run controlled authorised labs;
11. run selected genuine bug-bounty field validation again;
12. compare operator usefulness to Field Cases 001 and 002.

Do not publish a new public version at this point by default.

The improved build must earn another release through field evidence.

## 13. Testing policy for work packages

The testing strategy should be efficient but still evidence-led.

### Before implementation

For each package:

- reproduce/lock the included field failures from frozen evidence;
- add or identify the combined RED contract;
- verify RED for the intended reasons.

### During implementation

Use narrow tests as needed to debug the package.

Do not repeatedly run large suites after every small edit unless a particular regression risk warrants it.

### At package completion

Run:

1. combined focused package tests;
2. relevant owner suites;
3. broader/full regression once at the package boundary;
4. `compileall` where production Python changed;
5. `git diff --check`;
6. actual diff review.

If the package is very large and internally split into two Codex passes, a medium owner gate may be run between passes, but a full suite is not automatically required between them.

## 14. Codex usage policy

Codex should be used as an implementation assistant, not as the source of product direction.

Every production phase must receive a focused prompt tied to this source and the frozen field evidence.

Before each Codex phase, recommend the lowest model/reasoning level that is still strong enough.

Current default guidance:

- narrow deterministic/local correction: lower model or Terra High where available;
- ordinary multi-file coherent implementation: Sol Medium;
- architecture, trust-boundary, persistence or scope redesign: Sol High;
- exceptional maximum reasoning only when truly warranted.

Do not default to the highest tier.

Codex must not infer the bounty-first objective from old CTF-oriented tests alone.

The human review process remains:

1. assistant provides the focused Codex prompt;
2. code runs on Mint;
3. user returns actual diff/tests;
4. assistant reviews the real changes;
5. only then approve commit/push;
6. Kali later pulls the exact commit for acceptance.

## 15. Mint and Kali workflow

### Mint

Development only:

- source inspection;
- edits;
- tests;
- diff review;
- commits;
- pushes.

Repository:

`~/projects/bugslyce`

### Kali

Live reconnaissance and final acceptance only.

Repository:

`~/projects/bugslyce`

Kali transfer address unless the user reports it changed:

`192.168.122.43`

For large Kali outputs, redirect to a file rather than asking the user to manually select huge QTerminal output.

When transfer is needed, provide:

- Kali SSH start command;
- Mint `scp` command;
- Kali SSH stop/disable check as appropriate.

## 16. Command-delivery rules

These are operational requirements, not stylistic niceties.

- Label each command block outside the code block as **Mint** or **Kali**.
- When more than one command block is supplied, number the blocks.
- Keep command blocks clean. Do not put environment commentary inside them.
- Never provide two runnable command blocks with the same step number.
- If a command is superseded, correct it before presenting the runnable block, or mark the earlier block clearly as **DO NOT RUN**.
- Do not use a bare `exit` in an interactive command block where it could close the user's terminal.
- Prefer safe conditional guards that print `REFUSED` and return control to the shell.
- For potentially large output, write to a file and show a concise extract.
- Use UK English.
- Spell `artefact`.
- Avoid em dashes in project documents.

## 17. Change-control rules

A previously closed/public v1.3 issue is not reopened without fresh evidence.

A new product change must be tied to:

- a reproduced field defect;
- a field-supported architecture limitation;
- a necessary dependency of an approved work package;
- or a new regression reproduced during implementation.

Do not add opportunistic features merely because the relevant module is already being edited.

Do not silently broaden BugSlyce into active vulnerability testing.

Do not weaken scope because a same-owner redirect appears convenient.

## 18. Deferred work outside the first improvement round

Unless a work package genuinely requires a foundation for them, defer:

- GUI/dashboard work;
- AI-assisted interpretation;
- broad passive/CT attack-surface discovery;
- active vulnerability validation;
- exploitation;
- anti-bot circumvention;
- arbitrary browser automation;
- speculative protocol engines without reproduced need;
- cosmetic public versioning.

A future investigation workspace remains attractive, but it should visualise a strong evidence/application model rather than compensate for a weak one.

AI remains optional and subordinate to deterministic evidence/provenance.

## 19. Immediate next task

Start a fresh project conversation for implementation.

The new conversation must treat this source as the current working source of truth and begin with **Work Package 0 on Mint**.

The immediate actions are:

1. verify the exact Mint repository baseline and current `main` identity;
2. verify immutable `v1.3.0` tag identity;
3. inspect current worktree state;
4. map actual source/test owners for Work Package 1 and later packages;
5. identify how the frozen field evidence will become deterministic regression fixtures;
6. place/verify the approved bounty-first implementation source in the repository before production Codex work;
7. produce the first coherent Work Package 1 Codex prompt only after the source seams are known.

Do not begin with a production edit.

Do not run live recon during Work Package 0.

Do not split Work Package 1 into one tiny field identifier per commit unless source inspection proves that separation is genuinely safer.

## 20. Current one-line status

**BugSlyce v1.3.0 remains immutable and publicly valid for its released boundary; Field Cases 001 and 002 are closed and have produced enough cross-case evidence to authorise a bounty-first improvement round built as coherent work packages: first fix transport/evidence correctness, then semantic extraction, programme-first scope/fanout, native bounded recursive collection, and finally application/service composition, with all substantial changes validated on Mint and then re-tested on Kali before any future release is considered.**
