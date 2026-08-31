# Reconnaissance Workflow

BugSlyce has one normal operator reconnaissance workflow plus a manual setup
choice. The workflow name describes collection behaviour; it does not grant
permission to contact a target.

## Current Choices

| Choice | Internal profile | Purpose |
| --- | --- | --- |
| Manual Setup Only | none | Create project metadata and `scope.md` without recon. |
| Reconnaissance | `deep-bounded` | Run the complete bounded native discovery, recursive evidence feedback and offline analysis workflow. |

`deep-bounded` remains the internal and persisted execution identity. Existing
Deep model classes, artefact names and pipeline step IDs remain unchanged.

## Safety Boundaries

BugSlyce project workflows are for authorised targets only. The generated
`scope.md` template is not authorisation.

Reconnaissance remains bounded and non-exploitative:

- central programme-scope, pacing, concurrency, redirect and HTTP 429 enforcement;
- exact materialised-origin authority;
- bounded native root content discovery;
- one bounded depth-one evidence-feedback pass;
- no unrestricted or recursive crawling;
- no UDP pipeline phase or NSE scripts;
- no brute force, exploitation, password spraying or credential stuffing;
- no authentication testing or form submission;
- no browser automation or JavaScript execution;
- no query-bearing recursive requests, parameter replay, guessing or mutation;
- no vulnerability confirmation.

Static evidence and review leads remain evidence for manual analysis; they are not proof of vulnerability, exploitability or impact.
Query names and query-bearing references may still be retained and analysed as
offline evidence; they are not promoted to recursive collection requests.

## Workflow Contents

Reconnaissance uses the package-owned `deep-bounded-core` resource. It retains
the current full pipeline topology, including native content discovery,
PIPELINE-STEP-010D, PIPELINE-STEP-011D and depth-one recursive evidence
feedback.

The workflow includes bounded service and HTTP collection, source/route
collection, metadata review, static HTML and semantic JavaScript extraction,
shallow same-origin follow-up, form and parameter-name inventory, offline
orchestration, deterministic reports, status, runbooks and evidence-pack
export. Redirect destinations and evidence references do not acquire collection
authority.

Readiness requires:

- Python and core BugSlyce readiness;
- `nmap`;
- `curl`;
- `gobuster`;
- bundled `deep-bounded-core`.

Gobuster remains a required installed tool for runtime-less legacy paths, but
the normal project pipeline's critical content-discovery workload is owned by
BugSlyce native HTTP enforcement.

## Running

The normal command has no profile selector:

```bash
bugslyce project run --project /path/to/bugslyce_project.json --confirm
```

Use `--resume` only for a compatible recorded `deep-bounded` run. Historical
`lab-safe-tiny` and `standard-bounded` metadata may still be shown in read-only
status/report views, but those profiles cannot start or resume a new normal project execution.

## Bundled Discovery Resources

`deep-bounded-core` is the required normal-workflow resource. The older
`lab-root-tiny` and `standard-bounded-core` package resources may remain for
specialist or historical compatibility, but their absence does not block
Reconnaissance.

## Evidence and Reports

Reports, status files, runbooks, pipeline metadata and evidence packs are local
artefacts and may contain target evidence. Store and share them according to
the engagement rules. Manual validation remains required.
