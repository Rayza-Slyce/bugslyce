# BugSlyce

BugSlyce is a local-first, CLI-first bug bounty recon triage assistant. Its intended purpose is to ingest authorised recon outputs, organise attack surface data, evidence-link interesting signals, and eventually help produce careful manual testing reports.

This repository is currently in its first implementation phase: skeleton only, with fake portfolio-safe demo data. It does not include parsing, scoring, LLM calls, live recon, scanner execution, vulnerability confirmation, exploit generation, bypassing, brute forcing, or any active testing capability.

## What BugSlyce Is

- A Python project for organising already-collected, authorised recon outputs.
- A future deterministic triage helper for grouping hosts, URLs, notes, and evidence.
- A future report drafting assistant that keeps human validation at the centre.
- A portfolio-safe project designed to avoid storing private target data in the repo.

## What BugSlyce Is Not

- Not a recon scanner.
- Not an exploitation framework.
- Not a vulnerability confirmation tool.
- Not a brute force, bypass, fuzzing, or attack automation tool.
- Not a replacement for manual validation, programme scope review, or responsible disclosure judgement.

## v1 Scope

The planned v1 scope is intentionally narrow:

- Ingest existing recon outputs supplied by the user.
- Normalise and organise host, URL, HTTP metadata, and note records.
- Keep deterministic Python behaviour as the default foundation.
- Support no-LLM operation as a complete mode.
- Treat any future LLM mode as optional and assistive only.
- Generate careful report drafts that avoid claiming unconfirmed vulnerabilities.

## Safety Boundaries

BugSlyce is for authorised testing only. Use it only with programmes, assets, and data you are explicitly permitted to assess.

Do not commit raw recon files, private outputs, screenshots, Burp exports, HAR files, API keys, tokens, customer data, or any sensitive material. Keep private testing material outside the repository, such as in `private_recon/` or `raw-recon/`, both of which are ignored by default.

The demo data in this repository is fictional and sanitised. Domains such as `example-bounty.test` are not real targets and are included only to exercise future parsing and triage behaviour.

## Deterministic Python First, LLM Second

BugSlyce should work without an LLM provider. No-LLM mode must remain functional and useful.

Future LLM support may help summarise evidence or draft language, but it must be optional, conservative, and controlled. Raw recon should not be sent to any provider by default. The `BUGSLYCE_SEND_RAW_RECON=false` setting exists to make that boundary explicit.

## Current Status

This phase contains only:

- Repository skeleton.
- Placeholder Python modules with docstrings.
- Test folder placeholders.
- Safety-focused configuration files.
- Fake demo recon datasets for future parser and triage tests.

Implementation of parsers, scoring, classification, report generation, and LLM integrations is intentionally deferred.
