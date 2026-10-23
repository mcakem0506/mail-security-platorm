# AGENTS.md — Mail Security Platform

This file is the primary instruction contract for AI coding agents working in this repository.

It applies to Codex, Claude Code and other automated coding agents unless a narrower instruction file exists in a subdirectory.

## 1. Project identity

Mail Security Platform (MSP) is an on-premises email security platform for Microsoft Exchange Server.

The product combines:

- Outlook employee reporting;
- safe MIME/EML parsing;
- anti-phishing and BEC detection;
- sender impersonation and lookalike detection;
- URL/domain/attachment analysis;
- Threat Intelligence;
- multi-gateway integration;
- incidents and campaigns;
- Exchange remediation;
- Postfix-based gateway transport;
- Rspamd-based mail authentication and anti-spam;
- controlled enforcement in later stages.

The product must remain vendor-neutral. KSMG, EOP, FortiMail, Proofpoint, Cisco ESA, Mimecast and other gateways are integrations, not architectural dependencies.

## 2. Read before changing code

Before starting any substantial task, read:

1. `README.md`
2. `AGENTS.md`
3. `docs/ARCHITECTURE.md`
4. `docs/SECURITY_MODEL.md`
5. `docs/THREAT_MODEL.md`
6. the latest stage acceptance document relevant to the branch
7. the technical specification for the stage being implemented
8. `docs/DETECTION_GAPS.md` when changing detection/authentication/enforcement behavior

Do not infer current readiness from README alone. Acceptance documents and current tests define whether a stage is actually accepted.

## 3. Source-of-truth order

When sources disagree, use this order:

1. executable tests and verified runtime behavior;
2. accepted architecture/security invariants;
3. current stage technical specification;
4. current stage acceptance document;
5. implementation documentation;
6. README and comments.

Do not silently “fix” a conflict by choosing whichever source is easier. Record the discrepancy and resolve it explicitly.

## 4. Non-negotiable architecture invariants

The following are product invariants unless a new approved ADR explicitly changes them.

### 4.1 No absolute SAFE verdict

Absence of detection is not proof of safety.

Use classifications such as:

- `LOW_RISK`
- `SUSPICIOUS`
- `HIGH_RISK`
- `MALICIOUS`
- `UNKNOWN`

Missing evidence must remain visible.

### 4.2 Explainability is mandatory

Every material verdict or enforcement decision must retain:

- evidence;
- reason codes;
- source;
- timestamp;
- rule/policy version;
- engine version where relevant.

A bare numeric risk score is not sufficient.

### 4.3 External intelligence is not a critical mail-flow dependency

VirusTotal, external reputation APIs, external LLMs and similar providers must not be required for basic mail delivery.

Their outage must not cause accidental permanent rejection.

### 4.4 Privacy by design

Do not send full corporate email bodies, files, credentials, sensitive URL queries or internal identifiers to external providers by default.

External data transfer must pass an explicit policy/privacy gate.

### 4.5 No hidden destructive automation

Delete, purge, block, reject, quarantine or mass remediation must use the explicit policy/approval mechanisms defined for the current stage.

Do not add “convenient” side effects to analysis code.

### 4.6 Transport durability comes before analysis

Once SMTP has accepted a message, transport durability must not depend on:

- MSP API;
- PostgreSQL;
- Redis;
- VirusTotal;
- semantic analysis;
- analyst console;
- full detection workers.

Postfix queue remains the transport source of truth for gateway delivery.

### 4.7 Gateway clean verdict never lowers MSP security risk

`CLEAN`, `NO DETECTION`, `PASS` or equivalent upstream results are evidence only.

They must never suppress a stronger independent MSP signal.

### 4.8 Trust must be proven

Do not trust headers merely because they are named:

- `Authentication-Results`
- `Received-SPF`
- `X-KSMG-*`
- `X-Spam-*`
- `X-Virus-*`

Trust requires validated topology / trusted hop / authserv-id / local integration context.

### 4.9 Do not execute hostile content

Email attachments, HTML, JavaScript, macros and archive payloads must not execute in the normal application worker.

High-risk parsing belongs in bounded isolated processes or containers with no network access.

### 4.10 Enforcement must be staged

No single global `ENFORCEMENT=true`.

Each enforcement control has independent readiness and lifecycle.

Known Detection Gaps can technically block a control from activation.

## 5. Stage discipline

Do not implement future phases opportunistically.

Interfaces for later phases are allowed when necessary, but behavior must remain disabled until its stage.

Examples:

- do not turn shadow anti-spam into reject mode before enforcement acceptance;
- do not perform production MX changes from lab stages;
- do not add end-user quarantine release before the corresponding stage;
- do not claim HA before HA is tested.

## 6. Branch discipline

Use one branch per stage or tightly scoped remediation.

Recommended naming:

```text
msp-<version>-<short-name>
fix/<short-name>
docs/<short-name>
```

A new stage starts from the accepted/merged parent stage, not from an arbitrary older feature branch.

If branch ancestry is wrong, fix history before adding security-sensitive behavior.

## 7. Test-first rule for defects

For a discovered defect:

1. reproduce it;
2. add a regression/security test;
3. prove the test fails;
4. implement the fix;
5. prove the test passes;
6. run the relevant broader suite.

Do not patch first and invent a test afterward unless reproduction is impossible; document the exception.

## 8. Test tiers

The repository uses several test classes.

Expected categories include:

- unit;
- security;
- integration;
- e2e;
- gateway/live Postfix;
- Rspamd/spam;
- detection corpus/regression;
- platform-specific Linux tests.

A green unit suite does not prove a gateway stage is accepted.

Do not report skipped Linux/live tests as passed.

## 9. No retry-to-green for critical controls

Critical enforcement, durability, open-relay, TLS, policy, quarantine and rollback tests must be deterministic.

A flaky critical test is a defect or an explicit blocker, not something to hide with retries.

## 10. Detection rules

Rules must remain declarative and schema-validated.

Do not add:

- `eval`;
- arbitrary Python imports;
- executable YAML tags;
- network access from rule evaluation;
- unbounded regex.

New or materially changed rules should normally move through:

```text
DRAFT → REVIEW → SHADOW → VALIDATION → ACTIVE
```

## 11. Detection gaps

Never hide a known miss by weakening acceptance.

A real unsupported attack technique belongs in `docs/DETECTION_GAPS.md` and the machine-readable gap registry with:

- severity;
- owner;
- target release;
- examples;
- compensating controls;
- state.

Do not mark a gap `RESOLVED` because code exists. Resolution requires validation.

## 12. Mail authentication standards

When changing authentication behavior, verify against the applicable standards and the actual installed implementation.

Relevant standards include:

- SMTP: RFC 5321;
- SPF: RFC 7208;
- DKIM: RFC 6376;
- Authentication-Results: RFC 8601;
- ARC: RFC 8617;
- DMARC: RFC 9989.

Do not claim standards compliance solely because Rspamd/Postfix exposes a similarly named feature.

## 13. Security-sensitive configuration

Do not accept arbitrary Postfix/Rspamd/Lua configuration from the UI.

Use typed/versioned configuration models and controlled generators.

Before activation:

- validate schema;
- validate generated files;
- run native config checks;
- calculate checksum;
- activate atomically;
- health-check;
- rollback on failure.

## 14. Secrets

Never commit:

- passwords;
- API keys;
- private keys;
- AD credentials;
- Exchange service credentials;
- RBL secrets;
- signing keys.

Use mounted secrets, secret references or approved environment injection.

Do not print secrets in test output, SMTP replies, logs or screenshots.

## 15. Database changes

All persistent schema changes use Alembic.

For non-trivial migrations test:

```text
upgrade
downgrade
upgrade
alembic check
```

When existing rows are possible, migration tests must use seeded data.

## 16. API changes

New APIs require:

- authentication;
- RBAC/object authorization;
- input validation;
- bounded pagination;
- audit for privileged mutations;
- idempotency where retries are expected;
- OpenAPI compatibility.

Do not expose raw message bodies unless the role and endpoint explicitly require it.

## 17. Frontend changes

Security Console pages must:

- handle API failure visibly;
- never interpret missing data as “no problems”;
- avoid rendering remote active content;
- avoid clickable malicious URLs by default;
- preserve role boundaries.

A successful TypeScript build alone is insufficient. Critical routes should have mount/smoke coverage.

## 18. External providers

Every external provider must be behind an interface/adapter.

Provider failures must normalize into explicit states such as:

- `PROVIDER_UNAVAILABLE`;
- `RATE_LIMITED`;
- `TEMPERROR`;
- `POLICY_BLOCKED`;
- `UNKNOWN`.

Do not convert provider silence into a clean verdict.

## 19. Production guardrails

Unless the current accepted stage explicitly says otherwise, do not:

- change production MX;
- modify production Exchange connectors automatically;
- enable global SMTP reject;
- enable global quarantine;
- change public DNS;
- enable public RBL usage without license review;
- enable file upload to VirusTotal;
- send corporate mail to external LLMs.

## 20. Documentation required with behavior changes

Update the relevant architecture, security and operating documentation in the same change.

If behavior changes but documentation still describes the old behavior, the work is incomplete.

## 21. Definition of Done

A task is done only when applicable items are complete:

- implementation;
- automated tests;
- security tests;
- migrations;
- lint/type checks;
- config validation;
- documentation;
- observability;
- rollback behavior;
- acceptance evidence.

See `docs/DEFINITION_OF_DONE.md`.

## 22. Stage report format

Every stage should finish with:

```text
PHASE:
BASE_SHA:
FINAL_SHA:

IMPLEMENTED:
REUSED:
TESTS:
MIGRATIONS:
SECURITY_CHECKS:
LIVE_CHECKS:
KNOWN_WARNINGS:
OPEN_GAPS:

DECISION:
  READY...
  READY_WITH_WARNINGS
  NOT_READY
```

Do not use `READY` if required real-flow evidence does not exist.

## 23. When evidence is unavailable

Say so.

Use:

- `NOT_TESTED`
- `UNKNOWN`
- `READY_WITH_WARNINGS`
- `NOT_READY`

Never substitute synthetic success for real production evidence.

## 24. Agent behavior

An AI agent working in this repository must:

- inspect existing code before creating parallel abstractions;
- reuse established contracts;
- prefer a narrow change over a redesign;
- preserve compatibility unless the stage requires breaking it;
- state assumptions;
- identify blockers;
- not falsify acceptance;
- not weaken tests to make a release pass;
- not remove security controls without an explicit approved rationale.
