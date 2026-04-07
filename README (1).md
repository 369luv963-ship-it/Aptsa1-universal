# APTSA1 Universal Governance Engine
**Version 5.1.0-universal**

Cryptographic runtime AI governance engine.

Created by Leon George | Y✶KNOT AI CONSULTANT LTD (Company No. 17128151)
Patent: GB2521334.9 (priority date 10 December 2025, active at UKIPO)
Licence: Apache 2.0

---

## What This Is

APTSA1 sits between an AI system and its actions. Before any AI does
anything, APTSA1 checks it against invariant human safety constraints,
logs the decision cryptographically, and either permits or blocks it.

This is not a policy document. Not a monitoring dashboard. Not a model
evaluator. It is a runtime enforcement gate.

---

## Architecture

**CORE12 — Invariant Human Needs**
Twelve universal constraints that cannot be disabled, reordered, or
overridden at runtime. Cryptographically fingerprinted (SHA-256) at
startup. Any action that harms one or more activates enforcement.

```
water, food, shelter, clothing, health, companionship,
stimulation, security, income, hope, bonding, procreation
```

**Drift Detector**
Compares declared intent against observed action across four dimensions:
goal (0.5), scope (0.2), consent basis (0.2), target subject (0.1).
Score >= 0.5 triggers DEGRADE or DENY.

**ICS Policy Engine**
Evaluates actions against CORE12 harms and sector-supplied invariants.
Critical violations trigger HALT. Standard violations trigger DENY.

**Dissent Gate (D-Gate)**
Formal challenge mechanism. Any stakeholder can challenge a decision.
Weighted by evidence, drift score, and invariant breach score.

**Synthetic Contract**
Final adjudication. Priority order:
HALT > DENY > PENDING_APPROVAL > DEGRADE > ALLOW

**Tamper-Evident Ledger**
Every decision SHA-256 hashed, Ed25519 signed, chained to previous entry.
Append-only. Tamper with one entry and the chain breaks.

**FORTIFY Runtime Integrity Monitor**
Background daemon watching engine files. Modification detected while
running triggers SIGTERM. Cannot be silently tampered with while live.

---

## Security

- Ed25519 cryptographic signing on all ledger entries
- SHA-256 hash chain verification
- Scrypt password hashing (n=2 to the power of 14, r=8, p=1)
- HMAC constant-time password verification
- Fail-closed strict mode
- Redis rate limiting
- API token on all sensitive endpoints
- CORS restricted in production
- SQLite blocked in production, PostgreSQL required

---

## Roles

viewer - Read decisions and audit trail
approver - Approve PENDING_APPROVAL decisions with logged justification
safety_officer - Safety metadata, hazard log, CORE12 interpretation
audit - Forensic read access only
admin - Key management, user provisioning, configuration

---

## Database Tables

users, ledger_entries, approval_requests, outcome_records,
hazard_log, safety_metadata

---

## API Endpoints

GET  /healthz                              System status and seal check
POST /v1/auth/login                        Authenticate
POST /v1/evaluate                          Governance decision
POST /v1/dissent                           Challenge a decision
POST /v1/approve                           Authorise pending action
GET  /v1/approvals/{id}                    Retrieve approval record
POST /v1/cure/outcome                      Record outcome
POST /v1/safety/hazards                    Register hazard
GET  /v1/safety/hazards                    List hazards
PUT  /v1/safety/metadata                   Set safety metadata
GET  /v1/ledger/entries                    Audit trail
GET  /v1/ledger/verify                     Chain verification
GET  /v1/decisions/recent                  Recent decisions
GET  /v1/integrity/proof                   Tamper-evident proof
GET  /v1/core12                            CORE12 fingerprint
GET  /metrics                              Prometheus metrics

---

## Environment Variables

APTSA1_ENV=dev|test|prod
APTSA1_DOMAIN=universal|justice|education|finance|safeguarding
APTSA1_API_TOKEN=...
APTSA1_DB_URL=postgresql://...
REDIS_URL=redis://...
APTSA1_SIGNING_KEY_PEM=...
APTSA1_BOOTSTRAP_USERS_JSON=[{"username":"admin","password":"...","role":"admin"}]
APTSA1_SECTOR_CONFIG_JSON={"sector_invariants":[]}
APTSA1_CORS_ORIGIN=https://your-domain.org
APTSA1_FORTIFY_ENABLE=1
APTSA1_FORTIFY_PATHS_JSON=["./aptsa1_universal.py"]
APTSA1_SAFETY_OFFICER_ID=...
APTSA1_LEDGER_LOG_MODE=full|meta|hash

---

## Installation

pip install fastapi uvicorn sqlalchemy pydantic cryptography redis structlog prometheus_client slowapi

---

## Run

Development:
APTSA1_ENV=dev uvicorn aptsa1_universal:app --reload

Production:
APTSA1_ENV=prod APTSA1_DB_URL=postgresql://... APTSA1_SIGNING_KEY_PEM="..." APTSA1_API_TOKEN=... uvicorn aptsa1_universal:app --host 0.0.0.0 --port 8000

---

## Sector Configuration

Sector invariants injected via APTSA1_SECTOR_CONFIG_JSON. No hardcoding.
Each organisation fills relevant CORE12 slots and leaves others blank.

Example:
{"sector_invariants":[{"name":"consent_required","context_field":"consent_basis","must_equal":"confirmed","severity":"critical"}]}

---

## Deployment Modes

Shadow Mode: observe without blocking, collect baseline data
Enforcement Mode: blocking active, override workflow live
Operational: full CORE12 enforcement, continuous monitoring

---

## What This Is Not

Not a medical device. Not sector-specific. Not an LLM.
Not a replacement for human judgement.

Sector-specific builds available under licensing agreement.

---

## Intellectual Property

Patent GB2521334.9 covers: CORE12 Boolean Enforcer, FORTIFY daemon,
SEAL quorum approval gate, tamper-evident ledger (SHA-256 + Ed25519),
Policy Engine, LLM Harm Scorer.

CORE12 is the original work of Leon George, developed over 29 years.

---

## Contact

Y✶KNOT AI CONSULTANT LTD
Company No. 17128151
128 City Road, London, EC1V 2NX
https://aptsa1-runtime.emergent.host
