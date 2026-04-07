# APTSA1 — Universal Governance Engine
**Version 5.1.0-universal**

Autonomous Protective Threshold System Architecture

Created by Leon George | Y✶KNOT AI CONSULTANT LTD (Company No. 17128151)
Patent: GB2521334.9 (priority date 10 December 2025, active at UKIPO)

---

## What This Is

APTSA1 is a cryptographic runtime governance engine for AI systems.

It sits between an AI system and its actions — evaluating every decision
against invariant human safety constraints before output is permitted.

This is not a policy framework. Not a monitoring dashboard. Not a model
evaluator. It is a **gate** that enforces before the action occurs, logs
everything cryptographically, and cannot be silently bypassed.

---

## The Core Principle

Most AI governance operates after the fact — logs reviewed, audits conducted,
harm already done.

APTSA1 operates before the fact. Every decision passes through enforcement
gates before execution is permitted. If it fails, it blocks. Not logs and
continues. **Blocks.**

---

## CORE12 — The Twelve Universal Human Needs

```
C1  Water
C2  Food
C3  Shelter
C4  Clothing
C5  Health
C6  Companionship
C7  Stimulation
C8  Security
C9  Income
C10 Hope
C11 Bonding
C12 Procreation
```

These twelve needs are the invariant constraint scaffold. They are
cryptographically fingerprinted (SHA-256) at startup. Any action that
harms one or more of these needs activates enforcement.

They cannot be removed, reordered, or overridden at runtime.

**Each organisation fills the slots relevant to their sector.**
Others remain blank or secondary. The engine is agnostic — the
interpretation is yours.

Examples:

- **Finance (anti-money laundering):** C8 (security), C9 (income), C4 (privacy/clothing as dignity), C7 (equity/stimulation as fairness)
- **Safeguarding:** C1–C5 (basic welfare), C12 (child safety, absolute)
- **Justice:** C3 (shelter/dignity), C7 (equity), C10 (hope/reversibility)
- **Healthcare:** C5 (health), C12 (child safety), C3 (dignity), C8 (security)
- **Education:** C7 (stimulation/autonomy), C10 (hope), C3 (dignity)

---

## How It Works

```
AI system requests an action
         │
         ▼
┌─────────────────────────────┐
│   DriftDetector             │
│   Declared intent vs        │
│   observed action           │
│   Score: 0.0 – 1.0          │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   ICSPolicyEngine           │
│   CORE12 breach check       │
│   Sector invariant check    │
│   High-risk action check    │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   SyntheticContract         │
│   Final adjudication        │
│                             │
│   HALT             (critical breach)         │
│   DENY             (policy violation)        │
│   PENDING_APPROVAL (human gate required)     │
│   DEGRADE          (drift detected)          │
│   ALLOW            (all checks passed)       │
└────────────┬────────────────┘
             │
             ▼
┌─────────────────────────────┐
│   LedgerService             │
│   SHA-256 hash chain        │
│   Ed25519 cryptographic sig │
│   Append-only, verifiable   │
└─────────────────────────────┘
```

Every outcome — ALLOW or BLOCK — is signed and chained. Nothing is
silent. Nothing is unlogged.

---

## Architecture Components

| Component | Function |
|---|---|
| **DriftDetector** | Compares declared intent vs observed action across goal, scope, consent basis, target subject |
| **ICSPolicyEngine** | Evaluates CORE12 harms + sector-supplied invariants |
| **SyntheticContract** | Final adjudication — HALT / DENY / PENDING / DEGRADE / ALLOW |
| **DissentGate** | Stakeholder challenge framework — weighted by evidence, drift, invariant breach |
| **SEAL** | Human approval gate for PENDING_APPROVAL decisions |
| **FORTIFY** | Runtime integrity daemon — monitors own codebase, halts on tampering |
| **LedgerService** | Tamper-evident SHA-256 + Ed25519 hash chain |
| **LASTExplainer** | Human-readable explanation for every decision — no silent outcomes |

---

## RBAC — Roles

| Role | Permissions |
|---|---|
| `viewer` | Read decisions and audit trail |
| `approver` | Approve PENDING_APPROVAL decisions with logged justification |
| `safety_officer` | Manage safety metadata, hazards, CORE12 interpretation |
| `audit` | Forensic read access — cannot approve or execute |
| `admin` | Key management, user provisioning, configuration |

---

## API Endpoints

| Endpoint | Method | Function |
|---|---|---|
| `/v1/evaluate` | POST | Core governance decision |
| `/v1/dissent` | POST | Submit challenge to a decision |
| `/v1/approve` | POST | Authorize a pending decision |
| `/v1/ledger/entries` | GET | Retrieve audit trail |
| `/v1/ledger/verify` | GET | Cryptographically verify ledger chain |
| `/v1/integrity/proof` | GET | Tamper-evident proof of system state |
| `/v1/core12` | GET | CORE12 fingerprint and needs list |
| `/v1/safety/hazards` | POST/GET/PATCH | Safety hazard log |
| `/v1/safety/metadata` | PUT/GET | Safety officer metadata |
| `/healthz` | GET | System status and seal check |

---

## Security

- **Ed25519 cryptographic signing** on every ledger entry
- **SHA-256 hash chain** — tamper with one entry and the chain breaks
- **scrypt password hashing** for all user credentials
- **FORTIFY daemon** — monitors engine files, shuts down on detected modification
- **Redis rate limiting** — brute force protection
- **Fail-closed** in strict/prod mode — missing requirements halt startup, not warn

---

## Sector Configuration

Sector-specific invariants are injected via environment variable — no
hardcoding required. The engine is agnostic. Your sector logic is yours.

```json
APTSA1_SECTOR_CONFIG_JSON='{
  "sector_invariants": [
    {
      "name": "authorisation_required",
      "context_field": "authorised",
      "must_equal": true,
      "severity": "critical"
    },
    {
      "name": "consent_documented",
      "context_field": "consent_on_file",
      "must_equal": true,
      "severity": "violation"
    }
  ]
}'
```

---

## Environment Variables

```bash
APTSA1_ENV=dev|test|prod
APTSA1_DOMAIN=universal|justice|education|finance|safeguarding
APTSA1_API_TOKEN=...                    # required in prod
APTSA1_DB_URL=postgresql://...          # required in prod
REDIS_URL=redis://...
APTSA1_SIGNING_KEY_PEM=...             # required in prod
APTSA1_BOOTSTRAP_USERS_JSON='[{"username":"admin","password":"...","role":"admin"}]'
APTSA1_SECTOR_CONFIG_JSON='{"sector_invariants":[]}'
APTSA1_CORS_ORIGIN=https://your-domain.org
APTSA1_FORTIFY_ENABLE=1
APTSA1_FORTIFY_PATHS_JSON='["./aptsa1_universal.py"]'
APTSA1_SAFETY_OFFICER_ID=...
APTSA1_LEDGER_LOG_MODE=full|meta|hash
APTSA1_RATE_LIMIT=60/minute
```

---

## Run

```bash
pip install fastapi uvicorn sqlalchemy pydantic cryptography \
            redis structlog prometheus_client slowapi

uvicorn aptsa1_universal:app --host 0.0.0.0 --port 8000
```

Development (SQLite, auto-generated signing key):
```bash
APTSA1_ENV=dev uvicorn aptsa1_universal:app --reload
```

Production (PostgreSQL, explicit signing key required):
```bash
APTSA1_ENV=prod \
APTSA1_DB_URL=postgresql://user:pass@host/db \
APTSA1_SIGNING_KEY_PEM="$(cat signing.key)" \
APTSA1_API_TOKEN=your-token \
APTSA1_BOOTSTRAP_USERS_JSON='[{"username":"admin","password":"secure","role":"admin"}]' \
uvicorn aptsa1_universal:app --host 0.0.0.0 --port 8000
```

---

## Deployment Modes

**Shadow Mode (Recommended first step)**
Deploy alongside existing AI systems. Observe decisions without blocking.
Collect baseline data: what decisions are made, how often, what risks arise.
No operational disruption.

**Enforcement Mode**
Enable blocking for high-risk actions. Override workflow active — authorised
roles can override DENY with logged justification. Full audit trail operational.

**Operational**
Full CORE12 enforcement. Continuous drift monitoring. Regular audit exports.

---

## What This Is Not

- Not a medical device
- Not sector-specific (this is the universal build)
- Not a large language model
- Not a replacement for human judgement — it gates and logs human-authorised decisions

Sector-specific builds (NHS/DTAC-aligned, justice, safeguarding) are
available separately under licensing agreement.

---

## Intellectual Property

Patent GB2521334.9 covers six named components of the APTSA1 architecture
(priority date 10 December 2025, active at UKIPO).

CORE12 — the twelve universal human needs as a formal governance constraint
scaffold — is the original work of Leon George, developed over 29 years.

This universal build is released for open deployment. The interpretive
framework — how CORE12 applies to your sector, how drift thresholds are
calibrated, how sector invariants are structured — is the proprietary
consulting layer available through Y✶KNOT AI CONSULTANT LTD.

---

## Contact

**Y✶KNOT AI CONSULTANT LTD**
Company No. 17128151
128 City Road, London, EC1V 2NX

Website: https://aptsa1-runtime.emergent.host
