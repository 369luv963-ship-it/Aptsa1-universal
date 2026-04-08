#!/usr/bin/env python3
"""
APTSA1 – Universal Governance Engine
Version 5.1.0-universal

Autonomous Protective Threshold System Architecture
Created by Leon George | Y✶KNOT AI CONSULTANT LTD
Patent: GB2521334.9 (priority date 10 December 2025)

─────────────────────────────────────────────────────────────────────────────
LICENCE NOTICE
─────────────────────────────────────────────────────────────────────────────
This file is released as the universal, sector-agnostic reference
implementation of APTSA1. Any sector — justice, education, finance,
safeguarding, defence, or any other — may deploy this engine under their
own configuration. CORE12 constraints are invariant and must not be removed.

The NHS/DTAC-specific build (v5.1.0) is a separate, proprietary file and
is not included here.

─────────────────────────────────────────────────────────────────────────────
WHAT THIS ENGINE DOES
─────────────────────────────────────────────────────────────────────────────
APTSA1 is a cryptographic runtime governance engine. It sits between an AI
system and its actions, evaluating every decision against:

  1. CORE12 — twelve universal human needs (invariant, cannot be disabled)
  2. Sector invariants — supplied by the deploying organisation via config
  3. Drift detection — declared intent vs observed action
  4. Role-gated approval — human authorisation for high-risk decisions

Every decision is cryptographically signed (Ed25519) and appended to a
tamper-evident hash-chained ledger. Nothing is logged after the fact.
Everything is enforced before the action occurs.

─────────────────────────────────────────────────────────────────────────────
ENVIRONMENT VARIABLES
─────────────────────────────────────────────────────────────────────────────
  APTSA1_ENV=dev|test|prod
  APTSA1_DOMAIN=universal|justice|education|finance|safeguarding  (any string)
  APTSA1_API_TOKEN=...                    # required in prod
  APTSA1_DB_URL=postgresql://...          # required in prod (SQLite for dev)
  REDIS_URL=redis://...
  APTSA1_SIGNING_KEY_PEM=...             # required in prod
  APTSA1_SIGNING_KEY_B64=...             # alternative to PEM
  APTSA1_BOOTSTRAP_USERS_JSON='[{"username":"admin","password":"...","role":"admin"}]'
  APTSA1_SECTOR_CONFIG_JSON='{"sector_invariants":[]}'
  APTSA1_CORS_ORIGIN=https://your-domain.org
  APTSA1_FORTIFY_ENABLE=1
  APTSA1_FORTIFY_PATHS_JSON='["./aptsa1_universal.py"]'
  APTSA1_SAFETY_OFFICER_ID=...           # identifier of the responsible safety officer
  APTSA1_LEDGER_LOG_MODE=full|meta|hash
  APTSA1_RATE_LIMIT=60/minute

─────────────────────────────────────────────────────────────────────────────
ROLES
─────────────────────────────────────────────────────────────────────────────
  viewer         — read-only access to decisions and audit trail
  approver       — can approve PENDING_APPROVAL decisions with justification
  safety_officer — responsible for human safety invariants in this deployment
  audit          — forensic read access; cannot approve or execute
  admin          — system configuration and user management

─────────────────────────────────────────────────────────────────────────────
RUN
─────────────────────────────────────────────────────────────────────────────
  pip install fastapi uvicorn sqlalchemy pydantic cryptography redis \
              structlog prometheus_client slowapi
  uvicorn aptsa1_universal:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import redis
import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import Boolean, Column, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ─────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY
# ─────────────────────────────────────────────────────────────────────────────

REQUESTS_TOTAL      = Counter("aptsa1_requests_total",    "Total requests processed")
VIOLATIONS_TOTAL    = Counter("aptsa1_violations_total",  "Policy violations detected")
DISSENTS_TOTAL      = Counter("aptsa1_dissents_total",    "Dissent submissions received")
OUTCOMES_TOTAL      = Counter("aptsa1_outcomes_total",    "Outcomes recorded")
DECISION_LATENCY    = Histogram("aptsa1_decision_latency_seconds", "Decision evaluation latency")
SYSTEM_STATE        = Gauge("aptsa1_system_state", "System state", ["status"])

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger("aptsa1")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

APP_VERSION       = "5.1.0-universal"
LEDGER_SCHEMA_VER = "1.1"
APTSA1_ENV        = os.getenv("APTSA1_ENV", "dev").strip().lower()
DEPLOYMENT_DOMAIN = os.getenv("APTSA1_DOMAIN", "universal").strip().lower()
LEDGER_LOG_MODE   = os.getenv("APTSA1_LEDGER_LOG_MODE", "full").strip().lower()
DB_URL            = os.getenv("APTSA1_DB_URL", "sqlite:///./aptsa1_universal.db")
REDIS_URL         = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_TOKEN         = os.getenv("APTSA1_API_TOKEN")
APPROVAL_THRESHOLD = float(os.getenv("APTSA1_APPROVAL_THRESHOLD", "0.85"))
AUTH_MAX_ATTEMPTS = int(os.getenv("AUTH_MAX_ATTEMPTS", "5"))
AUTH_WINDOW_SECS  = int(os.getenv("AUTH_WINDOW_SECS", "300"))
STRICT_MODE       = APTSA1_ENV == "prod"
ALLOWED_CORS_ORIGIN = os.getenv("APTSA1_CORS_ORIGIN", "http://localhost")
SAFETY_OFFICER_ID = os.getenv("APTSA1_SAFETY_OFFICER_ID", "")


def _env_json(name: str, default: Any) -> Any:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        logger.warning("invalid_json_env", var=name)
        return default


def _validate_sector_config(raw: Any) -> Dict[str, Any]:
    """Validate sector config structure at startup. Fail-closed in strict mode."""
    if not isinstance(raw, dict):
        logger.warning("sector_config_invalid_not_dict")
        if STRICT_MODE:
            raise RuntimeError("APTSA1_SECTOR_CONFIG_JSON must be a JSON object in strict mode.")
        return {"sector_invariants": []}
    invariants = raw.get("sector_invariants", [])
    if not isinstance(invariants, list):
        logger.warning("sector_config_invariants_not_list")
        if STRICT_MODE:
            raise RuntimeError("sector_invariants must be a list in strict mode.")
        return {"sector_invariants": []}
    validated: List[Dict[str, Any]] = []
    for item in invariants:
        if not isinstance(item, dict):
            logger.warning("sector_config_invariant_not_dict", item=str(item))
            continue
        if not item.get("name") or not item.get("context_field"):
            logger.warning("sector_config_invariant_missing_fields", item=str(item))
            continue
        validated.append(item)
    return {"sector_invariants": validated}


SECTOR_CONFIG = _validate_sector_config(_env_json("APTSA1_SECTOR_CONFIG_JSON", {"sector_invariants": []}))

# ─────────────────────────────────────────────────────────────────────────────
# REDIS — Graceful in dev mode, required in prod/strict mode
# ─────────────────────────────────────────────────────────────────────────────
REDIS_AVAILABLE = False
redis_client = None

try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
    redis_client.ping()
    REDIS_AVAILABLE = True
    logger.info("redis_connected", url=REDIS_URL)
except Exception as _redis_exc:
    redis_client = None
    REDIS_AVAILABLE = False
    if STRICT_MODE:
        raise RuntimeError(f"Redis is required in strict/prod mode: {_redis_exc}") from _redis_exc
    else:
        logger.warning("redis_unavailable_falling_back_to_memory", env=APTSA1_ENV)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=REDIS_URL if REDIS_AVAILABLE else "memory://",
)

# ─────────────────────────────────────────────────────────────────────────────
# CORE12 — INVARIANT HUMAN NEEDS
# Cannot be removed, reordered, or overridden.
# These twelve needs are the universal constraint scaffold.
# Patent: GB2521334.9
# ─────────────────────────────────────────────────────────────────────────────

CORE12 = [
    "water",         # C1  — physical safety
    "food",          # C2  — physical safety
    "shelter",       # C3  — physical safety
    "clothing",      # C4  — physical safety
    "health",        # C5  — physical/psychological safety
    "companionship", # C6  — psychological safety / dignity
    "stimulation",   # C7  — psychological safety
    "security",      # C8  — safety / autonomy
    "income",        # C9  — autonomy / equity
    "hope",          # C10 — psychological safety / reversibility
    "bonding",       # C11 — consent / dignity
    "procreation",   # C12 — absolute / highest severity / no exception
]


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _core12_fingerprint() -> str:
    return _sha256_hex(_stable_json(CORE12))


CORE12_FINGERPRINT = _core12_fingerprint()

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def mk_correlation_id() -> str:
    return f"aptsa1-{secrets.token_hex(8)}-{int(time.time())}"


def safe_json_loads(raw: str, default: Any = None) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return default


def redact_payload(value: Any) -> Any:
    if LEDGER_LOG_MODE == "full":
        return value
    if LEDGER_LOG_MODE == "meta":
        if isinstance(value, dict):
            return {"keys": sorted(value.keys()), "type": "dict"}
        if isinstance(value, list):
            return {"len": len(value), "type": "list"}
        return {"type": type(value).__name__}
    return {"sha256": _sha256_hex(_stable_json(value))}


def scrub_sensitive(value: Any) -> Any:
    sensitive = {"password", "token", "secret", "key", "credential", "auth"}
    if isinstance(value, dict):
        return {
            k: "***REDACTED***" if any(s in k.lower() for s in sensitive) else scrub_sensitive(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub_sensitive(v) for v in value]
    return value

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    username     = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role         = Column(String(100), default="viewer")
    created_at   = Column(String(64), default=utc_now)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    ts_utc         = Column(String(64), index=True)
    entry_type     = Column(String(80), index=True)
    actor_id       = Column(String(200), index=True)
    payload_json   = Column(Text)
    prev_hash      = Column(String(64), default="0" * 64)
    entry_hash     = Column(String(64), unique=True, index=True)
    signature_b64  = Column(Text)
    schema_version = Column(String(20), default=LEDGER_SCHEMA_VER)
    domain         = Column(String(80), default=DEPLOYMENT_DOMAIN)
    safety_flag    = Column(Boolean, default=False)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    decision_ref  = Column(String(200), index=True)
    rationale     = Column(Text)
    required_role = Column(String(100), default="approver")
    approved      = Column(Boolean, default=False)
    approved_by   = Column(String(100), nullable=True)
    approved_role = Column(String(100), nullable=True)
    approved_at   = Column(String(64), nullable=True)
    created_at    = Column(String(64), default=utc_now)


class OutcomeRecord(Base):
    __tablename__ = "outcome_records"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    decision_ref  = Column(String(200), index=True)
    outcome_label = Column(String(200), index=True)
    outcome_value = Column(Text)
    recorded_by   = Column(String(200))
    recorded_at   = Column(String(64), default=utc_now)


class HazardLogItem(Base):
    """
    Sector-agnostic hazard log. In healthcare this maps to clinical hazards;
    in justice it maps to procedural risk; in education to safeguarding risk.
    The structure is identical — only the context changes.
    """
    __tablename__  = "hazard_log"
    id             = Column(Integer, primary_key=True, autoincrement=True)
    hazard_id      = Column(String(64), unique=True, index=True)
    title          = Column(String(200), nullable=False)
    description    = Column(Text, nullable=False)
    cause          = Column(Text, nullable=True)
    effect         = Column(Text, nullable=True)
    initial_risk   = Column(String(32), nullable=False)
    mitigation     = Column(Text, nullable=True)
    residual_risk  = Column(String(32), nullable=True)
    owner          = Column(String(100), nullable=True)
    status         = Column(String(32), default="open")
    created_at     = Column(String(64), default=utc_now)
    updated_at     = Column(String(64), default=utc_now)


class SafetyMetadata(Base):
    """
    Universal safety metadata. The safety_officer_identifier maps to whoever
    holds accountability for human safety in the deploying organisation.
    """
    __tablename__               = "safety_metadata"
    id                          = Column(Integer, primary_key=True, autoincrement=True)
    product_name                = Column(String(200), default="APTSA1")
    version                     = Column(String(50), default=APP_VERSION)
    safety_officer_name         = Column(String(200), nullable=True)
    safety_officer_identifier   = Column(String(200), nullable=True)
    intended_use                = Column(Text, nullable=True)
    deployment_scope            = Column(Text, nullable=True)
    out_of_scope                = Column(Text, nullable=True)
    safety_case_status          = Column(String(32), default="draft")
    updated_at                  = Column(String(64), default=utc_now)


_connect_args = {"check_same_thread": False} if "sqlite" in DB_URL else {}
engine = create_engine(DB_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

_AUTH_THROTTLE: Dict[str, List[float]] = defaultdict(list)
_AUTH_LOCK = threading.Lock()


def _throttle_check(username: str) -> bool:
    now = time.time()
    with _AUTH_LOCK:
        attempts = [t for t in _AUTH_THROTTLE[username] if now - t < AUTH_WINDOW_SECS]
        _AUTH_THROTTLE[username] = attempts
        if len(attempts) >= AUTH_MAX_ATTEMPTS:
            return False
        _AUTH_THROTTLE[username].append(now)
        return True


def scrypt_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.b64encode(salt + derived).decode("utf-8")


def scrypt_verify(password: str, encoded: str) -> bool:
    try:
        raw    = base64.b64decode(encoded.encode("utf-8"))
        salt   = raw[:16]
        stored = raw[16:]
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, stored)
    except Exception:
        return False


def bootstrap_users_strict() -> None:
    users = _env_json("APTSA1_BOOTSTRAP_USERS_JSON", [])
    if STRICT_MODE and not users:
        raise RuntimeError("APTSA1_BOOTSTRAP_USERS_JSON is required in strict mode")
    if not users:
        return
    with SessionLocal() as db:
        for item in users:
            username = str(item.get("username", "")).strip()
            password = str(item.get("password", "")).strip()
            role     = str(item.get("role", "viewer")).strip()
            if not username or not password:
                raise RuntimeError("Bootstrap users must include username and password")
            if db.query(User).filter(User.username == username).first():
                continue
            db.add(User(username=username, password_hash=scrypt_hash(password), role=role))
        db.commit()
        logger.info("bootstrap_users_initialised")

# ─────────────────────────────────────────────────────────────────────────────
# SIGNING KEYS — Ed25519
# ─────────────────────────────────────────────────────────────────────────────

_KEY_PATH    = Path(os.getenv("APTSA1_KEY_PATH", "./aptsa1_signing.key"))
_PUBKEY_PATH = _KEY_PATH.with_suffix(".pub")


def load_signing_key() -> Ed25519PrivateKey:
    pem = os.getenv("APTSA1_SIGNING_KEY_PEM")
    b64 = os.getenv("APTSA1_SIGNING_KEY_B64")
    if pem:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("Configured signing key is not Ed25519")
        return key
    if b64:
        key = serialization.load_pem_private_key(base64.b64decode(b64), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("Configured signing key is not Ed25519")
        return key
    if _KEY_PATH.exists():
        key = serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("Stored signing key is not Ed25519")
        return key
    if STRICT_MODE:
        raise RuntimeError("Signing key is required in strict mode")
    logger.warning("dev_mode_generating_ephemeral_signing_key")
    key = Ed25519PrivateKey.generate()
    _KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    _KEY_PATH.chmod(0o600)
    _PUBKEY_PATH.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return key


SIGNING_KEY = load_signing_key()
VERIFY_KEY  = SIGNING_KEY.public_key()


def export_public_key_b64() -> str:
    pub = VERIFY_KEY.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode("utf-8")

# ─────────────────────────────────────────────────────────────────────────────
# ENUMS / DATACLASSES
# ─────────────────────────────────────────────────────────────────────────────


class DecisionOutcome(str, Enum):
    ALLOW            = "allow"
    DEGRADE          = "degrade"
    DENY             = "deny"
    HALT             = "halt"
    PENDING_APPROVAL = "pending_approval"


class DissentOutcome(str, Enum):
    CONFIRMED_DRIFT            = "confirmed_drift"
    CONFIRMED_INVARIANT_BREACH = "confirmed_invariant_breach"
    PARTIAL_CONCERN            = "partial_concern"
    UNSUPPORTED_DISSENT        = "unsupported_dissent"
    MALICIOUS_OR_SPAM          = "malicious_or_spam"


@dataclass
class DriftAssessment:
    score: float
    reasons: List[str] = field(default_factory=list)


@dataclass
class PolicyAssessment:
    critical_violations: List[str] = field(default_factory=list)
    violations:          List[str] = field(default_factory=list)
    harmed_needs:        List[str] = field(default_factory=list)


@dataclass
class DissentAssessment:
    outcome:                DissentOutcome
    drift_score:            float
    invariant_breach_score: float
    credibility_score:      float
    reasons:                List[str]
    recommended_action:     str
    severity:               float

# ─────────────────────────────────────────────────────────────────────────────
# API MODELS
# ─────────────────────────────────────────────────────────────────────────────


class Core12Harms(BaseModel):
    """
    Each field maps directly to a CORE12 universal human need.
    Set to True if the proposed action harms that need.
    Any True value activates CORE12 enforcement — this cannot be bypassed.
    """
    water:         bool = False
    food:          bool = False
    shelter:       bool = False
    clothing:      bool = False
    health:        bool = False
    companionship: bool = False
    stimulation:   bool = False
    security:      bool = False
    income:        bool = False
    hope:          bool = False
    bonding:       bool = False
    procreation:   bool = False


class EvaluateRequest(BaseModel):
    actor_id:         str
    action:           str
    declared_intent:  Dict[str, Any] = Field(default_factory=dict)
    observed_action:  Dict[str, Any] = Field(default_factory=dict)
    context:          Dict[str, Any] = Field(default_factory=dict)
    core12_harms:     Core12Harms    = Field(default_factory=Core12Harms)
    requires_approval: bool          = False
    requested_role:   Optional[str]  = None
    correlation_id:   Optional[str]  = None


class DissentRequest(BaseModel):
    actor_id:        str
    target_id:       str
    target_type:     str
    claim:           str
    evidence:        List[Dict[str, Any]] = Field(default_factory=list)
    declared_intent: Dict[str, Any]       = Field(default_factory=dict)
    observed_action: Dict[str, Any]       = Field(default_factory=dict)
    context:         Dict[str, Any]       = Field(default_factory=dict)
    core12_harms:    Core12Harms          = Field(default_factory=Core12Harms)
    policy_result:   Dict[str, Any]       = Field(default_factory=dict)


class ApprovalActionRequest(BaseModel):
    request_id: int


class LoginRequest(BaseModel):
    username: str
    password: str


class OutcomeRequest(BaseModel):
    decision_ref:  str
    outcome_label: str
    outcome_value: Dict[str, Any]
    recorded_by:   str


class HazardCreateRequest(BaseModel):
    title:         str
    description:   str
    cause:         Optional[str] = None
    effect:        Optional[str] = None
    initial_risk:  str
    mitigation:    Optional[str] = None
    residual_risk: Optional[str] = None
    owner:         Optional[str] = None


class HazardUpdateRequest(BaseModel):
    hazard_id:     str
    mitigation:    Optional[str] = None
    residual_risk: Optional[str] = None
    status:        Optional[str] = None


class SafetyMetadataRequest(BaseModel):
    product_name:               str = "APTSA1"
    safety_officer_name:        Optional[str] = None
    safety_officer_identifier:  Optional[str] = None
    intended_use:               Optional[str] = None
    deployment_scope:           Optional[str] = None
    out_of_scope:               Optional[str] = None
    safety_case_status:         str = "draft"


class AuthenticatedUser(BaseModel):
    username: str
    role: str

# ─────────────────────────────────────────────────────────────────────────────
# LEDGER — Tamper-Evident Hash Chain
# ─────────────────────────────────────────────────────────────────────────────

_LEDGER_LOCK = threading.Lock()


class LedgerService:
    def __init__(self, db: Session):
        self.db = db

    def _prev_hash(self) -> str:
        last = self.db.query(LedgerEntry).order_by(LedgerEntry.id.desc()).first()
        return last.entry_hash if last else "0" * 64

    def append(self, entry_type: str, actor_id: str, payload: Dict[str, Any]) -> LedgerEntry:
        with _LEDGER_LOCK:
            try:
                ts        = utc_now()
                prev_hash = self._prev_hash()
                envelope  = {
                    "ts_utc":            ts,
                    "entry_type":        entry_type,
                    "actor_id":          actor_id,
                    "payload":           redact_payload(payload),
                    "prev_hash":         prev_hash,
                    "schema_version":    LEDGER_SCHEMA_VER,
                    "domain":            DEPLOYMENT_DOMAIN,
                    "core12_fingerprint": CORE12_FINGERPRINT,
                }
                stable     = _stable_json(envelope)
                entry_hash = _sha256_hex(stable)
                sig        = base64.b64encode(SIGNING_KEY.sign(stable.encode("utf-8"))).decode("utf-8")
                row = LedgerEntry(
                    ts_utc         = ts,
                    entry_type     = entry_type,
                    actor_id       = actor_id,
                    payload_json   = _stable_json(envelope["payload"]),
                    prev_hash      = prev_hash,
                    entry_hash     = entry_hash,
                    signature_b64  = sig,
                    schema_version = LEDGER_SCHEMA_VER,
                    domain         = DEPLOYMENT_DOMAIN,
                    safety_flag    = False,
                )
                self.db.add(row)
                self.db.commit()
                self.db.refresh(row)
                return row
            except Exception as exc:
                self.db.rollback()
                logger.error("ledger_append_failed", entry_type=entry_type, actor_id=actor_id, error=str(exc))
                raise

    def verify_chain(self) -> Dict[str, Any]:
        rows     = self.db.query(LedgerEntry).order_by(LedgerEntry.id.asc()).all()
        prev     = "0" * 64
        failures: List[Dict[str, Any]] = []
        for row in rows:
            envelope = {
                "ts_utc":            row.ts_utc,
                "entry_type":        row.entry_type,
                "actor_id":          row.actor_id,
                "payload":           safe_json_loads(row.payload_json, {}),
                "prev_hash":         row.prev_hash,
                "schema_version":    row.schema_version,
                "domain":            row.domain,
                "core12_fingerprint": CORE12_FINGERPRINT,
            }
            if row.prev_hash != prev:
                failures.append({"id": row.id, "reason": "prev_hash_mismatch"})
            computed = _sha256_hex(_stable_json(envelope))
            if computed != row.entry_hash:
                failures.append({"id": row.id, "reason": "entry_hash_mismatch"})
            try:
                VERIFY_KEY.verify(base64.b64decode(row.signature_b64), _stable_json(envelope).encode("utf-8"))
            except InvalidSignature:
                failures.append({"id": row.id, "reason": "signature_invalid"})
            prev = row.entry_hash
        return {
            "ok":              not failures,
            "entries_checked": len(rows),
            "failures":        failures,
            "public_key_b64":  export_public_key_b64(),
        }

# ─────────────────────────────────────────────────────────────────────────────
# DRIFT DETECTOR
# Compares declared intent against observed action.
# Drift above threshold triggers DEGRADE or DENY.
# ─────────────────────────────────────────────────────────────────────────────


class DriftDetector:
    @staticmethod
    def assess(declared_intent: Dict[str, Any], observed_action: Dict[str, Any]) -> DriftAssessment:
        # Type guard — accept strings (treated as goal-only) or dicts
        if isinstance(declared_intent, str):
            declared_intent = {"goal": declared_intent.strip()}
        if isinstance(observed_action, str):
            observed_action = {"goal": observed_action.strip()}
        if not isinstance(declared_intent, dict) or not isinstance(observed_action, dict):
            logger.warning("drift_detector_invalid_input_types")
            return DriftAssessment(score=0.0, reasons=["Invalid input types — drift assessment skipped."])
        reasons: List[str] = []
        score = 0.0
        if declared_intent.get("goal") != observed_action.get("goal"):
            score += 0.5
            reasons.append("Observed goal diverges from declared goal.")
        if declared_intent.get("scope") != observed_action.get("scope"):
            score += 0.2
            reasons.append("Observed scope diverges from declared scope.")
        if declared_intent.get("consent_basis") and declared_intent.get("consent_basis") != observed_action.get("consent_basis"):
            score += 0.2
            reasons.append("Consent basis drift detected.")
        if declared_intent.get("target_subject") and declared_intent.get("target_subject") != observed_action.get("target_subject"):
            score += 0.1
            reasons.append("Target subject changed between intent and action.")
        return DriftAssessment(score=round(min(score, 1.0), 3), reasons=reasons)

# ─────────────────────────────────────────────────────────────────────────────
# ICS POLICY ENGINE
# Evaluates actions against CORE12 and sector-supplied invariants.
# Sector invariants are injected via APTSA1_SECTOR_CONFIG_JSON — no hardcoding.
# ─────────────────────────────────────────────────────────────────────────────


class ICSPolicyEngine:
    @staticmethod
    def assess(action: str, context: Dict[str, Any], harms: Dict[str, bool]) -> PolicyAssessment:
        critical: List[str] = []
        violations: List[str] = []
        # CORE12 harm detection — invariant, cannot be disabled
        harmed_needs = [need for need, harmed in harms.items() if harmed]
        if harmed_needs:
            critical.append(f"CORE12 harms detected: {', '.join(harmed_needs)}")
        # Sector-supplied invariants from environment config
        for invariant in SECTOR_CONFIG.get("sector_invariants", []):
            name       = invariant.get("name", "unnamed_invariant")
            field_name = invariant.get("context_field")
            expected   = invariant.get("must_equal")
            severity   = invariant.get("severity", "violation")
            if field_name and context.get(field_name) != expected:
                message = f"Sector invariant failed: {name}"
                if severity == "critical":
                    critical.append(message)
                else:
                    violations.append(message)
        # Universal high-risk action detection
        action_lower = action.lower()
        if action_lower in {"delete_record", "override_consent", "suppress_alert"}:
            violations.append(f"High-risk action detected: {action}")
        if "disable_audit" in action_lower or "bypass_logging" in action_lower:
            critical.append("AUDIT_INTEGRITY_VIOLATION — cannot disable audit trail")
        return PolicyAssessment(
            critical_violations=critical,
            violations=violations,
            harmed_needs=harmed_needs,
        )

# ─────────────────────────────────────────────────────────────────────────────
# DISSENT GATE
# Processes formal challenges to decisions. Escalates to HALT on confirmed
# invariant breach. Degrades on confirmed drift. Logs all dissent.
# ─────────────────────────────────────────────────────────────────────────────


class DissentGate:
    @staticmethod
    def assess(
        claim:           str,
        evidence:        List[Dict[str, Any]],
        declared_intent: Dict[str, Any],
        observed_action: Dict[str, Any],
        policy_result:   Dict[str, Any],
        core12_harms:    Dict[str, bool],
    ) -> DissentAssessment:
        reasons: List[str] = []
        drift_score = invariant_breach_score = credibility_score = 0.0

        if evidence:
            credibility_score += 0.4
            reasons.append("Submitted dissent includes evidence.")
        else:
            reasons.append("No supporting evidence supplied.")

        drift = DriftDetector.assess(declared_intent, observed_action)
        if drift.score > 0:
            drift_score += drift.score
            reasons.extend(drift.reasons)

        harmed = [k for k, v in core12_harms.items() if v]
        if harmed:
            invariant_breach_score += 0.8
            reasons.append(f"Potential CORE12 harm: {', '.join(harmed)}.")

        if policy_result.get("violations"):
            invariant_breach_score += 0.2
            reasons.append("Policy violations present in challenged action.")
        if policy_result.get("critical_violations"):
            invariant_breach_score += 0.3
            reasons.append("Critical policy violations present.")

        lowered = claim.lower()
        if any(t in lowered for t in ["unsafe", "contradiction", "consent", "not what happened", "harm"]):
            credibility_score += 0.1
            reasons.append("Claim language indicates concrete challenge.")

        drift_score            = min(drift_score, 1.0)
        invariant_breach_score = min(invariant_breach_score, 1.0)
        credibility_score      = min(credibility_score, 1.0)
        severity = round(
            min((0.45 * drift_score) + (0.45 * invariant_breach_score) + (0.10 * credibility_score), 1.0), 3
        )

        if invariant_breach_score >= 0.8:
            outcome = DissentOutcome.CONFIRMED_INVARIANT_BREACH
            action  = "HALT target process and escalate for human review."
        elif drift_score >= 0.5:
            outcome = DissentOutcome.CONFIRMED_DRIFT
            action  = "DEGRADE autonomy, flag audit, and require explanation."
        elif severity >= 0.45:
            outcome = DissentOutcome.PARTIAL_CONCERN
            action  = "Queue supervised review and request more evidence."
        elif credibility_score < 0.1 and not evidence:
            outcome = DissentOutcome.MALICIOUS_OR_SPAM
            action  = "Log only and rate-limit repeated submissions."
        else:
            outcome = DissentOutcome.UNSUPPORTED_DISSENT
            action  = "Log challenge and return transparent explanation."

        return DissentAssessment(
            outcome=outcome,
            drift_score=round(drift_score, 3),
            invariant_breach_score=round(invariant_breach_score, 3),
            credibility_score=round(credibility_score, 3),
            reasons=reasons,
            recommended_action=action,
            severity=severity,
        )

# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC CONTRACT
# Final adjudication layer. Combines drift + policy into a binding decision.
# HALT > DENY > PENDING_APPROVAL > DEGRADE > ALLOW — in that priority order.
# ─────────────────────────────────────────────────────────────────────────────


class SyntheticContract:
    @staticmethod
    def adjudicate(
        drift:             DriftAssessment,
        policy:            PolicyAssessment,
        requires_approval: bool,
        requested_role:    Optional[str],
    ) -> Tuple[DecisionOutcome, List[str]]:
        reasons: List[str] = []
        if policy.critical_violations:
            reasons.extend(policy.critical_violations)
            return DecisionOutcome.HALT, reasons
        if policy.violations:
            reasons.extend(policy.violations)
            return DecisionOutcome.DENY, reasons
        if requires_approval:
            reasons.append(f"Approval required for role: {requested_role or 'approver'}")
            return DecisionOutcome.PENDING_APPROVAL, reasons
        if drift.score >= 0.5:
            reasons.extend(drift.reasons)
            return DecisionOutcome.DEGRADE, reasons
        reasons.append("No critical violations, policy denial, or significant drift.")
        return DecisionOutcome.ALLOW, reasons

# ─────────────────────────────────────────────────────────────────────────────
# LAST EXPLAINER
# Every decision produces a human-readable explanation. No silent outcomes.
# ─────────────────────────────────────────────────────────────────────────────


class LASTExplainer:
    @staticmethod
    def explain_decision(outcome: DecisionOutcome, reasons: List[str]) -> str:
        joined = " ".join(reasons) if reasons else "No additional reasons provided."
        mapping = {
            DecisionOutcome.ALLOW:            f"Allowed: governance checks found no blocking issue. {joined}",
            DecisionOutcome.DEGRADE:          f"Degraded: drift or uncertainty was detected. {joined}",
            DecisionOutcome.DENY:             f"Denied: policy constraints were violated. {joined}",
            DecisionOutcome.HALT:             f"Halted: a critical safety or invariant breach was detected. {joined}",
            DecisionOutcome.PENDING_APPROVAL: f"Pending approval: this action requires human authorisation. {joined}",
        }
        return mapping[outcome]

    @staticmethod
    def explain_dissent(assessment: DissentAssessment) -> str:
        return (
            f"Dissent outcome: {assessment.outcome.value}. "
            f"Severity={assessment.severity}. "
            f"Recommended action: {assessment.recommended_action} "
            f"Reasons: {' '.join(assessment.reasons)}"
        )

# ─────────────────────────────────────────────────────────────────────────────
# FORTIFY — Runtime Integrity Monitor
# Watches its own files. Any modification triggers SIGTERM and halts the engine.
# The governance engine cannot be silently tampered with while running.
# ─────────────────────────────────────────────────────────────────────────────


class FortifyMonitor:
    def __init__(self) -> None:
        self.enabled      = os.getenv("APTSA1_FORTIFY_ENABLE", "0") == "1"
        self.interval_sec = int(os.getenv("APTSA1_FORTIFY_INTERVAL_SEC", "30"))
        self.paths        = [Path(p) for p in _env_json("APTSA1_FORTIFY_PATHS_JSON", [])]
        self._baseline: Dict[str, str] = {}
        self._stop   = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _hash_file(self, path: Path) -> Optional[str]:
        if not path.exists() or not path.is_file():
            return None
        return _sha256_hex(path.read_bytes())

    def _scan(self) -> Dict[str, str]:
        return {str(path): digest for path in self.paths if (digest := self._hash_file(path)) is not None}

    def start(self) -> None:
        if not self.enabled or not self.paths:
            logger.info("fortify_disabled_or_no_paths")
            return
        self._baseline = self._scan()
        self._thread   = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("fortify_started", paths=len(self._baseline))

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.interval_sec)
            current = self._scan()
            if current != self._baseline:
                logger.critical("fortify_integrity_breach_terminating")
                SYSTEM_STATE.labels(status="fortify_breach").set(1)
                os.kill(os.getpid(), signal.SIGTERM)

    def stop(self) -> None:
        self._stop.set()

    def seal_check(self) -> Dict[str, Any]:
        checks = {
            "signing_key_present":      _KEY_PATH.exists() or bool(os.getenv("APTSA1_SIGNING_KEY_PEM") or os.getenv("APTSA1_SIGNING_KEY_B64")),
            "redis_reachable":          self._ping_redis(),
            "fortify_active":           self.enabled and self._thread is not None,
            "core12_fingerprint_valid": _core12_fingerprint() == CORE12_FINGERPRINT,
            "strict_mode":              STRICT_MODE,
            "api_token_required":       bool(API_TOKEN),
        }
        ok = all(checks.values()) if STRICT_MODE else True
        return {"status": "ok" if ok else "degraded", "checks": checks}

    def _ping_redis(self) -> bool:
        return REDIS_AVAILABLE


FORTIFY = FortifyMonitor()

# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME VALIDATION — Fail-Closed
# In prod/strict mode, missing requirements halt startup. Not warnings — errors.
# ─────────────────────────────────────────────────────────────────────────────


def validate_runtime_requirements() -> None:
    errors: List[str] = []
    if STRICT_MODE:
        if not (os.getenv("APTSA1_SIGNING_KEY_PEM") or os.getenv("APTSA1_SIGNING_KEY_B64") or _KEY_PATH.exists()):
            errors.append("Signing key is required in strict mode.")
        if not API_TOKEN:
            errors.append("APTSA1_API_TOKEN is required in strict mode.")
        if not os.getenv("APTSA1_BOOTSTRAP_USERS_JSON"):
            errors.append("APTSA1_BOOTSTRAP_USERS_JSON is required in strict mode.")
        if "sqlite" in DB_URL:
            errors.append("SQLite is not permitted in strict mode; use PostgreSQL or equivalent.")
        if ALLOWED_CORS_ORIGIN == "*":
            errors.append("Wildcard CORS is not permitted in strict mode.")
        try:
            redis_client.ping()
        except Exception:
            errors.append("Redis must be reachable in strict mode.")
    if errors:
        raise RuntimeError(" | ".join(errors))

# ─────────────────────────────────────────────────────────────────────────────
# AUTH DEPENDENCIES
# ─────────────────────────────────────────────────────────────────────────────


def require_api_token(x_api_token: Optional[str] = Header(default=None)) -> None:
    if API_TOKEN and x_api_token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


def require_user(
    login_username: str = Header(..., alias="X-APTSA1-Username"),
    login_password: str = Header(..., alias="X-APTSA1-Password"),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    if not _throttle_check(login_username):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    user = db.query(User).filter(User.username == login_username).first()
    if not user or not scrypt_verify(login_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return AuthenticatedUser(username=user.username, role=user.role)


def require_role(*allowed_roles: str):
    def dependency(user: AuthenticatedUser = Depends(require_user)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency

# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="APTSA1 Universal Governance Engine",
    description=(
        "Cryptographic runtime AI governance — universal sector-agnostic build. "
        f"Version {APP_VERSION} | Domain: {DEPLOYMENT_DOMAIN} | "
        "Patent GB2521334.9 | Leon George / Y✶KNOT AI CONSULTANT LTD"
    ),
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_CORS_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/metrics", make_asgi_app())
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


@app.on_event("startup")
def on_startup() -> None:
    validate_runtime_requirements()
    bootstrap_users_strict()
    FORTIFY.start()
    SYSTEM_STATE.labels(status="startup").set(1)
    logger.info(
        "aptsa1_startup_complete",
        version=APP_VERSION,
        domain=DEPLOYMENT_DOMAIN,
        core12_fingerprint=CORE12_FINGERPRINT,
        strict_mode=STRICT_MODE,
        redis_available=REDIS_AVAILABLE,
    )


@app.on_event("shutdown")
def on_shutdown() -> None:
    FORTIFY.stop()
    SYSTEM_STATE.labels(status="shutdown").set(1)
    logger.info("aptsa1_shutdown")


@app.middleware("http")
async def request_trace(request: Request, call_next):
    start    = time.time()
    response = await call_next(request)
    elapsed_ms = round((time.time() - start) * 1000, 2)
    response.headers["X-APTSA1-Version"]    = APP_VERSION
    response.headers["X-APTSA1-Domain"]     = DEPLOYMENT_DOMAIN
    response.headers["X-APTSA1-Elapsed-Ms"] = str(elapsed_ms)
    return response

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/healthz", tags=["System"])
def healthz() -> Dict[str, Any]:
    return {
        "ok":                True,
        "version":           APP_VERSION,
        "env":               APTSA1_ENV,
        "domain":            DEPLOYMENT_DOMAIN,
        "strict_mode":       STRICT_MODE,
        "core12_fingerprint": CORE12_FINGERPRINT,
        "public_key_b64":    export_public_key_b64(),
        "seal":              FORTIFY.seal_check(),
        "timestamp":         utc_now(),
    }


@app.post("/v1/auth/login", tags=["Auth"])
def login(req: LoginRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    if not _throttle_check(req.username):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not scrypt_verify(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"ok": True, "username": user.username, "role": user.role}


@app.post("/v1/evaluate", dependencies=[Depends(require_api_token)], tags=["Governance"])
@limiter.limit(os.getenv("APTSA1_RATE_LIMIT", "60/minute"))
def evaluate(
    request: Request,
    req:     EvaluateRequest,
    db:      Session = Depends(get_db),
    user:    AuthenticatedUser = Depends(require_role("viewer", "approver", "safety_officer", "audit", "admin")),
) -> JSONResponse:
    REQUESTS_TOTAL.inc()
    started = time.perf_counter()
    cid     = req.correlation_id or mk_correlation_id()
    harms   = req.core12_harms.model_dump()
    drift   = DriftDetector.assess(req.declared_intent, req.observed_action)
    policy  = ICSPolicyEngine.assess(req.action, req.context, harms)
    outcome, reasons = SyntheticContract.adjudicate(drift, policy, req.requires_approval, req.requested_role)
    decision_ref = _sha256_hex(_stable_json({
        "actor_id":        req.actor_id,
        "action":          req.action,
        "declared_intent": req.declared_intent,
        "observed_action": req.observed_action,
        "ts":              utc_now(),
    }))
    approval_request_id = None
    if outcome == DecisionOutcome.PENDING_APPROVAL:
        ar = ApprovalRequest(
            decision_ref  = decision_ref,
            rationale     = " ".join(reasons),
            required_role = req.requested_role or "approver",
        )
        db.add(ar)
        db.commit()
        db.refresh(ar)
        approval_request_id = ar.id
    explanation = LASTExplainer.explain_decision(outcome, reasons)
    latency_ms  = round((time.perf_counter() - started) * 1000, 2)
    DECISION_LATENCY.observe(max((time.perf_counter() - started), 0.0))
    payload = {
        "correlation_id":       cid,
        "decision_ref":         decision_ref,
        "actor_id":             req.actor_id,
        "action":               req.action,
        "evaluated_by":         user.username,
        "evaluator_role":       user.role,
        "drift_score":          drift.score,
        "drift_reasons":        drift.reasons,
        "policy": {
            "critical_violations": policy.critical_violations,
            "violations":          policy.violations,
            "harmed_needs":        policy.harmed_needs,
        },
        "outcome":              outcome.value,
        "approval_request_id":  approval_request_id,
        "explanation":          explanation,
        "core12_fingerprint":   CORE12_FINGERPRINT,
        "latency_ms":           latency_ms,
        "version":              APP_VERSION,
    }
    ledger_row = LedgerService(db).append("decision", user.username, payload)
    if outcome in {DecisionOutcome.DENY, DecisionOutcome.HALT}:
        VIOLATIONS_TOTAL.inc()
    logger.info("aptsa1_decision", outcome=outcome.value, decision_ref=decision_ref, actor=req.actor_id)
    status_map = {
        DecisionOutcome.ALLOW:            status.HTTP_200_OK,
        DecisionOutcome.DEGRADE:          status.HTTP_202_ACCEPTED,
        DecisionOutcome.PENDING_APPROVAL: status.HTTP_202_ACCEPTED,
        DecisionOutcome.DENY:             status.HTTP_403_FORBIDDEN,
        DecisionOutcome.HALT:             status.HTTP_423_LOCKED,
    }
    return JSONResponse(
        content    = {**payload, "ledger_id": ledger_row.id, "ledger_hash": ledger_row.entry_hash},
        status_code = status_map[outcome],
    )


@app.post("/v1/dissent", dependencies=[Depends(require_api_token)], tags=["D-Gate"])
def submit_dissent(
    req:  DissentRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("viewer", "approver", "safety_officer", "audit", "admin")),
) -> Dict[str, Any]:
    DISSENTS_TOTAL.inc()
    harms         = req.core12_harms.model_dump()
    policy_result = req.policy_result
    if not policy_result:
        policy = ICSPolicyEngine.assess(req.target_type, req.context, harms)
        policy_result = {
            "critical_violations": policy.critical_violations,
            "violations":          policy.violations,
            "harmed_needs":        policy.harmed_needs,
        }
    assessment = DissentGate.assess(
        claim           = req.claim,
        evidence        = req.evidence,
        declared_intent = req.declared_intent,
        observed_action = req.observed_action,
        policy_result   = policy_result,
        core12_harms    = harms,
    )
    outcome_map = {
        DissentOutcome.CONFIRMED_INVARIANT_BREACH: DecisionOutcome.HALT,
        DissentOutcome.CONFIRMED_DRIFT:            DecisionOutcome.DEGRADE,
        DissentOutcome.PARTIAL_CONCERN:            DecisionOutcome.PENDING_APPROVAL,
        DissentOutcome.MALICIOUS_OR_SPAM:          DecisionOutcome.DENY,
        DissentOutcome.UNSUPPORTED_DISSENT:        DecisionOutcome.ALLOW,
    }
    contract_outcome = outcome_map[assessment.outcome]
    decision_ref     = _sha256_hex(_stable_json({
        "actor_id":  req.actor_id,
        "target_id": req.target_id,
        "claim":     req.claim,
        "ts":        utc_now(),
    }))
    approval_request_id = None
    if contract_outcome == DecisionOutcome.PENDING_APPROVAL:
        ar = ApprovalRequest(
            decision_ref  = decision_ref,
            rationale     = assessment.recommended_action,
            required_role = "approver",
        )
        db.add(ar)
        db.commit()
        db.refresh(ar)
        approval_request_id = ar.id
    explanation = LASTExplainer.explain_dissent(assessment)
    payload = {
        "decision_ref":              decision_ref,
        "target_id":                 req.target_id,
        "target_type":               req.target_type,
        "claim":                     req.claim,
        "dissent_outcome":           assessment.outcome.value,
        "synthetic_contract_outcome": contract_outcome.value,
        "drift_score":               assessment.drift_score,
        "invariant_breach_score":    assessment.invariant_breach_score,
        "credibility_score":         assessment.credibility_score,
        "severity":                  assessment.severity,
        "reasons":                   assessment.reasons,
        "recommended_action":        assessment.recommended_action,
        "approval_request_id":       approval_request_id,
        "submitted_by":              user.username,
        "explanation":               explanation,
    }
    ledger_row = LedgerService(db).append("dissent", user.username, payload)
    return {"ok": True, "ledger_id": ledger_row.id, "ledger_hash": ledger_row.entry_hash, **payload}


@app.post("/v1/approve", dependencies=[Depends(require_api_token)], tags=["SEAL"])
def approve(
    req:  ApprovalActionRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("approver", "safety_officer", "admin")),
) -> Dict[str, Any]:
    row = db.query(ApprovalRequest).filter(ApprovalRequest.id == req.request_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Approval request not found")
    if row.approved:
        return {"ok": True, "already_approved": True, "request_id": row.id}
    if row.required_role and user.role != row.required_role and user.role != "admin":
        raise HTTPException(status_code=403, detail="Authenticated role does not satisfy required_role")
    row.approved      = True
    row.approved_by   = user.username
    row.approved_role = user.role
    row.approved_at   = utc_now()
    db.commit()
    db.refresh(row)
    ledger_row = LedgerService(db).append("approval", user.username, {
        "request_id":   row.id,
        "decision_ref": row.decision_ref,
        "approved_by":  user.username,
        "approved_role": user.role,
        "approved_at":  row.approved_at,
    })
    return {
        "ok":           True,
        "request_id":   row.id,
        "decision_ref": row.decision_ref,
        "approved":     row.approved,
        "ledger_hash":  ledger_row.entry_hash,
    }


@app.get("/v1/approvals/{request_id}", dependencies=[Depends(require_api_token)], tags=["SEAL"])
def get_approval(
    request_id: int,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("approver", "safety_officer", "admin", "audit")),
) -> Dict[str, Any]:
    row = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return {
        "id":            row.id,
        "decision_ref":  row.decision_ref,
        "rationale":     row.rationale,
        "required_role": row.required_role,
        "approved":      row.approved,
        "approved_by":   row.approved_by,
        "approved_role": row.approved_role,
        "approved_at":   row.approved_at,
        "created_at":    row.created_at,
    }


@app.post("/v1/cure/outcome", dependencies=[Depends(require_api_token)], tags=["CURE"])
def record_outcome(
    req:  OutcomeRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("audit", "safety_officer", "admin")),
) -> Dict[str, Any]:
    OUTCOMES_TOTAL.inc()
    row = OutcomeRecord(
        decision_ref  = req.decision_ref,
        outcome_label = req.outcome_label,
        outcome_value = _stable_json(req.outcome_value),
        recorded_by   = user.username,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    ledger_row = LedgerService(db).append("outcome", user.username, {
        "outcome_id":    row.id,
        "decision_ref":  row.decision_ref,
        "outcome_label": row.outcome_label,
        "outcome_value": req.outcome_value,
    })
    return {"ok": True, "outcome_id": row.id, "ledger_hash": ledger_row.entry_hash}


@app.post("/v1/safety/hazards", dependencies=[Depends(require_api_token)], tags=["Safety"])
def create_hazard(
    req:  HazardCreateRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("safety_officer", "admin")),
) -> Dict[str, Any]:
    hazard_id = _sha256_hex(f"{req.title}:{utc_now()}")[:12]
    row = HazardLogItem(
        hazard_id     = hazard_id,
        title         = req.title,
        description   = req.description,
        cause         = req.cause,
        effect        = req.effect,
        initial_risk  = req.initial_risk,
        mitigation    = req.mitigation,
        residual_risk = req.residual_risk,
        owner         = req.owner or user.username,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    ledger_row = LedgerService(db).append("hazard_created", user.username, {
        "hazard_id":    row.hazard_id,
        "title":        row.title,
        "initial_risk": row.initial_risk,
        "status":       row.status,
    })
    return {"ok": True, "hazard_id": row.hazard_id, "ledger_hash": ledger_row.entry_hash}


@app.patch("/v1/safety/hazards", dependencies=[Depends(require_api_token)], tags=["Safety"])
def update_hazard(
    req:  HazardUpdateRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("safety_officer", "admin")),
) -> Dict[str, Any]:
    row = db.query(HazardLogItem).filter(HazardLogItem.hazard_id == req.hazard_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Hazard not found")
    if req.mitigation    is not None: row.mitigation    = req.mitigation
    if req.residual_risk is not None: row.residual_risk = req.residual_risk
    if req.status        is not None: row.status        = req.status
    row.updated_at = utc_now()
    db.commit()
    db.refresh(row)
    ledger_row = LedgerService(db).append("hazard_updated", user.username, {
        "hazard_id":    row.hazard_id,
        "status":       row.status,
        "residual_risk": row.residual_risk,
    })
    return {"ok": True, "hazard_id": row.hazard_id, "status": row.status, "ledger_hash": ledger_row.entry_hash}


@app.get("/v1/safety/hazards", dependencies=[Depends(require_api_token)], tags=["Safety"])
def list_hazards(
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("safety_officer", "admin", "audit")),
) -> Dict[str, Any]:
    rows = db.query(HazardLogItem).order_by(HazardLogItem.created_at.desc()).all()
    return {
        "ok": True,
        "items": [
            {
                "hazard_id":    r.hazard_id,
                "title":        r.title,
                "description":  r.description,
                "initial_risk": r.initial_risk,
                "residual_risk": r.residual_risk,
                "status":       r.status,
                "owner":        r.owner,
                "updated_at":   r.updated_at,
            }
            for r in rows
        ],
    }


@app.put("/v1/safety/metadata", dependencies=[Depends(require_api_token)], tags=["Safety"])
def upsert_safety_metadata(
    req:  SafetyMetadataRequest,
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("safety_officer", "admin")),
) -> Dict[str, Any]:
    row = db.query(SafetyMetadata).first()
    if not row:
        row = SafetyMetadata()
        db.add(row)
    row.product_name              = req.product_name
    row.version                   = APP_VERSION
    row.safety_officer_name       = req.safety_officer_name
    row.safety_officer_identifier = req.safety_officer_identifier
    row.intended_use              = req.intended_use
    row.deployment_scope          = req.deployment_scope
    row.out_of_scope              = req.out_of_scope
    row.safety_case_status        = req.safety_case_status
    row.updated_at                = utc_now()
    db.commit()
    db.refresh(row)
    ledger_row = LedgerService(db).append("safety_metadata_updated", user.username, {
        "product_name":               row.product_name,
        "version":                    row.version,
        "safety_officer_identifier":  row.safety_officer_identifier,
        "safety_case_status":         row.safety_case_status,
    })
    return {"ok": True, "id": row.id, "ledger_hash": ledger_row.entry_hash}


@app.get("/v1/safety/metadata", dependencies=[Depends(require_api_token)], tags=["Safety"])
def get_safety_metadata(
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("safety_officer", "admin", "audit")),
) -> Dict[str, Any]:
    row = db.query(SafetyMetadata).first()
    if not row:
        return {"ok": True, "item": None}
    return {
        "ok": True,
        "item": {
            "product_name":               row.product_name,
            "version":                    row.version,
            "safety_officer_name":        row.safety_officer_name,
            "safety_officer_identifier":  row.safety_officer_identifier,
            "intended_use":               row.intended_use,
            "deployment_scope":           row.deployment_scope,
            "out_of_scope":               row.out_of_scope,
            "safety_case_status":         row.safety_case_status,
            "updated_at":                 row.updated_at,
        },
    }


@app.get("/v1/ledger/verify", dependencies=[Depends(require_api_token)], tags=["Audit"])
def verify_ledger(
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("audit", "safety_officer", "admin")),
) -> Dict[str, Any]:
    return LedgerService(db).verify_chain()


@app.get("/v1/ledger/entries", dependencies=[Depends(require_api_token)], tags=["Audit"])
def ledger_entries(
    limit:  int = 50,
    offset: int = 0,
    db:     Session = Depends(get_db),
    user:   AuthenticatedUser = Depends(require_role("audit", "safety_officer", "admin")),
) -> Dict[str, Any]:
    rows = db.query(LedgerEntry).order_by(LedgerEntry.id.desc()).offset(offset).limit(min(limit, 200)).all()
    return {
        "ok": True,
        "items": [
            {
                "id":           r.id,
                "ts_utc":       r.ts_utc,
                "entry_type":   r.entry_type,
                "actor_id":     r.actor_id,
                "entry_hash":   r.entry_hash,
                "safety_flag":  r.safety_flag,
                "domain":       r.domain,
                "payload":      safe_json_loads(r.payload_json, {}),
            }
            for r in rows
        ],
    }


@app.get("/v1/decisions/recent", dependencies=[Depends(require_api_token)], tags=["Audit"])
def recent_decisions(
    limit: int = 20,
    db:    Session = Depends(get_db),
    user:  AuthenticatedUser = Depends(require_role("audit", "safety_officer", "admin")),
) -> Dict[str, Any]:
    rows = (
        db.query(LedgerEntry)
        .filter(LedgerEntry.entry_type.in_(["decision", "dissent", "approval", "outcome"]))
        .order_by(LedgerEntry.id.desc())
        .limit(min(max(limit, 1), 100))
        .all()
    )
    return {
        "ok": True,
        "items": [
            {
                "id":         r.id,
                "ts_utc":     r.ts_utc,
                "entry_type": r.entry_type,
                "actor_id":   r.actor_id,
                "entry_hash": r.entry_hash,
                "payload":    safe_json_loads(r.payload_json, {}),
            }
            for r in rows
        ],
    }


@app.get("/v1/integrity/proof", dependencies=[Depends(require_api_token)], tags=["Audit"])
def integrity_proof(
    db:   Session = Depends(get_db),
    user: AuthenticatedUser = Depends(require_role("audit", "safety_officer", "admin")),
) -> Dict[str, Any]:
    last = db.query(LedgerEntry).order_by(LedgerEntry.id.desc()).first()
    tip  = last.entry_hash if last else None
    proof_input = _stable_json({
        "version":           APP_VERSION,
        "domain":            DEPLOYMENT_DOMAIN,
        "core12_fingerprint": CORE12_FINGERPRINT,
        "ledger_tip_hash":   tip,
        "public_key_b64":    export_public_key_b64(),
    })
    return {
        "ok":                True,
        "version":           APP_VERSION,
        "domain":            DEPLOYMENT_DOMAIN,
        "core12_fingerprint": CORE12_FINGERPRINT,
        "ledger_tip_hash":   tip,
        "public_key_b64":    export_public_key_b64(),
        "proof":             _sha256_hex(proof_input),
    }


@app.get("/v1/core12", tags=["Governance"])
def core12_info() -> Dict[str, Any]:
    return {
        "needs":       CORE12,
        "fingerprint": CORE12_FINGERPRINT,
        "invariant":   True,
        "version":     APP_VERSION,
        "description": (
            "Twelve universal human needs. Invariant across all sectors and deployments. "
            "Any action that harms one or more of these needs activates enforcement. "
            "This list cannot be modified, reordered, or overridden at runtime."
        ),
    }

# ─────────────────────────────────────────────────────────────────────────────
# SIGNALS / ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────


def _shutdown_handler(signum, frame):
    logger.info("aptsa1_shutdown_signal_received", signal=signum)
    SYSTEM_STATE.labels(status="shutdown_signal").set(1)
    FORTIFY.stop()


signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT, _shutdown_handler)


if __name__ == "__main__":
    import uvicorn

    print(f"APTSA1 Universal Governance Engine v{APP_VERSION}")
    print(f"Environment:        {APTSA1_ENV}")
    print(f"Domain:             {DEPLOYMENT_DOMAIN}")
    print(f"Strict mode:        {STRICT_MODE}")
    print(f"CORE12 fingerprint: {CORE12_FINGERPRINT}")
    uvicorn.run(
        "aptsa1_universal:app",
        host       = "0.0.0.0",
        port       = int(os.getenv("PORT", "8000")),
        reload     = os.getenv("APTSA1_RELOAD", "false").lower() == "true",
        workers    = int(os.getenv("APTSA1_WORKERS", "1")),
        log_level  = os.getenv("APTSA1_LOG_LEVEL", "info"),
    )
