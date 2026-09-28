"""Know Your Agent (KYA) reference implementation.

A small, self-contained implementation of the five KYA layers:
  L1 AgentRegistry   : Ed25519 agent keys and agent-bound payment tokens
  L2 Mandate         : signed permission slip (scope, limits, speed, expiry)
  L3 Checkpoint      : per-payment policy enforcement outside the agent
  L4 DecisionTrail   : signed, hash-chained append-only record
  L5 Escalation      : rule-triggered human decision hook

This is a research prototype, not production payment software.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass, field, asdict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- L1
class AgentRegistry:
    """Registers agents and issues tokens bound to one agent key."""

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        self.public = self._key.public_key()
        self.agents: dict[str, Ed25519PublicKey] = {}

    def register(self, agent_id: str, agent_pub: Ed25519PublicKey) -> dict:
        self.agents[agent_id] = agent_pub
        body = {"agent_id": agent_id, "token_id": sha(agent_id.encode())[:12]}
        return {"body": body, "sig": self._key.sign(canon(body)).hex()}

    def verify_token(self, token: dict, agent_id: str) -> bool:
        try:
            self.public.verify(bytes.fromhex(token["sig"]), canon(token["body"]))
        except InvalidSignature:
            return False
        return token["body"]["agent_id"] == agent_id


# ---------------------------------------------------------------- L2
@dataclass
class Mandate:
    principal: str
    agent_id: str
    payees: list
    per_item_limit: float
    total_budget: float
    speed_limit: float          # max paid actions per window
    window_s: float
    expires: float
    ask_over: float = math.inf   # step-up threshold for human approval
    sig: str = ""

    def body(self) -> dict:
        d = asdict(self)
        d.pop("sig")
        return {k: (str(v) if isinstance(v, float) and math.isinf(v) else v)
                for k, v in d.items()}

    def sign(self, principal_key: Ed25519PrivateKey) -> "Mandate":
        self.sig = principal_key.sign(canon(self.body())).hex()
        return self

    def mid(self) -> str:
        return sha(canon(self.body()))[:12]


# ---------------------------------------------------------------- L4
class DecisionTrail:
    """Append-only, hash-chained, signed decision records."""

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        self.public = self._key.public_key()
        self.records: list[dict] = []

    def log(self, **entry) -> dict:
        prev = self.records[-1]["hash"] if self.records else "0" * 64
        body = {"i": len(self.records), "prev": prev, **entry}
        h = sha(canon(body))
        rec = {**body, "hash": h, "sig": self._key.sign(h.encode()).hex()}
        self.records.append(rec)
        return rec

    def verify(self) -> tuple[bool, int | None]:
        prev = "0" * 64
        for r in self.records:
            body = {k: v for k, v in r.items() if k not in ("hash", "sig")}
            if body["prev"] != prev or sha(canon(body)) != r["hash"]:
                return False, r["i"]
            try:
                self.public.verify(bytes.fromhex(r["sig"]), r["hash"].encode())
            except InvalidSignature:
                return False, r["i"]
            prev = r["hash"]
        return True, None


# ---------------------------------------------------------------- L3 + L5
@dataclass
class Action:
    agent_id: str
    payee: str
    amount: float
    token: dict
    sig: str = ""

    def body(self):
        return {"agent_id": self.agent_id, "payee": self.payee,
                "amount": self.amount, "token_id": self.token["body"]["token_id"]}


class Checkpoint:
    """Policy enforcement point that runs outside the agent."""

    def __init__(self, registry: AgentRegistry, trail: DecisionTrail,
                 principal_keys: dict, human=None, principal_caps=None,
                 require_complete=True, near_cap=0.95, near_cap_count=3,
                 risk=None, risk_high=0.8, sink=None, currency="USD"):
        self.registry, self.trail = registry, trail
        self.principal_keys = principal_keys          # principal -> public key
        self.human = human or (lambda m, a, why: "DENY")
        self.spent: dict[str, float] = {}             # per mandate
        self.principal_spent: dict[str, float] = {}   # per principal (T5)
        self.principal_caps = principal_caps or {}
        self.recent: dict[str, deque] = {}
        self.suspended: set[str] = set()
        self.require_complete = require_complete   # all limit fields required
        self.near_cap, self.near_cap_count = near_cap, near_cap_count
        self.near: dict[str, deque] = {}
        # Adapter to the bank's existing fraud engine (e.g. network scoring,
        # FICO Falcon, NICE Actimize). Returns a score in [0, 1].
        # `risk` may be a RiskEngine (kya_risk.py) or a legacy callable(action, ctx).
        self.risk = risk or (lambda action, context: 0.0)
        self.risk_high = risk_high
        self.denials: dict[str, int] = {}
        self.sink = sink                  # flow 12: stream records to monitoring
        self.currency = currency
        self.requests: dict[str, object] = {}   # record hash -> RiskRequest

    def _log(self, m, a, now, result, human=None, flag=None, score=None,
             reasons=None, engine=None, req=None):
        if result.startswith("DENY"):
            self.denials[m.mid()] = self.denials.get(m.mid(), 0) + 1
        rec = self.trail.log(t=round(now, 3), mandate=m.mid(), principal=m.principal,
                             agent=a.agent_id, payee=a.payee, amount=a.amount,
                             result=result, human=human, flag=flag, risk=score,
                             risk_reasons=reasons, risk_engine=engine)
        if req is not None:
            self.requests[rec["hash"]] = req
        if self.sink:
            self.sink(rec)
        return rec

    def risk_request(self, m, a, now):
        """Standard payment fields plus the versioned KYA agent block (flow 11)."""
        from kya_risk import AgentContext, RiskRequest
        mid = m.mid()
        ctx = AgentContext(True, a.agent_id, mid, m.principal, m.per_item_limit,
                           m.total_budget - self.spent.get(mid, 0.0),
                           len(self.recent.get(mid, ())), m.speed_limit,
                           len(self.near.get(mid, ())), self.denials.get(mid, 0),
                           m.expires - now)
        return RiskRequest(a.amount, self.currency, a.payee, "agent", now, ctx)

    def _score(self, m, a, now):
        if hasattr(self.risk, "score"):                  # RiskEngine
            req = self.risk_request(m, a, now)
            if hasattr(self.risk, "features"):           # snapshot for feedback (14)
                req.features_at_decision = self.risk.features(req)
            r = self.risk.score(req)
            return r.score, r.reasons, r.engine, req
        return self.risk(a, self.agent_context(m, a, now)), None, None, None

    def agent_context(self, m, a, now):
        """Agent fields KYA adds to each fraud-engine request."""
        mid = m.mid()
        return {"agentic": True, "agent_id": a.agent_id, "mandate_id": mid,
                "principal": m.principal,
                "budget_left": m.total_budget - self.spent.get(mid, 0.0),
                "payments_in_window": len(self.recent.get(mid, ())),
                "near_cap_count": len(self.near.get(mid, ())),
                "past_denials": self.denials.get(mid, 0)}

    def check_payment(self, a: Action, m: Mandate, now: float) -> dict:
        # L1: the token must be bound to this agent, and the agent must sign
        agent_pub = self.registry.agents.get(a.agent_id)
        if agent_pub is None or not self.registry.verify_token(a.token, a.agent_id) \
                or a.agent_id != m.agent_id:
            return self._log(m, a, now, "DENY: unknown agent")
        try:
            agent_pub.verify(bytes.fromhex(a.sig), canon(a.body()))
        except (InvalidSignature, ValueError):
            return self._log(m, a, now, "DENY: bad agent signature")
        # L2: the mandate must be signed by its principal
        try:
            self.principal_keys[m.principal].verify(bytes.fromhex(m.sig), canon(m.body()))
        except (InvalidSignature, KeyError, ValueError):
            return self._log(m, a, now, "DENY: mandate not signed")
        if self.require_complete and not all(math.isfinite(x) for x in (
                m.per_item_limit, m.total_budget, m.speed_limit, m.expires)):
            return self._log(m, a, now, "DENY: incomplete mandate")
        mid = m.mid()
        if mid in self.suspended:
            return self._log(m, a, now, "DENY: mandate suspended")
        if now > m.expires or a.payee not in m.payees:
            return self._log(m, a, now, "DENY: outside mandate")
        if a.amount > m.per_item_limit:
            return self._log(m, a, now, "DENY: item too costly")
        if self.spent.get(mid, 0.0) + a.amount > m.total_budget:
            return self._log(m, a, now, "DENY: budget used up")
        cap = self.principal_caps.get(m.principal, math.inf)
        if self.principal_spent.get(m.principal, 0.0) + a.amount > cap:
            return self._log(m, a, now, "DENY: principal budget used up")
        q = self.recent.setdefault(mid, deque())
        while q and q[0] <= now - m.window_s:
            q.popleft()
        if len(q) >= m.speed_limit:                       # circuit breaker
            self.suspended.add(mid)
            answer = self.human(m, a, "speed")
            return self._log(m, a, now, "DENY: too fast, mandate suspended",
                             human=answer)
        # Existing fraud engine, called with agent context
        score, reasons, engine, req = self._score(m, a, now)
        kw = dict(score=score, reasons=reasons, engine=engine, req=req)
        if score >= self.risk_high:                       # step-up to principal
            answer = self.human(m, a, "high fraud score")
            if answer != "APPROVE":
                return self._log(m, a, now, "DENY: high fraud risk", human=answer, **kw)
            return self._allow(m, a, now, q, human=answer, **kw)
        # L5: step-up rules
        if a.amount > m.ask_over:
            answer = self.human(m, a, "large amount")
            if answer != "APPROVE":
                return self._log(m, a, now, "DENY: human declined", human=answer, **kw)
            return self._allow(m, a, now, q, human=answer, **kw)
        return self._allow(m, a, now, q, **kw)

    def _allow(self, m, a, now, q, human=None, **kw):
        mid = m.mid()
        self.spent[mid] = self.spent.get(mid, 0.0) + a.amount
        self.principal_spent[m.principal] = self.principal_spent.get(m.principal, 0.0) + a.amount
        q.append(now)
        flag = None                     # near-cap pattern (possible structuring)
        if math.isfinite(m.per_item_limit) and a.amount >= self.near_cap * m.per_item_limit:
            nq = self.near.setdefault(mid, deque())
            while nq and nq[0] <= now - 86400:
                nq.popleft()
            nq.append(now)
            if len(nq) >= self.near_cap_count:
                flag = "NEAR-CAP PATTERN"
                self.human(m, a, "near-cap pattern")   # notify, does not block
        if hasattr(self.risk, "observe"):
            self.risk.observe(m.principal, a.payee)
        return self._log(m, a, now, "ALLOW", human=human, flag=flag, **kw)


# ---------------------------------------------------------------- helpers
class Agent:
    def __init__(self, agent_id: str, registry: AgentRegistry):
        self.id = agent_id
        self._key = Ed25519PrivateKey.generate()
        self.token = registry.register(agent_id, self._key.public_key())

    def propose(self, payee: str, amount: float, token=None, as_id=None) -> Action:
        a = Action(as_id or self.id, payee, amount, token or self.token)
        a.sig = self._key.sign(canon(a.body())).hex()
        return a
