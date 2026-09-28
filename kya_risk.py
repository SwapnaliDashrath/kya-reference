"""Risk and fraud management layer interface for KYA.

KYA is a governance and orchestration layer. It does not replace the bank's
fraud systems. This module defines how KYA talks to them (Fig. 1, flows 11-14):

  11  RiskRequest / RiskEngine   checkpoint -> real-time fraud scoring -> score
  12  TransactionMonitor         decision trail -> monitoring and AML -> alerts
  13  CaseManager                alerts -> analyst cases with signed evidence
  14  FeedbackStore              analyst labels -> retraining of the engine

Compatibility: every request carries the usual card-payment fields plus one
versioned "agent" block. `to_flat()` maps the block to prefixed key-value
attributes, the form most fraud engines accept as custom data, so existing
engines can use the fields without schema changes.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Callable, Protocol

SCHEMA = "kya.risk.v1"


# ------------------------------------------------------------------ flow 11
@dataclass
class AgentContext:
    agentic: bool
    agent_id: str
    mandate_id: str
    principal: str
    per_item_limit: float
    budget_left: float
    payments_in_window: int
    speed_limit: float
    near_cap_count: int
    past_denials: int
    seconds_to_expiry: float

    @property
    def pace_ratio(self) -> float:          # share of the speed limit already used
        return 0.0 if not math.isfinite(self.speed_limit) or self.speed_limit == 0 \
            else self.payments_in_window / self.speed_limit


@dataclass
class RiskRequest:
    """One scoring request: standard payment fields plus the KYA agent block."""
    amount: float
    currency: str
    payee: str
    channel: str
    timestamp: float
    agent: AgentContext
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        d = asdict(self)
        d["agent"]["pace_ratio"] = round(self.agent.pace_ratio, 4)
        return d

    def to_flat(self, prefix: str = "kya_") -> dict[str, str]:
        """Key-value attributes for engines that accept custom fields."""
        flat = {f"{prefix}schema": self.schema, f"{prefix}agentic": "Y"}
        for k, v in asdict(self.agent).items():
            if k == "agentic":
                continue
            flat[prefix + k] = "inf" if isinstance(v, float) and math.isinf(v) else str(v)
        flat[prefix + "pace_ratio"] = f"{self.agent.pace_ratio:.4f}"
        return flat


@dataclass
class RiskResponse:
    score: float                 # 0 = safe, 1 = certain fraud
    reasons: list[str]
    engine: str


class RiskEngine(Protocol):
    name: str
    def score(self, req: RiskRequest) -> RiskResponse: ...


class CallbackEngine:
    """Wraps any function, for example a client for a vendor fraud API."""

    def __init__(self, fn: Callable, name: str = "external"):
        self.fn, self.name = fn, name

    def score(self, req: RiskRequest) -> RiskResponse:
        out = self.fn(req)
        if isinstance(out, RiskResponse):
            return out
        return RiskResponse(float(out), [], self.name)


class ReferenceEngine:
    """A small, transparent stand-in for a bank fraud engine.

    It uses agent-aware signals that human-only engines lack. Weights are the
    'model'; FeedbackStore.retrain() adjusts them from analyst labels.
    """
    name = "reference-engine"

    def __init__(self):
        self.w = {"pace": 0.35, "near_cap": 0.25, "denials": 0.25, "new_payee": 0.30}
        self.known_payees: dict[str, set] = defaultdict(set)

    def features(self, req: RiskRequest) -> dict[str, float]:
        a = req.agent
        return {"pace": min(a.pace_ratio, 1.0),
                "near_cap": min(a.near_cap_count / 3, 1.0),
                "denials": min(a.past_denials / 3, 1.0),
                "new_payee": 0.0 if req.payee in self.known_payees[a.principal] else 1.0}

    def score_features(self, f: dict) -> float:
        return round(min(sum(self.w[k] * v for k, v in f.items()), 1.0), 3)

    def score(self, req: RiskRequest) -> RiskResponse:
        f = self.features(req)
        s = min(sum(self.w[k] * v for k, v in f.items()), 1.0)
        reasons = [k for k, v in f.items() if v * self.w[k] >= 0.2]
        return RiskResponse(round(s, 3), reasons, self.name)

    def observe(self, principal: str, payee: str):
        self.known_payees[principal].add(payee)


# ------------------------------------------------------------------ flow 12
@dataclass
class Alert:
    kind: str
    principal: str
    mandate: str
    evidence: list[str]           # trail record hashes
    detail: str


class TransactionMonitor:
    """Reads the decision trail and raises alerts on patterns across payments."""

    def __init__(self, denial_burst=3, window_s=3600.0):
        self.denial_burst, self.window_s = denial_burst, window_s
        self.denials: dict[str, deque] = defaultdict(deque)
        self.seen: set[str] = set()

    def ingest(self, rec: dict) -> list[Alert]:
        if rec["hash"] in self.seen:
            return []
        self.seen.add(rec["hash"])
        out, res, key = [], rec["result"], rec["mandate"]
        who = rec.get("principal", "?")
        if "too fast" in res:
            out.append(Alert("runaway_loop", who, key, [rec["hash"]],
                             "speed breaker tripped, mandate suspended"))
        if rec.get("flag") == "NEAR-CAP PATTERN":
            out.append(Alert("possible_structuring", who, key, [rec["hash"]],
                             "repeated payments within 5% of the per-item limit"))
        if res == "DENY: high fraud risk":
            out.append(Alert("high_risk_declined", who, key, [rec["hash"]],
                             f"risk score {rec.get('risk')}"))
        if res.startswith("DENY"):
            q = self.denials[key]
            q.append((rec["t"], rec["hash"]))
            while q and q[0][0] <= rec["t"] - self.window_s:
                q.popleft()
            if len(q) == self.denial_burst:
                out.append(Alert("repeated_denials", who, key, [h for _, h in q],
                                 f"{len(q)} denials within {int(self.window_s)} s"))
        return out


# ------------------------------------------------------------------ flow 13
LABELS = ("fraud", "hijack", "agent_error", "false_alarm")


@dataclass
class Case:
    case_id: int
    alert: Alert
    evidence: list[dict]
    evidence_valid: bool
    label: str | None = None
    analyst: str | None = None


class CaseManager:
    """Analyst queue. Each case carries signed trail records as evidence."""

    def __init__(self, trail):
        self.trail, self.cases, self._n = trail, [], 0

    def open(self, alert: Alert) -> Case:
        ok, _ = self.trail.verify()
        idx = {r["hash"]: r for r in self.trail.records}
        ev = [idx[h] for h in alert.evidence if h in idx]
        self._n += 1
        c = Case(self._n, alert, ev, ok and len(ev) == len(alert.evidence))
        self.cases.append(c)
        return c

    def resolve(self, case: Case, label: str, analyst: str) -> Case:
        if label not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        case.label, case.analyst = label, analyst
        return case


# ------------------------------------------------------------------ flow 14
class FeedbackStore:
    """Turns analyst labels into hit and miss examples and retrains the engine."""

    def __init__(self):
        self.examples: list[tuple[dict, str]] = []

    def add(self, features: dict, label: str):
        self.examples.append((features, label))

    def retrain(self, engine: ReferenceEngine, lr=0.15, epochs=20):
        for feats, label in self.examples * epochs:
            target = 1.0 if label in ("fraud", "hijack") else 0.0
            pred = min(sum(engine.w[k] * v for k, v in feats.items()), 1.0)
            err = target - pred
            for k, v in feats.items():
                engine.w[k] = max(0.0, min(1.0, engine.w[k] + lr * err * v))
        self.examples.clear()
        return dict(engine.w)


# ------------------------------------------------------------------ wiring
class RiskLayer:
    """Connects KYA to the lower layer: engine (11), monitor (12),
    cases (13), and feedback (14). Pass `on_record` as the checkpoint sink."""

    def __init__(self, engine, trail, requests: dict):
        self.engine, self.requests = engine, requests
        self.monitor, self.cases = TransactionMonitor(), CaseManager(trail)
        self.feedback, self.alerts = FeedbackStore(), []

    def on_record(self, rec: dict):
        for al in self.monitor.ingest(rec):
            self.alerts.append(al)
            self.cases.open(al)

    def label(self, case: Case, label: str, analyst: str):
        self.cases.resolve(case, label, analyst)
        for rec in case.evidence:
            req = self.requests.get(rec["hash"])
            if req is not None and hasattr(self.engine, "features"):
                feats = getattr(req, "features_at_decision", None) or self.engine.features(req)
                self.feedback.add(feats, label)
