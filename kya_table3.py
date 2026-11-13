"""Comparison with common controls (Table II) and the slow-loop runs (Table IV) of the KYA paper.

Usage:  python kya_table3.py            (when this file sits next to kya_ref.py)
        python kya_table3.py /path/to/kya-reference
Writes kya_table3_results.json next to this script. Does not touch kya_results.json.

Setups
  token       : scoped bearer token (OAuth-style). The gateway checks the issuer's
                signature and the expiry claim. Scope is the payment API, not a payee list.
                Whoever presents the token is accepted.
  token+limit : the same, plus a per-item limit claim.
  kya         : the real Checkpoint from kya_ref.py.
"""
import json, math, sys, os
# Folder that holds kya_ref.py. Defaults to the folder this script is in.
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from kya_ref import AgentRegistry, DecisionTrail, Checkpoint, Mandate, Agent, canon

INF = math.inf


class BearerGateway:
    """Baseline: a signed bearer token with scope, expiry and an optional per-item limit."""

    def __init__(self):
        self._key = Ed25519PrivateKey.generate()
        self.public = self._key.public_key()

    def issue(self, expires, per_item_limit=None):
        claims = {"scope": "payments", "expires": expires, "per_item_limit": per_item_limit}
        return {"claims": claims, "sig": self._key.sign(canon(claims)).hex()}

    def check(self, token, payee, amount, now):
        try:
            self.public.verify(bytes.fromhex(token["sig"]), canon(token["claims"]))
        except InvalidSignature:
            return "DENY: bad token"
        c = token["claims"]
        if now > c["expires"]:
            return "DENY: token expired"
        if c["per_item_limit"] is not None and amount > c["per_item_limit"]:
            return "DENY: item too costly"
        return "ALLOW"


def kya(caps=None):
    reg, trail = AgentRegistry(), DecisionTrail()
    pk = Ed25519PrivateKey.generate()
    cp = Checkpoint(reg, trail, {"priya": pk.public_key()}, principal_caps=caps)
    return reg, pk, cp


def mandate(pk, agent_id, **kw):
    base = dict(principal="priya", agent_id=agent_id, payees=["vendorA", "vendorB"],
                per_item_limit=100.0, total_budget=5000.0, speed_limit=60,
                window_s=300.0, expires=86400.0)
    base.update(kw)
    return Mandate(**base).sign(pk)


def verdict(results):
    n = sum(r == "ALLOW" for r in results)
    if n == 0:
        return "blocked"
    if n == len(results):
        return "allowed" if n == 1 else f"allowed ({n} of {n})"
    return f"blocked after {n} of {len(results)}"


def baseline(limit):
    """Run each scenario against the bearer-token gateway."""
    lim = 100.0 if limit else None
    out = {}
    g = BearerGateway(); t = g.issue(86400.0, lim)
    out["Injected payee"] = verdict([g.check(t, "attacker-acct", 40, 10)])
    out["Stolen token"] = verdict([g.check(t, "vendorA", 40, 10)])      # thief presents it
    g = BearerGateway(); t = g.issue(100.0, lim)
    out["Expired mandate"] = verdict([g.check(t, "vendorA", 40, 101)])
    g = BearerGateway(); t = g.issue(100.0, lim); t["claims"]["expires"] = 10**9
    out["Edited mandate"] = verdict([g.check(t, "vendorA", 40, 101)])
    g = BearerGateway(); t = g.issue(86400.0, lim)
    out["Runaway loop"] = verdict([g.check(t, "vendorA", 3.33, i * 0.22) for i in range(80)])
    t1, t2 = g.issue(86400.0, lim), g.issue(86400.0, lim)
    out["Two agents split a budget"] = verdict(
        [g.check(t, "vendorA", 50, i + 1) for i, t in enumerate([t1, t2, t1, t2])])
    out["Single oversized payment"] = verdict([g.check(t1, "vendorA", 150, 10)])
    return out


def kya_column():
    out = {}
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
    out["Injected payee"] = verdict([cp.check_payment(ag.propose("attacker-acct", 40), m, 10)["result"]])
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); thief = Agent("rogue-bot", reg)
    m = mandate(pk, ag.id)
    out["Stolen token"] = verdict([cp.check_payment(
        thief.propose("vendorA", 40, token=ag.token, as_id=ag.id), m, 10)["result"]])
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); m = mandate(pk, ag.id, expires=100.0)
    out["Expired mandate"] = verdict([cp.check_payment(ag.propose("vendorA", 40), m, 101)["result"]])
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); m = mandate(pk, ag.id, expires=100.0)
    m.expires = 10**9
    out["Edited mandate"] = verdict([cp.check_payment(ag.propose("vendorA", 40), m, 101)["result"]])
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
    out["Runaway loop"] = verdict([cp.check_payment(ag.propose("vendorA", 3.33), m, i * 0.22)["result"]
                                   for i in range(80)])
    reg, pk, cp = kya(caps={"priya": 150.0})
    a1, a2 = Agent("bot-1", reg), Agent("bot-2", reg)
    m1, m2 = mandate(pk, a1.id), mandate(pk, a2.id)
    out["Two agents split a budget"] = verdict(
        [cp.check_payment(a.propose("vendorA", 50), m, i + 1)["result"]
         for i, (a, m) in enumerate([(a1, m1), (a2, m2), (a1, m1), (a2, m2)])])
    reg, pk, cp = kya(); ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
    out["Single oversized payment"] = verdict([cp.check_payment(ag.propose("vendorA", 150), m, 10)["result"]])
    return out


def slow_loop(rate, cost=50000 / 15000, max_s=6 * 3600):
    """One looping agent at a constant rate, full KYA mandate (60 per 300 s, budget 5,000)."""
    reg, pk, cp = kya(); ag = Agent("acct-bot", reg); m = mandate(pk, ag.id)
    a = ag.propose("vendorA", cost)
    spent = loss_1h = 0.0; stop = why = None; i = 0
    while i / rate <= max_s:
        now = i / rate
        if now > 3600 and loss_1h == 0.0:
            loss_1h = spent
        r = cp.check_payment(a, m, now)["result"]
        if r == "ALLOW":
            spent += cost
        else:
            stop, why = now, r
            break
        i += 1
    return {"rate_per_s": rate, "loss_1h_usd": round(loss_1h or spent), "final_loss_usd": round(spent),
            "stopped_at_s": None if stop is None else round(stop, 1), "stopped_by": why}


if __name__ == "__main__":
    table = {"Token only": baseline(False), "Token + per-item limit": baseline(True), "KYA": kya_column()}
    rows = list(table["KYA"])
    print(f"{'Scenario':28}" + "".join(f"{k:26}" for k in table))
    for r in rows:
        print(f"{r:28}" + "".join(f"{table[k][r]:26}" for k in table))
    slow = [slow_loop(r) for r in (0.05, 0.1, 0.19, 0.2, 0.21, 0.25, 0.5)]
    print()
    for s in slow:
        print(s)
    json.dump({"table3": table, "slow_loop": slow},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "kya_table3_results.json"), "w"), indent=1)
