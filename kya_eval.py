"""Tests, runaway replay and latency benchmark for the KYA reference implementation."""
import json
import math
import statistics
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kya_ref import AgentRegistry, DecisionTrail, Checkpoint, Mandate, Agent

INF = math.inf
results = []


def setup(human=None, caps=None, require_complete=True, risk=None):
    reg, trail = AgentRegistry(), DecisionTrail()
    pkey = Ed25519PrivateKey.generate()
    cp = Checkpoint(reg, trail, {"priya": pkey.public_key()}, human=human,
                    principal_caps=caps, require_complete=require_complete, risk=risk)
    return reg, trail, pkey, cp


def mandate(pkey, agent_id, **kw):
    base = dict(principal="priya", agent_id=agent_id, payees=["vendorA", "vendorB"],
                per_item_limit=100.0, total_budget=5000.0, speed_limit=60,
                window_s=300.0, expires=86400.0)
    base.update(kw)
    return Mandate(**base).sign(pkey)


def record(test, expected, got, ok):
    results.append({"test": test, "expected": expected, "got": got, "pass": bool(ok)})


# S1 runaway loop is covered by the replay below; here a short functional check
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
out = [cp.check_payment(ag.propose("vendorA", 3.33), m, t * 0.22)["result"] for t in range(80)]
n_allow = out.count("ALLOW")
record("S1 runaway loop (80 calls in 18 s)", "breaker trips after 60",
       f"{n_allow} allowed, then '{out[n_allow]}'", n_allow == 60 and "suspended" in out[n_allow])

# S2 injected payee
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
r = cp.check_payment(ag.propose("attacker-acct", 40), m, 10)["result"]
record("S2 injected new payee", "deny, outside mandate", r, r == "DENY: outside mandate")

# S3 stolen token replayed by another agent
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); thief = Agent("rogue-bot", reg); m = mandate(pk, ag.id)
r = cp.check_payment(thief.propose("vendorA", 40, token=ag.token, as_id=ag.id), m, 10)["result"]
record("S3 stolen token, other agent key", "deny", r, r.startswith("DENY"))
r2 = cp.check_payment(thief.propose("vendorA", 40, token=ag.token), m, 11)["result"]
record("S3b stolen token, own agent id", "deny, unknown agent", r2, r2 == "DENY: unknown agent")

# S4 expired mandate
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id, expires=100.0)
r = cp.check_payment(ag.propose("vendorA", 40), m, 101)["result"]
record("S4 purchase after expiry", "deny, outside mandate", r, r == "DENY: outside mandate")

# Forged mandate (edited limit after signing)
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id); m.total_budget = 10**6
r = cp.check_payment(ag.propose("vendorA", 40), m, 10)["result"]
record("Mandate edited after signing", "deny, not signed", r, r == "DENY: mandate not signed")

# L5 escalation: approve and decline
answers = iter(["APPROVE", "DENY"])
reg, trail, pk, cp = setup(human=lambda m, a, why: next(answers))
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id, ask_over=80.0)
r1 = cp.check_payment(ag.propose("vendorA", 90), m, 10)
r2 = cp.check_payment(ag.propose("vendorA", 95), m, 20)
record("L5 step-up, human approves", "allow, approval recorded",
       f"{r1['result']} (human={r1['human']})", r1["result"] == "ALLOW" and r1["human"] == "APPROVE")
record("L5 step-up, human declines", "deny, answer recorded", r2["result"],
       r2["result"] == "DENY: human declined")

# T5 two agents split one principal budget
reg, trail, pk, cp = setup(caps={"priya": 150.0})
a1, a2 = Agent("bot-1", reg), Agent("bot-2", reg)
m1, m2 = mandate(pk, a1.id), mandate(pk, a2.id)
seq = [cp.check_payment(a1.propose("vendorA", 50), m1, 1)["result"],
       cp.check_payment(a2.propose("vendorA", 50), m2, 2)["result"],
       cp.check_payment(a1.propose("vendorA", 50), m1, 3)["result"],
       cp.check_payment(a2.propose("vendorA", 50), m2, 4)["result"]]
record("T5 two agents split a 150 USD cap", "4th payment denied", seq[3],
       seq[:3] == ["ALLOW"] * 3 and seq[3] == "DENY: principal budget used up")

# Incomplete mandate (no per-item limit): a single near-budget payment
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id, per_item_limit=INF)
r = cp.check_payment(ag.propose("vendorA", 4999.99), m, 10)["result"]
record("Mandate without per-item limit, 4,999.99 USD", "deny, incomplete mandate", r,
       r == "DENY: incomplete mandate")

# Structuring: repeated payments one cent under the per-item limit
notified = []
reg, trail, pk, cp = setup(human=lambda m, a, why: notified.append(why) or "DENY")
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
recs = [cp.check_payment(ag.propose("vendorA", 99.99), m, i * 60) for i in range(5)]
flags = [r["flag"] for r in recs]
record("Five payments of 99.99 USD (limit 100)", "allowed, flagged from 3rd",
       f"{[r['result'] for r in recs].count('ALLOW')} allowed, flagged: {[i+1 for i,f in enumerate(flags) if f]}",
       all(r["result"] == "ALLOW" for r in recs) and flags[:2] == [None, None] and all(flags[2:]) and len(notified) == 3)

# Fraud engine adapter: high score escalates to the principal
seen = []
def engine(action, ctx):
    seen.append(ctx)
    return 0.95 if action.payee == "vendorB" else 0.1
reg, trail, pk, cp = setup(human=lambda m, a, why: "DENY", risk=engine)
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
r1 = cp.check_payment(ag.propose("vendorA", 40), m, 1)
r2 = cp.check_payment(ag.propose("vendorB", 40), m, 2)
record("Fraud engine: low score", "allow, score in trail", f"{r1['result']} (risk={r1['risk']})",
       r1["result"] == "ALLOW" and r1["risk"] == 0.1)
record("Fraud engine: high score, principal declines", "deny, score in trail",
       f"{r2['result']} (risk={r2['risk']})", r2["result"] == "DENY: high fraud risk" and r2["risk"] == 0.95)
ctx = seen[-1]
record("Agent context sent to fraud engine", "agent, mandate, budget, pace, denials",
       ", ".join(k for k in ctx), all(k in ctx for k in ("agentic", "agent_id", "mandate_id",
       "budget_left", "payments_in_window", "near_cap_count", "past_denials")))
# A low score never overrides a mandate denial
reg, trail, pk, cp = setup(risk=lambda a, c: 0.0)
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
r = cp.check_payment(ag.propose("attacker-acct", 40), m, 1)["result"]
record("Low fraud score, payee outside mandate", "still denied", r, r == "DENY: outside mandate")

# ---------------- risk and fraud management layer (flows 11-14) ----------------
from kya_risk import (ReferenceEngine, CallbackEngine, RiskLayer, Alert, SCHEMA)

def wired(human=None, engine=None, payees=("vendorA", "vendorB", "vendorC")):
    reg, trail = AgentRegistry(), DecisionTrail()
    pk = Ed25519PrivateKey.generate()
    eng = engine or ReferenceEngine()
    cp = Checkpoint(reg, trail, {"priya": pk.public_key()}, human=human, risk=eng)
    layer = RiskLayer(eng, trail, cp.requests)
    cp.sink = layer.on_record
    ag = Agent("procure-bot", reg)
    m = mandate(pk, ag.id, payees=list(payees))
    return cp, layer, ag, m, trail, eng

# 11: message format sent to the risk layer
cp, layer, ag, m, trail, eng = wired()
req = cp.risk_request(m, ag.propose("vendorA", 40), 10)
d, flat = req.to_dict(), req.to_flat()
std = all(k in d for k in ("amount", "currency", "payee", "channel", "timestamp"))
agent_keys = ("agentic", "agent_id", "mandate_id", "principal", "per_item_limit", "budget_left",
              "payments_in_window", "speed_limit", "near_cap_count", "past_denials",
              "seconds_to_expiry", "pace_ratio")
record("11 Request format (schema kya.risk.v1)", "standard fields + agent block, flat custom fields",
       f"{d['schema']}, {len(d['agent'])} agent fields, {len(flat)} flat attributes",
       std and d["schema"] == SCHEMA and all(k in d["agent"] for k in agent_keys)
       and d["channel"] == "agent" and all(k.startswith("kya_") and isinstance(v, str) for k, v in flat.items()))

# 11: a vendor engine that only reads flat custom fields works unchanged
vendor = CallbackEngine(lambda r: 0.9 if r.to_flat()["kya_past_denials"] != "0" else 0.05, "vendor-x")
cp, layer, ag, m, trail, eng = wired(engine=vendor)
r1 = cp.check_payment(ag.propose("vendorA", 20), m, 1)
cp.check_payment(ag.propose("attacker", 20), m, 2)
r3 = cp.check_payment(ag.propose("vendorA", 20), m, 3)
record("11 Vendor engine via flat fields", "low first, high after a denial",
       f"{r1['risk']} ({r1['risk_engine']}), then {r3['risk']}: {r3['result']}",
       r1["risk"] == 0.05 and r3["risk"] == 0.9 and r3["result"] == "DENY: high fraud risk")

# 12 + 13: runaway loop becomes an alert and a case with verified evidence
cp, layer, ag, m, trail, eng = wired()
eng.observe("priya", "vendorA")
for i in range(80):
    cp.check_payment(ag.propose("vendorA", 3.33), m, i * 0.22)
kinds = [a.kind for a in layer.alerts]
case = next(c for c in layer.cases.cases if c.alert.kind == "runaway_loop")
record("12-13 Runaway loop to analyst case", "alert, case with valid signed evidence",
       f"alerts {sorted(set(kinds))}; case {case.case_id} evidence valid={case.evidence_valid}",
       "runaway_loop" in kinds and case.evidence_valid and len(case.evidence) == 1)

# 12: repeated denials and near-cap structuring raise alerts
cp, layer, ag, m, trail, eng = wired()
for i in range(3):
    cp.check_payment(ag.propose("attacker", 40), m, 10 + i)
for i in range(3):
    cp.check_payment(ag.propose("vendorA", 99.99), m, 100 + i * 60)
kinds = [a.kind for a in layer.alerts]
rd = next(a for a in layer.alerts if a.kind == "repeated_denials")
record("12 Repeated denials and near-cap pattern", "two alert types with evidence",
       f"{sorted(set(kinds))}; denial alert cites {len(rd.evidence)} records",
       "repeated_denials" in kinds and "possible_structuring" in kinds and len(rd.evidence) == 3)

# 13 + 14: a missed hijack is labelled by an analyst and the engine learns
cp, layer, ag, m, trail, eng = wired()
eng.observe("priya", "vendorA")
cp.check_payment(ag.propose("attacker", 40), m, 1)             # one denial
miss = cp.check_payment(ag.propose("vendorC", 60), m, 2)       # new payee, allowed
before = miss["risk"]
case = layer.cases.open(Alert("customer_dispute", "priya", m.mid(), [miss["hash"]], "not authorized"))
layer.label(case, "hijack", "analyst-1")
w = layer.feedback.retrain(eng)
after = eng.score_features(cp.requests[miss["hash"]].features_at_decision)
record("13-14 Missed hijack labelled, engine retrained", "same pattern now escalates",
       f"score {before} before, {after} after; label={case.label}",
       miss["result"] == "ALLOW" and before < 0.8 <= after)

# 14: a false alarm lowers the weight that caused it
cp, layer, ag, m, trail, eng = wired(human=lambda m, a, why: "APPROVE")
for i in range(3):
    cp.check_payment(ag.propose("vendorA", 99.99), m, i * 60)
case = next(c for c in layer.cases.cases if c.alert.kind == "possible_structuring")
wb = eng.w["near_cap"]
layer.label(case, "false_alarm", "analyst-2")
layer.feedback.retrain(eng)
record("14 False alarm labelled", "near-cap weight lowered",
       f"near_cap weight {wb} to {round(eng.w['near_cap'], 3)}", eng.w["near_cap"] < wb)

# S5 dispute: find the record, verify the chain; then tamper
reg, trail, pk, cp = setup()
ag = Agent("procure-bot", reg); m = mandate(pk, ag.id)
for t in range(20):
    cp.check_payment(ag.propose("vendorA", 10 + t), m, t)
ok, bad = trail.verify()
rec = trail.records[7]
record("S5 dispute lookup and chain check", "record found, chain valid",
       f"record 7: {rec['result']}, {rec['amount']} USD, chain valid={ok}", ok and rec["mandate"] == m.mid())
trail.records[12]["amount"] = 999.0
ok2, bad2 = trail.verify()
record("Trail tamper (edit record 12)", "detected at record 12", f"valid={ok2}, first bad={bad2}",
       (not ok2) and bad2 == 12)

# Latency of one full check on the allow path
reg, trail, pk, cp = setup(require_complete=False)
ag = Agent("procure-bot", reg)
m = mandate(pk, ag.id, total_budget=INF, speed_limit=INF, per_item_limit=INF)
acts = [ag.propose("vendorA", 1.0) for _ in range(3000)]
lat = []
for i, a in enumerate(acts):
    t0 = time.perf_counter(); cp.check_payment(a, m, i); lat.append((time.perf_counter() - t0) * 1e6)
lat.sort()
latency = {"median_us": round(statistics.median(lat)), "p99_us": round(lat[int(0.99 * len(lat))])}

# Latency with the full risk layer wired (engine, monitoring, cases)
reg2, trail2 = AgentRegistry(), DecisionTrail()
pk2 = Ed25519PrivateKey.generate()
eng2 = ReferenceEngine()
cp2 = Checkpoint(reg2, trail2, {"priya": pk2.public_key()}, risk=eng2, require_complete=False)
layer2 = RiskLayer(eng2, trail2, cp2.requests); cp2.sink = layer2.on_record
ag2 = Agent("procure-bot", reg2)
m2 = mandate(pk2, ag2.id, total_budget=INF, speed_limit=INF, per_item_limit=INF)
acts2 = [ag2.propose("vendorA", 1.0) for _ in range(3000)]
lat2 = []
for i, a in enumerate(acts2):
    t0 = time.perf_counter(); cp2.check_payment(a, m2, i); lat2.append((time.perf_counter() - t0) * 1e6)
lat2.sort()
latency["full_layer_median_us"] = round(statistics.median(lat2))
latency["full_layer_p99_us"] = round(lat2[int(0.99 * len(lat2))])

# Runaway replay using the real checkpoint
RATE, COST, HORIZON = 15000 / (55 * 60), 50000 / 15000, 3600


def replay(cfg, rate=RATE):
    reg, trail, pk, cp = setup(require_complete=False)   # baselines lack fields
    ag = Agent("acct-bot", reg)
    m = mandate(pk, ag.id, **cfg)
    a = ag.propose("vendorA", COST)          # same signed call repeated
    curve, acc, spent, n = [0.0], 0.0, 0.0, 0
    first_block = None
    for sec in range(1, HORIZON + 1):
        acc += rate; k = int(acc); acc -= k
        for j in range(k):
            now = sec - 1 + j / max(k, 1)
            r = cp.check_payment(a, m, now)
            n += 1
            if r["result"] == "ALLOW":
                spent += COST
            elif first_block is None:
                first_block = now
        curve.append(spent)
    ok, _ = trail.verify()
    return {"loss": round(spent), "stop_s": first_block, "calls": n,
            "trail_records": len(trail.records), "trail_valid": ok, "curve": curve}


CFG = {
    "No controls": dict(per_item_limit=INF, total_budget=INF, speed_limit=INF),
    "Per-item limit only": dict(per_item_limit=100.0, total_budget=INF, speed_limit=INF),
    "Total budget only": dict(per_item_limit=100.0, total_budget=5000.0, speed_limit=INF),
    "Full KYA (budget + speed breaker)": dict(per_item_limit=100.0, total_budget=5000.0, speed_limit=60),
}
runs = {k: replay(v) for k, v in CFG.items()}
sweep = {}
for rate in [0.5, 1, 2, 4.5, 10, 20]:
    sweep[rate] = {k: replay(CFG[k], rate)["loss"] for k in ["No controls", "Full KYA (budget + speed breaker)"]}

summary = {
    "tests": results,
    "passed": sum(r["pass"] for r in results), "total": len(results),
    "latency": latency,
    "replay": {k: {x: v[x] for x in ("loss", "stop_s", "calls", "trail_records", "trail_valid")}
               for k, v in runs.items()},
    "sweep": sweep,
}
json.dump(summary, open("kya_results.json", "w"), indent=1)
json.dump({k: v["curve"] for k, v in runs.items()}, open("kya_curves.json", "w"))
print(json.dumps(summary, indent=1))
