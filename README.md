# Know Your Agent (KYA) reference implementation

Research prototype accompanying the paper "When AI Agents Pay: A Know Your Agent
Governance Architecture" (IEEE AIEI 2027 submission).

KYA is a governance and orchestration layer. It sits on top of the risk and fraud
systems banks already run and makes them agent-aware (Fig. 1 of the paper).

## Files

- `kya_ref.py`: the KYA layers.
  - L1 `AgentRegistry`: Ed25519 agent keys and agent-bound tokens.
  - L2 `Mandate`: signed permission slip (scope, per-item limit, budget, speed, expiry).
  - L3 `Checkpoint`: runs every check outside the agent and orchestrates the risk layer.
  - L4 `DecisionTrail`: signed, hash-chained record of every allow and deny.
  - L5: human decision hook (simulated in tests).
- `kya_risk.py`: interface to the risk and fraud management layer (flows 11 to 14).
  - `RiskRequest` (schema `kya.risk.v1`): standard payment fields plus an agent block.
    `to_flat()` exposes the block as `kya_`-prefixed custom attributes for existing engines.
  - `RiskEngine` protocol, `CallbackEngine` (wrap a vendor API client), and a transparent
    `ReferenceEngine` with agent-aware features.
  - `TransactionMonitor` (flow 12), `CaseManager` (flow 13), `FeedbackStore` (flow 14),
    and `RiskLayer`, which wires them to the checkpoint.
- `kya_eval.py`: 23 functional tests, latency benchmarks, and a replay of a runaway-agent
  incident. Writes `kya_results.json` and `kya_curves.json`.
- `fig_from_ref.py`: draws the replay chart.

## Connecting a real fraud engine

    from kya_ref import Checkpoint
    from kya_risk import CallbackEngine, RiskLayer, RiskResponse

    def call_vendor(req):                 # your client for the bank's engine
        attrs = req.to_flat()             # kya_agent_id, kya_mandate_id, kya_pace_ratio, ...
        score = my_engine_client.score(amount=req.amount, payee=req.payee, custom=attrs)
        return RiskResponse(score, [], "bank-engine")

    engine = CallbackEngine(call_vendor, "bank-engine")
    checkpoint = Checkpoint(registry, trail, principal_keys, risk=engine)
    layer = RiskLayer(engine, trail, checkpoint.requests)
    checkpoint.sink = layer.on_record     # stream decisions to monitoring

## Run

    pip install cryptography matplotlib numpy
    python kya_eval.py
    python fig_from_ref.py

This is not production payment software. Workloads are synthetic, and the reference
engine is a stand-in for a real fraud engine.
