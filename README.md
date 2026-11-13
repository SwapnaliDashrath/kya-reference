# Know Your Agent (KYA) reference implementation

Research prototype accompanying the paper "Know Your Agent: Verifiable Delegation for
AI Agents That Pay" (submitted to AGENT 2027, the workshop on agentic engineering at
ICSE 2027).

KYA is a governance and orchestration layer. It sits on top of the risk and fraud
systems banks already run and makes them agent-aware.

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
- `kya_table3.py`: comparison with two common controls (Table II of the paper) and the
  slow-loop runs (Table IV). Writes `kya_table3_results.json`.
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
    python kya_table3.py
    python fig_from_ref.py

`kya_eval.py` reproduces the functional tests, the replay (Table III) and the latency
figures. Latency depends on the machine. The numbers in the paper and in
`kya_results.json` come from an Intel Core i5-4300M (2.60 GHz, 2 cores), Windows 10
and Python 3.14.3. `kya_table3.py` uses no timing, so its output is the same on any
machine.

## What the prototype leaves out

The paper's design includes replay protection (nonce and timestamp), reserve-then-commit
across replicas, reinstatement and revocation calls, the sub-agent rule, and external
anchoring of the trail. These are not implemented here. See Section III-E of the paper.

This is not production payment software. Workloads are synthetic, and the reference
engine is a stand-in for a real fraud engine.
