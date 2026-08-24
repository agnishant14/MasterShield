# MasterShield AI: Hackathon Master Plan

## 1. Winning Position

MasterShield should be presented as a **payment-security cyber range**: a safe system in which an AI red team continuously creates plausible, synthetic payment attacks; a blue team scores and routes them; and model governance decides what is allowed to learn or ship.

The memorable sentence is:

> Every miss becomes tomorrow's test, but no model is promoted without evidence, safety gates, and a human-readable reason.

This is stronger than a generic fraud model because it connects threat discovery, simulation, detection, policy, learning, and governance in one closed loop.

## 2. What Already Exists

- 24 attack hypotheses across cards, RTP/bank transfers, wallets, QR, acquiring, merchants, refunds, identity, and social engineering.
- Correlated synthetic payment events rather than isolated random fraud flags.
- Explainable hybrid detector: trainable logistic model plus high-confidence domain priors.
- Policy actions: approve, step-up, review, hold, and decline.
- Adaptive synthetic mutation search that finds bounded detector blind spots without live targets, credentials, or payment actions.
- Immutable holdout, rolling validation, unseen-family stress, missing-feature stress, data-quality checks, model registry, challenger gates, rollback, audit events, and optional SQLite persistence.
- Operations console views for overview, attack intelligence, simulation, defense, evidence, fidelity, and adaptive red teaming.

Repository references: `sentinel/taxonomy.py`, `sentinel/generator.py`, `sentinel/model.py`, `sentinel/attacker.py`, `sentinel/governance.py`, `sentinel/policy.py`, `web/index.html`, and `docs/runbook.md`.

## 3. The Core Demo

Use one primary scenario and two supporting scenarios. Do not walk through all 24 in the live pitch.

### Primary: Deepfake executive payment (`atk-001`)

1. Show a new beneficiary, unusual amount, semantic pressure, voice mismatch, and mule proximity.
2. Score the transfer and show the reason codes plus the policy action.
3. Run adaptive mutation search to lower the risk while preserving the synthetic attack label.
4. Point to the blind spot and its mutation path.
5. Retrain the challenger on that hard case.
6. Show promotion gates, holdout safety, and the new policy decision.

### Supporting: wallet provisioning (`atk-005`)

Use this to show device age, biometric risk, token age, and post-provision velocity. It makes the product feel multimodal and relevant to modern wallets.

### Supporting: merchant/network abuse (`atk-024` or `atk-012`)

Use this to prove MasterShield is not only an issuer card model. Show merchant-card graph signals, reciprocal flows, review similarity, settlement velocity, and network-level controls.

## 4. What Judges Must See

- **Novelty:** the attack catalog is a living hypothesis graph, not a static rules list.
- **Technical depth:** events are correlated across transaction, device, identity, session, language, biometric, merchant, and graph signals.
- **Closed loop:** red-team misses flow into a challenger dataset and back through evaluation gates.
- **Operational realism:** a score becomes an action with friction, expected-loss, controls, and reason codes.
- **Safety:** all adversarial generation is synthetic and bounded; no phishing text, credentials, targets, or payment-rail activity are generated.
- **Deployability:** the production path is explicit: ISO 8583/ISO 20022/wallet adapters, online enrichment, low-latency risk service, policy orchestration, confirmed outcomes, and signed model artifacts.

## 5. Highest-Value Additions

### P0: do these before adding new AI

1. Add a **before/after comparison panel**: baseline detector, current detector, and challenger across F1, recall, FPR, missed attacks, customer friction, and expected loss.
2. Add a **kill-chain timeline** for the selected scenario: discovery -> social/session signal -> authentication or payee change -> payment -> cash-out.
3. Make the mutation result the visual centerpiece: original risk, lowest-risk successful synthetic variant, changed features, risk delta, and next training action.
4. Add a small **network graph view** for customer/device/payee/merchant relationships. It can be a deterministic canvas visualization; it does not need Neo4j for the demo.
5. Add a **counterfactual slider**: “What if beneficiary cooling period, device attestation, or out-of-band confirmation existed?” Re-score the same event and show risk, action, friction, and loss changes.
6. Add a visible **synthetic evidence banner** and a “not production performance” label beside every metric.

### P1: strong if time remains

- Harder overlap/noise in the generator so the holdout is not trivially separable.
- Rules-only versus logistic-only versus hybrid comparison in the defense view.
- Time-split metrics by rail and attack family.
- Analyst feedback with a visible audit event and training-cycle linkage.
- Scenario-level detection matrix: intensity on one axis, attack family on the other.
- Signed dataset/model hash in the report export.
- Replay mode: deterministic seed, run ID, model version, and exact recipe produce the same result.

### P2: production-grade extensions

- Temporal heterogeneous graph model for customer-device-payee-merchant-merchant-cluster relationships.
- Sequence model for account/session/payment journeys, with the current reason-code contract preserved.
- Multimodal deepfake and document provenance adapters: voice anti-spoof, liveness, OCR/layout drift, metadata, and content provenance.
- Streaming architecture: Kafka/Pulsar -> feature store -> online graph -> risk API -> policy orchestrator -> outcome stream.
- Model registry and gates using MLflow/Kubeflow or a signed artifact store; policy gates expressed with OPA-style rules.
- Privacy-preserving consortium signals: tokenized identifiers, federated learning, secure aggregation, differential privacy, and strict retention.
- Observability: OpenTelemetry traces, per-feature drift, calibration drift, latency SLOs, and rail-specific incident replay.
- Shadow mode, canary rollout, champion/challenger, rollback, and human override with immutable audit trails.

## 6. Technology Choices by Purpose

| Purpose | Demo choice | Production choice |
| --- | --- | --- |
| Event simulation | Seeded Python generator | Replayable event stream and scenario compiler |
| Detector | Explainable hybrid logistic model | Gradient boosting/sequence/graph ensemble behind same contract |
| Network intelligence | In-memory graph metrics + canvas | Streaming graph store or graph database |
| Language/deepfake evidence | Synthetic scalar signals | Specialized anti-spoof/provenance models plus calibrated fusion |
| Policy | `RiskPolicy` thresholds | Policy service with rail/customer/merchant risk appetite |
| Learning | Feedback queue + challenger gates | Outcome lake, label-delay handling, signed registry |
| Persistence | Memory or SQLite | Managed Postgres/KV/event store and artifact registry |
| Observability | Audit endpoint and report | OpenTelemetry, dashboards, alerts, incident replay |

Do not add an LLM merely to say “AI.” Use an LLM only where it has a clear contract: attack-hypothesis synthesis, multilingual semantic-pressure scoring, analyst explanation, or scenario recipe generation. Keep the final payment decision deterministic, bounded, and auditable.

## 7. Credibility Fixes

The current bootstrap holdout is very strong: approximately F1 0.998, AUC 1.0, recall 1.0, and FPR 0.0019 on generated data. Treat this as a mechanics proof, not a performance claim. A judge may ask whether the generator made fraud too easy.

Show the harder evidence instead:

- known low-intensity attack recall: about 0.922;
- missing-feature attack recall: about 0.464;
- bounded adversarial mutation success: about 0.097;
- fidelity mean feature distance: about 0.049;
- deterministic seed reproducibility: true;
- policy trade-off: explicitly show friction versus expected loss.

Add overlap/noise and a rules-only baseline before claiming improvement. The strongest story is not “we have 100% detection”; it is “we can measure where the detector fails, safely generate that failure, and improve it without contaminating the holdout.”

## 8. 90-Second Walkthrough

**0-10 seconds:** “Payment fraud is becoming an adaptive software problem. Static rules wait for yesterday's attack.”

**10-25 seconds:** Open Overview. Point to the catalog, current model cycle, FPR guardrail, and synthetic-evidence label.

**25-45 seconds:** Open `atk-001`. Run a short high-intensity stream. Explain the correlated bundle: new payee + pressure + voice mismatch + mule proximity.

**45-60 seconds:** Open a missed or borderline transaction. Show feature contributions, policy action, and the selected control.

**60-75 seconds:** Run mutation search. Show the lower-risk synthetic variant and the exact mutation path. Say: “This is the attacker asking us where we are weak.”

**75-87 seconds:** Retrain. Show challenger gates, immutable holdout, and before/after policy/loss metrics.

**87-90 seconds:** “MasterShield makes payment defense measurable as a loop: hypothesize, simulate, detect, govern, learn.”

## 9. Deck Structure

1. Problem: GenAI increases attack speed, personalization, and cross-channel coordination.
2. Why current defenses miss: rails are siloed, labels arrive late, and static rules do not explore unknowns.
3. Product: the red-team/blue-team payment cyber range.
4. Architecture: hypothesis graph -> correlated simulator -> detector -> policy -> feedback -> governed challenger.
5. Live proof: the primary deepfake-transfer scenario.
6. Evidence: low-intensity, unseen-family, missing-feature, mutation, fidelity, and latency results.
7. Business value: avoided loss, reduced false positives, controlled customer friction, faster analyst learning.
8. Production path: event adapters, feature/graph enrichment, shadow mode, policy orchestration, outcomes, registry.
9. Safety and privacy: synthetic-only red team, tokenization, access control, human review, retention, rollback.
10. Ask: pilot with a small set of tokenized historical/replay events in shadow mode.

## 10. Judge Questions

**Are the metrics real?** They are measured on generated holdout and stress data. They demonstrate the mechanics, not Mastercard production performance.

**Why not use a large language model for the final decision?** Payment actions need stable latency, calibration, auditability, and rollback. Language models can enrich hypotheses and explanations; the final policy remains deterministic and governed.

**How do you avoid overfitting?** The immutable holdout is never reused for feedback training. Challengers also face rolling, unseen-family, missing-feature, and adversarial tests.

**What makes this different from a fraud rules engine?** The system actively searches for detector blind spots and converts misses into the next red-team frontier.

**How is this safe?** The attacker mutates synthetic feature values only. It never generates credentials, phishing copy, targets, or live payment actions.

**What happens after a score?** A risk policy maps it to approve, step-up, review, hold, or decline, with reason codes and estimated friction/loss.

**How would this integrate?** Map ISO 8583, ISO 20022, wallet, merchant, and identity events into the existing transaction contract, enrich online, run shadow mode, then canary policy actions.

## 11. Do Not Do This

- Do not lead with all 24 scenarios; it sounds like a feature list.
- Do not claim “100% fraud detection” or real Mastercard accuracy.
- Do not add a chatbot as the product surface.
- Do not demonstrate live evasion, phishing, credential use, or payment execution.
- Do not spend hackathon time on distributed infrastructure that cannot appear in the demo.
- Do not hide false positives and customer friction; showing the trade-off increases trust.

## 12. Build Order

1. Freeze the story and primary scenario.
2. Add baseline/challenger comparison and counterfactual controls.
3. Add the graph/timeline visualization.
4. Make the mutation -> retrain -> gate loop one click and deterministic.
5. Add a harder stress dataset and label all metrics synthetic.
6. Rehearse the 90-second demo and a five-minute deep dive.
7. Export the report, runbook, architecture, tests, and exact replay commands.

