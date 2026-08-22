# MasterShield AI

MasterShield AI is a closed-loop red-team / blue-team payment-security prototype for the Mastercard Innovation Challenge @ GFF 2026.

It treats fraud discovery, attack simulation, and defense as one system:

```text
24 attack hypotheses -> correlated synthetic payment stream -> explainable detector
         ^                                                   |
         |---------------- hard-case feedback ---------------|
```

The prototype is intentionally dependency-light. The backend, synthetic generator, model, API, and test suite use Python's standard library. The web console is plain HTML/CSS/JavaScript so a judge can run it without a frontend build step.

## What Is Implemented

- **Identify:** 24 emerging GenAI-enabled payment attack hypotheses spanning CNP cards, RTP / bank transfers, wallets, QR, acquiring, merchant abuse, refunds, identity, and social engineering.
- **Generate:** a seeded simulator that produces legitimate baselines and attack streams with correlated amount, velocity, device, account, identity, graph, biometric, session, remote-access, merchant, and generated-language signals.
- **Defend:** a from-scratch weighted logistic detector blended with a small high-confidence domain-prior layer. The model calibrates a threshold under a false-positive guardrail and returns feature-level explanations.
- **Learn:** false negatives and simulator feedback are promoted into the next training frontier. Holdout evaluation data remains separate.
- **Adapt:** a safe deterministic red-team composer mutates synthetic attacks, searches for lower-risk variants, and records the mutation path.
- **Measure:** fidelity, robustness, PR-AUC, calibration, recall at a fixed FPR, policy trade-offs, and measured scoring latency are exposed as synthetic evidence.
- **Operate:** typed feedback buckets, policy actions, request IDs, schema validation, audit events, and optional SQLite persistence support a production-shaped workflow.
- **Govern:** challenger models are evaluated against the immutable holdout and robustness gates before promotion; approved snapshots can be rolled back and compared through the model API.
- **Quality:** dataset-health checks report missing fields, non-finite features, duplicate IDs, label balance, zero-variance columns, and measured drift.
- **Prototype:** an original Mastercard-inspired operations console with overview, attack intelligence, simulation lab, defense evidence, and judge-ready feasibility views.

## Run It

Requires Python 3.10+.

```bash
python3 app.py
```

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765).

Optional flags:

```bash
python3 app.py --host 0.0.0.0 --port 8765
```

## Deploy to Vercel

The repository includes a Vercel configuration and a WSGI entrypoint in `app.py`. From the project directory:

```bash
npx vercel login
npx vercel
```

Use `npx vercel --prod` when you are ready to promote the deployment to a production URL. Vercel will detect `requirements.txt`, build the Python function, and route both the API and the `web/` console through the same entrypoint.

This deployment is suitable for demos and reviews. `DefenseEngine` keeps feedback, transactions, and model state in process memory, so Vercel cold starts or multiple serverless instances can reset or diverge from that state. A production rollout should move those stores to durable infrastructure such as Vercel KV, Postgres, or another managed database.

The first boot trains two model cycles so the overview can show hard-case mining. On a modern laptop this usually takes a few seconds.

## API Surface

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Liveness and model version |
| `GET /api/overview` | KPIs, history, recent stream, feature importance |
| `GET /api/attacks` | Full 24-scenario attack catalog with live detection rates |
| `GET /api/transactions?limit=100` | Recent annotated decisions |
| `POST /api/simulate` | Generate and score an attack stream |
| `POST /api/retrain` | Train on queued simulator feedback and hard cases |
| `POST /api/score` | Score one transaction-shaped JSON object |
| `GET /api/fidelity` | Synthetic fidelity, robustness, and policy evidence |
| `POST /api/mutate` | Search safe synthetic mutations for detector blind spots |
| `POST /api/feedback` | Submit an analyst outcome for a scored transaction |
| `GET /api/simulations` | Review recent simulation runs |
| `GET /api/report` | Export a synthetic evaluation report |
| `GET /api/models` | Model versions, statuses, gates, and active version |
| `POST /api/models/rollback` | Restore an in-memory model snapshot by version |
| `GET /api/audit` | Structured audit events (bounded, redacted) |

Append `?format=csv` to `/api/report` or `/api/simulations` for a flat CSV export. JSON remains the default.

Example:

```bash
curl -X POST http://127.0.0.1:8765/api/simulate \
  -H 'content-type: application/json' \
  -d '{"attack_ids":["atk-001","atk-005","atk-008"],"count":120,"intensity":1.1}'
```

## Repository Map

```text
app.py                    # no-dependency HTTP API + static-file server
sentinel/taxonomy.py      # 24 attack hypotheses and mitigations
sentinel/generator.py     # seeded correlated transaction simulator
sentinel/features.py      # raw-to-model feature transformation
sentinel/model.py         # weighted logistic model, calibration, explanations
sentinel/engine.py        # closed-loop orchestration and API-ready state
sentinel/attacker.py      # adaptive synthetic mutation search
sentinel/fidelity.py      # fidelity and robustness measurements
sentinel/policy.py        # configurable operational actions
sentinel/storage.py       # memory / optional SQLite event store
web/                      # operations console
tests/                    # deterministic unit and integration-style tests
scripts/                  # dataset export and model report helpers
docs/                     # architecture notes and demo runbook
```

## Evaluation Notes

The numbers shown in the UI are measured on generated holdout data, not real Mastercard production data. They demonstrate the mechanics of a closed loop and should be presented as simulation results. For a production pilot, replace the generator's schema adapter with tokenized ISO 8583 / ISO 20022 events, add confirmed fraud outcomes, and run a time-based rather than random split.

The model intentionally optimizes for a low false-positive rate first. The prototype now includes a transparent policy layer around the model score: approve, step-up, review, hold, and decline are different operational actions and are accompanied by synthetic friction/loss estimates. A production rollout must calibrate those policies against issuer risk appetite, customer impact, regulation, and confirmed outcomes.

Retraining creates a challenger snapshot, evaluates it on the immutable holdout plus rolling and stress suites, and promotes it only when `sentinel/governance.py` gates pass. Rejected challengers remain visible in `/api/models`; rollback restores the stored detector state and re-scores the current synthetic stream. Analyst feedback is retained in the audit store after queue consumption.

All fidelity, robustness, and model metrics are explicitly synthetic evidence. They are not claims about Mastercard production performance. The immutable holdout is kept separate from feedback retraining; rolling validation and robustness reports expose distribution shift and unseen-attack behavior.

For optional local persistence, set `MASTERSHIELD_DB=work/mastershield.db`. Without it, the event store remains in memory for a dependency-free demo.

## Design Positioning

The interface uses a Mastercard-inspired black / red / amber visual language and overlapping-circle mark, but the product name, layout, copy, and visual components are original. It includes an independent-prototype note so it is clear this is a challenge submission, not an official Mastercard product.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 scripts/train_model.py --report work/model-report.json
python3 scripts/generate_dataset.py --rows 10000 --output data/synthetic_payments.jsonl
```
