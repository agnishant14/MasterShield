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
web/                      # operations console
tests/                    # deterministic unit and integration-style tests
scripts/                  # dataset export and model report helpers
docs/                     # architecture and pitch-deck blueprint
```

## Evaluation Notes

The numbers shown in the UI are measured on generated holdout data, not real Mastercard production data. They demonstrate the mechanics of a closed loop and should be presented as simulation results. For a production pilot, replace the generator's schema adapter with tokenized ISO 8583 / ISO 20022 events, add confirmed fraud outcomes, and run a time-based rather than random split.

The model intentionally optimizes for a low false-positive rate first. A production rollout should use a policy layer around the model score: approve, step-up / review, hold, and decline are different operational actions and should be tied to customer impact, regulatory controls, and issuer risk appetite.

## Design Positioning

The interface uses a Mastercard-inspired black / red / amber visual language and overlapping-circle mark, but the product name, layout, copy, and visual components are original. It includes an independent-prototype note so it is clear this is a challenge submission, not an official Mastercard product.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 scripts/train_model.py --report work/model-report.json
python3 scripts/generate_dataset.py --rows 10000 --output data/synthetic_payments.jsonl
```
