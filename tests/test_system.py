from __future__ import annotations

import json
import math
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

from sentinel import DefenseEngine
from sentinel.features import FEATURES, vectorize
from sentinel.generator import SyntheticGenerator
from sentinel.attacker import AdaptiveAttacker
from sentinel.fidelity import compare_streams
from sentinel.fidelity import seed_reproducibility
from sentinel.contracts import validate_score_payload, validate_simulate_payload, validate_rollback_payload
from sentinel.governance import PromotionGates
from sentinel.quality import assess_dataset
from sentinel.policy import RiskPolicy
from sentinel.storage import EventStore
from sentinel.taxonomy import ATTACKS, ATTACK_BY_ID
from app import app


ROOT = Path(__file__).resolve().parents[1]


class AttackCatalogTests(unittest.TestCase):
    def test_catalog_has_breadth_and_unique_ids(self) -> None:
        self.assertEqual(24, len(ATTACKS))
        self.assertEqual(24, len(ATTACK_BY_ID))
        self.assertGreaterEqual(len({attack.family for attack in ATTACKS}), 14)
        self.assertGreaterEqual(len({attack.rail for attack in ATTACKS}), 8)

    def test_every_scenario_is_actionable(self) -> None:
        for attack in ATTACKS:
            self.assertGreaterEqual(len(attack.leading_signals), 4)
            self.assertGreaterEqual(len(attack.mitigations), 3)
            self.assertTrue(attack.simulation_recipe)


class GeneratorTests(unittest.TestCase):
    def test_seed_is_reproducible(self) -> None:
        first = SyntheticGenerator(99).generate_attacks(4, ["atk-001"])
        second = SyntheticGenerator(99).generate_attacks(4, ["atk-001"])
        self.assertEqual(first, second)

    def test_attack_recipe_moves_correlated_signals(self) -> None:
        generator = SyntheticGenerator(7)
        rows = generator.generate_attacks(30, ["atk-001"], intensity=1.1)
        self.assertTrue(all(row["label"] == 1 for row in rows))
        self.assertGreater(sum(row["new_payee"] for row in rows) / len(rows), 0.9)
        self.assertGreater(sum(row["prompt_pressure_score"] for row in rows) / len(rows), 0.6)
        self.assertGreater(sum(row["graph_mule_score"] for row in rows) / len(rows), 0.4)

    def test_scenario_overlays_match_catalog_recipes(self) -> None:
        generator = SyntheticGenerator(12)
        otp = generator.generate_attacks(12, ["atk-009"])
        fallback = generator.generate_attacks(12, ["atk-016"])
        supplier = generator.generate_attacks(12, ["atk-022"])
        self.assertTrue(all(row["remote_access"] == 1 for row in otp))
        self.assertTrue(all(row["auth_downgrade"] == 1 for row in fallback))
        self.assertGreater(sum(row["merchant_age_risk"] for row in supplier) / len(supplier), 0.4)

    def test_feature_vector_is_complete(self) -> None:
        row = SyntheticGenerator(3).generate_legitimate(1)[0]
        values = vectorize(row)
        self.assertEqual(len(FEATURES), len(values))
        self.assertTrue(all(isinstance(value, float) for value in values))


class NewCapabilityTests(unittest.TestCase):
    def test_contracts_reject_unknown_nonfinite_and_bad_ranges(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unexpected scoring fields"):
            validate_score_payload({"amount": 1, "currency": "USD", "rail": "wallet", "channel": "app", "account_age_days": 1, "device_age_days": 1, "secret": "x"})
        with self.assertRaisesRegex(ValueError, "amount must be finite"):
            validate_score_payload({"amount": float("nan"), "currency": "USD", "rail": "wallet", "channel": "app", "account_age_days": 1, "device_age_days": 1})
        with self.assertRaisesRegex(ValueError, "count must be between"):
            validate_simulate_payload({"count": 501})
        with self.assertRaisesRegex(ValueError, "model_version must"):
            validate_rollback_payload({"model_version": ""})

    def test_governance_has_explicit_gate_results(self) -> None:
        result = PromotionGates().evaluate({"f1": 0.95, "recall": 0.95}, {"f1": 0.96, "recall": 0.96, "false_positive_rate": 0.01}, {"unseen_attack_families": {"attack_recall": 0.9}})
        self.assertTrue(result["passed"])
        self.assertIn("checks", result)

    def test_quality_and_seed_evidence_are_deterministic(self) -> None:
        rows = SyntheticGenerator(51).generate_mixed(16)
        quality = assess_dataset(rows)
        self.assertTrue(quality["synthetic_evidence"])
        self.assertEqual(16, quality["rows"])
        self.assertTrue(seed_reproducibility(51, 16)["reproducible"])
    def test_adaptive_attacker_is_seeded_and_safe(self) -> None:
        row = SyntheticGenerator(4).generate_attacks(1, ["atk-001"])[0]
        attacker = AdaptiveAttacker(77)
        first = attacker.mutate(row, count=3)
        second = AdaptiveAttacker(77).mutate(row, count=3)
        self.assertEqual(first, second)
        self.assertTrue(all(candidate[0]["synthetic_only"] for candidate in first))
        self.assertTrue(all(candidate[0]["label"] == 1 for candidate in first))

    def test_fidelity_report_is_synthetic_and_bounded(self) -> None:
        first = SyntheticGenerator(1).generate_mixed(20)
        second = SyntheticGenerator(2).generate_mixed(20)
        report = compare_streams(first, second)
        self.assertTrue(report["synthetic_evidence"])
        self.assertGreaterEqual(report["mean_feature_distance"], 0)
        self.assertLessEqual(report["mean_feature_distance"], 1)

    def test_policy_exposes_operational_actions(self) -> None:
        policy = RiskPolicy()
        decision = policy.decide({"amount": 2500, "new_payee": 1, "rail": "instant_transfer"}, 0.95)
        self.assertEqual("decline", decision.action)
        self.assertIn("notify_analyst", decision.controls)

    def test_event_store_memory_and_sqlite(self) -> None:
        memory = EventStore()
        memory.append("audit", {"event": "test"})
        self.assertEqual("test", memory.list("audit")[0]["payload"]["event"])
        with tempfile.NamedTemporaryFile(suffix=".db") as handle:
            sqlite_store = EventStore(handle.name)
            sqlite_store.append("models", {"cycle": 2})
            self.assertEqual(2, sqlite_store.list("models")[0]["payload"]["cycle"])

    def test_feedback_and_mutation_targets_are_retrainable_and_explicit(self) -> None:
        engine = DefenseEngine(seed=2030)
        transaction = engine.generator.generate_attacks(1, ["atk-001"])[0]
        transaction.pop("id")
        scored = engine.score_transaction(transaction)
        self.assertRegex(scored["id"], r"^score-\d+-\d{6}$")
        self.assertTrue(any(row.get("id") == scored["id"] for row in engine.live_transactions))

        fraud_feedback = engine.submit_feedback(scored["id"], "confirmed_fraud")
        self.assertTrue(fraud_feedback["queued_for_retraining"])
        self.assertEqual(1, engine.feedback_rows[-1]["label"])

        legitimate = next(row for row in engine.live_transactions if row.get("label") == 0)
        legitimate_feedback = engine.submit_feedback(legitimate["id"], "confirmed_legitimate")
        self.assertTrue(legitimate_feedback["queued_for_retraining"])
        self.assertEqual(0, engine.feedback_rows[-1]["label"])

        uncertain_feedback = engine.submit_feedback(legitimate["id"], "uncertain")
        self.assertFalse(uncertain_feedback["queued_for_retraining"])
        self.assertEqual(2, len(engine.feedback_rows))
        self.assertEqual(2, engine.retrain()["feedback_rows"])

        with self.assertRaisesRegex(ValueError, "Unknown attack ID"):
            engine.mutate_transaction(attack_id="not-an-attack", count=1)
        with self.assertRaisesRegex(ValueError, "Transaction not found"):
            engine.mutate_transaction(transaction_id="not-a-transaction", count=1)


class ClosedLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = DefenseEngine(seed=2026)

    def test_model_meets_simulated_holdout_guardrails(self) -> None:
        metrics = self.engine.metrics
        self.assertGreaterEqual(metrics["f1"], 0.9)
        self.assertGreaterEqual(metrics["recall"], 0.9)
        self.assertLessEqual(metrics["false_positive_rate"], 0.035)
        self.assertEqual(24, self.engine.history[-1]["attack_coverage"])

    def test_scoring_returns_decision_and_explanations(self) -> None:
        row = SyntheticGenerator(11).generate_attacks(1, ["atk-005"], intensity=1.2)[0]
        scored = self.engine.score_transaction(row)
        self.assertIn(scored["decision"], {"approve", "review", "decline"})
        self.assertGreaterEqual(scored["risk_score"], 0)
        self.assertIsInstance(scored["explanations"], list)

    def test_feedback_advances_cycle(self) -> None:
        previous_cycle = self.engine.cycle
        run = self.engine.simulate(["atk-016", "atk-018"], count=25, intensity=1.05)
        self.assertEqual(25, run["feedback_ready"])
        result = self.engine.retrain()
        self.assertEqual(previous_cycle + 1, result["cycle"])
        self.assertEqual(0, len(self.engine.feedback_rows))

    def test_holdout_is_not_reused_for_bootstrap_training(self) -> None:
        training_ids = {row["id"] for row in self.engine.training_rows}
        holdout_ids = {row["id"] for row in self.engine.holdout_rows}
        self.assertTrue(training_ids.isdisjoint(holdout_ids))
        self.assertEqual(len(self.engine.holdout_rows), sum(self.engine.overview()["validation"]["risk_distribution"]["legitimate"]) + sum(self.engine.overview()["validation"]["risk_distribution"]["attack"]))

    def test_immutable_holdout_survives_retrain(self) -> None:
        original_ids = {row["id"] for row in self.engine.immutable_holdout_rows}
        self.engine.simulate(["atk-001"], count=5)
        self.engine.retrain()
        self.assertEqual(original_ids, {row["id"] for row in self.engine.immutable_holdout_rows})
        self.assertEqual(self.engine.detector.evaluate(self.engine.immutable_holdout_rows), self.engine.metrics)

    def test_fidelity_is_reproducible_without_advancing_live_generator(self) -> None:
        engine = DefenseEngine(seed=2040)
        before = (engine.generator.rng.getstate(), engine.generator._clock, engine.generator._counter)
        first = engine.fidelity()
        after = (engine.generator.rng.getstate(), engine.generator._clock, engine.generator._counter)
        second = engine.fidelity()
        self.assertEqual(before, after)
        self.assertEqual(first, second)

    def test_model_registry_and_rollback_restore_snapshot(self) -> None:
        engine = DefenseEngine(seed=2077)
        original = engine.active_model_version
        result = engine.retrain()
        self.assertIn(result["candidate_model_version"], {item["version"] for item in engine.models()})
        self.assertTrue(engine.active_model_version)
        rollback = engine.rollback_model(original)
        self.assertEqual(original, rollback["model_version"])
        self.assertEqual(original, engine.active_model_version)

    def test_confirmed_analyst_feedback_is_consumed_but_archived(self) -> None:
        engine = DefenseEngine(seed=2078)
        row = next(item for item in engine.live_transactions if item.get("label") == 0)
        engine.submit_feedback(row["id"], "confirmed_fraud", "analyst evidence")
        result = engine.retrain()
        self.assertGreaterEqual(result["feedback_rows"], 1)
        self.assertEqual(0, len(engine.feedback_rows))
        self.assertTrue(any(item.get("training_cycle") == engine.cycle for item in engine.feedback_records))

    def test_latency_uses_nearest_rank_p95(self) -> None:
        engine = DefenseEngine(seed=2041)
        engine.latencies_ms = [float(value) for value in range(1, 21)]
        self.assertEqual(19.0, engine._p95_latency())

    def test_retrain_reports_measured_duration(self) -> None:
        engine = DefenseEngine(seed=2042)
        result = engine.retrain()
        self.assertGreater(result["duration_ms"], 0)

    def test_feedback_buckets_and_mutation_search(self) -> None:
        run = self.engine.simulate(["atk-001"], count=5)
        self.assertIn("feedback_buckets", run)
        result = self.engine.mutate_transaction(attack_id="atk-001", count=3)
        self.assertEqual(3, result["candidate_count"])
        self.assertIn("safety", result)

    def test_score_requires_schema(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.score_transaction({})


class WebArtifactTests(unittest.TestCase):
    def test_web_console_has_all_judge_views(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        for view in ("view-overview", "view-attacks", "view-simulate", "view-defense", "view-evidence", "view-fidelity"):
            self.assertIn(view, html)
        self.assertIn("independent challenge prototype", html.lower())
        self.assertIn("run-mutation", html)
        self.assertIn("/favicon.svg", html)
        self.assertNotIn("/_vercel/insights/script.js", html)

    def test_offline_demo_supports_new_read_only_views(self) -> None:
        script = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        for endpoint in ("/api/health", "/api/fidelity", "/api/report", "/api/mutate"):
            self.assertIn(f'url === "{endpoint}"', script)
        self.assertIn('setConnectionStatus(isOfflineDemo() ? "offline" : currentBackend ? "live" : "outdated")', script)

    def test_vercel_wsgi_entrypoint_serves_health_and_console(self) -> None:
        def request(path: str, method: str = "GET", body: bytes = b"") -> tuple[str, dict[str, str], bytes]:
            captured: dict[str, object] = {}
            parsed = urlparse(path)

            def start_response(status: str, headers: list[tuple[str, str]], _exc_info=None) -> None:
                captured["status"] = status
                captured["headers"] = dict(headers)

            environ = {
                "REQUEST_METHOD": method,
                "PATH_INFO": parsed.path,
                "QUERY_STRING": parsed.query,
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": BytesIO(body),
            }
            response = b"".join(app(environ, start_response))
            return captured["status"], captured["headers"], response

        status, headers, body = request("/api/health")
        self.assertEqual("200 OK", status)
        self.assertEqual("application/json; charset=utf-8", headers["Content-Type"])
        health = json.loads(body)
        self.assertEqual("ok", health["status"])
        self.assertIn("fidelity", health["capabilities"])
        self.assertIn("mutate", health["capabilities"])
        self.assertIn("models", health["capabilities"])
        self.assertIn("rollback", health["capabilities"])
        self.assertIn("audit", health["capabilities"])
        self.assertTrue(health["api_version"])

        status, headers, body = request("/api/models")
        self.assertEqual("200 OK", status)
        self.assertTrue(json.loads(body)["models"])
        status, headers, body = request("/api/audit?limit=5")
        self.assertEqual("200 OK", status)
        self.assertIsInstance(json.loads(body)["audit"], list)
        status, headers, body = request("/api/report?format=csv")
        self.assertEqual("200 OK", status)
        self.assertIn("text/csv", headers["Content-Type"])

        for path in ("/api/fidelity", "/api/fidelity/"):
            status, headers, body = request(path)
            self.assertEqual("200 OK", status)
            self.assertTrue(json.loads(body)["synthetic_evidence"])

        for path in ("/api/mutate", "/api/mutate/"):
            status, headers, body = request(path, "POST", json.dumps({"attack_id": "atk-001", "count": 2}).encode())
            self.assertEqual("200 OK", status)
            self.assertEqual(2, json.loads(body)["candidate_count"])

        for path in ("/api/simulations", "/api/simulations/"):
            status, headers, body = request(path)
            self.assertEqual("200 OK", status)
            self.assertIsInstance(json.loads(body)["simulations"], list)

        status, headers, body = request("/api/score", "POST", b"{}")
        self.assertEqual("400 Bad Request", status)
        self.assertIn("request_id", json.loads(body))

        status, headers, body = request("/api/simulate", "POST", json.dumps({"attack_ids": "atk-001"}).encode())
        self.assertEqual("400 Bad Request", status)
        self.assertIn("list of strings", json.loads(body)["error"])

        status, headers, body = request("/api/mutate", "POST", json.dumps({"attack_id": "not-an-attack"}).encode())
        self.assertEqual("400 Bad Request", status)
        self.assertIn("Unknown attack ID", json.loads(body)["error"])

        status, headers, body = request("/")
        self.assertEqual("200 OK", status)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"MasterShield", body)


if __name__ == "__main__":
    unittest.main()
