"""Closed-loop orchestration for red-team generation and blue-team defense."""

from __future__ import annotations

import random
import threading
import os
import time
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .generator import SyntheticGenerator, scenario_stats
from .attacker import AdaptiveAttacker
from .fidelity import compare_streams, robustness_report
from .model import HybridFraudDetector, classification_metrics
from .policy import RiskPolicy
from .storage import EventStore
from .taxonomy import ATTACKS, ATTACK_BY_ID, catalog


class DefenseEngine:
    """Owns the attack catalog, synthetic stream, detector, evaluation, and feedback loop."""

    def __init__(self, seed: int = 2026):
        self.seed = seed
        self.lock = threading.RLock()
        self.generator = SyntheticGenerator(seed)
        self.detector = HybridFraudDetector(seed)
        self.attacker = AdaptiveAttacker(seed)
        self.policy = RiskPolicy()
        self.store = EventStore(os.environ.get("MASTERSHIELD_DB") or None)
        self.cycle = 0
        self.training_rows: list[dict] = []
        self.feedback_rows: list[dict] = []
        self.live_transactions: list[dict] = []
        self.history: list[dict] = []
        self.metrics: dict = {}
        self.holdout_rows: list[dict] = []
        self.immutable_holdout_rows: list[dict] = []
        self.rolling_validation_rows: list[dict] = []
        self.validation_reports: dict = {}
        self.simulation_history: list[dict] = []
        self.feedback_records: list[dict] = []
        self.latencies_ms: list[float] = []
        self._bootstrap()

    def _bootstrap(self) -> None:
        known_attack_ids = [attack.id for attack in ATTACKS[:16]]
        train = self.generator.generate_legitimate(2100)
        train.extend(self.generator.generate_attacks(1050, known_attack_ids, intensity=0.92))
        random.Random(self.seed).shuffle(train)
        calibration = self.generator.generate_legitimate(650)
        calibration.extend(self.generator.generate_attacks(330, intensity=1.0))
        evaluation = self.generator.generate_legitimate(1050)
        evaluation.extend(self.generator.generate_attacks(520, intensity=1.0))
        random.Random(self.seed + 1).shuffle(calibration)
        random.Random(self.seed + 2).shuffle(evaluation)

        self.training_rows = train
        self.detector.fit(train)
        self.detector.calibrate(calibration)
        baseline = self.detector.evaluate(evaluation)
        self.holdout_rows = list(evaluation)
        self.immutable_holdout_rows = list(evaluation)
        self.cycle = 1
        self.history.append(self._history_point("Initial frontier", baseline, evaluation))

        # Mine errors from a separate frontier sample so evaluation remains untouched.
        frontier = self.generator.generate_attacks(560, [attack.id for attack in ATTACKS[16:]], intensity=0.88)
        hard_cases = [row for row in frontier if self.detector.predict(row) == 0]
        stabilizers = self.generator.generate_legitimate(720)
        self.training_rows.extend(hard_cases * 2 + frontier + stabilizers)
        random.Random(self.seed + 3).shuffle(self.training_rows)
        self.detector.fit(self.training_rows)
        self.detector.calibrate(calibration)
        self.metrics = self.detector.evaluate(evaluation)
        self.validation_reports = self._validation_report(include_robustness=False)
        self.cycle = 2
        self.history.append(self._history_point("Hard-case retrain", self.metrics, evaluation))

        seed_stream = self.generator.generate_mixed(140, attack_rate=0.22, intensity=1.02)
        self.live_transactions = [self.detector.score_and_annotate(row) for row in seed_stream][-140:]

    def _risk_distribution(self, rows: list[dict], bins: int = 10) -> dict:
        distribution = {"legitimate": [0] * bins, "attack": [0] * bins}
        for row in rows:
            score = self.detector.score(row)
            index = min(bins - 1, int(score * bins))
            distribution["attack" if row.get("label") else "legitimate"][index] += 1
        return distribution

    def _history_point(self, name: str, metrics: dict, rows: list[dict]) -> dict:
        detected_ids = {
            row.get("attack_id") for row in rows
            if row.get("label") == 1 and self.detector.predict(row) == 1 and row.get("attack_id")
        }
        return {
            "cycle": len(self.history) + 1,
            "name": name,
            "f1": metrics["f1"],
            "recall": metrics["recall"],
            "precision": metrics["precision"],
            "fpr": metrics["false_positive_rate"],
            "attack_coverage": len(detected_ids),
        }

    def _attack_performance(self) -> list[dict]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for row in self.live_transactions:
            if row.get("attack_id"):
                groups[row["attack_id"]].append(row)
        performance = []
        for attack in ATTACKS:
            rows = groups.get(attack.id, [])
            detected = sum(row.get("decision") != "approve" for row in rows)
            performance.append({
                "attack_id": attack.id,
                "name": attack.name,
                "family": attack.family,
                "samples": len(rows),
                "detection_rate": round(detected / len(rows), 3) if rows else None,
                "mean_risk": round(sum(row.get("risk_score", 0) for row in rows) / len(rows), 3) if rows else None,
            })
        return performance

    def overview(self) -> dict:
        with self.lock:
            decisions = Counter(row.get("decision") for row in self.live_transactions)
            attack_mix = Counter(row.get("attack_name") for row in self.live_transactions if row.get("attack_name"))
            high_risk = [row for row in self.live_transactions if row.get("decision") in {"review", "decline"}]
            detected_attack_ids = {row.get("attack_id") for row in high_risk if row.get("attack_id")}
            return {
                "product": "MasterShield AI",
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "cycle": self.cycle,
                "metrics": self.metrics,
                "validation_reports": self.validation_reports,
                "history": self.history,
                "catalog_size": len(ATTACKS),
                "detected_attack_coverage": len(detected_attack_ids),
                "training_rows": len(self.training_rows),
                "stream_size": len(self.live_transactions),
                "feedback_queue_size": len(self.feedback_rows),
                "feedback_buckets": self._feedback_bucket_counts(),
                "simulation_history": list(self.simulation_history[-10:]),
                "policy_tradeoff": self.policy.tradeoff(self.immutable_holdout_rows, self.detector),
                "decisions": dict(decisions),
                "attack_mix": [{"name": name, "count": count} for name, count in attack_mix.most_common(7)],
                "feature_importance": self.detector.feature_importance(),
                "attack_performance": self._attack_performance(),
                "recent_transactions": list(reversed(self.live_transactions[-24:])),
                "validation": {
                    "sample_count": len(self.immutable_holdout_rows),
                    "risk_distribution": self._risk_distribution(self.immutable_holdout_rows),
                    "synthetic_evidence": True,
                },
                "system": {
                    "red_team": "online",
                    "simulator": "online",
                    "detector": "online",
                    "feedback_loop": "armed",
                    "latency_ms_p95": self._p95_latency(),
                    "model_version": f"hybrid-logit-c{self.cycle}",
                },
            }

    def attacks(self) -> list[dict]:
        with self.lock:
            performance = {item["attack_id"]: item for item in self._attack_performance()}
            rows = []
            for attack in catalog():
                attack.update({
                    "samples": performance[attack["id"]]["samples"],
                    "detection_rate": performance[attack["id"]]["detection_rate"],
                    "mean_risk": performance[attack["id"]]["mean_risk"],
                })
                rows.append(attack)
            return rows

    def transactions(self, limit: int = 100) -> list[dict]:
        with self.lock:
            limit = max(0, min(int(limit), 500))
            return list(reversed(self.live_transactions[-limit:])) if limit else []

    def simulate(self, attack_ids: list[str], count: int = 80, intensity: float = 1.0) -> dict:
        with self.lock:
            valid_ids = [attack_id for attack_id in attack_ids if attack_id in ATTACK_BY_ID]
            invalid_ids = [attack_id for attack_id in attack_ids if attack_id not in ATTACK_BY_ID]
            if invalid_ids:
                raise ValueError(f"Unknown attack IDs: {', '.join(invalid_ids)}")
            count = max(5, min(int(count), 500))
            intensity = max(0.35, min(float(intensity), 1.4))
            rows = self.generator.generate_attacks(count, valid_ids or None, intensity)
            control_count = max(5, count // 5)
            controls = self.generator.generate_legitimate(control_count)
            annotated_attacks = [self.detector.score_and_annotate(row) for row in rows]
            annotated_controls = [self.detector.score_and_annotate(row) for row in controls]
            for row in annotated_attacks + annotated_controls:
                self.latencies_ms.append(float(row.get("scoring_latency_ms", 0.0)))
            self.live_transactions.extend(annotated_attacks + annotated_controls)
            self.live_transactions = self.live_transactions[-500:]
            detected = [row for row in annotated_attacks if row["decision"] != "approve"]
            missed = [row for row in annotated_attacks if row["decision"] == "approve"]
            false_positives = [row for row in annotated_controls if row["decision"] != "approve"]
            for row in missed:
                self._queue_feedback(row, "missed_attack")
            for row in false_positives:
                self._queue_feedback(row, "false_positive")
            for row in detected:
                self._queue_feedback(row, "correct_detection")
            # Keep the legacy count compatible with the original demo while exposing typed buckets.
            self.feedback_rows.extend(rows)
            result = {
                "run_id": f"sim-{self.cycle}-{len(self.simulation_history) + 1:05d}",
                "scenario_stats": scenario_stats(rows),
                "generated": count,
                "controls": control_count,
                "detected": len(detected),
                "missed": len(missed),
                "false_positives": len(false_positives),
                "detection_rate": round(len(detected) / max(1, count), 4),
                "mean_risk": round(sum(row["risk_score"] for row in annotated_attacks) / max(1, count), 4),
                "feedback_ready": len(self.feedback_rows),
                "feedback_buckets": self._feedback_bucket_counts(),
                "sample": list(reversed(annotated_attacks[-12:])),
            }
            self.simulation_history.append({key: result[key] for key in ("run_id", "generated", "controls", "detected", "missed", "false_positives", "detection_rate", "mean_risk", "feedback_ready")})
            self.store.append("simulations", result)
            self.store.append("audit", {"event": "simulation", "run_id": result["run_id"], "cycle": self.cycle})
            return result

    def retrain(self) -> dict:
        with self.lock:
            feedback = list(self.feedback_rows)
            if not feedback:
                feedback = self.generator.generate_attacks(180, intensity=1.08)
            annotated = [self.detector.score_and_annotate(row) for row in feedback]
            hard = [row for row in feedback if self.detector.predict(row) == 0]
            # All simulated attacks are retained, while missed attacks receive extra weight.
            augmentation = feedback + hard * 2 + self.generator.generate_legitimate(max(280, len(feedback)))
            max_training = 7000
            self.training_rows = (self.training_rows + augmentation)[-max_training:]
            random.Random(self.seed + self.cycle).shuffle(self.training_rows)
            calibration = self.generator.generate_mixed(850, attack_rate=0.27, intensity=1.0)
            evaluation = self.generator.generate_mixed(1250, attack_rate=0.25, intensity=1.04)
            previous = self.detector.evaluate(evaluation)
            self.detector.fit(self.training_rows)
            self.detector.calibrate(calibration)
            self.metrics = self.detector.evaluate(evaluation)
            self.rolling_validation_rows = list(evaluation)
            self.cycle += 1
            self.history.append(self._history_point("Feedback retrain", self.metrics, evaluation))
            self.validation_reports = self._validation_report()
            self.store.append("models", {"cycle": self.cycle, "metrics": self.metrics, "training_rows": len(self.training_rows)})
            self.store.append("audit", {"event": "retrain", "cycle": self.cycle, "feedback_rows": len(feedback)})
            self.feedback_rows.clear()
            self.feedback_records.clear()
            # Rescore the live stream with the latest model for a consistent dashboard.
            self.live_transactions = [self.detector.score_and_annotate(row) for row in self.live_transactions]
            return {
                "cycle": self.cycle,
                "feedback_rows": len(feedback),
                "hard_cases": len(hard),
                "previous_metrics": previous,
                "metrics": self.metrics,
                "deltas": {
                    key: round(self.metrics.get(key, 0) - previous.get(key, 0), 4)
                    for key in ("precision", "recall", "f1", "auc", "false_positive_rate")
                },
                "fit": {
                    "epochs": self.detector.fit_summary.epochs,
                    "training_rows": self.detector.fit_summary.training_rows,
                    "loss": round(self.detector.fit_summary.final_loss, 5),
                },
                "validation_reports": self.validation_reports,
            }

    def score_transaction(self, transaction: dict) -> dict:
        with self.lock:
            self._validate_transaction(transaction)
            started = time.perf_counter()
            result = self.detector.score_and_annotate(transaction)
            result["policy"] = self.policy.decide(result, result["risk_score"]).to_dict()
            self.latencies_ms.append((time.perf_counter() - started) * 1000)
            self.store.append("audit", {"event": "score", "transaction_id": result.get("id"), "decision": result.get("decision")})
            return result

    def mutate_transaction(self, transaction_id: str | None = None, attack_id: str | None = None, count: int = 24) -> dict:
        with self.lock:
            row = next((item for item in reversed(self.live_transactions) if item.get("id") == transaction_id), None) if transaction_id else None
            if row is None and attack_id:
                generated = self.generator.generate_attacks(1, [attack_id], intensity=0.92)
                row = self.detector.score_and_annotate(generated[0])
            if row is None:
                row = next((item for item in reversed(self.live_transactions) if item.get("attack_id")), None)
            if row is None:
                raise ValueError("No synthetic attack transaction is available to mutate")
            return self.attacker.search(row, self.detector.score, self.detector.predict, count=count)

    def fidelity(self) -> dict:
        with self.lock:
            reference = self.generator.generate_mixed(420, attack_rate=0.22, intensity=0.92)
            candidate = self.generator.generate_mixed(420, attack_rate=0.22, intensity=1.04)
            report = compare_streams(reference, candidate)
            report["robustness"] = robustness_report(self.detector, self.generator, self.seed)
            report["policy_tradeoff"] = self.policy.tradeoff(self.immutable_holdout_rows, self.detector)
            return report

    def submit_feedback(self, transaction_id: str, outcome: str, note: str = "") -> dict:
        allowed = {"confirmed_fraud", "confirmed_legitimate", "uncertain"}
        if outcome not in allowed:
            raise ValueError(f"outcome must be one of: {', '.join(sorted(allowed))}")
        with self.lock:
            row = next((item for item in self.live_transactions if item.get("id") == transaction_id), None)
            if row is None:
                raise ValueError("Transaction not found")
            feedback = {"transaction_id": transaction_id, "outcome": outcome, "note": str(note)[:500], "row": dict(row)}
            self.feedback_records.append(feedback)
            self.store.append("feedback", feedback)
            self.store.append("audit", {"event": "feedback", "transaction_id": transaction_id, "outcome": outcome})
            return feedback

    def report(self) -> dict:
        with self.lock:
            return {"synthetic_evidence": True, "cycle": self.cycle, "metrics": self.metrics, "validation": self.validation_reports, "fidelity": self.fidelity(), "simulations": list(self.simulation_history), "feedback": self._feedback_bucket_counts()}

    def _queue_feedback(self, row: dict, category: str) -> None:
        item = {"category": category, "transaction_id": row.get("id"), "row": dict(row)}
        self.feedback_records.append(item)
        self.store.append("feedback", item)

    def _feedback_bucket_counts(self) -> dict:
        counts = Counter(item.get("category", item.get("outcome", "uncertain")) for item in self.feedback_records)
        return {key: counts.get(key, 0) for key in ("missed_attack", "false_positive", "correct_detection", "confirmed_fraud", "confirmed_legitimate", "uncertain")}

    def _p95_latency(self) -> float:
        values = sorted(self.latencies_ms[-1000:])
        if not values:
            return 0.0
        return round(values[min(len(values) - 1, int(len(values) * 0.95))], 3)

    def _validation_report(self, include_robustness: bool = True) -> dict:
        robust = robustness_report(self.detector, self.generator, self.seed) if include_robustness else {"status": "available via fidelity endpoint"}
        labels = [int(row.get("label", 0)) for row in self.immutable_holdout_rows]
        hybrid_scores = [self.detector.score(row) for row in self.immutable_holdout_rows]
        logistic_scores = [self.detector.model_score(row) for row in self.immutable_holdout_rows]
        rule_scores = [self.detector.expert_score(row) for row in self.immutable_holdout_rows]
        return {
            "synthetic_evidence": True,
            "immutable_holdout": {"rows": len(self.immutable_holdout_rows), "metrics": self.detector.evaluate(self.immutable_holdout_rows)},
            "baselines": {
                "rules_only": classification_metrics(labels, rule_scores, self.detector.threshold),
                "logistic_only": classification_metrics(labels, logistic_scores, self.detector.threshold),
                "hybrid": classification_metrics(labels, hybrid_scores, self.detector.threshold),
            },
            "segments": self._segment_metrics(self.immutable_holdout_rows),
            "robustness": robust,
        }

    def _segment_metrics(self, rows: list[dict]) -> dict:
        segments: dict[str, dict[str, list[dict]]] = {"rail": defaultdict(list), "attack_family": defaultdict(list)}
        for row in rows:
            segments["rail"][str(row.get("rail", "unknown"))].append(row)
            segments["attack_family"][str(row.get("attack_family", "legitimate"))].append(row)
        result = {}
        for group, buckets in segments.items():
            result[group] = {}
            for name, bucket in buckets.items():
                result[group][name] = self.detector.evaluate(bucket)
        return result

    @staticmethod
    def _validate_transaction(transaction: dict) -> None:
        required = ("amount", "currency", "rail", "channel", "account_age_days", "device_age_days")
        missing = [field for field in required if field not in transaction]
        if missing:
            raise ValueError(f"Missing required transaction fields: {', '.join(missing)}")
        if not isinstance(transaction.get("rail"), str) or not isinstance(transaction.get("channel"), str):
            raise ValueError("rail and channel must be strings")
        try:
            amount = float(transaction["amount"])
        except (TypeError, ValueError) as exc:
            raise ValueError("amount must be numeric") from exc
        if not math.isfinite(amount) or amount < 0 or amount > 1_000_000:
            raise ValueError("amount must be finite and between 0 and 1000000")
