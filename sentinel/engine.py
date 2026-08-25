"""Closed-loop orchestration for red-team generation and blue-team defense."""

from __future__ import annotations

import random
import threading
import os
import time
import math
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .generator import SyntheticGenerator, scenario_stats
from .attacker import AdaptiveAttacker
from .fidelity import compare_streams, robustness_report
from .governance import PromotionGates
from .model import HybridFraudDetector, classification_metrics
from .policy import RiskPolicy
from .quality import assess_dataset
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
        self.score_sequence = 0
        self.model_versions: list[dict] = []
        self.model_snapshots: dict[str, dict] = {}
        self.active_model_version: str | None = None
        self.previous_model_version: str | None = None
        self.mutation_history: list[dict] = []
        self.governance = PromotionGates()
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
        version = self._next_model_version()
        self.active_model_version = version
        self._register_model({
            "version": version,
            "cycle": self.cycle,
            "status": "ACTIVE",
            "created_at": self._now(),
            "dataset_version": self._dataset_version(self.training_rows),
            "training_rows": len(self.training_rows),
            "feedback_rows": 0,
            "duration_ms": 0.0,
            "immutable_holdout_metrics": self.metrics,
            "rolling_metrics": {},
            "robustness": self.validation_reports.get("robustness", {}),
            "gate_results": {"passed": True, "checks": {"bootstrap": True}},
            "previous_model_version": None,
        }, self.detector.export_state())

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _next_model_version(self) -> str:
        return f"hybrid-logit-c{self.cycle}-v{len(self.model_versions) + 1:03d}"

    @staticmethod
    def _dataset_version(rows: list[dict]) -> str:
        digest = hashlib.sha256()
        for row in sorted(rows, key=lambda item: str(item.get("id", ""))):
            digest.update(str(row.get("id", "")).encode("utf-8"))
            digest.update(str(int(row.get("label", 0))).encode("ascii"))
        return digest.hexdigest()[:16]

    def _register_model(self, metadata: dict, snapshot: dict | None = None) -> dict:
        item = dict(metadata)
        item.setdefault("synthetic_evidence", True)
        self.model_versions.append(item)
        if snapshot is not None:
            self.model_snapshots[item["version"]] = snapshot
        self.store.append("models", item)
        return item

    def models(self) -> list[dict]:
        with self.lock:
            return [dict(item) for item in reversed(self.model_versions)]

    def audit(self, limit: int = 100) -> list[dict]:
        with self.lock:
            return self.store.list("audit", limit)

    def rollback_model(self, model_version: str) -> dict:
        with self.lock:
            if model_version not in self.model_snapshots:
                raise ValueError("Model version is unavailable for rollback")
            metadata = next((item for item in self.model_versions if item.get("version") == model_version), None)
            if metadata and metadata.get("status") == "REJECTED":
                raise ValueError("Rejected model versions cannot be rolled back into service")
            if model_version == self.active_model_version:
                return {"status": "unchanged", "model_version": model_version, "cycle": self.cycle}
            previous = self.active_model_version
            self.detector.load_state(self.model_snapshots[model_version])
            self.previous_model_version = previous
            self.active_model_version = model_version
            for item in self.model_versions:
                if item["version"] == previous:
                    item["status"] = "ROLLED_BACK"
                elif item["version"] == model_version:
                    item["status"] = "ACTIVE"
            self.metrics = self.detector.evaluate(self.immutable_holdout_rows)
            self.validation_reports = self._validation_report(self.detector, include_robustness=False)
            self.live_transactions = [self.detector.score_and_annotate(row) for row in self.live_transactions]
            result = {
                "status": "rolled_back",
                "model_version": model_version,
                "previous_model_version": previous,
                "cycle": self.cycle,
                "metrics": self.metrics,
                "synthetic_evidence": True,
            }
            self.store.append("audit", {"event": "model_rollback", **result})
            return result

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
                "model_versions": self.models(),
                "active_model_version": self.active_model_version,
                "data_quality": {
                    "training": assess_dataset(self.training_rows, self.immutable_holdout_rows),
                    "immutable_holdout": assess_dataset(self.immutable_holdout_rows),
                    "rolling_validation": assess_dataset(self.rolling_validation_rows, self.immutable_holdout_rows) if self.rolling_validation_rows else None,
                },
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
                    "model_version": self.active_model_version or f"hybrid-logit-c{self.cycle}",
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
                    "last_evaluated_model_version": self.active_model_version,
                })
                rows.append(attack)
            return rows

    def transactions(self, limit: int = 100) -> list[dict]:
        with self.lock:
            limit = max(0, min(int(limit), 500))
            return list(reversed(self.live_transactions[-limit:])) if limit else []

    def simulations(self, limit: int = 100) -> list[dict]:
        with self.lock:
            limit = max(0, min(int(limit), 500))
            return list(reversed(self.simulation_history[-limit:])) if limit else []

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
                "control_sample": annotated_controls[-1] if annotated_controls else None,
            }
            self.simulation_history.append({key: result[key] for key in ("run_id", "generated", "controls", "detected", "missed", "false_positives", "detection_rate", "mean_risk", "feedback_ready")})
            self.store.append("simulations", result)
            self.store.append("audit", {"event": "simulation", "run_id": result["run_id"], "cycle": self.cycle})
            return result

    def retrain(self, confirm: bool = False) -> dict:
        with self.lock:
            started = time.perf_counter()
            queued = list(self.feedback_rows)
            queued_ids = {str(row.get("id")) for row in queued if row.get("id")}
            # Analyst-confirmed outcomes are archived in feedback_records. Include them
            # explicitly in the challenger dataset even when a caller populated the
            # queue through a persistence-backed feedback workflow.
            analyst_rows = []
            for item in self.feedback_records:
                outcome = item.get("outcome")
                row = item.get("row")
                if outcome not in {"confirmed_fraud", "confirmed_legitimate"} or not isinstance(row, dict) or item.get("training_cycle") is not None:
                    continue
                if str(row.get("id") or item.get("transaction_id")) in queued_ids:
                    continue
                copy = dict(row)
                copy["label"] = int(outcome == "confirmed_fraud")
                analyst_rows.append(copy)
            feedback = queued + analyst_rows
            if not feedback:
                feedback = self.generator.generate_attacks(180, intensity=1.08)
            hard = [row for row in feedback if self.detector.predict(row) == 0]
            augmentation = feedback + hard * 2 + self.generator.generate_legitimate(max(280, len(feedback)))
            max_training = 7000
            candidate_training = list((self.training_rows + augmentation)[-max_training:])
            random.Random(self.seed + self.cycle).shuffle(candidate_training)
            calibration = self.generator.generate_mixed(850, attack_rate=0.27, intensity=1.0)
            evaluation = self.generator.generate_mixed(1250, attack_rate=0.25, intensity=1.04)
            previous = self.detector.evaluate(self.immutable_holdout_rows)
            challenger = self.detector.clone()
            challenger.fit(candidate_training)
            challenger.calibrate(calibration)
            rolling_metrics = challenger.evaluate(evaluation)
            candidate_metrics = challenger.evaluate(self.immutable_holdout_rows)
            candidate_validation = self._validation_report(challenger, rolling_rows=evaluation)
            gates = self.governance.evaluate(previous, candidate_metrics, candidate_validation.get("robustness", {}))
            next_cycle = self.cycle + 1
            candidate_version = f"hybrid-logit-c{next_cycle}-v{len(self.model_versions) + 1:03d}"
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            candidate_metadata = {
                "version": candidate_version,
                "cycle": next_cycle,
                "status": "ACTIVE" if gates["passed"] else "REJECTED",
                "created_at": self._now(),
                "dataset_version": self._dataset_version(candidate_training),
                "training_rows": len(candidate_training),
                "feedback_rows": len(feedback),
                "duration_ms": duration_ms,
                "immutable_holdout_metrics": candidate_metrics,
                "rolling_metrics": rolling_metrics,
                "robustness": candidate_validation.get("robustness", {}),
                "gate_results": gates,
                "previous_model_version": self.active_model_version,
            }
            self._register_model(candidate_metadata, challenger.export_state())
            self.cycle = next_cycle
            accepted = bool(gates["passed"])
            if accepted:
                old_version = self.active_model_version
                self.previous_model_version = old_version
                self.active_model_version = candidate_version
                self.detector = challenger
                self.training_rows = candidate_training
                self.metrics = candidate_metrics
                self.rolling_validation_rows = list(evaluation)
                self.validation_reports = candidate_validation
                for item in self.model_versions:
                    if item["version"] == old_version:
                        item["status"] = "APPROVED"
                self.history.append(self._history_point("Feedback retrain", self.metrics, self.immutable_holdout_rows))
                self.live_transactions = [self.detector.score_and_annotate(row) for row in self.live_transactions]
            # The queue is consumed by this candidate decision, while feedback_records
            # remains an immutable analyst/audit trail for future review.
            consumed = len(self.feedback_rows)
            self.feedback_rows.clear()
            for item in self.feedback_records:
                if item.get("outcome") in {"confirmed_fraud", "confirmed_legitimate"} and item.get("training_cycle") is None:
                    item["training_cycle"] = self.cycle
            result = {
                "cycle": self.cycle,
                "duration_ms": duration_ms,
                "feedback_rows": len(feedback),
                "hard_cases": len(hard),
                "accepted": accepted,
                "model_version": self.active_model_version,
                "previous_model_version": self.previous_model_version,
                "candidate_model_version": candidate_version,
                "previous_metrics": previous,
                "metrics": self.metrics,
                "candidate_metrics": candidate_metrics,
                "rolling_metrics": rolling_metrics,
                "deltas": {key: round(self.metrics.get(key, 0) - previous.get(key, 0), 4) for key in ("precision", "recall", "f1", "auc", "false_positive_rate")},
                "fit": {
                    "epochs": challenger.fit_summary.epochs,
                    "training_rows": challenger.fit_summary.training_rows,
                    "loss": round(challenger.fit_summary.final_loss, 5),
                },
                "validation_reports": self.validation_reports if accepted else candidate_validation,
                "promotion_gates": gates,
                "queue_consumed": consumed,
                "synthetic_evidence": True,
            }
            self.store.append("audit", {"event": "retrain", "cycle": self.cycle, "feedback_rows": len(feedback), "accepted": accepted, "model_version": candidate_version})
            return result

    def score_transaction(self, transaction: dict) -> dict:
        with self.lock:
            self._validate_transaction(transaction)
            started = time.perf_counter()
            result = self.detector.score_and_annotate(transaction)
            if not result.get("id"):
                self.score_sequence += 1
                result["id"] = f"score-{self.cycle}-{self.score_sequence:06d}"
            result["policy"] = self.policy.decide(result, result["risk_score"]).to_dict()
            self.latencies_ms.append((time.perf_counter() - started) * 1000)
            existing_index = next((index for index, item in enumerate(self.live_transactions) if item.get("id") == result["id"]), None)
            if existing_index is None:
                self.live_transactions.append(result)
            else:
                self.live_transactions[existing_index] = result
            self.live_transactions = self.live_transactions[-500:]
            self.store.append("audit", {"event": "score", "transaction_id": result.get("id"), "decision": result.get("decision")})
            return result

    def mutate_transaction(self, transaction_id: str | None = None, attack_id: str | None = None, count: int = 24) -> dict:
        with self.lock:
            row = None
            if transaction_id is not None:
                row = next((item for item in reversed(self.live_transactions) if item.get("id") == transaction_id), None)
                if row is None:
                    raise ValueError("Transaction not found")
            if attack_id is not None and attack_id not in ATTACK_BY_ID:
                raise ValueError(f"Unknown attack ID: {attack_id}")
            if row is None and attack_id is not None:
                generated = self.generator.generate_attacks(1, [attack_id], intensity=0.92)
                row = self.detector.score_and_annotate(generated[0])
            if row is None:
                row = next((item for item in reversed(self.live_transactions) if item.get("attack_id")), None)
            if row is None:
                raise ValueError("No synthetic attack transaction is available to mutate")
            result = self.attacker.search(row, self.detector.score, self.detector.predict, count=count)
            result["cycle"] = self.cycle
            result["model_version"] = self.active_model_version
            self.mutation_history.append(result)
            self.store.append("audit", {"event": "mutation_search", "cycle": self.cycle, "model_version": self.active_model_version, "candidate_count": result["candidate_count"], "blind_spots": result["blind_spots"]})
            return result

    def fidelity(self) -> dict:
        with self.lock:
            generator = self._evaluation_generator("fidelity")
            reference = generator.generate_mixed(420, attack_rate=0.22, intensity=0.92)
            candidate = generator.generate_mixed(420, attack_rate=0.22, intensity=1.04)
            report = compare_streams(reference, candidate)
            report["robustness"] = robustness_report(self.detector, self._evaluation_generator("fidelity-robustness"), self.seed)
            report["policy_tradeoff"] = self.policy.tradeoff(self.immutable_holdout_rows, self.detector)
            report["model_version"] = self.active_model_version
            report["measured_scoring_latency_ms_p95"] = self._p95_latency()
            return report

    def submit_feedback(self, transaction_id: str, outcome: str, note: str = "", override_decision: str | None = None) -> dict:
        allowed = {"confirmed_fraud", "confirmed_legitimate", "uncertain"}
        if outcome not in allowed:
            raise ValueError(f"outcome must be one of: {', '.join(sorted(allowed))}")
        with self.lock:
            row = next((item for item in self.live_transactions if item.get("id") == transaction_id), None)
            if row is None:
                raise ValueError("Transaction not found")
            queued_for_retraining = outcome in {"confirmed_fraud", "confirmed_legitimate"}
            feedback = {
                "transaction_id": transaction_id,
                "outcome": outcome,
                "note": str(note)[:500],
                "row": dict(row),
                "queued_for_retraining": queued_for_retraining,
            }
            if override_decision is not None:
                feedback["override_decision"] = override_decision
            self.feedback_records.append(feedback)
            if queued_for_retraining:
                training_row = dict(row)
                training_row["label"] = int(outcome == "confirmed_fraud")
                self.feedback_rows.append(training_row)
            self.store.append("feedback", feedback)
            self.store.append("audit", {"event": "feedback", "transaction_id": transaction_id, "outcome": outcome})
            return feedback

    def report(self) -> dict:
        with self.lock:
            fraud_rows = [row for row in self.live_transactions if row.get("label") == 1]
            return {
                "synthetic_evidence": True,
                "generated_at": self._now(),
                "executive_summary": {
                    "active_model_version": self.active_model_version,
                    "cycle": self.cycle,
                    "attack_catalog_size": len(ATTACKS),
                    "stream_rows": len(self.live_transactions),
                    "fraud_rows_in_stream": len(fraud_rows),
                    "limitations": "Synthetic evidence only; no production performance claim.",
                },
                "cycle": self.cycle,
                "metrics": self.metrics,
                "validation": self.validation_reports,
                "fidelity": self.fidelity(),
                "simulations": list(self.simulation_history),
                "feedback": self._feedback_bucket_counts(),
                "model_history": self.models(),
                "data_quality": {
                    "training": assess_dataset(self.training_rows, self.immutable_holdout_rows),
                    "immutable_holdout": assess_dataset(self.immutable_holdout_rows),
                },
                "mutations": list(self.mutation_history[-20:]),
                "policy_tradeoff": self.policy.tradeoff(self.immutable_holdout_rows, self.detector),
                "recommendations": ["Replay confirmed outcomes by rail and attack family before production promotion.", "Shadow policy actions and measure customer friction against observed loss."],
                "limitations": ["All transactions and metrics are synthetic evidence.", "Production deployment requires tokenized event adapters, durable storage, access control, and human review."],
            }

    def _queue_feedback(self, row: dict, category: str) -> None:
        item = {"category": category, "transaction_id": row.get("id"), "row": dict(row)}
        self.feedback_records.append(item)
        self.store.append("feedback", item)

    def _feedback_bucket_counts(self) -> dict:
        counts = Counter(item.get("category", item.get("outcome", "uncertain")) for item in self.feedback_records)
        return {key: counts.get(key, 0) for key in ("missed_attack", "false_positive", "correct_detection", "confirmed_fraud", "confirmed_legitimate", "uncertain")}

    def feedback_queue(self, limit: int = 100) -> list[dict]:
        with self.lock:
            bounded = max(0, min(int(limit), 500))
            if bounded == 0:
                return []
            # The UI badge reports feedback_rows, which is the exact set consumed
            # by retraining. Return that same queue here rather than the broader
            # feedback audit history, otherwise the badge and dialog can disagree.
            if self.feedback_rows:
                categories = {
                    str(item.get("transaction_id")): item.get("category", item.get("outcome"))
                    for item in self.feedback_records
                    if item.get("transaction_id")
                }
                queued = []
                for row in reversed(self.feedback_rows[-bounded:]):
                    item = {"transaction_id": row.get("id"), "row": dict(row)}
                    category = categories.get(str(row.get("id")))
                    if category:
                        item["category"] = category
                    queued.append(item)
                return queued
            return [item.get("payload", item) for item in self.store.list("feedback", bounded)]

    def _p95_latency(self) -> float:
        values = sorted(self.latencies_ms[-1000:])
        if not values:
            return 0.0
        return round(values[max(0, math.ceil(len(values) * 0.95) - 1)], 3)

    def _evaluation_generator(self, purpose: str) -> SyntheticGenerator:
        material = f"{self.seed}:{self.cycle}:{purpose}".encode("utf-8")
        derived_seed = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
        return SyntheticGenerator(derived_seed)

    def _validation_report(self, detector=None, rolling_rows: list[dict] | None = None, include_robustness: bool = True) -> dict:
        detector = detector or self.detector
        robust = robustness_report(detector, self._evaluation_generator("validation-robustness"), self.seed) if include_robustness else {"status": "available via fidelity endpoint"}
        labels = [int(row.get("label", 0)) for row in self.immutable_holdout_rows]
        hybrid_scores = [detector.score(row) for row in self.immutable_holdout_rows]
        logistic_scores = [detector.model_score(row) for row in self.immutable_holdout_rows]
        rule_scores = [detector.expert_score(row) for row in self.immutable_holdout_rows]
        threshold = detector.threshold
        return {
            "synthetic_evidence": True,
            "immutable_holdout": {"rows": len(self.immutable_holdout_rows), "metrics": detector.evaluate(self.immutable_holdout_rows)},
            "time_split": {"rows": len(rolling_rows or self.rolling_validation_rows), "metrics": detector.evaluate(rolling_rows or self.rolling_validation_rows) if (rolling_rows or self.rolling_validation_rows) else {}},
            "baselines": {
                "rules_only": classification_metrics(labels, rule_scores, threshold),
                "logistic_only": classification_metrics(labels, logistic_scores, threshold),
                "hybrid": classification_metrics(labels, hybrid_scores, threshold),
            },
            "segments": self._segment_metrics(self.immutable_holdout_rows, detector),
            "leave_one_family_out": self._leave_one_family_out_report(detector),
            "robustness": robust,
            "data_quality": {"holdout": assess_dataset(self.immutable_holdout_rows), "rolling": assess_dataset(rolling_rows or self.rolling_validation_rows, self.immutable_holdout_rows) if (rolling_rows or self.rolling_validation_rows) else None},
        }

    def _segment_metrics(self, rows: list[dict], detector=None) -> dict:
        detector = detector or self.detector
        segments: dict[str, dict[str, list[dict]]] = {"rail": defaultdict(list), "attack_family": defaultdict(list)}
        for row in rows:
            segments["rail"][str(row.get("rail", "unknown"))].append(row)
            segments["attack_family"][str(row.get("attack_family", "legitimate"))].append(row)
        result = {}
        for group, buckets in segments.items():
            result[group] = {}
            for name, bucket in buckets.items():
                result[group][name] = detector.evaluate(bucket)
        return result

    def _leave_one_family_out_report(self, detector) -> dict:
        """Measure candidate recall on each labeled family without retraining on it."""
        groups: dict[str, list[dict]] = defaultdict(list)
        for row in self.immutable_holdout_rows:
            if row.get("label") == 1:
                groups[str(row.get("attack_family", "unknown"))].append(row)
        metrics = {family: detector.evaluate(rows) for family, rows in groups.items() if rows}
        recalls = [item.get("recall", 0.0) for item in metrics.values()]
        return {"synthetic_evidence": True, "families": metrics, "mean_family_recall": round(sum(recalls) / max(1, len(recalls)), 4), "minimum_family_recall": round(min(recalls), 4) if recalls else 0.0}

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
