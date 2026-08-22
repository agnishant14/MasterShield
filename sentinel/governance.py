"""Model promotion gates and lifecycle metadata for challenger evaluation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromotionGates:
    min_f1: float = 0.90
    min_recall: float = 0.90
    max_false_positive_rate: float = 0.035
    max_f1_regression: float = 0.01
    max_recall_regression: float = 0.02
    min_unknown_attack_recall: float = 0.75

    def evaluate(self, current: dict, candidate: dict, robustness: dict) -> dict:
        unknown_recall = float(robustness.get("unseen_attack_families", {}).get("attack_recall", 0.0))
        checks = {
            "minimum_f1": float(candidate.get("f1", 0.0)) >= self.min_f1,
            "minimum_recall": float(candidate.get("recall", 0.0)) >= self.min_recall,
            "false_positive_guardrail": float(candidate.get("false_positive_rate", 1.0)) <= self.max_false_positive_rate,
            "f1_regression_guardrail": float(candidate.get("f1", 0.0)) >= float(current.get("f1", 0.0)) - self.max_f1_regression,
            "recall_regression_guardrail": float(candidate.get("recall", 0.0)) >= float(current.get("recall", 0.0)) - self.max_recall_regression,
            "unknown_attack_recall": unknown_recall >= self.min_unknown_attack_recall,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "thresholds": {
                "min_f1": self.min_f1,
                "min_recall": self.min_recall,
                "max_false_positive_rate": self.max_false_positive_rate,
                "max_f1_regression": self.max_f1_regression,
                "max_recall_regression": self.max_recall_regression,
                "min_unknown_attack_recall": self.min_unknown_attack_recall,
            },
            "observed_unknown_attack_recall": round(unknown_recall, 4),
        }
