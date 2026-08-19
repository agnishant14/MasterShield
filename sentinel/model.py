"""Dependency-free weighted logistic detector with calibration and explanations."""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass

from .features import FEATURE_LABELS, FEATURES, vectorize


def _sigmoid(value: float) -> float:
    value = max(-35.0, min(35.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def classification_metrics(labels: list[int], scores: list[float], threshold: float, include_curves: bool = True) -> dict:
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores):
        pred = int(score >= threshold)
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / max(1, len(labels))
    fpr = fp / (fp + tn) if fp + tn else 0.0
    auc = roc_auc(labels, scores)
    pr_auc = precision_recall_auc(labels, scores) if include_curves else 0.0
    brier = sum((score - label) ** 2 for label, score in zip(labels, scores)) / max(1, len(labels)) if include_curves else 0.0
    recall_at_fpr = recall_at_false_positive_rate(labels, scores, 0.035) if include_curves else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "auc": round(auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score": round(brier, 4),
        "recall_at_fpr_3_5": round(recall_at_fpr, 4),
        "accuracy": round(accuracy, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(fpr, 4),
        "threshold": round(threshold, 3),
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def precision_recall_auc(labels: list[int], scores: list[float]) -> float:
    """Compute trapezoidal PR-AUC in O(n log n) over ranked scores.

    The previous implementation rebuilt a prediction vector for every distinct
    threshold, which made retrain validation quadratic in the holdout size.
    Equal-score rows are evaluated as one threshold step, preserving the curve
    semantics while keeping the endpoint responsive on ordinary hardware.
    """
    if not labels or len(labels) != len(scores) or not any(labels):
        return 0.0
    positives = sum(labels)
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    points = [(0.0, 1.0)]
    true_positives = false_positives = 0
    index = 0
    while index < len(ranked):
        threshold = ranked[index][0]
        end = index
        while end < len(ranked) and ranked[end][0] == threshold:
            if ranked[end][1]:
                true_positives += 1
            else:
                false_positives += 1
            end += 1
        recall = true_positives / positives
        precision = true_positives / max(1, true_positives + false_positives)
        points.append((recall, precision))
        index = end
    return round(sum((right[0] - left[0]) * (left[1] + right[1]) / 2 for left, right in zip(points, points[1:])), 8)


def recall_at_false_positive_rate(labels: list[int], scores: list[float], max_fpr: float) -> float:
    best = 0.0
    for threshold in [index / 100 for index in range(1, 100)]:
        metrics = classification_metrics_basic(labels, scores, threshold)
        if metrics["fpr"] <= max_fpr:
            best = max(best, metrics["recall"])
    return best


def classification_metrics_basic(labels: list[int], scores: list[float], threshold: float) -> dict:
    tp = fp = tn = fn = 0
    for label, score in zip(labels, scores):
        pred = int(score >= threshold)
        if label and pred:
            tp += 1
        elif not label and pred:
            fp += 1
        elif not label and not pred:
            tn += 1
        else:
            fn += 1
    return {"fpr": fp / max(1, fp + tn), "recall": tp / max(1, tp + fn)}


def roc_auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return 0.5
    ranked = sorted(zip(scores, labels), key=lambda item: item[0])
    rank_sum = 0.0
    i = 0
    while i < len(ranked):
        j = i + 1
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        rank_sum += avg_rank * sum(label for _, label in ranked[i:j])
        i = j
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


@dataclass
class FitSummary:
    epochs: int
    training_rows: int
    positive_rate: float
    final_loss: float


class HybridFraudDetector:
    """Weighted logistic model blended with a small domain-prior score.

    The learned component makes the prototype a real trainable classifier. The domain
    prior reflects how production fraud platforms combine ML with high-confidence
    controls, while keeping the total decision fully explainable.
    """

    def __init__(self, seed: int = 2026):
        self.seed = seed
        self.means = [0.0] * len(FEATURES)
        self.scales = [1.0] * len(FEATURES)
        self.weights = [0.0] * len(FEATURES)
        self.bias = 0.0
        self.threshold = 0.5
        self.fit_summary = FitSummary(0, 0, 0.0, 0.0)

    def _standardize(self, values: list[float]) -> list[float]:
        return [(value - mean) / scale for value, mean, scale in zip(values, self.means, self.scales)]

    def export_state(self) -> dict:
        """Return an internal rollback snapshot without exposing it through the API."""
        return {
            "seed": self.seed,
            "means": list(self.means),
            "scales": list(self.scales),
            "weights": list(self.weights),
            "bias": self.bias,
            "threshold": self.threshold,
            "fit_summary": {
                "epochs": self.fit_summary.epochs,
                "training_rows": self.fit_summary.training_rows,
                "positive_rate": self.fit_summary.positive_rate,
                "final_loss": self.fit_summary.final_loss,
            },
        }

    def load_state(self, state: dict) -> None:
        self.seed = int(state["seed"])
        self.means = [float(value) for value in state["means"]]
        self.scales = [float(value) for value in state["scales"]]
        self.weights = [float(value) for value in state["weights"]]
        self.bias = float(state["bias"])
        self.threshold = float(state["threshold"])
        summary = state["fit_summary"]
        self.fit_summary = FitSummary(
            int(summary["epochs"]),
            int(summary["training_rows"]),
            float(summary["positive_rate"]),
            float(summary["final_loss"]),
        )

    def clone(self) -> "HybridFraudDetector":
        clone = HybridFraudDetector(self.seed)
        clone.load_state(self.export_state())
        return clone

    def fit(self, rows: list[dict], epochs: int = 105, learning_rate: float = 0.055, l2: float = 0.018) -> FitSummary:
        if not rows:
            raise ValueError("Training requires at least one row")
        matrix = [vectorize(row) for row in rows]
        labels = [int(row.get("label", 0)) for row in rows]
        n = len(matrix)
        d = len(FEATURES)
        self.means = [sum(row[j] for row in matrix) / n for j in range(d)]
        self.scales = []
        for j in range(d):
            variance = sum((row[j] - self.means[j]) ** 2 for row in matrix) / n
            self.scales.append(max(0.025, math.sqrt(variance)))
        x = [self._standardize(row) for row in matrix]
        self.weights = [0.0] * d
        self.bias = 0.0
        positives = max(1, sum(labels))
        negatives = max(1, n - positives)
        positive_weight = min(5.0, negatives / positives)
        order = list(range(n))
        rng = random.Random(self.seed + n)
        final_loss = 0.0
        for epoch in range(epochs):
            rng.shuffle(order)
            grad_w = [0.0] * d
            grad_b = 0.0
            loss = 0.0
            for idx in order:
                row = x[idx]
                label = labels[idx]
                score = _sigmoid(self.bias + sum(w * value for w, value in zip(self.weights, row)))
                sample_weight = positive_weight if label else 1.0
                error = (score - label) * sample_weight
                grad_b += error
                for j, value in enumerate(row):
                    grad_w[j] += error * value
                loss -= sample_weight * (label * math.log(max(score, 1e-9)) + (1 - label) * math.log(max(1 - score, 1e-9)))
            rate = learning_rate / (1.0 + epoch * 0.006)
            normalizer = sum(positive_weight if label else 1.0 for label in labels)
            self.bias -= rate * grad_b / normalizer
            for j in range(d):
                self.weights[j] -= rate * (grad_w[j] / normalizer + l2 * self.weights[j])
            final_loss = loss / normalizer
        self.fit_summary = FitSummary(epochs, n, positives / n, final_loss)
        return self.fit_summary

    def model_score(self, row: dict) -> float:
        values = self._standardize(vectorize(row))
        return _sigmoid(self.bias + sum(w * value for w, value in zip(self.weights, values)))

    def expert_score(self, row: dict) -> float:
        values = dict(zip(FEATURES, vectorize(row)))
        weighted = (
            0.16 * values["graph_mule_score"]
            + 0.12 * values["credential_reset_24h"]
            + 0.11 * values["new_payee"]
            + 0.10 * values["remote_access"]
            + 0.09 * values["auth_downgrade"]
            + 0.09 * values["prompt_pressure_score"]
            + 0.08 * values["biometric_risk"]
            + 0.08 * values["synthetic_identity_score"]
            + 0.07 * values["velocity_10m"]
            + 0.05 * values["merchant_risk"]
            + 0.05 * values["descriptor_drift"]
        )
        return min(1.0, weighted / 0.74)

    def score(self, row: dict) -> float:
        return min(1.0, max(0.0, 0.84 * self.model_score(row) + 0.16 * self.expert_score(row)))

    def predict(self, row: dict) -> int:
        return int(self.score(row) >= self.threshold)

    def calibrate(self, rows: list[dict], max_false_positive_rate: float = 0.035) -> dict:
        labels = [int(row.get("label", 0)) for row in rows]
        scores = [self.score(row) for row in rows]
        best = None
        for index in range(18, 93):
            threshold = index / 100
            metrics = classification_metrics(labels, scores, threshold, include_curves=False)
            if metrics["false_positive_rate"] <= max_false_positive_rate:
                objective = metrics["f1"] + 0.08 * metrics["recall"]
                if best is None or objective > best[0]:
                    best = (objective, threshold, metrics)
        if best is None:
            best = (0.0, 0.72, classification_metrics(labels, scores, 0.72))
        self.threshold = best[1]
        return best[2]

    def evaluate(self, rows: list[dict]) -> dict:
        labels = [int(row.get("label", 0)) for row in rows]
        scores = [self.score(row) for row in rows]
        return classification_metrics(labels, scores, self.threshold)

    def explain(self, row: dict, limit: int = 4) -> list[dict]:
        values = vectorize(row)
        standardized = self._standardize(values)
        contributions = []
        for index, (name, raw, weight, z_value) in enumerate(zip(FEATURES, values, self.weights, standardized)):
            contribution = weight * z_value
            if contribution > 0.02:
                contributions.append({
                    "feature": name,
                    "label": FEATURE_LABELS[name],
                    "value": round(raw, 3),
                    "baseline": round(self.means[index], 3),
                    "anomaly_magnitude": round(abs(z_value), 3),
                    "contribution": round(contribution, 3),
                })
        ranked = sorted(contributions, key=lambda item: item["contribution"], reverse=True)[:limit]
        total = sum(item["contribution"] for item in ranked)
        for item in ranked:
            item["contribution_share"] = round(item["contribution"] / total, 4) if total else 0.0
        return ranked

    def feature_importance(self, limit: int = 12) -> list[dict]:
        pairs = [
            {"feature": name, "label": FEATURE_LABELS[name], "importance": round(abs(weight), 4), "direction": "risk" if weight >= 0 else "trust"}
            for name, weight in zip(FEATURES, self.weights)
        ]
        return sorted(pairs, key=lambda item: item["importance"], reverse=True)[:limit]

    def score_and_annotate(self, row: dict) -> dict:
        annotated = dict(row)
        started = time.perf_counter()
        risk = self.score(row)
        annotated["risk_score"] = round(risk, 4)
        decline_threshold = max(0.82, self.threshold + 0.18)
        annotated["decision"] = "decline" if risk >= decline_threshold else "review" if risk >= self.threshold else "approve"
        annotated["risk_level"] = "critical" if risk >= decline_threshold else "high" if risk >= self.threshold else "medium" if risk >= self.threshold * 0.65 else "low"
        annotated["explanations"] = self.explain(row)
        annotated["scoring_latency_ms"] = round((time.perf_counter() - started) * 1000, 4)
        return annotated
