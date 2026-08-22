"""Dataset health measurements for synthetic training and evaluation rows."""

from __future__ import annotations

import math
from collections import Counter

from .features import FEATURES, vectorize


REQUIRED_FIELDS = ("id", "amount", "currency", "rail", "channel", "account_age_days", "device_age_days", "label")


def assess_dataset(rows: list[dict], reference: list[dict] | None = None) -> dict:
    missing = Counter()
    invalid_numeric = Counter()
    identifiers = Counter()
    labels = Counter()
    vectors: list[list[float]] = []
    for row in rows:
        for field in REQUIRED_FIELDS:
            if field not in row or row.get(field) in (None, ""):
                missing[field] += 1
        if row.get("id"):
            identifiers[str(row["id"])] += 1
        labels[str(int(bool(row.get("label", 0))))] += 1
        if row.get("label") not in (0, 1, False, True):
            invalid_numeric["invalid_label"] += 1
        try:
            values = vectorize(row)
            if not all(math.isfinite(value) for value in values):
                invalid_numeric["non_finite_feature"] += 1
            else:
                vectors.append(values)
        except (TypeError, ValueError, OverflowError):
            invalid_numeric["unparseable_feature"] += 1
    duplicate_ids = sum(count - 1 for count in identifiers.values() if count > 1)
    zero_variance = []
    if vectors:
        for index, feature in enumerate(FEATURES):
            values = [row[index] for row in vectors]
            if max(values) - min(values) < 1e-12:
                zero_variance.append(feature)
    drift = None
    if reference and rows:
        reference_vectors = [vectorize(row) for row in reference]
        current_vectors = [vectorize(row) for row in rows]
        distances = []
        for index in range(len(FEATURES)):
            reference_values = [row[index] for row in reference_vectors]
            current_values = [row[index] for row in current_vectors]
            reference_mean = sum(reference_values) / max(1, len(reference_values))
            current_mean = sum(current_values) / max(1, len(current_values))
            scale = max(0.05, max(reference_values, default=0.0) - min(reference_values, default=0.0), max(current_values, default=0.0) - min(current_values, default=0.0))
            distances.append(min(1.0, abs(reference_mean - current_mean) / scale))
        drift = round(sum(distances) / max(1, len(distances)), 4)
    issue_count = sum(missing.values()) + sum(invalid_numeric.values()) + duplicate_ids
    quality_score = max(0.0, 1.0 - issue_count / max(1, len(rows) * len(REQUIRED_FIELDS)))
    positives = labels.get("1", 0)
    return {
        "synthetic_evidence": True,
        "rows": len(rows),
        "quality_score": round(quality_score, 4),
        "missing_required": dict(missing),
        "invalid_numeric": dict(invalid_numeric),
        "duplicate_ids": duplicate_ids,
        "label_balance": {
            "legitimate": labels.get("0", 0),
            "attack": positives,
            "attack_rate": round(positives / max(1, len(rows)), 4),
        },
        "zero_variance_features": zero_variance,
        "feature_drift_from_reference": drift,
    }
