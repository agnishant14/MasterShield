"""Dependency-free fidelity and robustness measurements for synthetic streams."""

from __future__ import annotations

import math
from collections import Counter
from statistics import mean

from .features import FEATURES, vectorize


def _mean(values: list[float]) -> float:
    return mean(values) if values else 0.0


def _variance(values: list[float], average: float) -> float:
    return _mean([(value - average) ** 2 for value in values])


def _feature_profile(rows: list[dict]) -> dict:
    profile = {}
    for index, feature in enumerate(FEATURES):
        values = [vectorize(row)[index] for row in rows]
        average = _mean(values)
        profile[feature] = {"mean": round(average, 4), "std": round(math.sqrt(_variance(values, average)), 4), "min": round(min(values), 4) if values else 0.0, "max": round(max(values), 4) if values else 0.0}
    return profile


def _distribution_distance(left: list[float], right: list[float], bins: int = 10) -> float:
    if not left or not right:
        return 1.0
    low = min(min(left), min(right))
    high = max(max(left), max(right))
    width = (high - low) / bins if high > low else 1.0
    left_bins = [0] * bins
    right_bins = [0] * bins
    for value in left:
        left_bins[min(bins - 1, int((value - low) / width))] += 1
    for value in right:
        right_bins[min(bins - 1, int((value - low) / width))] += 1
    return round(sum(abs(a / len(left) - b / len(right)) for a, b in zip(left_bins, right_bins)) / 2.0, 4)


def compare_streams(reference: list[dict], candidate: list[dict]) -> dict:
    distances = {}
    for index, feature in enumerate(FEATURES):
        distances[feature] = _distribution_distance([vectorize(row)[index] for row in reference], [vectorize(row)[index] for row in candidate])
    reference_attack = Counter(row.get("attack_id") for row in reference if row.get("label") == 1)
    candidate_attack = Counter(row.get("attack_id") for row in candidate if row.get("label") == 1)
    keys = set(reference_attack) | set(candidate_attack)
    reference_total = max(1, sum(reference_attack.values()))
    candidate_total = max(1, sum(candidate_attack.values()))
    coverage_distance = sum(abs(reference_attack[key] / reference_total - candidate_attack[key] / candidate_total) for key in keys) / 2 if keys else 0.0
    return {
        "synthetic_evidence": True,
        "sample_counts": {"reference": len(reference), "candidate": len(candidate)},
        "feature_distance": distances,
        "mean_feature_distance": round(_mean(list(distances.values())), 4),
        "scenario_mix_distance": round(coverage_distance, 4),
        "reference_profile": _feature_profile(reference),
        "candidate_profile": _feature_profile(candidate),
    }


def robustness_report(detector, generator, seed: int = 2026) -> dict:
    """Run deterministic synthetic stress tests for the current detector."""
    normal = generator.generate_legitimate(320)
    known = generator.generate_attacks(320, ["atk-001", "atk-005", "atk-008"], intensity=0.72)
    unseen = generator.generate_attacks(320, ["atk-020", "atk-021", "atk-024"], intensity=0.82)
    noisy = []
    for row in generator.generate_mixed(320, attack_rate=0.35, intensity=0.9):
        copy = dict(row)
        for key in ("ip_risk", "merchant_risk", "session_entropy", "prompt_pressure_score"):
            copy.pop(key, None)
        noisy.append(copy)

    def capture(rows: list[dict]) -> dict:
        positives = [row for row in rows if row.get("label") == 1]
        detected = sum(detector.predict(row) for row in positives)
        return {"rows": len(rows), "attack_rows": len(positives), "attack_recall": round(detected / max(1, len(positives)), 4), "mean_risk": round(_mean([detector.score(row) for row in rows]), 4)}

    return {"synthetic_evidence": True, "seed": seed, "known_low_intensity": capture(known), "unseen_attack_families": capture(unseen), "missing_features": capture(noisy), "legitimate_baseline": capture(normal)}
