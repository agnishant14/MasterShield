"""Dependency-free fidelity and robustness measurements for synthetic streams."""

from __future__ import annotations

import math
import hashlib
import json
from collections import Counter
from statistics import mean
from datetime import datetime

from .features import FEATURES, vectorize
from .attacker import AdaptiveAttacker


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


def _pearson(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or len(left) < 2:
        return 0.0
    left_mean = _mean(left)
    right_mean = _mean(right)
    numerator = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    denominator = math.sqrt(sum((a - left_mean) ** 2 for a in left) * sum((b - right_mean) ** 2 for b in right))
    return numerator / denominator if denominator else 0.0


def _correlation_preservation(reference: list[dict], candidate: list[dict]) -> dict:
    ref_vectors = [vectorize(row) for row in reference]
    cand_vectors = [vectorize(row) for row in candidate]
    pairs = []
    for left_index, left_name in enumerate(FEATURES):
        for right_index in range(left_index + 1, len(FEATURES)):
            right_name = FEATURES[right_index]
            ref_corr = _pearson([row[left_index] for row in ref_vectors], [row[right_index] for row in ref_vectors])
            cand_corr = _pearson([row[left_index] for row in cand_vectors], [row[right_index] for row in cand_vectors])
            pairs.append({"features": [left_name, right_name], "reference": round(ref_corr, 4), "candidate": round(cand_corr, 4), "absolute_delta": round(abs(ref_corr - cand_corr), 4)})
    pairs.sort(key=lambda item: item["absolute_delta"], reverse=True)
    return {
        "mean_absolute_delta": round(_mean([item["absolute_delta"] for item in pairs]), 4),
        "max_absolute_delta": pairs[0]["absolute_delta"] if pairs else 0.0,
        "largest_changes": pairs[:8],
    }


def _temporal_profile(rows: list[dict]) -> dict:
    buckets = Counter()
    for row in rows:
        try:
            timestamp = str(row.get("timestamp", "")).replace("Z", "+00:00")
            stamp = datetime.fromisoformat(timestamp)
            buckets[stamp.strftime("%Y-%m-%dT%H:%M")] += 1
        except (TypeError, ValueError):
            continue
    counts = list(buckets.values())
    average = _mean(counts)
    return {"buckets": len(buckets), "peak_per_minute": max(counts) if counts else 0, "mean_per_minute": round(average, 4), "burst_ratio": round(max(counts) / average, 4) if average else 0.0}


def _graph_profile(rows: list[dict]) -> dict:
    customers = Counter(str(row.get("customer_id", "unknown")) for row in rows)
    merchants = Counter(str(row.get("merchant_id", "unknown")) for row in rows)
    scores = [float(row.get("graph_mule_score", 0.0) or 0.0) for row in rows]
    return {
        "unique_customers": len(customers),
        "unique_merchants": len(merchants),
        "customer_concentration": round(max(customers.values()) / max(1, len(rows)), 4) if customers else 0.0,
        "merchant_concentration": round(max(merchants.values()) / max(1, len(rows)), 4) if merchants else 0.0,
        "mean_graph_mule_score": round(_mean(scores), 4),
    }


def _scenario_coverage(rows: list[dict]) -> dict:
    counts = Counter(str(row.get("attack_id")) for row in rows if row.get("label") == 1 and row.get("attack_id"))
    return {"families": len({row.get("attack_family") for row in rows if row.get("label") == 1 and row.get("attack_family")}), "scenarios": len(counts), "counts": dict(sorted(counts.items()))}


def seed_reproducibility(seed: int, count: int = 48) -> dict:
    from .generator import SyntheticGenerator
    first = SyntheticGenerator(seed).generate_mixed(count, attack_rate=0.25, intensity=0.95)
    second = SyntheticGenerator(seed).generate_mixed(count, attack_rate=0.25, intensity=0.95)
    first_hash = hashlib.sha256(json.dumps(first, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    second_hash = hashlib.sha256(json.dumps(second, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    return {"seed": seed, "samples": count, "reproducible": first == second, "evidence_hash_equal": first_hash == second_hash, "first_hash": first_hash, "second_hash": second_hash}


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
        "correlation": _correlation_preservation(reference, candidate),
        "temporal": {"reference": _temporal_profile(reference), "candidate": _temporal_profile(candidate), "burst_ratio_delta": round(abs(_temporal_profile(reference)["burst_ratio"] - _temporal_profile(candidate)["burst_ratio"]), 4)},
        "graph": {"reference": _graph_profile(reference), "candidate": _graph_profile(candidate)},
        "scenario_coverage": {"reference": _scenario_coverage(reference), "candidate": _scenario_coverage(candidate)},
    }


def robustness_report(detector, generator, seed: int = 2026, sample_size: int = 320) -> dict:
    """Run deterministic synthetic stress tests for the current detector."""
    sample_size = max(24, min(int(sample_size), 640))
    normal = generator.generate_legitimate(sample_size)
    known = generator.generate_attacks(sample_size, ["atk-001", "atk-005", "atk-008"], intensity=0.72)
    unseen = generator.generate_attacks(sample_size, ["atk-020", "atk-021", "atk-024"], intensity=0.82)
    noisy = []
    for row in generator.generate_mixed(sample_size, attack_rate=0.35, intensity=0.9):
        copy = dict(row)
        for key in ("ip_risk", "merchant_risk", "session_entropy", "prompt_pressure_score"):
            copy.pop(key, None)
        noisy.append(copy)

    def capture(rows: list[dict]) -> dict:
        positives = [row for row in rows if row.get("label") == 1]
        detected = sum(detector.predict(row) for row in positives)
        return {"rows": len(rows), "attack_rows": len(positives), "attack_recall": round(detected / max(1, len(positives)), 4), "mean_risk": round(_mean([detector.score(row) for row in rows]), 4)}

    mutation_source = unseen[:24]
    attacker = AdaptiveAttacker(seed + 91)
    candidates = []
    for row in mutation_source:
        candidates.extend(attacker.mutate(row, count=3))
    successes = [candidate for candidate, _ in candidates if not detector.predict(candidate)]
    feature_changes = Counter()
    costs = []
    for candidate, mutations in candidates:
        costs.append(sum(abs(float(item.after or 0) - float(item.before or 0)) for item in mutations) / max(1, len(mutations)))
        for mutation in mutations:
            if not detector.predict(candidate):
                feature_changes[mutation.feature] += 1
    original_risk = [detector.score(row) for row in mutation_source]
    candidate_risk = [detector.score(candidate) for candidate, _ in candidates]
    adversarial = {
        "samples": len(candidates),
        "attack_success_rate": round(len(successes) / max(1, len(candidates)), 4),
        "adversarial_accuracy": round(1.0 - len(successes) / max(1, len(candidates)), 4),
        "mean_perturbation_cost": round(_mean(costs), 4),
        "worst_case_risk_drop": round(max(0.0, max(original_risk, default=0.0) - min(candidate_risk, default=0.0)), 4),
        "vulnerable_features": [{"feature": key, "count": count} for key, count in feature_changes.most_common(8)],
    }
    return {
        "synthetic_evidence": True,
        "seed": seed,
        "seed_reproducibility": seed_reproducibility(seed),
        "known_low_intensity": capture(known),
        "unseen_attack_families": capture(unseen),
        "missing_features": capture(noisy),
        "legitimate_baseline": capture(normal),
        "adversarial": adversarial,
    }
