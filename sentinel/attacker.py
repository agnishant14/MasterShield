"""Safe, deterministic adaptive mutation of synthetic attack transactions.

The composer only changes synthetic feature values. It never emits social-engineering
copy, credentials, targets, or instructions for interacting with a live payment rail.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Mutation:
    feature: str
    before: float | int | str | None
    after: float | int | str | None
    reason: str

    def to_dict(self) -> dict:
        return {"feature": self.feature, "before": self.before, "after": self.after, "reason": self.reason}


@dataclass(frozen=True)
class MutationCandidate:
    transaction: dict
    mutations: tuple[Mutation, ...]
    risk_score: float
    detected: bool
    objective: float

    def to_dict(self) -> dict:
        return {
            "transaction": self.transaction,
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "risk_score": self.risk_score,
            "detected": self.detected,
            "objective": self.objective,
        }


class AdaptiveAttacker:
    """Searches a bounded synthetic mutation space for detector blind spots."""

    MUTATIONS: tuple[tuple[str, str], ...] = (
        ("amount", "amount shaping"), ("velocity_10m", "short-window pacing"),
        ("velocity_1h", "long-window pacing"), ("device_age_days", "device provenance"),
        ("graph_mule_score", "network proximity"), ("session_entropy", "session regularity"),
        ("typing_consistency", "behavioral consistency"), ("synthetic_identity_score", "identity evidence"),
        ("prompt_pressure_score", "semantic pressure"), ("llm_similarity_score", "generated-language similarity"),
        ("biometric_confidence", "biometric confidence"), ("ip_risk", "network reputation"),
        ("merchant_risk", "merchant risk"), ("merchant_age_days", "merchant provenance"),
        ("descriptor_drift", "descriptor consistency"), ("refund_velocity", "refund pacing"),
    )

    def __init__(self, seed: int = 2026):
        self.seed = seed

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return round(max(low, min(high, value)), 4)

    def _value(self, row: dict, feature: str, rng: random.Random) -> tuple[object, object]:
        before = row.get(feature)
        if feature == "amount":
            after = self._clamp(float(before or 0.0) * rng.uniform(0.62, 0.91), 1.0, 50000.0)
        elif feature in {"velocity_10m", "velocity_1h"}:
            after = max(0, int(float(before or 0) * rng.uniform(0.45, 0.85)))
        elif feature in {"device_age_days", "merchant_age_days"}:
            after = max(1, int(float(before or 1) * rng.uniform(1.2, 3.8)))
        elif feature == "biometric_confidence":
            after = self._clamp(float(before if before is not None else 0.9) + rng.uniform(0.03, 0.08), 0.55, 0.999)
        elif feature == "typing_consistency":
            after = self._clamp(float(before if before is not None else 0.85) + rng.uniform(0.03, 0.11), 0.35, 1.0)
        elif feature == "session_entropy":
            after = self._clamp(float(before or 0.1) * rng.uniform(0.35, 0.75), 0.0, 1.0)
        else:
            after = self._clamp(float(before or 0.0) * rng.uniform(0.35, 0.78), 0.0, 1.0)
        return before, after

    def mutate(self, row: dict, count: int = 16, intensity: float = 1.0) -> list[tuple[dict, tuple[Mutation, ...]]]:
        count = max(1, min(int(count), 100))
        intensity = max(0.35, min(float(intensity), 1.4))
        candidates: list[tuple[dict, tuple[Mutation, ...]]] = []
        for index in range(count):
            rng = random.Random(self.seed + index * 7919)
            candidate = dict(row)
            selected = list(self.MUTATIONS)
            rng.shuffle(selected)
            mutation_count = max(2, min(5, int(round(2 + intensity * 2))))
            mutations: list[Mutation] = []
            for feature, reason in selected[:mutation_count]:
                before, after = self._value(candidate, feature, rng)
                candidate[feature] = after
                mutations.append(Mutation(feature, before, after, reason))
            candidate["mutation_id"] = f"mut-{self.seed}-{index:04d}"
            candidate["synthetic_only"] = True
            candidates.append((candidate, tuple(mutations)))
        return candidates

    def search(self, row: dict, scorer: Callable[[dict], float], predictor: Callable[[dict], int], count: int = 24, top_k: int = 8) -> dict:
        """Find lower-risk variants while retaining the original attack label."""
        original_score = float(scorer(row))
        evaluated: list[MutationCandidate] = []
        for candidate, mutations in self.mutate(row, count=count):
            score = float(scorer(candidate))
            detected = bool(predictor(candidate))
            objective = score + (0.12 if detected else 0.0)
            evaluated.append(MutationCandidate(candidate, mutations, round(score, 4), detected, round(objective, 4)))
        evaluated.sort(key=lambda item: (item.objective, item.risk_score))
        return {
            "original": {"id": row.get("id"), "attack_id": row.get("attack_id"), "risk_score": round(original_score, 4), "detected": bool(predictor(row))},
            "candidate_count": len(evaluated),
            "blind_spots": sum(not item.detected for item in evaluated),
            "candidates": [item.to_dict() for item in evaluated[:max(1, min(top_k, 20))]],
            "safety": "synthetic feature mutations only; no live targets, credentials, or payment actions",
        }
