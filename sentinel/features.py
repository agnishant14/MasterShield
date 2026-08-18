"""Feature definitions shared by simulation, training, scoring, and explanations."""

from __future__ import annotations

import math


FEATURES: tuple[str, ...] = (
    "log_amount",
    "amount_zscore",
    "account_age_risk",
    "device_age_risk",
    "distance_risk",
    "velocity_10m",
    "velocity_1h",
    "new_payee",
    "credential_reset_24h",
    "biometric_risk",
    "session_entropy_risk",
    "typing_inconsistency",
    "ip_risk",
    "merchant_risk",
    "graph_mule_score",
    "synthetic_identity_score",
    "prompt_pressure_score",
    "llm_similarity_score",
    "remote_access",
    "auth_downgrade",
    "token_age_risk",
    "merchant_age_risk",
    "descriptor_drift",
    "refund_velocity",
)


FEATURE_LABELS: dict[str, str] = {
    "log_amount": "Transaction amount",
    "amount_zscore": "Amount deviation",
    "account_age_risk": "Account age",
    "device_age_risk": "Device age",
    "distance_risk": "Distance / geovelocity",
    "velocity_10m": "10-minute velocity",
    "velocity_1h": "1-hour velocity",
    "new_payee": "New payee",
    "credential_reset_24h": "Recent credential reset",
    "biometric_risk": "Biometric anomaly",
    "session_entropy_risk": "Session automation",
    "typing_inconsistency": "Behavioral mismatch",
    "ip_risk": "Network reputation",
    "merchant_risk": "Merchant risk",
    "graph_mule_score": "Mule-network proximity",
    "synthetic_identity_score": "Synthetic identity evidence",
    "prompt_pressure_score": "Social pressure language",
    "llm_similarity_score": "Generated-language similarity",
    "remote_access": "Remote-access evidence",
    "auth_downgrade": "Authentication downgrade",
    "token_age_risk": "New wallet token",
    "merchant_age_risk": "Young merchant",
    "descriptor_drift": "Descriptor drift",
    "refund_velocity": "Refund velocity",
}


def enrich(transaction: dict) -> dict:
    """Return a copy with normalized model features derived from raw payment fields."""
    row = dict(transaction)
    amount = max(0.0, float(row.get("amount", 0.0)))
    rail_center = {
        "card_not_present": 55.0,
        "card_present": 38.0,
        "wallet": 42.0,
        "instant_transfer": 120.0,
        "bank_transfer": 310.0,
        "qr": 32.0,
    }.get(str(row.get("rail")), 60.0)
    row["log_amount"] = min(1.5, math.log1p(amount) / 8.0)
    row["amount_zscore"] = min(1.5, abs(math.log1p(amount) - math.log1p(rail_center)) / 3.2)
    row["account_age_risk"] = max(
        float(row.get("account_age_risk", 0.0)),
        math.exp(-max(0.0, float(row.get("account_age_days", 0.0))) / 120.0),
    )
    row["device_age_risk"] = max(
        float(row.get("device_age_risk", 0.0)),
        math.exp(-max(0.0, float(row.get("device_age_days", 0.0))) / 22.0),
    )
    row["distance_risk"] = min(1.5, float(row.get("distance_from_home_km", 0.0)) / 650.0)
    row["velocity_10m"] = min(1.5, float(row.get("velocity_10m", 0.0)) / 16.0)
    row["velocity_1h"] = min(1.5, float(row.get("velocity_1h", 0.0)) / 60.0)
    row["biometric_risk"] = 1.0 - float(row.get("biometric_confidence", 1.0))
    row["session_entropy_risk"] = float(row.get("session_entropy", 0.0))
    row["typing_inconsistency"] = 1.0 - float(row.get("typing_consistency", 1.0))
    row["token_age_risk"] = max(
        float(row.get("token_age_risk", 0.0)),
        math.exp(-max(0.0, float(row.get("token_age_hours", 0.0))) / 20.0),
    )
    row["merchant_age_risk"] = max(
        float(row.get("merchant_age_risk", 0.0)),
        math.exp(-max(0.0, float(row.get("merchant_age_days", 0.0))) / 120.0),
    )
    return row


def vectorize(transaction: dict) -> list[float]:
    row = enrich(transaction)
    return [float(row.get(name, 0.0)) for name in FEATURES]
