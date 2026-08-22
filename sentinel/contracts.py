"""Dependency-free API contracts shared by local and WSGI dispatchers."""

from __future__ import annotations

import math

from .features import FEATURES


MAX_BODY_BYTES = 1_000_000

SCORE_REQUIRED_FIELDS = {
    "amount",
    "currency",
    "rail",
    "channel",
    "account_age_days",
    "device_age_days",
}

SCORE_STRING_FIELDS = {
    "id": 128,
    "timestamp": 64,
    "currency": 8,
    "rail": 64,
    "channel": 64,
    "country": 16,
    "merchant_category": 32,
    "merchant_id": 128,
    "customer_id": 128,
    "device_id": 128,
    "auth_method": 32,
    "attack_id": 64,
    "attack_family": 64,
    "attack_name": 160,
}

SCORE_NUMERIC_RANGES = {
    "amount": (0.0, 1_000_000.0),
    "account_age_days": (0.0, 100_000.0),
    "device_age_days": (0.0, 100_000.0),
    "hour": (0.0, 23.0),
    "distance_from_home_km": (0.0, 50_000.0),
    "velocity_10m": (0.0, 10_000.0),
    "velocity_1h": (0.0, 100_000.0),
    "new_payee": (0.0, 1.0),
    "credential_reset_24h": (0.0, 1.0),
    "biometric_confidence": (0.0, 1.0),
    "session_entropy": (0.0, 1.0),
    "typing_consistency": (0.0, 1.0),
    "ip_risk": (0.0, 1.0),
    "merchant_risk": (0.0, 1.0),
    "graph_mule_score": (0.0, 1.0),
    "synthetic_identity_score": (0.0, 1.0),
    "prompt_pressure_score": (0.0, 1.0),
    "llm_similarity_score": (0.0, 1.0),
    "remote_access": (0.0, 1.0),
    "auth_downgrade": (0.0, 1.0),
    "token_age_hours": (0.0, 1_000_000.0),
    "merchant_age_days": (0.0, 100_000.0),
    "descriptor_drift": (0.0, 1.0),
    "refund_velocity": (0.0, 100.0),
    "card_present": (0.0, 1.0),
    "tokenized": (0.0, 1.0),
    "label": (0.0, 1.0),
    **{feature: (0.0, 1.5) for feature in FEATURES},
}

SCORE_ALLOWED_FIELDS = set(SCORE_STRING_FIELDS) | set(SCORE_NUMERIC_RANGES) | {
    "synthetic_only",
}


def _reject_unknown(payload: dict, allowed: set[str], operation: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"Unexpected {operation} fields: {', '.join(unknown)}")


def _finite_number(value: object, field: str, low: float, high: float, *, integer: bool = False) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field} must be finite")
    if number < low or number > high:
        raise ValueError(f"{field} must be between {low:g} and {high:g}")
    if integer and not number.is_integer():
        raise ValueError(f"{field} must be an integer")
    return int(number) if integer else number


def _bounded_string(value: object, field: str, max_length: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = value.strip()
    if required and not cleaned:
        raise ValueError(f"{field} must not be empty")
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value


def validate_score_payload(payload: dict) -> dict:
    _reject_unknown(payload, SCORE_ALLOWED_FIELDS, "scoring")
    missing = sorted(SCORE_REQUIRED_FIELDS - set(payload))
    if missing:
        raise ValueError(f"Missing required transaction fields: {', '.join(missing)}")
    for field, max_length in SCORE_STRING_FIELDS.items():
        if field in payload:
            _bounded_string(payload[field], field, max_length, required=field in SCORE_REQUIRED_FIELDS)
    currency = str(payload["currency"])
    if len(currency) != 3 or not currency.isalpha():
        raise ValueError("currency must be a three-letter code")
    for field, (low, high) in SCORE_NUMERIC_RANGES.items():
        if field in payload:
            integer = field in {
                "account_age_days", "device_age_days", "hour", "velocity_10m", "velocity_1h",
                "new_payee", "credential_reset_24h", "remote_access", "auth_downgrade",
                "merchant_age_days", "card_present", "tokenized", "label",
            }
            _finite_number(payload[field], field, low, high, integer=integer)
    if "synthetic_only" in payload and not isinstance(payload["synthetic_only"], bool):
        raise ValueError("synthetic_only must be a boolean")
    return payload


def validate_simulate_payload(payload: dict) -> dict:
    _reject_unknown(payload, {"attack_ids", "count", "intensity"}, "simulation")
    attack_ids = payload.get("attack_ids", [])
    if not isinstance(attack_ids, list) or not all(isinstance(item, str) and item.strip() for item in attack_ids):
        raise ValueError("attack_ids must be a list of strings with non-empty values")
    if len(attack_ids) > 100:
        raise ValueError("attack_ids must contain at most 100 values")
    _finite_number(payload.get("count", 80), "count", 5, 500, integer=True)
    _finite_number(payload.get("intensity", 1.0), "intensity", 0.35, 1.4)
    return payload


def validate_mutate_payload(payload: dict) -> dict:
    _reject_unknown(payload, {"transaction_id", "attack_id", "count"}, "mutation")
    for field in ("transaction_id", "attack_id"):
        if payload.get(field) is not None:
            _bounded_string(payload[field], field, 128, required=True)
    _finite_number(payload.get("count", 24), "count", 1, 100, integer=True)
    return payload


def validate_retrain_payload(payload: dict) -> dict:
    _reject_unknown(payload, {"confirm"}, "retrain")
    if "confirm" in payload and not isinstance(payload["confirm"], bool):
        raise ValueError("confirm must be a boolean")
    return payload


def validate_feedback_payload(payload: dict) -> dict:
    _reject_unknown(payload, {"transaction_id", "outcome", "note", "override_decision"}, "feedback")
    _bounded_string(payload.get("transaction_id"), "transaction_id", 128, required=True)
    _bounded_string(payload.get("outcome"), "outcome", 64, required=True)
    if "note" in payload:
        _bounded_string(payload["note"], "note", 500)
    if payload.get("override_decision") is not None:
        _bounded_string(payload["override_decision"], "override_decision", 32, required=True)
        if payload["override_decision"] not in {"approve", "review", "step_up", "hold", "decline"}:
            raise ValueError("override_decision must be approve, review, step_up, hold, or decline")
    return payload


def validate_rollback_payload(payload: dict) -> dict:
    _reject_unknown(payload, {"model_version"}, "rollback")
    _bounded_string(payload.get("model_version"), "model_version", 64, required=True)
    return payload


def validate_limit(value: object, *, maximum: int = 500) -> int:
    if isinstance(value, str):
        value = value.strip()
        if not value:
            raise ValueError("limit must be a number")
        try:
            value = float(value)
        except ValueError as exc:
            raise ValueError("limit must be a number") from exc
    return int(_finite_number(value, "limit", 0, maximum, integer=True))
