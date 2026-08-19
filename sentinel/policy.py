"""Configurable operational actions around a model risk score."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    reason: str
    friction_cost: float
    expected_loss: float
    controls: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"action": self.action, "reason": self.reason, "friction_cost": round(self.friction_cost, 4), "expected_loss": round(self.expected_loss, 4), "controls": list(self.controls)}


class RiskPolicy:
    def __init__(self, thresholds: dict | None = None):
        config = thresholds or {}
        self.thresholds = {"review": 0.50, "hold": 0.68, "decline": 0.82, **{key: value for key, value in config.items() if key in {"review", "hold", "decline"}}}
        self.rail_thresholds = dict(config.get("rail_thresholds", {}))
        self.amount_thresholds = list(config.get("amount_thresholds", []))
        self.customer_risk_thresholds = dict(config.get("customer_risk_thresholds", {}))
        self.merchant_risk_thresholds = dict(config.get("merchant_risk_thresholds", {}))
        self.attack_family_thresholds = dict(config.get("attack_family_thresholds", {}))
        self.action_controls = {
            "approve": ("continue_monitoring",),
            "step_up": ("step_up_auth", "retain_reason_codes"),
            "review": ("retain_reason_codes", "notify_analyst"),
            "hold": ("cooling_period", "step_up", "notify_analyst"),
            "decline": ("retain_reason_codes", "notify_analyst"),
            **dict(config.get("action_controls", {})),
        }

    def _configured_thresholds(self, row: dict) -> dict:
        values = dict(self.thresholds)
        rail = str(row.get("rail", "unknown"))
        family = str(row.get("attack_family", "unknown"))
        values.update(self.rail_thresholds.get(rail, {}))
        values.update(self.attack_family_thresholds.get(family, {}))
        amount = float(row.get("amount", 0.0) or 0.0)
        for band in self.amount_thresholds:
            if isinstance(band, dict) and float(band.get("min", 0)) <= amount < float(band.get("max", float("inf"))):
                values.update({key: value for key, value in band.items() if key in {"review", "hold", "decline"}})
        customer_risk = float(row.get("synthetic_identity_score", 0.0) or 0.0)
        merchant_risk = float(row.get("merchant_risk", 0.0) or 0.0)
        for mapping, score, key in ((self.customer_risk_thresholds, customer_risk, "customer"), (self.merchant_risk_thresholds, merchant_risk, "merchant")):
            for floor, overrides in sorted(mapping.items(), key=lambda item: float(item[0])):
                if score >= float(floor) and isinstance(overrides, dict):
                    values.update({name: value for name, value in overrides.items() if name in {"review", "hold", "decline"}})
        return values

    def decide(self, row: dict, risk_score: float) -> PolicyDecision:
        risk = max(0.0, min(1.0, float(risk_score)))
        amount = max(0.0, float(row.get("amount", 0.0) or 0.0))
        rail = str(row.get("rail", "unknown"))
        thresholds = self._configured_thresholds(row)
        high_value = amount >= 1000.0
        new_payee = bool(row.get("new_payee", 0))
        if risk >= thresholds["decline"] and (high_value or new_payee):
            return PolicyDecision("decline", "high risk with material payment exposure", 0.95, amount * risk, tuple(self.action_controls["decline"]))
        if risk >= thresholds["hold"]:
            return PolicyDecision("hold", "risk exceeds payment-hold threshold", 0.65, amount * risk * 0.55, tuple(self.action_controls["hold"]))
        if risk >= thresholds["review"]:
            action = "step_up" if rail in {"wallet", "instant_transfer", "card_not_present"} else "review"
            return PolicyDecision(action, "risk requires additional customer or analyst evidence", 0.35, amount * risk * 0.35, tuple(self.action_controls[action]))
        return PolicyDecision("approve", "risk is below the configured intervention threshold", 0.02, amount * risk * 0.08, tuple(self.action_controls["approve"]))

    def tradeoff(self, rows: list[dict], detector) -> dict:
        totals = {"approve": 0, "step_up": 0, "hold": 0, "review": 0, "decline": 0}
        friction = 0.0
        loss = 0.0
        for row in rows:
            decision = self.decide(row, detector.score(row))
            totals[decision.action] = totals.get(decision.action, 0) + 1
            friction += decision.friction_cost
            loss += decision.expected_loss
        return {"synthetic_evidence": True, "actions": totals, "estimated_customer_friction": round(friction / max(1, len(rows)), 4), "estimated_expected_loss": round(loss / max(1, len(rows)), 4)}
