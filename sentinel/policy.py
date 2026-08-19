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
        self.thresholds = {"review": 0.50, "hold": 0.68, "decline": 0.82, **(thresholds or {})}

    def decide(self, row: dict, risk_score: float) -> PolicyDecision:
        risk = max(0.0, min(1.0, float(risk_score)))
        amount = max(0.0, float(row.get("amount", 0.0) or 0.0))
        rail = str(row.get("rail", "unknown"))
        high_value = amount >= 1000.0
        new_payee = bool(row.get("new_payee", 0))
        if risk >= self.thresholds["decline"] and (high_value or new_payee):
            return PolicyDecision("decline", "high risk with material payment exposure", 0.95, amount * risk, ("retain_reason_codes", "notify_analyst"))
        if risk >= self.thresholds["hold"]:
            return PolicyDecision("hold", "risk exceeds payment-hold threshold", 0.65, amount * risk * 0.55, ("cooling_period", "step_up", "notify_analyst"))
        if risk >= self.thresholds["review"]:
            action = "step_up" if rail in {"wallet", "instant_transfer", "card_not_present"} else "review"
            return PolicyDecision(action, "risk requires additional customer or analyst evidence", 0.35, amount * risk * 0.35, ("step_up_auth", "retain_reason_codes"))
        return PolicyDecision("approve", "risk is below the configured intervention threshold", 0.02, amount * risk * 0.08, ("continue_monitoring",))

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
