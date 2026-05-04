from __future__ import annotations

from .models import RiskAssessment, SecurityEvent, VehicleSnapshot


class RiskEngine:
    def assess(
        self,
        security_event: SecurityEvent,
        snapshot: VehicleSnapshot,
    ) -> RiskAssessment:
        score = self._base_score(security_event.severity)
        phase = snapshot.phase()

        if snapshot.is_armed:
            score += 10
        if phase in {"AIRBORNE", "MISSION", "RETURN", "LANDING"}:
            score += 10
        if security_event.rule_id in {"position_jump", "health_loss"} and phase != "GROUND":
            score += 10
        if security_event.rule_id == "arm_flapping" and phase == "GROUND":
            score += 5

        score = min(score, 100)
        level = self._score_to_level(score)
        recommended_action = self._recommend_action(level, snapshot)
        reason = (
            f"Событие {security_event.rule_id} в фазе {phase}, "
            f"severity={security_event.severity}, итоговый риск={score}"
        )
        return RiskAssessment(
            level=level,
            score=score,
            reason=reason,
            recommended_action=recommended_action,
            phase=phase,
            security_event=security_event,
        )

    def _base_score(self, severity: str) -> int:
        return {
            "LOW": 25,
            "MEDIUM": 50,
            "HIGH": 75,
            "CRITICAL": 90,
        }.get(severity.upper(), 10)

    def _score_to_level(self, score: int) -> str:
        if score >= 90:
            return "CRITICAL"
        if score >= 75:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        return "LOW"

    def _recommend_action(self, level: str, snapshot: VehicleSnapshot) -> str:
        airborne = snapshot.phase() in {"AIRBORNE", "MISSION", "RETURN", "LANDING"}

        if level == "LOW":
            return "log_only"
        if level == "MEDIUM":
            return "alert_operator"
        if level == "HIGH":
            return "hold_position" if airborne else "block_command_source"
        return "return_or_land" if airborne else "lockdown"
