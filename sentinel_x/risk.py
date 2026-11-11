"""Transparent heuristic triage scoring; not a calibrated compromise probability."""
from __future__ import annotations

SEVERITY_BASE = {"info": 5, "low": 20, "medium": 40, "high": 70, "critical": 90}

def score_alert(alert: dict) -> int:
    evidence = alert.get("evidence", {})
    base = SEVERITY_BASE.get(str(alert.get("severity", "info")).lower(), 5)
    criteria = int(evidence.get("matched_criteria", 0))
    score = base + min(12, criteria * 3)
    if evidence.get("method") == "median_mad_minute_rate":
        threshold = max(1.0, float(evidence.get("threshold_events_per_minute", 1)))
        observed = float(evidence.get("observed_current_minute_events", 0))
        score = base + min(15, int((observed / threshold) * 5))
    return min(100, max(0, score))

def fuse_incident_score(existing: int, incoming: int, alert_count: int) -> int:
    corroboration_bonus = min(15, max(0, alert_count - 1) * 3)
    return min(100, max(existing, incoming) + corroboration_bonus)
