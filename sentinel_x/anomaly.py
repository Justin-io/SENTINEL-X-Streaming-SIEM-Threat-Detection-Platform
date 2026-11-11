"""Robust host event-rate anomaly detector; CPU-only and explainable."""
from __future__ import annotations
import statistics
import uuid
from datetime import datetime,timezone
from .schema import NormalizedEvent
from .storage import Store

class HostBurstDetector:
    """Compare the current minute with prior active minute buckets using median/MAD."""
    rule_id="SX-ANOM-001"
    def __init__(self,enabled=True,lookback_minutes=15,minimum_active_minutes=5,
                 minimum_history_events=20,absolute_floor=12,mad_multiplier=3.0):
        self.enabled=enabled; self.lookback_minutes=lookback_minutes
        self.minimum_active_minutes=minimum_active_minutes; self.minimum_history_events=minimum_history_events
        self.absolute_floor=absolute_floor; self.mad_multiplier=mad_multiplier
    def evaluate(self,event:NormalizedEvent,store:Store)->list[dict]:
        if not self.enabled or not event.host_name: return []
        history=store.host_minute_counts(event.host_name,event.timestamp,self.lookback_minutes)
        active=[n for n in history if n>0]
        if len(active)<self.minimum_active_minutes or sum(active)<self.minimum_history_events: return []
        median=statistics.median(active)
        mad=statistics.median([abs(n-median) for n in active])
        robust_sigma=max(1.0,1.4826*mad)
        threshold=max(float(self.absolute_floor),median+self.mad_multiplier*robust_sigma)
        current=store.host_current_minute_count(event.host_name,event.timestamp)
        if current<threshold: return []
        return [{"alert_id":str(uuid.uuid5(uuid.NAMESPACE_URL,f"{event.event_id}:{self.rule_id}")),
          "event_id":event.event_id,"rule_id":self.rule_id,
          "title":"Host telemetry burst above robust baseline","severity":"medium","technique_ids":[],
          "evidence":{"method":"median_mad_minute_rate","host_name":event.host_name,
            "lookback_minutes":self.lookback_minutes,"active_baseline_buckets":len(active),
            "baseline_events_per_minute":median,"median_absolute_deviation":mad,
            "robust_sigma_estimate":robust_sigma,"threshold_events_per_minute":threshold,
            "observed_current_minute_events":current,
            "caveat":"Statistical triage signal only; event-rate spikes do not establish malicious activity."},
          "created_at":datetime.now(timezone.utc).isoformat()}]
