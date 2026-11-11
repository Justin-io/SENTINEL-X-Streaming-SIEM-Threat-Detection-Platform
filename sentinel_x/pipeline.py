from __future__ import annotations
from collections import deque
from time import perf_counter
from datetime import datetime,timezone
from .normalize import normalize
from .detection import RuleEngine
from .storage import Store
from .anomaly import HostBurstDetector
from .risk import score_alert

class Pipeline:
    def __init__(self,store:Store,engine:RuleEngine,anomaly_detector:HostBurstDetector|None=None):
        self.store,self.engine=store,engine
        self.anomaly_detector=anomaly_detector or HostBurstDetector()
        self._processing_samples=deque(maxlen=10000); self._lag_samples=deque(maxlen=10000)
        self.metrics={"accepted":0,"duplicates":0,"invalid":0,"alerts":0,"incidents":0,
          "anomaly_alerts":0,"mirror_errors":0,"clock_skew_events":0,
          "ingestion_lag_ms_last":0.0,"ingestion_lag_ms_max":0.0,"ingestion_lag_ms_p95":0.0,
          "processing_ms_last":0.0,"processing_ms_max":0.0,"processing_ms_p95":0.0}
    @staticmethod
    def _percentile(values,percentile):
        if not values:return 0.0
        ordered=sorted(values); position=max(0,min(len(ordered)-1,round((len(ordered)-1)*percentile)))
        return ordered[position]
    def _record_timing(self,started,event=None):
        elapsed=(perf_counter()-started)*1000; self._processing_samples.append(elapsed)
        self.metrics["processing_ms_last"]=round(elapsed,3)
        self.metrics["processing_ms_max"]=round(max(self._processing_samples),3)
        self.metrics["processing_ms_p95"]=round(self._percentile(self._processing_samples,.95),3)
        if event is not None:
            lag=(datetime.now(timezone.utc)-event.timestamp.astimezone(timezone.utc)).total_seconds()*1000
            if lag<0:self.metrics["clock_skew_events"]+=1; lag=0.0
            self._lag_samples.append(lag)
            self.metrics["ingestion_lag_ms_last"]=round(lag,3)
            self.metrics["ingestion_lag_ms_max"]=round(max(self._lag_samples),3)
            self.metrics["ingestion_lag_ms_p95"]=round(self._percentile(self._lag_samples,.95),3)
        self.metrics["mirror_errors"]=self.store.mirror_errors
    def process(self,payload:dict,source_type=None):
        started=perf_counter()
        try:event=normalize(payload,source_type)
        except Exception as exc:
            self.metrics["invalid"]+=1; self.store.dead_letter(payload,str(exc)); self._record_timing(started)
            return {"accepted":False,"error":str(exc),"alerts":[]}
        if not self.store.ingest(event):
            self.metrics["duplicates"]+=1; self._record_timing(started,event)
            return {"accepted":False,"duplicate":True,"event_id":event.event_id,"alerts":[]}
        self.metrics["accepted"]+=1
        alerts=self.engine.evaluate(event)
        try:alerts.extend(self.anomaly_detector.evaluate(event,self.store))
        except Exception as exc:self.store.dead_letter({"event_id":event.event_id,"subsystem":"anomaly"},str(exc))
        created=[]
        for alert in alerts:
            alert["risk_score"]=score_alert(alert)
            if self.store.add_alert(alert):
                created.append(alert); self.metrics["alerts"]+=1
                if alert["rule_id"].startswith("SX-ANOM-"):self.metrics["anomaly_alerts"]+=1
                self.store.create_or_update_incident(alert,event.model_dump(mode="json"))
                self.metrics["incidents"]+=1
        self._record_timing(started,event)
        return {"accepted":True,"event_id":event.event_id,"alerts":created}
