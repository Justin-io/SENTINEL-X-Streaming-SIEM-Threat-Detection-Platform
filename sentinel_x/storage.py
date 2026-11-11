from __future__ import annotations
import json,sqlite3,uuid
from datetime import datetime,timezone,timedelta
from pathlib import Path
from typing import Any
from .schema import NormalizedEvent
from .correlation import entity_keys,score_entities

SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,ts TEXT NOT NULL,source_type TEXT NOT NULL,host_name TEXT,user_name TEXT,source_ip TEXT,destination_ip TEXT,normalized_json TEXT NOT NULL,raw_json TEXT NOT NULL,ingested_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host_name,ts);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(user_name,ts);
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,rule_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,technique_ids TEXT NOT NULL,evidence_json TEXT NOT NULL,created_at TEXT NOT NULL,risk_score INTEGER NOT NULL DEFAULT 0,UNIQUE(event_id,rule_id),FOREIGN KEY(event_id) REFERENCES events(event_id));
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,host_name TEXT,user_name TEXT,technique_ids TEXT NOT NULL,alert_ids TEXT NOT NULL,timeline_json TEXT NOT NULL,updated_at TEXT NOT NULL,entity_keys_json TEXT NOT NULL DEFAULT '{}',risk_score INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit_log(audit_id INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,object_type TEXT NOT NULL,object_id TEXT NOT NULL,actor TEXT NOT NULL,details_json TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dead_letters(id INTEGER PRIMARY KEY AUTOINCREMENT,payload TEXT NOT NULL,error TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incident_feedback(feedback_id TEXT PRIMARY KEY,incident_id TEXT NOT NULL,analyst TEXT NOT NULL,verdict TEXT NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(incident_id));
"""

class Store:
    def __init__(self,path:str|Path,clickhouse_sink=None):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.clickhouse_sink=clickhouse_sink; self.mirror_errors=0
        with self.connect() as c:
            c.executescript(SCHEMA)
            cols={r[1] for r in c.execute("PRAGMA table_info(incidents)")}
            if "entity_keys_json" not in cols:c.execute("ALTER TABLE incidents ADD COLUMN entity_keys_json TEXT NOT NULL DEFAULT '{}'")
            if "risk_score" not in cols:c.execute("ALTER TABLE incidents ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
            cols={r[1] for r in c.execute("PRAGMA table_info(alerts)")}
            if "risk_score" not in cols:c.execute("ALTER TABLE alerts ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
    def connect(self):
        c=sqlite3.connect(self.path,timeout=15); c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA busy_timeout=15000"); return c
    def dead_letter(self,payload:Any,error:str):
        with self.connect() as c:c.execute("INSERT INTO dead_letters(payload,error,created_at) VALUES(?,?,?)",(json.dumps(payload,default=str),error,datetime.now(timezone.utc).isoformat()))
    def ingest(self,event:NormalizedEvent)->bool:
        payload=event.model_dump(mode="json"); now=datetime.now(timezone.utc).isoformat()
        with self.connect() as c:
            cur=c.execute("""INSERT OR IGNORE INTO events(event_id,ts,source_type,host_name,user_name,source_ip,destination_ip,normalized_json,raw_json,ingested_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
              (event.event_id,event.timestamp.astimezone(timezone.utc).isoformat(),event.source_type,event.host_name,event.user_name,event.source_ip,event.destination_ip,json.dumps(payload),json.dumps(event.raw_event),now))
            inserted=cur.rowcount==1
            if not inserted:c.execute("INSERT INTO audit_log(action,object_type,object_id,actor,details_json,created_at) VALUES(?,?,?,?,?,?)",("event_duplicate_suppressed","event",event.event_id,"ingestion",'{"reason":"event_id already exists"}',now))
        if inserted and self.clickhouse_sink:
            try:self.clickhouse_sink.insert_event(event,now)
            except Exception as exc:
                self.mirror_errors+=1; self.dead_letter({"event_id":event.event_id,"mirror":"clickhouse"},str(exc))
        return inserted
    def events(self,limit=100,host=None,user=None,source_type=None,action=None,ip=None):
        filters=[]; args=[]
        for col,val in (("host_name",host),("user_name",user),("source_type",source_type)):
            if val:filters.append(f"{col}=?"); args.append(val)
        if action:filters.append("json_extract(normalized_json,'$.event_action')=?"); args.append(action)
        if ip:filters.append("(source_ip=? OR destination_ip=?)"); args.extend([ip,ip])
        q="SELECT normalized_json FROM events"+(" WHERE "+" AND ".join(filters) if filters else "")+" ORDER BY ts DESC LIMIT ?"
        args.append(min(max(limit,1),1000))
        with self.connect() as c:rows=c.execute(q,args).fetchall()
        return [json.loads(r[0]) for r in rows]
    def analytics_events(self,**kwargs):
        if not self.clickhouse_sink:raise RuntimeError("ClickHouse analytics is not configured")
        return self.clickhouse_sink.events(**kwargs)
    def backfill_clickhouse(self,batch_size=500):
        if not self.clickhouse_sink:raise RuntimeError("ClickHouse analytics is not configured")
        if batch_size<1 or batch_size>5000:raise ValueError("batch_size must be between 1 and 5000")
        copied=failed=0
        with self.connect() as c:
            cur=c.execute("SELECT normalized_json,ingested_at FROM events ORDER BY ts,event_id")
            while rows:=cur.fetchmany(batch_size):
                records=[(NormalizedEvent.model_validate(json.loads(r["normalized_json"])),r["ingested_at"]) for r in rows]
                try:
                    if hasattr(self.clickhouse_sink,"insert_events"):self.clickhouse_sink.insert_events(records)
                    else:
                        for e,t in records:self.clickhouse_sink.insert_event(e,t)
                    copied+=len(records)
                except Exception as exc:
                    failed+=len(records); self.mirror_errors+=1
                    self.dead_letter({"operation":"clickhouse_backfill","event_ids":[e.event_id for e,_ in records]},str(exc))
        return {"copied":copied,"failed_batches_events":failed,"batch_size":batch_size,"mirror_errors":self.mirror_errors}
    def event_by_id(self,event_id):
        with self.connect() as c:r=c.execute("SELECT normalized_json FROM events WHERE event_id=?",(event_id,)).fetchone()
        return json.loads(r[0]) if r else None
    def host_minute_counts(self,host,before,minutes=15):
        end=before.astimezone(timezone.utc).replace(second=0,microsecond=0); start=end-timedelta(minutes=minutes)
        with self.connect() as c:rows=c.execute("SELECT substr(ts,1,16) bucket,COUNT(*) n FROM events WHERE host_name=? AND ts>=? AND ts<? GROUP BY bucket",(host,start.isoformat(),end.isoformat())).fetchall()
        counts={r["bucket"]:r["n"] for r in rows}
        return [int(counts.get((end-timedelta(minutes=o)).strftime("%Y-%m-%dT%H:%M"),0)) for o in range(minutes,0,-1)]
    def host_current_minute_count(self,host,timestamp):
        start=timestamp.astimezone(timezone.utc).replace(second=0,microsecond=0); end=start+timedelta(minutes=1)
        with self.connect() as c:r=c.execute("SELECT COUNT(*) FROM events WHERE host_name=? AND ts>=? AND ts<?",(host,start.isoformat(),end.isoformat())).fetchone()
        return int(r[0])
    def add_alert(self,a):
        with self.connect() as c:
            cur=c.execute("INSERT OR IGNORE INTO alerts(alert_id,event_id,rule_id,title,severity,technique_ids,evidence_json,created_at,risk_score) VALUES(?,?,?,?,?,?,?,?,?)",
              (a["alert_id"],a["event_id"],a["rule_id"],a["title"],a["severity"],json.dumps(a["technique_ids"]),json.dumps(a["evidence"]),a["created_at"],a.get("risk_score",0)))
            if not cur.rowcount:c.execute("INSERT INTO audit_log(action,object_type,object_id,actor,details_json,created_at) VALUES(?,?,?,?,?,?)",("alert_duplicate_suppressed","alert",a["alert_id"],"detection-engine",json.dumps({"event_id":a["event_id"],"rule_id":a["rule_id"]}),datetime.now(timezone.utc).isoformat()))
            return cur.rowcount==1
    def alerts(self,limit=100):
        with self.connect() as c:rows=c.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?",(min(limit,1000),)).fetchall()
        return [{**dict(r),"technique_ids":json.loads(r["technique_ids"]),"evidence":json.loads(r["evidence_json"])} for r in rows]
    def create_or_update_incident(self,alert,event,window_minutes=15):
        now=datetime.now(timezone.utc); event_time=datetime.fromisoformat(str(event.get("timestamp") or now.isoformat()))
        if event_time.tzinfo is None:event_time=event_time.replace(tzinfo=timezone.utc)
        event_time=event_time.astimezone(timezone.utc); event_text=event_time.isoformat(); keys=entity_keys(event)
        with self.connect() as c:
            candidates=c.execute("SELECT * FROM incidents WHERE status IN ('open','investigating') ORDER BY updated_at DESC LIMIT 250").fetchall()
            chosen=None; best=(0,[])
            for candidate in candidates:
                try:
                    first=datetime.fromisoformat(candidate["first_seen"]); last=datetime.fromisoformat(candidate["last_seen"])
                    distance=first-event_time if event_time<first else event_time-last if event_time>last else timedelta(0)
                    if distance>timedelta(minutes=window_minutes):continue
                except (TypeError,ValueError):continue
                score,matched=score_entities(keys,json.loads(candidate["entity_keys_json"] or "{}"))
                if score>=3 and score>best[0]:chosen,best=candidate,(score,matched)
            if chosen:
                from .risk import fuse_incident_score
                iid=chosen["incident_id"]; ids=json.loads(chosen["alert_ids"])
                if alert["alert_id"] not in ids:ids.append(alert["alert_id"])
                techniques=sorted(set(json.loads(chosen["technique_ids"])+alert["technique_ids"]))
                old=json.loads(chosen["entity_keys_json"] or "{}"); merged={**old,**{k:v for k,v in keys.items() if not old.get(k)}}
                timeline=json.loads(chosen["timeline_json"])
                timeline.append({"at":event_text,"ingested_at":alert["created_at"],"alert_id":alert["alert_id"],"title":alert["title"],"event_id":alert["event_id"],"correlation":{"score":best[0],"matched_entities":best[1]}})
                timeline.sort(key=lambda x:x["at"])
                severity=max([chosen["severity"],alert["severity"]],key=lambda x:{"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(x,0))
                c.execute("UPDATE incidents SET severity=?,first_seen=?,last_seen=?,technique_ids=?,alert_ids=?,timeline_json=?,updated_at=?,entity_keys_json=?,risk_score=? WHERE incident_id=?",
                  (severity,min(first,event_time).isoformat(),max(last,event_time).isoformat(),json.dumps(techniques),json.dumps(ids),json.dumps(timeline),now.isoformat(),json.dumps(merged),fuse_incident_score(int(chosen["risk_score"]),int(alert.get("risk_score",0)),len(ids)),iid))
            else:
                iid=str(uuid.uuid4()); timeline=[{"at":event_text,"ingested_at":alert["created_at"],"alert_id":alert["alert_id"],"title":alert["title"],"event_id":alert["event_id"],"correlation":{"score":0,"matched_entities":[]}}]
                c.execute("""INSERT INTO incidents(incident_id,title,severity,status,first_seen,last_seen,host_name,user_name,technique_ids,alert_ids,timeline_json,updated_at,entity_keys_json,risk_score) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (iid,f"Suspicious activity on {event.get('host_name') or event.get('user_name') or 'unknown entity'}",alert["severity"],"open",event_text,event_text,event.get("host_name"),event.get("user_name"),json.dumps(alert["technique_ids"]),json.dumps([alert["alert_id"]]),json.dumps(timeline),now.isoformat(),json.dumps(keys),int(alert.get("risk_score",0))))
            c.execute("INSERT INTO audit_log(action,object_type,object_id,actor,details_json,created_at) VALUES(?,?,?,?,?,?)",("incident_correlated","incident",iid,"detection-engine",json.dumps({"alert_id":alert["alert_id"],"event_id":alert["event_id"],"entity_keys":keys,"match_score":best[0],"matched_entities":best[1]}),now.isoformat()))
            return iid
    def incidents(self,limit=100):
        with self.connect() as c:rows=c.execute("SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",(min(limit,1000),)).fetchall()
        out=[]
        for row in rows:
            x=dict(row); x["technique_ids"]=json.loads(x["technique_ids"]); x["alert_ids"]=json.loads(x["alert_ids"]); x["timeline"]=json.loads(x.pop("timeline_json")); x["entities"]=json.loads(x.pop("entity_keys_json") or "{}"); out.append(x)
        return out
    def incident_by_id(self,iid):return next((x for x in self.incidents(1000) if x["incident_id"]==iid),None)
    def update_incident(self,iid,status,actor="analyst"):
        if status not in {"open","investigating","resolved","false_positive"}:raise ValueError("invalid status")
        now=datetime.now(timezone.utc).isoformat()
        with self.connect() as c:
            cur=c.execute("UPDATE incidents SET status=?,updated_at=? WHERE incident_id=?",(status,now,iid))
            if cur.rowcount:c.execute("INSERT INTO audit_log(action,object_type,object_id,actor,details_json,created_at) VALUES(?,?,?,?,?,?)",("status_changed","incident",iid,actor,json.dumps({"status":status}),now))
            return cur.rowcount==1
    def add_feedback(self,iid,verdict,note,analyst="analyst"):
        if verdict not in {"true_positive","false_positive","benign","needs_review"}:raise ValueError("invalid feedback verdict")
        fid,now=str(uuid.uuid4()),datetime.now(timezone.utc).isoformat()
        with self.connect() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE incident_id=?",(iid,)).fetchone():return None
            c.execute("INSERT INTO incident_feedback VALUES(?,?,?,?,?,?)",(fid,iid,analyst,verdict,note[:4000],now))
            c.execute("INSERT INTO audit_log(action,object_type,object_id,actor,details_json,created_at) VALUES(?,?,?,?,?,?)",("analyst_feedback","incident",iid,analyst,json.dumps({"feedback_id":fid,"verdict":verdict,"note":note[:4000]}),now))
        return {"feedback_id":fid,"incident_id":iid,"analyst":analyst,"verdict":verdict,"note":note[:4000],"created_at":now}
    def feedback(self,iid):
        with self.connect() as c:rows=c.execute("SELECT * FROM incident_feedback WHERE incident_id=? ORDER BY created_at",(iid,)).fetchall()
        return [dict(r) for r in rows]
    def audit(self,object_id=None,limit=100):
        q="SELECT * FROM audit_log"; args=[]
        if object_id:q+=" WHERE object_id=?"; args.append(object_id)
        q+=" ORDER BY created_at DESC LIMIT ?"; args.append(min(limit,1000))
        with self.connect() as c:rows=c.execute(q,args).fetchall()
        return [{**dict(r),"details":json.loads(r["details_json"])} for r in rows]
    def counts(self):
        with self.connect() as c:return {t:c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("events","alerts","incidents","dead_letters")}
