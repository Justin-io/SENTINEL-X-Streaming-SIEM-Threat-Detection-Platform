"""Optional ClickHouse event mirror; SQLite remains authoritative."""
from __future__ import annotations
from datetime import datetime,timezone
import os,json
class ClickHouseEventSink:
 def __init__(self,host=None,port=None,username=None,password=None,database=None):
  try:import clickhouse_connect
  except ImportError as exc:raise RuntimeError("Install the optional clickhouse-connect dependency") from exc
  self.client=clickhouse_connect.get_client(host=host or os.getenv("SENTINEL_CLICKHOUSE_HOST","localhost"),port=port or int(os.getenv("SENTINEL_CLICKHOUSE_PORT","8123")),username=username or os.getenv("SENTINEL_CLICKHOUSE_USER","default"),password=password if password is not None else os.getenv("SENTINEL_CLICKHOUSE_PASSWORD",""),database=database or os.getenv("SENTINEL_CLICKHOUSE_DATABASE","default"))
  self.client.command("""CREATE TABLE IF NOT EXISTS sentinel_events(event_id String,event_time DateTime64(3,'UTC'),source_type LowCardinality(String),host_name Nullable(String),user_name Nullable(String),source_ip Nullable(String),destination_ip Nullable(String),normalized_json String,raw_json String,ingested_at DateTime64(3,'UTC')) ENGINE=ReplacingMergeTree(ingested_at) ORDER BY(event_id)""")
 @staticmethod
 def _event_row(event,ingested_at):
  data=event.model_dump(mode="json")
  return [event.event_id,event.timestamp.astimezone(timezone.utc),event.source_type,event.host_name,event.user_name,event.source_ip,event.destination_ip,json.dumps(data),json.dumps(event.raw_event),datetime.fromisoformat(ingested_at).astimezone(timezone.utc)]
 def insert_event(self,event,ingested_at):self.insert_events([(event,ingested_at)])
 def insert_events(self,records):
  if not records:return
  rows=[self._event_row(e,t) for e,t in records]
  self.client.insert("sentinel_events",rows,column_names=["event_id","event_time","source_type","host_name","user_name","source_ip","destination_ip","normalized_json","raw_json","ingested_at"])
 def events(self,limit=100,host=None,user=None,source_type=None,action=None,ip=None):
  conditions=[]; params={"limit":min(max(int(limit),1),1000)}
  for col,val,key in (("host_name",host,"host"),("user_name",user,"user"),("source_type",source_type,"source_type")):
   if val:conditions.append(f"{col}={{{key}:String}}"); params[key]=val
  if action:conditions.append("JSONExtractString(normalized_json,'event_action')={action:String}"); params["action"]=action
  if ip:conditions.append("(source_ip={ip:String} OR destination_ip={ip:String})"); params["ip"]=ip
  where=" WHERE "+" AND ".join(conditions) if conditions else ""
  result=self.client.query("SELECT normalized_json FROM sentinel_events FINAL"+where+" ORDER BY event_time DESC LIMIT {limit:UInt32}",parameters=params)
  return [json.loads(row[0]) for row in result.result_rows]
 def health(self):
  ok=self.client.query("SELECT 1").result_rows
  count=self.client.query("SELECT count() FROM sentinel_events").result_rows[0][0]
  return {"status":"ok" if ok and ok[0][0]==1 else "degraded","backend":"clickhouse-event-mirror","events":count}
 def close(self):self.client.close()
def configured_sink():
 return ClickHouseEventSink() if os.getenv("SENTINEL_CLICKHOUSE_ENABLED","false").lower() in {"1","true","yes"} else None
