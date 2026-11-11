from pathlib import Path
from datetime import datetime,timezone,timedelta
import json,pytest  # noqa: F401
from fastapi.testclient import TestClient
from sentinel_x.storage import Store
from sentinel_x.detection import RuleEngine
from sentinel_x.pipeline import Pipeline
from sentinel_x.generator import generate_events,replay  # noqa: F401
from sentinel_x.api import app

RULES=Path(__file__).parents[1]/"rules"
def make_pipe(tmp_path):return Pipeline(Store(tmp_path/"test.db"),RuleEngine(RULES))

def test_sigma_positive_and_attack_tags(tmp_path):
 p=make_pipe(tmp_path); r=p.process({"event_id":"sigma-pos","process_name":"powershell.exe","process_command_line":"powershell -enc AAA","process_parent_name":"winword.exe"})
 a=next(x for x in r["alerts"] if x["rule_id"].startswith("7dd2"))
 assert a["technique_ids"]==["T1059.001","T1204.002"]
def test_sigma_negative_parent(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"sigma-neg","process_name":"powershell.exe","process_command_line":"powershell -enc AAA","process_parent_name":"explorer.exe"})
 assert not any(x["rule_id"].startswith("7dd2") for x in r["alerts"])
def test_root_auth_rule(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"auth","event_action":"auth_failure","user_name":"root","outcome":"failure"})
 assert "SX-002" in [x["rule_id"] for x in r["alerts"]]
def test_network_port_rule(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"port","destination_port":4444,"network_protocol":"tcp"})
 assert "SX-003" in [x["rule_id"] for x in r["alerts"]]
def test_public_path_rule(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"path","event_action":"file_create","file_path":r"C:\Users\Public\x.exe"})
 assert "SX-004" in [x["rule_id"] for x in r["alerts"]]
def test_web_shell_rule(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"shell","process_name":"/bin/bash","process_parent_name":"nginx"})
 assert "SX-005" in [x["rule_id"] for x in r["alerts"]]
def test_admin_port_rule(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"ssh","destination_port":22})
 assert "SX-006" in [x["rule_id"] for x in r["alerts"]]
def test_duplicate_event_is_suppressed_and_audited(tmp_path):
 p=make_pipe(tmp_path); e={"event_id":"dup","event_action":"normal"}
 assert p.process(e)["accepted"] and p.process(e)["duplicate"]
 assert any(x["action"]=="event_duplicate_suppressed" for x in p.store.audit())
def test_raw_payload_preserved(tmp_path):
 p=make_pipe(tmp_path); p.process({"event_id":"raw","custom_field":"preserve"})
 assert p.store.event_by_id("raw")["raw_event"]["custom_field"]=="preserve"
def test_invalid_timestamp_dead_lettered(tmp_path):
 p=make_pipe(tmp_path); r=p.process({"event_id":"bad","timestamp":"not-time"})
 assert not r["accepted"] and p.store.counts()["dead_letters"]==1
def test_incident_correlates_same_host_user(tmp_path):
 p=make_pipe(tmp_path)
 p.process({"event_id":"case1","host_name":"w1","user_name":"alice","process_name":"powershell","process_command_line":"-enc","process_parent_name":"winword"})
 p.process({"event_id":"case2","host_name":"w1","user_name":"alice","destination_port":4444,"network_protocol":"tcp"})
 assert len(p.store.incidents())==1 and len(p.store.incidents()[0]["alert_ids"])==2
def test_correlation_uses_private_ip_cross_host(tmp_path):
 p=make_pipe(tmp_path)
 p.process({"event_id":"ip1","host_name":"a","source_ip":"10.1.1.4","destination_port":4444,"network_protocol":"tcp"})
 p.process({"event_id":"ip2","host_name":"b","destination_ip":"10.1.1.4","destination_port":22})
 assert len(p.store.incidents())==1
def test_public_ip_does_not_correlate(tmp_path):
 p=make_pipe(tmp_path)
 p.process({"event_id":"pub1","host_name":"a","destination_ip":"8.8.8.8","destination_port":4444,"network_protocol":"tcp"})
 p.process({"event_id":"pub2","host_name":"b","destination_ip":"8.8.8.8","destination_port":22})
 assert len(p.store.incidents())==2
def test_event_time_window_and_timeline_sort(tmp_path):
 p=make_pipe(tmp_path); t=datetime(2024,1,1,tzinfo=timezone.utc)
 for name,minute in [("t0",0),("t10",10),("t5",5)]:
  p.process({"event_id":name,"timestamp":(t+timedelta(minutes=minute)).isoformat(),"host_name":"timehost","process_name":"bash","process_parent_name":"nginx"})
 case=p.store.incidents()[0]
 assert len(case["alert_ids"])==3 and [x["event_id"] for x in case["timeline"]]==["t0","t5","t10"]
def test_outside_event_time_window_separate(tmp_path):
 p=make_pipe(tmp_path); t=datetime(2024,1,1,tzinfo=timezone.utc)
 for name,minute in [("old",0),("new",30)]:
  p.process({"event_id":name,"timestamp":(t+timedelta(minutes=minute)).isoformat(),"host_name":"same","process_name":"bash","process_parent_name":"nginx"})
 assert len(p.store.incidents())==2
def test_feedback_and_audit(tmp_path):
 p=make_pipe(tmp_path); p.process({"event_id":"fb","host_name":"h","process_name":"bash","process_parent_name":"nginx"})
 i=p.store.incidents()[0]; f=p.store.add_feedback(i["incident_id"],"false_positive","approved","analyst")
 assert f["verdict"]=="false_positive" and p.store.feedback(i["incident_id"])
 assert any(x["action"]=="analyst_feedback" for x in p.store.audit(i["incident_id"]))
def test_burst_detector_requires_baseline_and_fires(tmp_path):
 p=make_pipe(tmp_path); now=datetime.now(timezone.utc).replace(second=0,microsecond=0)
 for minute in range(6,0,-1):
  for index in range(4):p.process({"event_id":f"b{minute}-{index}","timestamp":(now-timedelta(minutes=minute,seconds=15-index)).isoformat(),"host_name":"burst","event_action":"normal"})
 found=[]
 for index in range(14):found+=p.process({"event_id":f"spike{index}","timestamp":(now+timedelta(seconds=index)).isoformat(),"host_name":"burst","event_action":"normal"})["alerts"]
 anomaly=next(x for x in found if x["rule_id"]=="SX-ANOM-001")
 assert anomaly["evidence"]["active_baseline_buckets"]>=5
def test_generator_fixed_seed_and_anchor():
 anchor=datetime(2026,1,1,tzinfo=timezone.utc)
 assert generate_events(20,42,anchor)==generate_events(20,42,anchor)
def test_zeek_adapter():
 from sentinel_x.parsers import parse_zeek_json
 from sentinel_x.normalize import normalize
 e=normalize(parse_zeek_json({"ts":1767225600,"id.orig_h":"10.0.0.1","id.resp_h":"10.0.0.2","id.resp_p":443,"proto":"tcp"}))
 assert e.source_type=="zeek" and e.destination_ip=="10.0.0.2"
def test_suricata_adapter():
 from sentinel_x.parsers import parse_suricata_eve
 from sentinel_x.normalize import normalize
 e=normalize(parse_suricata_eve({"timestamp":"2026-01-01T00:00:00Z","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"203.0.113.5","dest_port":80,"proto":"TCP","alert":{"signature_id":1,"severity":2}}))
 assert e.severity=="medium" and e.tags==["1"]
def test_sysmon_adapter_preserves_raw_xml():
 from sentinel_x.parsers import parse_sysmon_xml
 xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><Computer>WIN</Computer><TimeCreated SystemTime="2026-01-01T00:00:00Z"/></System><EventData><Data Name="Image">powershell.exe</Data><Data Name="ProcessId">123</Data></EventData></Event>'
 e=parse_sysmon_xml(xml); assert e["host_name"]=="WIN" and e["raw_event"]["raw_xml"]==xml
def test_linux_audit_adapter():
 from sentinel_x.parsers import parse_linux_audit
 from sentinel_x.normalize import normalize
 e=normalize(parse_linux_audit('type=USER_AUTH msg=audit(1767225600.123:12): acct="root" addr=10.0.0.9 res=failed'))
 assert e.event_action=="auth_failure" and e.source_ip=="10.0.0.9"
def test_kafka_codec_round_trip():
 from sentinel_x.streaming import encode_event,decode_event
 e={"event_id":"codec","snowman":"☃"}; assert decode_event(encode_event(e))==e
def test_clickhouse_mirror_insert_is_idempotent(tmp_path):
 class Sink:
  def __init__(self):self.ids=[]
  def insert_event(self,event,at):self.ids.append(event.event_id)
 sink=Sink(); store=Store(tmp_path/"mirror.db",sink)
 from sentinel_x.normalize import normalize
 e=normalize({"event_id":"mirror"})
 assert store.ingest(e) and not store.ingest(e) and sink.ids==["mirror"]
def test_clickhouse_backfill_batches(tmp_path):
 store=Store(tmp_path/"backfill.db"); p=Pipeline(store,RuleEngine(RULES))
 for i in range(3):p.process({"event_id":f"backfill{i}"})
 class Sink:
  def __init__(self):self.batches=[]
  def insert_events(self,records):self.batches.append([e.event_id for e,_ in records])
 sink=Sink(); store.clickhouse_sink=sink
 assert store.backfill_clickhouse(2)["copied"]==3 and len(sink.batches)==2
def test_risk_score_is_bounded(tmp_path):
 r=make_pipe(tmp_path).process({"event_id":"risk","process_name":"powershell","process_command_line":"-enc","process_parent_name":"winword"})
 assert 0<=r["alerts"][0]["risk_score"]<=100
def test_api_end_to_end_triage_and_metrics():
 c=TestClient(app); import uuid
 eid="api-"+str(uuid.uuid4())
 r=c.post("/api/v1/events",json={"event_id":eid,"host_name":"api-win","process_name":"powershell","process_command_line":"-enc","process_parent_name":"winword"})
 assert r.status_code==200 and r.json()["alerts"]
 i=next(x for x in c.get("/api/v1/incidents").json() if eid in str(x["timeline"]))
 iid=i["incident_id"]
 assert c.get("/api/v1/incidents/"+iid).status_code==200
 assert c.patch("/api/v1/incidents/"+iid,json={"status":"investigating"}).status_code==200
 assert c.post("/api/v1/incidents/"+iid+"/feedback",json={"verdict":"true_positive","note":"fixture"}).status_code==200
 assert c.get("/metrics").status_code==200 and "SENTINEL-X" in c.get("/").text
def test_api_analytics_unavailable_without_sink(monkeypatch):
 import sentinel_x.api as api
 monkeypatch.setattr(api.store,"clickhouse_sink",None)
 assert TestClient(api.app).get("/api/v1/analytics/events").status_code==503
def test_api_bulk_ingest():
 c=TestClient(app); r=c.post("/api/v1/events/bulk",json=[{"event_id":"bulk-a"},{"event_id":"bulk-b"}])
 assert r.status_code==200 and len(r.json()["results"])==2
def test_compose_profile_manifest():
 import yaml
 p=Path(__file__).parents[1]/"docker-compose.yml"; data=yaml.safe_load(p.read_text())
 assert {"sentinel-x","sentinel-seed","redpanda","sentinel-stream-worker","clickhouse"}<=set(data["services"])
