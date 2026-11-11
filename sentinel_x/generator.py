from __future__ import annotations
import random,uuid
from datetime import datetime,timezone,timedelta
def generate_events(count=100,seed=42,start_time=None):
 """Generate inert synthetic records; fixed seed/time anchor are reproducible."""
 if count<0:raise ValueError("count must be non-negative")
 rng=random.Random(seed); anchor=start_time or datetime.now(timezone.utc); events=[]; hosts=["lab-win-01","lab-linux-01","lab-web-01"]
 for i in range(count):
  ts=(anchor-timedelta(seconds=count-i)).isoformat(); host=rng.choice(hosts)
  base={"event_id":str(uuid.uuid5(uuid.NAMESPACE_URL,f"sentinel-x:{seed}:{i}:{ts}")),"timestamp":ts,"source_type":rng.choice(["sysmon","linux_audit","zeek","suricata"]),"host_name":host,"user_name":rng.choice(["alice","bob","svc-web"]),"severity":"info"}
  if i%23==0:base.update({"source_type":"sysmon","event_action":"process_create","process_name":"powershell.exe","process_command_line":"powershell.exe -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA","process_parent_name":"winword.exe","event_category":["process"],"event_type":["start"]})
  elif i%29==0:base.update({"source_type":"linux_audit","event_action":"auth_failure","outcome":"failure","user_name":"root","event_category":["authentication"]})
  elif i%31==0:base.update({"source_type":"zeek","event_action":"connection","destination_port":4444,"destination_ip":"198.51.100.23","source_ip":"10.10.0.8","network_protocol":"tcp","event_category":["network"]})
  elif i%41==0:base.update({"source_type":"suricata","event_action":"flow","destination_port":443,"destination_ip":"203.0.113.25","source_ip":"10.10.0.9","network_protocol":"tcp","event_category":["network"]})
  elif i%37==0:base.update({"source_type":"sysmon","event_action":"file_create","file_path":r"C:\Users\Public\startup.exe","process_name":"unknown.exe","event_category":["file"]})
  else:base.update({"event_action":"normal_activity","process_name":rng.choice(["chrome.exe","sshd","nginx"]),"event_category":["process"]})
  events.append(base)
 return events
def replay(path,pipeline,source_type=None):
 from .parsers import iter_telemetry_records
 results=[]
 try:
  for record in iter_telemetry_records(str(path),source_type):results.append(pipeline.process(record))
 except Exception as exc:
  pipeline.store.dead_letter({"path":str(path),"source_type":source_type},str(exc)); raise
 return results
