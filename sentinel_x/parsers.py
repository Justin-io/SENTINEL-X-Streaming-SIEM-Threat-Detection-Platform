"""Native adapters for Zeek JSON, Suricata EVE, Sysmon XML and Linux audit."""
from __future__ import annotations
import hashlib,json,re,xml.etree.ElementTree as ET
from datetime import datetime,timezone
from typing import Any
def stable_event_id(payload:dict[str,Any])->str:
 return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
def parse_zeek_json(payload):
 ts=payload.get("ts")
 return {"event_id":payload.get("event_id") or stable_event_id(payload),"timestamp":datetime.fromtimestamp(float(ts),timezone.utc).isoformat() if ts is not None else None,"source_type":"zeek","event_category":["network"],"event_action":payload.get("_path") or "connection","source_ip":payload.get("id.orig_h"),"source_port":payload.get("id.orig_p"),"destination_ip":payload.get("id.resp_h"),"destination_port":payload.get("id.resp_p"),"network_protocol":payload.get("proto"),"outcome":payload.get("conn_state"),"raw_event":payload}
def parse_suricata_eve(payload):
 alert=payload.get("alert") or {}; sev={1:"high",2:"medium",3:"low"}.get(alert.get("severity"),"info")
 return {"event_id":payload.get("event_id") or stable_event_id(payload),"timestamp":payload.get("timestamp"),"source_type":"suricata","event_category":["network","intrusion_detection"],"event_action":payload.get("event_type","event"),"source_ip":payload.get("src_ip"),"source_port":payload.get("src_port"),"destination_ip":payload.get("dest_ip"),"destination_port":payload.get("dest_port"),"network_protocol":payload.get("proto"),"severity":sev,"outcome":"alert" if alert else payload.get("event_type"),"tags":[str(alert["signature_id"])] if alert.get("signature_id") else [],"raw_event":payload}
def parse_sysmon_xml(event_xml):
 raw_xml=event_xml if isinstance(event_xml,str) else ET.tostring(event_xml,encoding="unicode")
 element=ET.fromstring(event_xml) if isinstance(event_xml,str) else event_xml
 ns={"e":"http://schemas.microsoft.com/win/2004/08/events/event"}; system=element.find("e:System",ns); data=element.find("e:EventData",ns); values={}
 if data is not None:
  for node in data.findall("e:Data",ns):
   if node.attrib.get("Name"):values[node.attrib["Name"]]=node.text or ""
 eid=system.find("e:EventID",ns) if system is not None else None; comp=system.find("e:Computer",ns) if system is not None else None; tc=system.find("e:TimeCreated",ns) if system is not None else None
 code=int(eid.text) if eid is not None and eid.text else None
 action={1:"process_create",3:"network_connect",5:"process_terminate",7:"image_load",10:"process_access",11:"file_create",22:"dns_query"}.get(code,"sysmon_event")
 out={"event_id":stable_event_id({"event_code":code,"time":tc.attrib.get("SystemTime") if tc is not None else None,"values":values}),"timestamp":tc.attrib.get("SystemTime") if tc is not None else None,"source_type":"sysmon","event_id_code":code,"host_name":comp.text if comp is not None else None,"event_category":["process"] if action.startswith("process") else ["file"] if action=="file_create" else ["network"],"event_action":action,"process_name":values.get("Image"),"process_command_line":values.get("CommandLine"),"process_parent_name":values.get("ParentImage"),"process_parent_command_line":values.get("ParentCommandLine"),"process_pid":values.get("ProcessId"),"process_parent_pid":values.get("ParentProcessId"),"user_name":values.get("User"),"file_path":values.get("TargetFilename"),"raw_event":{"raw_xml":raw_xml,"system":{"event_id":code,"computer":comp.text if comp is not None else None},"event_data":values}}
 return {k:v for k,v in out.items() if v is not None}
_AUDIT_FIELD=re.compile(r"""([A-Za-z_][\w.-]*)=(?:"([^"]*)"|'([^']*)'|(\S+))""")
def parse_linux_audit(line):
 pairs={}
 for m in _AUDIT_FIELD.finditer(line):pairs[m.group(1)]=next((v for v in m.groups()[1:] if v is not None),"")
 typ=pairs.get("type","AUDIT"); success=pairs.get("success","").lower(); result=pairs.get("res","").lower(); failed=success in {"no","false","0"} or result in {"failed","failure","no"}
 if typ in {"USER_AUTH","USER_LOGIN","USER_ACCT"}:action,outcome,category=("auth_failure","failure",["authentication"]) if failed else ("auth_success","success",["authentication"])
 elif typ in {"EXECVE","SYSCALL"}:action,outcome,category="process_exec","success",["process"]
 elif typ in {"PATH","CWD"}:action,outcome,category="file_access","success",["file"]
 else:action,outcome,category=typ.lower(),None,["host"]
 args=[pairs[k] for k in sorted(pairs) if re.fullmatch(r"a\d+",k)]; stamp=re.search(r"audit\((\d+(?:\.\d+)?):\d+\)",line)
 ts=datetime.fromtimestamp(float(stamp.group(1)),timezone.utc).isoformat() if stamp else None
 out={"event_id":stable_event_id({"line":line}),"timestamp":ts,"source_type":"linux_audit","event_category":category,"event_action":action,"host_name":pairs.get("node"),"user_name":pairs.get("acct") or pairs.get("auid") or pairs.get("uid"),"process_name":pairs.get("comm") or pairs.get("exe"),"process_command_line":" ".join(args) if args else None,"process_pid":pairs.get("pid"),"process_parent_pid":pairs.get("ppid"),"source_ip":pairs.get("addr"),"outcome":outcome,"severity":"medium" if action=="auth_failure" else "info","raw_event":{"line":line,"fields":pairs}}
 return {k:v for k,v in out.items() if v is not None}
def parse_json_record(payload,source_type=None):
 source=(source_type or payload.get("source_type") or payload.get("source") or "").lower()
 if source in {"zeek","bro"} or "id.orig_h" in payload:return parse_zeek_json(payload)
 if source in {"suricata","eve"} or ("event_type" in payload and ("src_ip" in payload or "dest_ip" in payload)):return parse_suricata_eve(payload)
 return payload
def iter_telemetry_records(path,source_type=None):
 source=(source_type or "").lower()
 if source in {"sysmon-xml","sysmon_xml"}:
  for _,element in ET.iterparse(path,events=("end",)):
   if element.tag.endswith("Event"):yield parse_sysmon_xml(element); element.clear()
  return
 with open(path,encoding="utf-8") as handle:
  for number,line in enumerate(handle,1):
   if not line.strip():continue
   if source in {"linux-audit","linux_audit","audit"}:yield parse_linux_audit(line); continue
   payload=json.loads(line)
   if not isinstance(payload,dict):raise ValueError(f"line {number}: expected a JSON object")
   yield parse_json_record(payload,source or None)
