from __future__ import annotations
import os,time
from fastapi import FastAPI,HTTPException,Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel,Field
from prometheus_client import Counter,Histogram,generate_latest,CONTENT_TYPE_LATEST
from starlette.responses import Response
from .config import DB_PATH,RULES_DIR
from .storage import Store
from .detection import RuleEngine
from .pipeline import Pipeline
from .clickhouse_sink import configured_sink
from .streaming import publish_event
from .telemetry import configure_telemetry

app=FastAPI(title="SENTINEL-X SIEM API",version="0.2.0",description="Synthetic-first lab SIEM.")
store=Store(DB_PATH,clickhouse_sink=configured_sink()); engine=RuleEngine(RULES_DIR); pipeline=Pipeline(store,engine)
OTEL_CONFIGURED=configure_telemetry(app)
INGESTED=Counter("sentinel_events_ingested_total","Accepted normalized events")
ALERTED=Counter("sentinel_alerts_created_total","New alerts")
DEAD=Counter("sentinel_dead_letters_total","Dead-letter records")
REQUESTS=Counter("sentinel_http_requests_total","HTTP requests",["method","route","status"])
DURATION=Histogram("sentinel_http_request_duration_seconds","HTTP request duration",["method","route"])
class IncidentStatus(BaseModel):
 status:str
 actor:str="analyst"
class IncidentFeedback(BaseModel):
 verdict:str
 note:str=Field(default="",max_length=4000)
 analyst:str="analyst"

DASHBOARD="""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>SENTINEL-X</title><style>
body{margin:0;background:#080d18;color:#e5edf8;font:14px system-ui}main{max-width:1200px;margin:auto;padding:28px}h1{letter-spacing:3px}.muted,small{color:#91a4bd}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card{background:#111c2d;border:1px solid #26364e;border-radius:12px;padding:16px;margin:12px 0}.metric{font-size:26px;font-weight:700}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #26364e}button,input,select{background:#0b1422;color:#e5edf8;border:1px solid #26364e;border-radius:7px;padding:9px}button{cursor:pointer}.high,.critical{color:#ff7180}.medium{color:#f4c36f}.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:750px){.grid{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}main{padding:14px}}</style></head><body><main><small>SYNTHETIC-FIRST LAB SIEM</small><h1>SENTINEL-X</h1><p class=muted>Evidence-first threat detection and incident triage</p><div id=health class=muted>Loading service…</div><section class=grid id=metrics></section><section class=card><h2>Incident queue</h2><input id=q placeholder='Search incidents' oninput=render()><select id=status onchange=render()><option value=''>All statuses</option><option>open</option><option>investigating</option><option>resolved</option><option>false_positive</option></select><div style='overflow:auto'><table><thead><tr><th>Severity</th><th>Risk</th><th>Incident</th><th>Entity</th><th>Status</th><th>Alerts</th></tr></thead><tbody id=incidents></tbody></table></div></section><section class=split><div class=card><h2>Recent alerts</h2><div id=alerts></div></div><div class=card><h2>Event hunt</h2><input id=host placeholder=Host><input id=ip placeholder=IP><button onclick=hunt()>Search</button><div id=events></div></div></section><p><a href=/docs>API docs</a> · <a href=/metrics>Metrics</a></p></main><script>
let cases=[],alerts=[];const $=x=>document.getElementById(x),esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function get(u){let r=await fetch(u);if(!r.ok)throw Error(await r.text());return r.json()}
async function refresh(){try{let [h,m,c,a]=await Promise.all([get('/health'),get('/api/v1/metrics'),get('/api/v1/incidents'),get('/api/v1/alerts')]);$('health').textContent='SERVICE '+h.status.toUpperCase()+' · '+h.rules_loaded+' RULES';cases=c;alerts=a;$('metrics').innerHTML=Object.entries(m).map(([k,v])=>'<div class=card><small>'+esc(k.replaceAll('_',' '))+'</small><div class=metric>'+esc(v)+'</div></div>').join('');render();$('alerts').innerHTML=alerts.slice(0,20).map(a=>'<p><b>'+esc(a.rule_id)+'</b> '+esc(a.title)+' <small>'+esc(a.severity)+' · risk '+esc(a.risk_score)+'</small></p>').join('')}catch(e){$('health').textContent='SERVICE DEGRADED';console.error(e)}}
function render(){let q=$('q').value.toLowerCase(),s=$('status').value;let rows=cases.filter(x=>(!s||x.status===s)&&JSON.stringify(x).toLowerCase().includes(q));$('incidents').innerHTML=rows.map(i=>'<tr><td class='+esc(i.severity)+'>'+esc(i.severity)+'</td><td>'+esc(i.risk_score)+'/100</td><td>'+esc(i.title)+'<br><small>'+esc(i.incident_id)+'</small><br>'+i.timeline.map(t=>'<small>'+esc(t.at)+' · '+esc(t.title)+'</small>').join('<br>')+'</td><td>'+esc(i.host_name||i.user_name)+'</td><td>'+esc(i.status)+'</td><td>'+i.alert_ids.length+'<br><button onclick="setStatus(\''+esc(i.incident_id)+'\',\'investigating\')">Investigate</button> <button onclick="setStatus(\''+esc(i.incident_id)+'\',\'resolved\')">Resolve</button> <button onclick="feedback(\''+esc(i.incident_id)+'\')">Feedback</button></td></tr>').join('')||'<tr><td colspan=6>No incidents</td></tr>'}
async function setStatus(id,status){await fetch('/api/v1/incidents/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status,actor:'dashboard'})});await refresh()}
async function feedback(id){let verdict=prompt('Verdict: true_positive / false_positive / benign / needs_review','needs_review');if(!verdict)return;let note=prompt('Analyst note','')||'';let r=await fetch('/api/v1/incidents/'+id+'/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({verdict,note,analyst:'dashboard'})});if(!r.ok)alert(await r.text());await refresh()}
async function hunt(){let p=new URLSearchParams();if($('host').value)p.set('host',$('host').value);if($('ip').value)p.set('ip',$('ip').value);let data=await get('/api/v1/events?'+p);$('events').innerHTML=data.slice(0,30).map(e=>'<p><b>'+esc(e.event_action||e.process_name||e.source_type)+'</b><br><small>'+esc(e.timestamp)+' · '+esc(e.host_name)+' · '+esc(e.source_ip)+' → '+esc(e.destination_ip)+'</small></p>').join('')||'No events'}
refresh();setInterval(refresh,15000)</script></body></html>"""

@app.middleware("http")
async def observe_http(request,call_next):
 started=time.perf_counter(); status="500"
 try:
  response=await call_next(request); status=str(response.status_code); return response
 finally:
  route=getattr(request.scope.get("route"),"path",request.url.path)
  REQUESTS.labels(request.method,route,status).inc(); DURATION.labels(request.method,route).observe(time.perf_counter()-started)

@app.get("/",response_class=HTMLResponse)
def dashboard():return DASHBOARD
@app.get("/health")
def health():
 out={"status":"ok","storage":"sqlite-wal-authoritative","rules_loaded":len(engine.rules),"clickhouse_enabled":bool(store.clickhouse_sink),"kafka_enabled":os.getenv("SENTINEL_KAFKA_ENABLED","false").lower() in {"1","true","yes"},"opentelemetry_enabled":OTEL_CONFIGURED}
 if store.clickhouse_sink:
  try:out["clickhouse"]=store.clickhouse_sink.health()
  except Exception as exc:out.update(status="degraded",clickhouse_error=str(exc))
 return out

def process_with_metrics(payload,source_type=None):
 invalid=pipeline.metrics["invalid"]; result=pipeline.process(payload,source_type)
 if result.get("accepted"):INGESTED.inc()
 ALERTED.inc(len(result.get("alerts",[])))
 if pipeline.metrics["invalid"]>invalid:DEAD.inc()
 return result
@app.post("/api/v1/events")
def ingest(payload:dict,source_type:str|None=None):
 result=process_with_metrics(payload,source_type)
 if result.get("error"):raise HTTPException(422,result)
 return result
@app.post("/api/v1/events/bulk")
def bulk(payload:list[dict]):
 if len(payload)>1000:raise HTTPException(413,"batch limit is 1000")
 return {"results":[process_with_metrics(x) for x in payload]}
@app.get("/api/v1/events")
def get_events(limit:int=Query(100,ge=1,le=1000),host:str|None=None,user:str|None=None,source_type:str|None=None,action:str|None=None,ip:str|None=None):
 return store.events(limit=limit,host=host,user=user,source_type=source_type,action=action,ip=ip)
@app.get("/api/v1/analytics/events")
def analytics_events(limit:int=Query(100,ge=1,le=1000),host:str|None=None,user:str|None=None,source_type:str|None=None,action:str|None=None,ip:str|None=None):
 try:return store.analytics_events(limit=limit,host=host,user=user,source_type=source_type,action=action,ip=ip)
 except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
 except Exception as exc:raise HTTPException(502,f"ClickHouse query failed: {exc}") from exc
@app.get("/api/v1/alerts")
def get_alerts(limit:int=Query(100,ge=1,le=1000)):return store.alerts(limit)
@app.get("/api/v1/incidents")
def get_incidents(limit:int=Query(100,ge=1,le=1000)):return store.incidents(limit)
@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id:str):
 item=store.incident_by_id(incident_id)
 if not item:raise HTTPException(404,"incident not found")
 item["feedback"]=store.feedback(incident_id); item["audit"]=store.audit(incident_id); return item
@app.patch("/api/v1/incidents/{incident_id}")
def update_incident(incident_id:str,payload:IncidentStatus):
 try:ok=store.update_incident(incident_id,payload.status,payload.actor)
 except ValueError as exc:raise HTTPException(422,str(exc)) from exc
 if not ok:raise HTTPException(404,"incident not found")
 return {"updated":True,"incident_id":incident_id,"status":payload.status}
@app.post("/api/v1/incidents/{incident_id}/feedback")
def incident_feedback(incident_id:str,payload:IncidentFeedback):
 try:result=store.add_feedback(incident_id,payload.verdict,payload.note,payload.analyst)
 except ValueError as exc:raise HTTPException(422,str(exc)) from exc
 if not result:raise HTTPException(404,"incident not found")
 return result
@app.get("/api/v1/incidents/{incident_id}/audit")
def incident_audit(incident_id:str):
 if not store.incident_by_id(incident_id):raise HTTPException(404,"incident not found")
 return store.audit(incident_id)
@app.post("/api/v1/stream/publish")
async def stream_publish(payload:dict):
 if os.getenv("SENTINEL_KAFKA_ENABLED","false").lower() not in {"1","true","yes"}:raise HTTPException(503,"Kafka publishing is disabled")
 try:await publish_event(payload,os.getenv("SENTINEL_KAFKA_BOOTSTRAP_SERVERS","redpanda:9092"),os.getenv("SENTINEL_KAFKA_TOPIC","sentinel.events"))
 except RuntimeError as exc:raise HTTPException(503,str(exc)) from exc
 except Exception as exc:raise HTTPException(502,f"Kafka publish failed: {exc}") from exc
 return {"published":True}
@app.get("/metrics")
def metrics():return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
@app.get("/api/v1/metrics")
def app_metrics():return {**pipeline.metrics,**store.counts(),"loaded_rules":len(engine.rules)}
