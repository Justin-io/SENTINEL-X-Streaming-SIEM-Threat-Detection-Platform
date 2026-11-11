from __future__ import annotations
import csv,json,os,platform,resource,statistics,sys,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from sentinel_x.storage import Store
from sentinel_x.detection import RuleEngine
from sentinel_x.pipeline import Pipeline
from sentinel_x.normalize import normalize
from sentinel_x.generator import generate_events
OUT=ROOT/"reports"; OUT.mkdir(exist_ok=True)
N=int(sys.argv[1]) if len(sys.argv)>1 else 1500
ROUNDS=int(sys.argv[2]) if len(sys.argv)>2 else 3
ANCHOR=datetime(2026,1,1,tzinfo=timezone.utc); EVENTS=generate_events(N,42,ANCHOR)
def pct(values,p):
 a=sorted(values); return a[min(len(a)-1,max(0,round((len(a)-1)*p)))] if a else 0
def size(path):return sum(x.stat().st_size for x in path.parent.glob(path.name+"*") if x.is_file())
def baseline(path):
 store=Store(path); latency=[]; start=time.perf_counter()
 for payload in EVENTS:
  t=time.perf_counter(); store.ingest(normalize(payload)); latency.append((time.perf_counter()-t)*1000)
 elapsed=time.perf_counter()-start; sz=size(path)
 return {"events_per_second":N/elapsed,"latency_p50_ms":pct(latency,.5),"latency_p95_ms":pct(latency,.95),"storage_bytes_per_million_events":sz*1_000_000/N}
def full(path):
 store=Store(path); pipe=Pipeline(store,RuleEngine(ROOT/"rules")); latency=[]; start=time.perf_counter()
 for payload in EVENTS:
  t=time.perf_counter(); pipe.process(payload); latency.append((time.perf_counter()-t)*1000)
 elapsed=time.perf_counter()-start; sz=size(path)
 return {"events_per_second":N/elapsed,"latency_p50_ms":pct(latency,.5),"latency_p95_ms":pct(latency,.95),"storage_bytes_per_million_events":sz*1_000_000/N,"accepted":pipe.metrics["accepted"],"duplicates":pipe.metrics["duplicates"],"invalid":pipe.metrics["invalid"],"alerts":pipe.metrics["alerts"],"anomaly_alerts":pipe.metrics["anomaly_alerts"],"incidents":store.counts()["incidents"],"dead_letters":store.counts()["dead_letters"]}
runs={"baseline":[],"full_pipeline":[]}
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp)
 for i in range(ROUNDS):
  runs["baseline"].append(baseline(root/f"base-{i}.db")); runs["full_pipeline"].append(full(root/f"full-{i}.db"))
def summary(rows,key):
 v=[r[key] for r in rows]; return {"median":statistics.median(v),"min":min(v),"max":max(v)}
result={"dataset":{"name":"synthetic_lab_mix","events":N,"seed":42,"anchor_time":ANCHOR.isoformat(),"repeated_runs":ROUNDS,"split_strategy":"not applicable; no learned model"},
 "baseline_ingest_only":{k:summary(runs["baseline"],k) for k in ("events_per_second","latency_p50_ms","latency_p95_ms","storage_bytes_per_million_events")},
 "full_detection_pipeline":{k:summary(runs["full_pipeline"],k) for k in ("events_per_second","latency_p50_ms","latency_p95_ms","storage_bytes_per_million_events")},
 "full_pipeline_last_run_counts":{k:runs["full_pipeline"][-1][k] for k in ("accepted","duplicates","invalid","alerts","anomaly_alerts","incidents","dead_letters")},
 "hardware":{"platform":platform.platform(),"python":platform.python_version(),"cpu_count":os.cpu_count(),"max_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},
 "method":"same seeded synthetic records; baseline normalizes and writes; full runs detections, anomaly scoring, alert writes and incident correlation; separate temporary SQLite stores per run",
 "limitations":"Sequential synthetic workload; no labelled ground truth or concurrent transport. Not production throughput or detection quality."}
(OUT/"benchmark.json").write_text(json.dumps(result,indent=2))
with (OUT/"benchmark.csv").open("w",newline="") as f:
 w=csv.writer(f); w.writerow(["mode","run","events_per_second","latency_p50_ms","latency_p95_ms","storage_bytes_per_million_events"])
 for mode,rows in runs.items():
  for i,r in enumerate(rows,1):w.writerow([mode,i,r["events_per_second"],r["latency_p50_ms"],r["latency_p95_ms"],r["storage_bytes_per_million_events"]])
print(json.dumps(result,indent=2))
