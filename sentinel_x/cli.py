from __future__ import annotations
import argparse,asyncio,json,os
from pathlib import Path
from .config import DB_PATH,RULES_DIR
from .storage import Store
from .detection import RuleEngine
from .pipeline import Pipeline
from .generator import generate_events,replay
from .clickhouse_sink import configured_sink
from .streaming import consume_events
def build_pipeline():return Pipeline(Store(DB_PATH,clickhouse_sink=configured_sink()),RuleEngine(RULES_DIR))
def main():
 p=argparse.ArgumentParser(prog="sentinel-x"); sub=p.add_subparsers(dest="cmd",required=True)
 g=sub.add_parser("generate"); g.add_argument("--count",type=int,default=100); g.add_argument("--seed",type=int,default=42); g.add_argument("--output",default="data/sample-events.jsonl")
 r=sub.add_parser("replay"); r.add_argument("file"); r.add_argument("--source-type",choices=["zeek","suricata","sysmon-xml","linux-audit"])
 sub.add_parser("stats")
 c=sub.add_parser("consume"); c.add_argument("--bootstrap-servers",default=os.getenv("SENTINEL_KAFKA_BOOTSTRAP_SERVERS","localhost:9092")); c.add_argument("--topic",default=os.getenv("SENTINEL_KAFKA_TOPIC","sentinel.events")); c.add_argument("--group-id",default=os.getenv("SENTINEL_KAFKA_GROUP_ID","sentinel-x-ingest"))
 b=sub.add_parser("backfill-clickhouse"); b.add_argument("--batch-size",type=int,default=500)
 args=p.parse_args()
 if args.cmd=="generate":
  path=Path(args.output); path.parent.mkdir(parents=True,exist_ok=True)
  with path.open("w",encoding="utf-8") as f:
   for event in generate_events(args.count,args.seed):f.write(json.dumps(event,ensure_ascii=False)+"\n")
  print(f"Wrote {args.count} synthetic events to {path}"); return
 pipe=build_pipeline()
 if args.cmd=="replay":
  result=replay(args.file,pipe,args.source_type); print(json.dumps({"processed":len(result),"metrics":pipe.metrics},indent=2))
 elif args.cmd=="backfill-clickhouse":print(json.dumps(pipe.store.backfill_clickhouse(args.batch_size),indent=2))
 elif args.cmd=="consume":
  print("Starting at-least-once Kafka consumer; Ctrl+C to stop."); asyncio.run(consume_events(pipe,args.bootstrap_servers,args.topic,args.group_id))
 else:print(json.dumps({**pipe.store.counts(),**pipe.metrics},indent=2))
if __name__=="__main__":main()
