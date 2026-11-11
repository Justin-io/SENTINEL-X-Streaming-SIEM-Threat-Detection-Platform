"""Optional Kafka consumer and producer; commits after processing."""
from __future__ import annotations
import json
from typing import Any
def encode_event(event:dict[str,Any])->bytes:return json.dumps(event,separators=(",",":"),ensure_ascii=False).encode()
def decode_event(value:bytes)->dict[str,Any]:
 result=json.loads(value.decode())
 if not isinstance(result,dict):raise ValueError("Kafka event payload must be a JSON object")
 return result
async def consume_events(pipeline,bootstrap_servers,topic="sentinel.events",group_id="sentinel-x-ingest",client_id="sentinel-x-worker"):
 try:from aiokafka import AIOKafkaConsumer
 except ImportError as exc:raise RuntimeError("Kafka worker requires optional aiokafka dependency") from exc
 consumer=AIOKafkaConsumer(topic,bootstrap_servers=bootstrap_servers,group_id=group_id,client_id=client_id,enable_auto_commit=False,auto_offset_reset="earliest")
 await consumer.start(); processed=0
 try:
  async for message in consumer:
   try:payload=decode_event(message.value)
   except Exception as exc:pipeline.store.dead_letter({"topic":message.topic,"partition":message.partition,"offset":message.offset,"payload_hex":message.value.hex()},f"kafka_decode_error: {exc}")
   else:pipeline.process(payload)
   await consumer.commit(); processed+=1
 finally:await consumer.stop()
 return processed
async def publish_event(payload:dict[str,Any],bootstrap_servers,topic="sentinel.events"):
 try:from aiokafka import AIOKafkaProducer
 except ImportError as exc:raise RuntimeError("Kafka publishing requires optional aiokafka dependency") from exc
 producer=AIOKafkaProducer(bootstrap_servers=bootstrap_servers,enable_idempotence=True); await producer.start()
 try:await producer.send_and_wait(topic,encode_event(payload))
 finally:await producer.stop()
