"""Optional OpenTelemetry FastAPI tracing, disabled by default."""
from __future__ import annotations
import os
def configure_telemetry(app)->bool:
 if os.getenv("SENTINEL_OTEL_ENABLED","false").lower() not in {"1","true","yes"}:return False
 try:
  from opentelemetry import trace
  from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
  from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
  from opentelemetry.sdk.resources import Resource
  from opentelemetry.sdk.trace import TracerProvider
  from opentelemetry.sdk.trace.export import BatchSpanProcessor
 except ImportError as exc:raise RuntimeError("Install the optional observability dependencies") from exc
 provider=TracerProvider(resource=Resource.create({"service.name":os.getenv("OTEL_SERVICE_NAME","sentinel-x")}))
 endpoint=os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT","http://localhost:4318/v1/traces")
 provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
 trace.set_tracer_provider(provider); FastAPIInstrumentor.instrument_app(app,tracer_provider=provider)
 return True
