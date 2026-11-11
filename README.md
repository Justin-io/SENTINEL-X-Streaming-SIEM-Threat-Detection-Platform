# SENTINEL-X — Streaming SIEM & Threat Detection Platform

SENTINEL-X is a synthetic-first lab SIEM for endpoint, Linux and network telemetry. It normalizes source events, preserves raw evidence, runs deterministic YAML and Sigma-subset detections plus a robust event-rate heuristic, correlates alerts into incidents, maps supported findings to MITRE ATT&CK and provides an analyst dashboard, hunt API, case workflow and metrics.

> **Lab-only:** Do not connect this system to customer, public or third-party networks. Synthetic adversary-like records are inert data; no commands or network traffic are executed. ATT&CK mappings and risk scores are investigative context, not proof of compromise or attribution.

## Start the lab

With Docker Engine and Docker Compose installed:

```bash
docker compose up --build
```

Open http://127.0.0.1:8000 (dashboard), /docs (API), or /metrics (Prometheus). The default deployment binds to loopback and persists SQLite data in a named volume. A seed job creates and replays 250 synthetic events. Stop with `docker compose down`; avoid `down -v` unless you intentionally want to delete stored lab evidence.

## Local Python

Python 3.11+:

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn sentinel_x.api:app --host 127.0.0.1 --port 8000
```

Generate and replay telemetry:

```bash
python -m sentinel_x.cli generate --count 250 --seed 42 --output data/lab.jsonl
python -m sentinel_x.cli replay data/lab.jsonl
python -m sentinel_x.cli stats
```

## Supported sources

- Sysmon XML event records: `sentinel-x replay events.xml --source-type sysmon-xml`
- Linux audit text: `sentinel-x replay audit.log --source-type linux-audit`
- Zeek JSON lines: `sentinel-x replay conn.jsonl --source-type zeek`
- Suricata EVE JSON lines: `sentinel-x replay eve.jsonl --source-type suricata`
- Generic normalized JSON through API or JSONL replay.

Original source evidence is retained in `raw_event`; Sysmon XML is preserved as `raw_event.raw_xml`.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | /api/v1/events | Ingest one JSON event |
| POST | /api/v1/events/bulk | Ingest up to 1,000 events |
| GET | /api/v1/events?host=...&user=...&source_type=...&action=...&ip=... | Search authoritative SQLite events |
| GET | /api/v1/analytics/events | Explicitly query optional ClickHouse mirror |
| GET | /api/v1/alerts | Alert evidence, ATT&CK context and risk |
| GET | /api/v1/incidents | Incident queue and timelines |
| GET | /api/v1/incidents/{id} | Case details, feedback and audit |
| PATCH | /api/v1/incidents/{id} | Change status |
| POST | /api/v1/incidents/{id}/feedback | Analyst verdict and note |
| GET | /api/v1/incidents/{id}/audit | Audit history |
| POST | /api/v1/stream/publish | Publish to Kafka when enabled |
| GET | /health | Service and optional dependency state |
| GET | /api/v1/metrics, /metrics | Application and Prometheus metrics |

## Detections

| Rule | Logic | ATT&CK |
|---|---|---|
| Sigma encoded PowerShell | Encoded PowerShell launched by Office; all three selectors must match | T1059.001, T1204.002 |
| SX-002 | Failed root authentication | No direct mapping for a single failure |
| SX-003 | TCP destination port 4444 | T1571 context only |
| SX-004 | File creation under Users/Public | No direct mapping |
| SX-005 | Bash spawned by nginx | T1059.004 context only |
| SX-006 | Connection to SSH/RDP port | T1021 |
| SX-ANOM-001 | Host minute-rate burst above median/MAD baseline | Generic rate signal |

The Sigma adapter is an explicit subset, not full Sigma/pySigma conformance. It supports map selectors, OR value lists, AND field semantics, boolean conditions, parentheses, 1-of/all-of selection patterns, wildcards and common modifiers. Unsupported constructs fail visibly. See docs/rule-engine.md.

## Correlation and triage

The 15-minute correlator uses weighted host, host-scoped user, domain-qualified identity, host-scoped PID/parent PID and private-IP entities. Public IPs are not standalone correlation keys. Windows use source event timestamps, not ingestion wall-clock time; timelines are sorted by event time.

Alert and incident risk scores are transparent 0–100 triage rankings based on severity and evidence count, with a bounded corroboration bonus. They are not calibrated probabilities. Analyst feedback and status changes are audited. Duplicate event and alert suppression is database-enforced and audit logged; no silent time-based suppression is enabled.

## Optional services

### Redpanda/Kafka

Install `pip install -e '.[streaming]'`; start the optional profile:

```bash
SENTINEL_KAFKA_ENABLED=true docker compose --profile streaming up --build
```

The consumer uses manual offset commits after processing (at-least-once); event IDs make replay idempotent. Broker restart and consumer recovery need external validation.

### ClickHouse

Install `pip install -e '.[clickhouse]'`; start:

```bash
SENTINEL_CLICKHOUSE_ENABLED=true docker compose --profile analytics up --build
docker compose --profile analytics exec sentinel-x python -m sentinel_x.cli backfill-clickhouse
```

SQLite remains authoritative for event search, idempotency and cases. ClickHouse is an analytical mirror; `/api/v1/analytics/events` explicitly queries it. The backfill command copies existing SQLite evidence in bounded batches. Mirror errors are dead-lettered and counted.

### OpenTelemetry

Install `pip install -e '.[observability]'`, set `SENTINEL_OTEL_ENABLED=true` and configure `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`. Tracing is disabled by default.

## Tests and benchmark

```bash
pytest
python -m compileall -q sentinel_x tests scripts
python scripts/benchmark.py 1500 3
```

The benchmark compares ingest-only storage with the full detection pipeline on the same synthetic event set, with repeated clean database runs. Results are written to reports/benchmark.json and reports/benchmark.csv.

## Limitations and security

- Default retention is indefinite; no automatic TTL/deletion is configured.
- No third-party dataset is bundled. Verify upstream provenance and licence before importing CIC-IDS2017 or other datasets.
- No API authentication, RBAC, TLS termination or multi-tenancy. Keep the lab on loopback; do not expose it to untrusted networks.
- SQLite is a laptop-scale default. ClickHouse is a mirror, not a transactional replacement for case data.
- The anomaly detector is a statistical heuristic, not trained ML. No labelled precision/recall or false-positive rate is claimed.
- Docker, Redpanda, ClickHouse and OTLP services require environment-level validation; they were unavailable in the build environment used for this implementation.

See docs/architecture.md, docs/assumptions.md, docs/risk-register.md, docs/implementation-plan.md, docs/rule-engine.md, docs/validation-log.md and docs/official-references.md.
