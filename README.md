# SENTINEL-X — Streaming SIEM & Threat Detection Platform

SENTINEL-X is a synthetic-first lab SIEM that accepts endpoint, Linux and network telemetry; normalizes it into a common event envelope; runs deterministic YAML and Sigma-subset detections plus a robust host-rate anomaly heuristic; correlates evidence into incidents; maps supported findings to MITRE ATT&CK; and provides an analyst dashboard, hunt API, case workflow and metrics.

> **Lab-only boundary:** Do not connect this system to customer, public, or other third-party networks. The included generator creates inert telemetry records; it does not execute adversary techniques or transmit network traffic. ATT&CK tags and risk scores are investigative context, not proof of compromise or attribution.

## One-command lab start

With Docker Engine and the Compose plugin installed:

```bash
docker compose up --build
```

The default stack binds the dashboard/API to `127.0.0.1:8000`, seeds a deterministic synthetic event set, and persists SQLite data in a named volume. Open `http://127.0.0.1:8000`; the interactive API is at `/docs`, Prometheus metrics at `/metrics`.

To stop without deleting stored data:

```bash
docker compose down
```

Do not use `docker compose down -v` unless you intentionally want to delete the lab's persistent event and case data.

## Local Python start

Validated with Python 3.13.5. Core tested dependency versions are pinned in `requirements.txt`.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
uvicorn sentinel_x.api:app --host 127.0.0.1 --port 8000
```

Generate and replay a fresh event set in a second terminal:

```bash
python -m sentinel_x.cli generate --count 250 --seed 42 --output data/lab.jsonl
python -m sentinel_x.cli replay data/lab.jsonl
python -m sentinel_x.cli stats
```

## Source formats

- **Sysmon:** XML event records (`--source-type sysmon-xml`), including process create, network connect and file create IDs.
- **Linux audit:** audit log text (`--source-type linux-audit`), including authentication, process and file events.
- **Zeek:** JSON lines (`--source-type zeek`), mapping `id.orig_h`, `id.resp_h`, ports, protocol, path and connection state.
- **Suricata:** EVE JSON lines (`--source-type suricata`), mapping event type, flow tuple, alert signature and severity.
- **Generic normalized JSON:** direct ingestion and JSONL replay without `--source-type`.

The adapter implementation and field mappings are described in `docs/architecture.md` and `docs/rule-engine.md`. Source records are retained under `raw_event`; Sysmon XML source is preserved in `raw_event.raw_xml`.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/v1/events` | Ingest one JSON event |
| `POST` | `/api/v1/events/bulk` | Ingest at most 1,000 events per request |
| `GET` | `/api/v1/events?host=...&user=...&source_type=...&action=...&ip=...` | Hunt/filter authoritative SQLite events |
| `GET` | `/api/v1/analytics/events?...` | Query the optional ClickHouse mirror explicitly |
| `GET` | `/api/v1/alerts` | Recent alerts with rule evidence, ATT&CK and risk score |
| `GET` | `/api/v1/incidents` | Incident queue and timelines |
| `GET` | `/api/v1/incidents/{id}` | Incident details, feedback and audit records |
| `PATCH` | `/api/v1/incidents/{id}` | Set `open`, `investigating`, `resolved` or `false_positive` |
| `POST` | `/api/v1/incidents/{id}/feedback` | Record true-positive, false-positive, benign or needs-review feedback |
| `GET` | `/api/v1/incidents/{id}/audit` | Inspect incident audit history |
| `POST` | `/api/v1/stream/publish` | Publish JSON to Kafka when enabled |
| `GET` | `/health` | Service and optional dependency state |
| `GET` | `/api/v1/metrics`, `/metrics` | Application counters and Prometheus exposition |

## Detection catalogue

| Detection | Logic | ATT&CK mapping |
|---|---|---|
| Sigma: Encoded PowerShell from Office | Encoded PowerShell command line with Office parent process; all three selectors must match | T1059.001, T1204.002 |
| SX-002 | Root authentication failure | No direct ATT&CK mapping for a single failure |
| SX-003 | TCP connection to lab port 4444 | T1571 |
| SX-004 | Executable created under `Users\\Public` | No direct mapping |
| SX-005 | Bash launched by nginx | T1059.004 |
| SX-006 | Connection to SSH/RDP port | T1021 |
| SX-ANOM-001 | Per-host minute event rate exceeds a median/MAD baseline | No ATT&CK mapping; generic rate signal |

The Sigma adapter supports an explicit subset, not the full Sigma specification. It handles map selectors, OR value lists, AND field semantics, boolean conditions, parentheses, `1 of` / `all of` patterns, wildcards and common modifiers. Unsupported constructs fail visibly. See `docs/rule-engine.md`.

## Correlation and case triage

The 15-minute incident correlator uses weighted entity keys: host, host-scoped user, domain-qualified identity, process/parent PID scoped by host, and private IP. Public IPs are not used as standalone links because shared infrastructure can produce false correlations. Correlation windows use source event timestamps, and each timeline entry records event time, ingestion time, matched entity keys and correlation score.

Alert and incident risk scores are transparent 0–100 triage rankings based on configured severity and evidence count, with a bounded incident corroboration bonus. They are not calibrated probabilities. Analyst feedback and status changes are audit logged. Duplicate event IDs and duplicate alert IDs are suppressed using database uniqueness constraints and suppression is audit logged; no silent time-based alert suppression is enabled.

## Optional infrastructure profiles

### Redpanda / Kafka

Install the optional client locally with `pip install -e '.[streaming]'`. Start the broker and consumer worker:

```bash
SENTINEL_KAFKA_ENABLED=true docker compose --profile streaming up --build
```

The consumer uses manual offset commits after processing (at-least-once) and event-ID idempotency. Publish to the `sentinel.events` topic using `/api/v1/stream/publish` or a Kafka-compatible producer. Broker recovery and consumer-group load tests must be run before relying on it.

### ClickHouse analytical mirror

Install `pip install -e '.[clickhouse]'`. Start the optional ClickHouse profile and enable the event mirror:

```bash
SENTINEL_CLICKHOUSE_ENABLED=true docker compose --profile analytics up --build
```

SQLite remains authoritative for events, idempotency, alerts and incidents. The normal `/api/v1/events` hunt API always reads SQLite so mirror lag or insert failure cannot hide accepted records. `/api/v1/analytics/events` explicitly queries the mirror. Existing SQLite records are not automatically backfilled. After enabling the analytics profile, run `docker compose --profile analytics exec sentinel-x python -m sentinel_x.cli backfill-clickhouse` (or `sentinel-x backfill-clickhouse` locally) to copy existing evidence in bounded batches. Repeating the command is safe for the `ReplacingMergeTree` event-ID key. Mirror failures are dead-lettered and counted.

### OpenTelemetry tracing

Install `pip install -e '.[observability]'`, then set `SENTINEL_OTEL_ENABLED=true` and `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` to an OTLP/HTTP endpoint (default `http://localhost:4318/v1/traces`). Tracing is disabled by default.

## Benchmark and validation

Run the repeated baseline/full-pipeline benchmark:

```bash
python scripts/benchmark.py 1500 3
```

Machine-readable results are written to `reports/benchmark.json` and `reports/benchmark.csv`; the interpretation is in `reports/benchmark-report.md`. The baseline stores normalized events only; the full mode also runs detections, statistical anomaly evaluation, alert writes, correlation and incident updates.

Tests:

```bash
pytest
python -m compileall -q sentinel_x tests scripts
```

CI runs lint checks and tests. Docker, Redpanda and ClickHouse were not available in the build environment used for this revision, so their container services are not represented as runtime-validated here.

## Data retention, licensing and limitations

- Default retention is indefinite; no TTL or automatic deletion is configured. Define operator-approved retention and backup before importing non-synthetic logs.
- All bundled sample/test telemetry is synthetic. No CIC-IDS2017 or third-party capture data is bundled. Verify upstream provenance, licence and redistribution terms before use.
- There is no API authentication, user role system, TLS termination or production multi-tenancy. Bind to loopback as supplied; do not expose the API to untrusted networks.
- SQLite is a laptop-scale default. ClickHouse is currently an optional analytical mirror, not a transactional replacement for all case data.
- The anomaly rule is an interpretable heuristic, not a trained model. Precision, recall and false positives per endpoint-day require labelled data and have not been established by synthetic fixtures.
- Performance numbers are synthetic microbenchmarks on a single local environment, not production capacity guarantees.

See `docs/architecture.md`, `docs/assumptions.md`, `docs/risk-register.md`, `docs/implementation-plan.md`, `docs/validation-log.md`, `docs/official-references.md` and `reports/benchmark-report.md` for detailed decisions and evidence.
