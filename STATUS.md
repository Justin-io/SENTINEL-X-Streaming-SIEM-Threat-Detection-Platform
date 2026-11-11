# SENTINEL-X implementation status

## Implemented
- ECS-inspired normalization and immutable raw source evidence.
- Sysmon XML, Linux audit, Zeek JSON and Suricata EVE adapters.
- FastAPI ingestion/bulk API, JSONL generator and replay.
- SQLite WAL, idempotency, dead letters, audited duplicate suppression.
- Six deterministic rules and an explicit Sigma syntax subset.
- Median/MAD host-rate anomaly heuristic with evidence.
- Weighted host, domain identity, process ancestry and private-IP event-time correlation.
- Incident timeline, ATT&CK context, heuristic risk ranking, analyst feedback and audit.
- Analyst dashboard, hunt APIs and Prometheus metrics.
- Optional Kafka consumer/producer, ClickHouse mirror/backfill and OTLP tracing.
- Dockerfile, Compose profiles, CI, benchmark and documentation.
- 47 local unit/API/integration tests passed; syntax compile and wheel build passed.

## External validation still required
- Full Sigma language/backend conformance is not implemented.
- Docker, Kafka, ClickHouse and OTLP service runtime tests were unavailable locally.
- Ruff was unavailable locally.
- Labelled dataset detection quality and correlation precision are not established.
- Authentication, RBAC, TLS, tenant isolation, backup/restore and retention controls are required before non-lab use.

The application is lab-only. The anomaly and risk scores are heuristics, not calibrated probabilities.
