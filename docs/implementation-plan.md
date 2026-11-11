# Implementation plan

| Milestone | Deliverable | Acceptance evidence | Status |
|---|---|---|---|
| 1 | Threat scenarios, schema, volume and retention | Assumptions and architecture docs | Complete |
| 2 | Synthetic generator and importers | Seeded generator; Zeek, Suricata, Sysmon XML, Linux audit | Complete |
| 3 | Ingestion, validation, DLQ, idempotency, raw retention | FastAPI, SQLite WAL, tests | Complete |
| 4 | Deterministic detections and Sigma adapter | Native rules, Sigma subset, positive/negative tests | Complete for documented subset |
| 5 | Entity and time correlation | Host, identity, process ancestry, private IP, event-time tests | Complete for documented model |
| 6 | Anomaly and risk scoring | Median/MAD heuristic and transparent triage score | Partial by design; no trained ML |
| 7 | Timeline, ATT&CK, hunt and feedback | Dashboard, APIs, audit and feedback tests | Complete |
| 8 | Deployment, CI and benchmark | Compose, CI and repeated benchmark | Partial; Docker and optional services not runtime-tested here |

## Next external gates

1. Run Docker Compose on a Docker-enabled host.
2. Exercise Redpanda recovery and consumer redelivery.
3. Validate ClickHouse mirror recovery and backfill.
4. Run Ruff and resolve any findings.
5. Evaluate on labelled, licensed representative telemetry.
6. Add authentication, RBAC, TLS, backup/restore and explicit retention before non-lab use.
