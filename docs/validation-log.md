# Validation log

Environment: Python 3.13.5, Linux x86_64, five CPUs visible. Docker, Ruff, Kafka and ClickHouse services were unavailable in the build environment.

| Gate | Command | Result |
|---|---|---|
| Unit/API/integration tests | pytest | 47 passed in the local full build |
| Syntax compilation | python -m compileall -q sentinel_x tests scripts | Passed |
| Compose manifest | PyYAML parse and required service assertions | Passed; containers not run |
| Packaging | pip wheel --no-deps --no-build-isolation | Passed; Sigma and native rule data included once |
| Benchmark | python scripts/benchmark.py 1500 3 | Three runs per mode; see reports/benchmark.json |
| Ruff | ruff check sentinel_x tests scripts | Not run; executable unavailable and package index inaccessible |
| Docker runtime | docker compose up --build | Not run; Docker unavailable |
| Kafka/ClickHouse/OTLP | Optional profiles | Not run; services/clients unavailable |

Measured synthetic benchmark medians: baseline 1,352.3 events/s, p50 0.667 ms, p95 0.909 ms; full pipeline 617.6 events/s, p50 1.295 ms, p95 3.255 ms. Last full run: 1,500 accepted, 203 alerts, 6 anomaly alerts, 3 incidents, zero dead letters. This is sequential synthetic data, not field performance.

Backtracking corrections: fixed JSONL newline output; aligned Windows Users/Public matching fixtures; changed correlation windows to source event time and sorted case timelines by event time; made SQLite authoritative for event hunting and added explicit ClickHouse backfill; preserved full Sysmon XML in raw evidence; narrowed ATT&CK mapping for weak indicators.

Not measured: labelled precision/recall, endpoint-day false positives, correlation precision, live broker lag, concurrent drops, or production capacity. These require labelled representative data and real infrastructure.
