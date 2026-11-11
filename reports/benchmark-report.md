# SENTINEL-X benchmark report

Three repeated runs on 1,500 deterministic synthetic events (seed 42, fixed anchor), each with a fresh SQLite database.

| Metric | Ingest-only median | Full-pipeline median |
|---|---:|---:|
| Throughput | 1,352.3 events/s | 617.6 events/s |
| p50 per-event processing | 0.667 ms | 1.295 ms |
| p95 per-event processing | 0.909 ms | 3.255 ms |
| Extrapolated storage / million | 4.67 GB | 5.15 GB |

The full pipeline reached 45.7% of baseline ingest-only throughput in this sequential synthetic run. Last full run: 1,500 accepted, 0 duplicates, 0 invalid, 203 alerts, 6 anomaly alerts, 3 incidents and 0 dead letters.

Environment: Python 3.13.5, Linux x86_64 container, five CPUs visible, peak RSS 125,852 KiB. Baseline normalizes and stores only; full mode adds rules, median/MAD anomaly detection, alerts, correlation and incident writes.

These results are not concurrent producer throughput, field performance, or capacity guarantees. No labelled ground truth exists; precision, recall, F1, endpoint-day false positives and correlation precision are not reported. Storage extrapolates SQLite file size and varies with raw payloads, WAL checkpointing, indexes and retention.
