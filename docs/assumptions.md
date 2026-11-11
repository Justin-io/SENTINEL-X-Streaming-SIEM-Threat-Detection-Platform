# Assumptions and provenance

- This is an isolated synthetic-first lab. Never connect to customer, public, or third-party networks.
- Bundled data is synthetic/inert; no commands or network traffic are executed by the generator.
- Initial engineering target: 100 events/sec on developer hardware; benchmark before raising it.
- Normalized schema is ECS-inspired, not full ECS. Raw input is retained under raw_event.
- Naive timestamps are interpreted as UTC. Zeek epoch and Linux audit timestamps are converted to UTC.
- Stable source event IDs are idempotent. Source records without IDs receive a deterministic content hash.
- Default retention is indefinite. Operators must define retention and backup before real telemetry.
- SQLite is authoritative. ClickHouse is an optional mirror; explicit backfill copies existing SQLite records.
- Kafka consumption is at-least-once; event-ID idempotency handles redelivery.
- Domain-qualified identities may correlate across hosts; unqualified usernames remain host-scoped. Only private IPs are correlation keys.
- Sigma support is an explicit subset. Unsupported syntax fails visibly.
- Anomaly and risk scores are heuristics, not calibrated ML or compromise probability.
- No CIC-IDS2017 or third-party dataset is bundled. Verify upstream licence and provenance before import.
- No secrets are required by default. Secure optional services and restrict access outside the laptop lab.
