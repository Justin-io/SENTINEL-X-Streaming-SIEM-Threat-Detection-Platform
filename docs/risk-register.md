# Risk register

| Risk | Impact | Mitigation / status |
|---|---|---|
| SQLite contention | High | Single-node lab; benchmark; ClickHouse mirror option |
| Sigma syntax gap | High | Explicit subset; unsupported syntax fails closed |
| Detection false positives | High | Positive/negative fixtures; labelled evaluation still required |
| Over-correlation | High | Weighted keys, private IP only, event-time window, visible matched entities |
| PID reuse | Medium | Host-scoped PIDs and short event-time window |
| Private IP reuse/NAT | Medium | Corroborating key only, never a sole compromise claim |
| Anomaly cold start | Medium | Minimum active buckets and minimum history volume |
| Uncalibrated risk score | High | Display as triage priority, not probability |
| ClickHouse divergence | Medium | SQLite authoritative, dead-letter mirror errors, explicit backfill |
| Kafka redelivery | Medium | At-least-once consumer and event-ID idempotency |
| Unbounded retention | Medium | No silent deletion; operator-defined policy required |
| Unauthenticated API | High | Bind loopback; add auth/RBAC/TLS before network exposure |
| ATT&CK overinterpretation | High | Technique tags are contextual, not proof or attribution |
| External dataset licensing | High | No third-party data bundled; verify before importing |
| Unverified service runtime | Medium | Docker/Kafka/ClickHouse need environment-level tests |
