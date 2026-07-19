# ADR 0001: Alert Schema Design

## Status
Accepted

## Context
The platform needs to ingest alerts from various security tools (SIEMs, EDRs, firewalls). We need a consistent JSON structure to represent incoming alerts to allow the enrichment worker and the AI summary worker to parse IOCs and metadata reliably.

## Decision
We will enforce a structured alert schema using Pydantic validation on ingestion. The schema contains:
1. **Metadata**: Unique ID, source tool, severity, timestamp.
2. **Context**: Title, description, host/user affected.
3. **Indicators of Compromise (IOCs)**: List of structured IOCs, each containing a type (`ip`, `domain`, `hash`) and the value.

Example JSON structure:
```json
{
  "alert_id": "alert-12345",
  "source": "CrowdStrike",
  "severity": "high",
  "timestamp": "2026-07-19T15:00:00Z",
  "title": "Suspicious Executable Execution",
  "description": "A non-standard binary attempted to establish an outbound TCP connection.",
  "iocs": [
    {"type": "ip", "value": "198.51.100.42"},
    {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
  ]
}
```

## Alternatives considered
- **STIX 2.1 (Structured Threat Information Expression)**: Standardized for threat sharing but adds unnecessary complexity and nesting for simple alert ingestion.
- **Schemaless JSON**: Very easy to ingest but shifts validation burden to downstream Celery workers, increasing risk of silent enrichment task failures.

## Consequences
- Predictable and strictly typed ingestion gateway.
- Simplified mapping from HTTP payload to database fields.
- Upfront validation prevents invalid formats from clogging celery queues.
