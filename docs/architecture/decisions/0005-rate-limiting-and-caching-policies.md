# ADR 0005: Rate-limiting, Caching, and Retry Policies for External Enrichment APIs

## Context

During Phase 5, the SOAR platform will asynchronously enrich Indicators of Compromise (IOCs) using external intelligence sources (e.g., VirusTotal, AbuseIPDB). These external APIs enforce strict rate limits on their free tiers:
- **VirusTotal**: 4 requests per minute.
- **AbuseIPDB**: 1,000 requests per day.

Uncontrolled queries triggered by every incoming alert could quickly exhaust these limits, leading to HTTP `429 Too Many Requests` status codes, service denials, or platform rate-limit lockouts. We need a robust mechanism to cache results, control query rates, and handle rate-limiting errors gracefully using our existing stack (FastAPI, Redis, Celery, Postgres).

## Proposed Design Decisions

### 1. Cache Enrichment Results in PostgreSQL and Redis
To minimize external API requests, we will implement a dual-layer caching strategy:
- **Primary Cache (PostgreSQL `enrichments` table)**: Used as the long-term historical source of truth. Before querying an external API, the Celery task checks the `enrichments` table for a recent (e.g., < 24 hours) entry for the specific IOC.
- **Secondary Cache (Redis)**: If a fast in-memory check is needed, or to track temporary transient API failures/empty responses, Redis keys can be used with a set Time-To-Live (TTL).
- **TTL Configuration**: A default TTL of 24 hours will be applied to successful enrichments. This prevents checking the same IOC multiple times if many alerts contain the same indicator during a single campaign or scan.

### 2. Celery Rate Limiting & Task Retry with Exponential Backoff
To respect external API limits and handle transient errors:
- **Celery Task Rate Limits**: We will configure task rate limits on specific tasks (e.g., `rate_limit="4/m"` for the VirusTotal task). Celery natively queues and schedules tasks to stay within this limit.
- **Graceful Error Handling (HTTP 429)**: When an external client encounters an HTTP `429 Too Many Requests` or connection timeout, the task will catch this specific exception and trigger a Celery self-retry.
- **Exponential Backoff**: We will configure retries with exponential backoff and jitter (e.g., retry after $2^n \times \text{base}$ seconds) to avoid thundering herd issues, up to a maximum retry limit (e.g., 5 retries).

### 3. Dedicated Async Queues
We will partition Celery task execution into dedicated queues:
- `default`: For fast ingestion and correlation tasks.
- `enrichment`: For rate-limited external API calls. This ensures slow/retried enrichment tasks do not block the critical path of alert ingestion.

## Consequences
- **Positive**: High reliability, protection of API keys from blocklists, and predictable API usage.
- **Neutral**: Delay in enrichment details showing up for some alerts if queue backlogs form during high-rate attack campaigns, which is acceptable since alerts are ingested immediately and grouped.
