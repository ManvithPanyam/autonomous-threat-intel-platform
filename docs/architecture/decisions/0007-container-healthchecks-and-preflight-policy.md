# ADR 0007: Container Healthchecks and Pre-Flight Verification Policy

## Context

During a post-Phase-9 review of the demo recording (`docs/demo_recording.webp`), the recording was found to be entirely invalid — all frames showed a "Connection Error / Failed to fetch" state in the React dashboard, meaning the backend container was not reachable when the recording was made.

Additionally, the `docker-compose.yml` did not declare a `celery_worker` service. The worker was only started manually during development sessions, meaning any reviewer performing a fresh `docker compose up --build -d` would have a running stack with no Celery workers — silently breaking async enrichment and containment execution.

Two questions needed explicit policy decisions:

1. **Should container healthchecks be added to `docker-compose.yml`?**
2. **Should there be a mandatory pre-flight verification gate before any demo recording is made?**

## Decision

### 1. Add `celery_worker` as a Declared Service in `docker-compose.yml`

**Decision**: Yes — `celery_worker` is declared as a first-class service.

**Rationale**: The Celery worker is a required architectural component (Phase 5: async enrichment, Phase 8: containment execution). A compose file that omits it misrepresents the operational stack and breaks the platform for any reviewer who follows the Quick Start guide. The compose file is the canonical definition of the deployment topology; all runtime components must appear in it.

### 2. Add Docker Healthchecks to `backend`, `postgres`, and `redis`

**Decision**: Yes — `HEALTHCHECK` directives added to all three stateful/networked services.

**Rationale**: The default `docker compose ps` output only reports whether the container process started — not whether the service inside it is actually accepting connections. Without healthchecks:
- `postgres` may show `Up` while still initializing and rejecting connections.
- `backend` may show `Up` while uvicorn is still loading modules.
- Automation and demo scripts cannot reliably determine when the stack is ready.

Healthcheck commands chosen:
- **postgres**: `pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}` (built-in postgres utility).
- **redis**: `redis-cli ping | grep PONG` (built-in redis utility).
- **backend**: `python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"` (uses the existing `/health` endpoint; no extra tooling required in the image).

### 3. Mandatory Pre-Flight Checklist Before Any Demo Recording

**Decision**: Yes — a three-gate checklist is required and documented in both the README and the demo script.

The gates are:
1. **`docker compose ps`** output must show all 5 services `Up` with `(healthy)` on backend, postgres, and redis.
2. **`curl http://localhost:8000/health`** must return `{"status": "ok"}`.
3. **`http://localhost:5173`** must be manually opened in a real browser tab and the case queue must render with real case data (not an error state) before the recording starts.

Only after all three gates pass may a recording proceed.

## Consequences

### Positive
- Reviewers running `docker compose up --build -d` now get a complete, working stack including the Celery worker.
- `docker compose ps` now provides actionable readiness information (`healthy` vs `starting` vs `unhealthy`).
- Demo recordings are guaranteed to start from a verified-working state.
- The pre-flight checklist is reproducible and explicit — anyone re-recording the demo follows the same verification process.

### Neutral
- Container startup time is marginally longer because healthcheck polling adds a small delay before a service is declared healthy.
- The healthcheck `retries: 5` / `interval: 5s` means up to 25 seconds may elapse before a service transitions from `starting` to `healthy` under slow machines.

### Negative
- None identified. The tradeoffs are all in favour of correctness and reproducibility.
