# Autonomous Threat Intelligence & Response Platform

An autonomous threat intelligence and response (SOAR) platform that ingests raw threat feeds, enriches Indicators of Compromise (IOCs) via external threat-intel APIs, maps behavior to the MITRE ATT&CK framework, generates AI-driven incident summaries, and requires human approval before containment actions execute.

## Build Progress

- **[Phase 0: Project Genesis](file:///home/mannu/projects/autonomous-threat-intel-platform/docs/journal/00-project-genesis.md)**
  * Conceived a decoupled SOAR-style orchestration backend instead of a standard VM-based SOC lab to emphasize software engineering design patterns, asynchronous queues, database transactions, and AI-assisted synthesis.
- **[Phase 1: Setup](file:///home/mannu/projects/autonomous-threat-intel-platform/docs/journal/phase-01-setup.md)**
  * Containerized the entire stack using Docker Compose (FastAPI, Postgres, Redis, Celery) to ensure local parity with target deployment. Resolved WSL2 socket integration hurdles to bind Docker services directly to the local distribution namespace.
- **[Phase 2: Architecture](file:///home/mannu/projects/autonomous-threat-intel-platform/docs/journal/phase-02-architecture.md)**
  * Defined a Pydantic-validated JSON alert ingestion schema and set up a Human-in-the-Loop (HITL) approval model for containment responses (IP blocking, host isolation, auto-ticketing) to mitigate false-positive service disruptions.
- [ ] Phase 3: Database & Models
- [ ] Phase 4: Ingestion API
- [ ] Phase 5: Async Enrichment Worker
- [ ] Phase 6: MITRE ATT&CK Mapper
- [ ] Phase 7: AI Incident Summarizer
- [ ] Phase 8: Approval Workflows & Actions
- [ ] Phase 9: Frontend Dashboard
- [ ] Phase 10: Production Readiness & Tuning
- [ ] Phase 11: Deployment & Presentation
