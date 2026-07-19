# ADR 0002: Containment Response Action Scope

## Status
Accepted

## Context
When a threat is detected and verified, the platform needs containment response capabilities to mitigate the threat. Because this is a development/learning SOAR platform, we need realistic yet safe action scopes.

## Decision
We define three core containment actions:
1. **Block IP** (Adds the malicious IP to a firewall/blocklist mock).
2. **Host Isolation** (Quarantines the host in EDR mock).
3. **Auto-Ticket Creation** (Spins up an incident ticket in Jira/ServiceNow mock).

Crucially, to prevent automated false positive disruptions, we enforce a **Human-in-the-Loop (HITL) approval gateway**. 
- Actions are queued in a `pending` state in PostgreSQL.
- Celery will not execute containment until an analyst hits the FastAPI `/approvals/{id}/approve` endpoint.

## Alternatives considered
- **Fully Autonomous execution**: Triggers actions instantly when thresholds are met. While faster, it carries a high risk of service disruptions (e.g. blocking a critical internal IP).
- **Read-Only / No containment**: Safer, but does not demonstrate SOAR response orchestration.

## Consequences
- Clean state transitions: `pending` -> `approved` -> `executing` -> `executed` or `failed`.
- Detailed audit logs capturing *who* approved the containment and *when*.
- Extensible action schema to add more integrations later.
