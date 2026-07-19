# ADR 0004: IOC Normalization, Deduplication, and Enrichment History

## Status
Accepted

## Context
A major component of a SOAR platform is the correlation of threat indicators across different events and cases. Indicators of Compromise (IOCs) are ingested from various incoming alerts in diverse raw formats. If they are not normalized, simple differences in formatting (e.g., lowercase vs. uppercase domains, or defanged formats like `1.2.3[.]4` or `hxxp://`) will bypass deduplication checks and result in duplicate IOC records.
Additionally, threat intelligence is dynamic; a clean IP address or domain today may be flagged as malicious tomorrow. We need to decide if the `enrichments` table keeps a history of API lookups or only stores the latest status.

## Decision
1. **IOC Table Identity Key & Constraints:**
   - Define a unique constraint on `(ioc_type, value)` in the `iocs` table.
   - Supported `ioc_type` enum values: `ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `url`.
2. **Normalization Rules (Before Insertion):**
   - **Domains**: Convert to lowercase, remove protocol prefixes (`http://`, `https://`), strip defanged brackets (e.g. `[.]` -> `.`), and trim whitespace.
   - **IPs**: Strip defanged brackets (e.g. `[.]` -> `.`), and trim whitespace. Normalize IPv6 if necessary.
   - **Hashes**: Convert to lowercase.
3. **Enrichment History Storage:**
   - Establish a 1-to-many relationship between `iocs` and `enrichments`.
   - Each lookup creates a *new* row in `enrichments` with a `created_at` timestamp.
   - To check the current status, queries will fetch the latest entry ordered by `created_at DESC`. This preserves historical timelines for incident auditing (e.g., proving an IP was clean at alert time but marked malicious later).

## Alternatives considered
- **Bare Unique Constraint on Value**: If we only make `value` unique, an IP and a hash with the same text representation would collide (unlikely but theoretically possible).
- **Latest-only Upsert**: Reduces database size by overwriting the enrichment row. *Tradeoff:* Prevents analyzing changes in threat reputation over time, which is critical for case investigation timelines.

## Consequences
- Clean, deduplicated relation tree between alerts and unique IOC entities.
- Robust audit capabilities to see how an indicator's reputation evolved over time.
- Standardized parser/cleaner utility function required at the ingestion/parsing layer.
