import json
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.models.ioc import IOC
from app.models.enrichment import Enrichment
from app.core.config import settings

class RateLimitException(Exception):
    """Raised when an external API rate limit is encountered (HTTP 429)."""
    pass

def get_cached_enrichment(db: Session, ioc_id: int, source: str) -> dict | None:
    """
    Checks the database for an enrichment result for this IOC and source
    that was created within the last 24 hours.
    """
    time_limit = datetime.now(timezone.utc) - timedelta(hours=24)
    cached = (
        db.query(Enrichment)
        .filter(Enrichment.ioc_id == ioc_id)
        .filter(Enrichment.source == source)
        .filter(Enrichment.created_at >= time_limit)
        .order_by(Enrichment.created_at.desc())
        .first()
    )
    if cached:
        print(f"[CACHE] Found valid cache entry for IOC ID {ioc_id} ({source})")
        return cached.raw_response
    return None

def save_enrichment(
    db: Session,
    ioc_id: int,
    source: str,
    raw_response: dict,
    status: str = "success",
    summary_score: int | None = None,
) -> Enrichment:
    """
    Saves a new enrichment response to the database.
    """
    enrichment = Enrichment(
        ioc_id=ioc_id,
        source=source,
        status=status,
        summary_score=summary_score,
        raw_response=raw_response,
    )
    db.add(enrichment)
    db.commit()
    db.refresh(enrichment)
    return enrichment

def query_virustotal(ioc_type: str, value: str) -> dict:
    """
    Queries the VirusTotal API v3 for the given indicator.
    """
    if not settings.VT_API_KEY or settings.VT_API_KEY == "your_key_here":
        print("[VT] Warning: VT_API_KEY is not set or placeholder.")
        return {"error": "API key not configured"}

    url_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "hash_md5": f"https://www.virustotal.com/api/v3/files/{value}",
        "hash_sha1": f"https://www.virustotal.com/api/v3/files/{value}",
        "hash_sha256": f"https://www.virustotal.com/api/v3/files/{value}",
        "url": f"https://www.virustotal.com/api/v3/urls/{value}"  # URLs require base64/hash in VT, simplified lookup
    }

    if ioc_type not in url_map:
        return {"error": f"Unsupported VirusTotal type: {ioc_type}"}

    url = url_map[ioc_type]
    req = urllib.request.Request(url)
    req.add_header("x-apikey", settings.VT_API_KEY)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimitException("VirusTotal API rate limit hit")
        if e.code == 404:
            return {"status": "not_found", "message": f"{value} not found in VirusTotal"}
        raise e

def query_abuseipdb(ioc_type: str, value: str) -> dict:
    """
    Queries the AbuseIPDB API v2 for the given IP address.
    """
    if ioc_type != "ip":
        return {"error": "AbuseIPDB only supports IP address indicators"}

    if not settings.ABUSEIPDB_API_KEY or settings.ABUSEIPDB_API_KEY == "your_key_here":
        print("[AbuseIPDB] Warning: ABUSEIPDB_API_KEY is not set or placeholder.")
        return {"error": "API key not configured"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Key", settings.ABUSEIPDB_API_KEY)
    req.add_header("Accept", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimitException("AbuseIPDB API rate limit hit")
        raise e

def enrich_ioc(db: Session, ioc: IOC) -> dict:
    """
    Enriches a single IOC from caching layer or external APIs.
    """
    results = {}
    sources = []
    if ioc.ioc_type in ("ip", "domain", "hash_md5", "hash_sha1", "hash_sha256"):
        sources.append("virustotal")
    if ioc.ioc_type == "ip":
        sources.append("abuseipdb")

    for source in sources:
        # Check cache
        cached = get_cached_enrichment(db, ioc.id, source)
        if cached:
            results[source] = cached
            continue

        # Cache miss - query API
        try:
            if source == "virustotal":
                res = query_virustotal(ioc.ioc_type, ioc.value)
            elif source == "abuseipdb":
                res = query_abuseipdb(ioc.ioc_type, ioc.value)
            else:
                res = {"error": f"Unknown source: {source}"}

            if "error" not in res:
                save_enrichment(db, ioc.id, source, res)
            results[source] = res
        except RateLimitException as rle:
            # Re-raise to let the caller (Celery task) handle backoff/retries
            raise rle
        except Exception as e:
            print(f"[ENRICHMENT] Failed to query {source} for {ioc.value}: {str(e)}")
            results[source] = {"error": str(e)}

    return results
