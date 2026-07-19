import re
from sqlalchemy.orm import Session
from app.models.ioc import IOC

def normalize_ioc(ioc_type: str, value: str) -> str:
    """
    Normalizes threat indicators to prevent duplicates.
    - Strips defanged formats like [.] or [:]
    - Lowercases domains, hashes, and URLs
    - Trims leading/trailing whitespace
    """
    cleaned = value.strip()
    
    # Strip defanging brackets: e.g. 1.2.3[.]4 -> 1.2.3.4, or google[.]com -> google.com
    cleaned = re.sub(r'\[\.\]', '.', cleaned)
    cleaned = re.sub(r'\[:\]', ':', cleaned)
    cleaned = re.sub(r'\[at\]', '@', cleaned)
    
    # Lowercase domains, hashes, and URLs
    if ioc_type in ("domain", "hash_md5", "hash_sha1", "hash_sha256", "url"):
        cleaned = cleaned.lower()
        
    # Strip protocols from domains if passed that way (e.g., http://malicious.com -> malicious.com)
    if ioc_type == "domain":
        cleaned = re.sub(r'^https?://', '', cleaned)
        cleaned = cleaned.split('/')[0]  # Just keep the domain hostname portion

    return cleaned

def get_or_create_ioc(db: Session, ioc_type: str, value: str) -> IOC:
    """
    Normalizes the indicator value and queries the database for an existing IOC.
    If it exists, returns it. If not, inserts it and returns the new instance.
    Utilizes savepoints to handle race conditions gracefully.
    """
    normalized_value = normalize_ioc(ioc_type, value)
    
    # Try querying first
    existing = db.query(IOC).filter_by(ioc_type=ioc_type, value=normalized_value).first()
    if existing:
        return existing
        
    # Create new IOC using a database savepoint to handle concurrency safely
    db.begin_nested()
    try:
        ioc = IOC(ioc_type=ioc_type, value=normalized_value)
        db.add(ioc)
        db.commit()
        return ioc
    except Exception:
        db.rollback()  # Rollback savepoint if a concurrent transaction inserted it
        # Re-query
        return db.query(IOC).filter_by(ioc_type=ioc_type, value=normalized_value).first()
