import re
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.case import Case
from app.models.mitre import MITRETechnique

MITRE_RULES = [
    {
        "keywords": ["brute force", "bruteforce", "credential stuffing", "login attempt"],
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    {
        "keywords": ["beaconing", "c2", "cobalt strike", "reverse shell", "outbound beacon"],
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control"
    },
    {
        "keywords": ["lateral movement", "ssh connections", "psexec", "remote desktop", "rdp"],
        "technique_id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement"
    },
    {
        "keywords": ["exfiltration", "data upload", "mega.nz", "ftp upload", "outbound transfer"],
        "technique_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration"
    },
    {
        "keywords": ["ransomware", "encrypt", "delete backup", "wiper", "destruction"],
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact"
    },
    {
        "keywords": ["reconnaissance", "nmap", "port scan", "directory traversal", "scanning"],
        "technique_id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance"
    }
]

TACTIC_WEIGHTS = {
    "Reconnaissance": 1,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 2,
    "Persistence": 2,
    "Privilege Escalation": 2,
    "Defense Evasion": 2,
    "Credential Access": 3,
    "Discovery": 2,
    "Lateral Movement": 3,
    "Collection": 3,
    "Command and Control": 3,
    "Exfiltration": 4,
    "Impact": 4
}

SEVERITY_BASE = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 9
}

def get_or_create_mitre_technique(db: Session, technique_id: str, name: str, tactic: str) -> MITRETechnique:
    """
    Retrieves a MITRE technique by technique_id, or creates it if it doesn't exist.
    """
    tech = db.query(MITRETechnique).filter_by(technique_id=technique_id).first()
    if not tech:
        try:
            tech = MITRETechnique(technique_id=technique_id, name=name, tactic=tactic)
            db.add(tech)
            db.flush()
        except Exception:
            db.rollback()
            tech = db.query(MITRETechnique).filter_by(technique_id=technique_id).first()
    return tech

def map_alert_to_mitre_techniques(db: Session, alert: Alert) -> list[MITRETechnique]:
    """
    Analyses the alert title and description using heuristic keywords
    to map it to matching MITRE ATT&CK techniques.
    """
    mapped_techniques = []
    text_to_search = f"{alert.title or ''} {alert.description or ''}".lower()

    for rule in MITRE_RULES:
        for keyword in rule["keywords"]:
            if re.search(r'\b' + re.escape(keyword) + r'\b', text_to_search):
                tech = get_or_create_mitre_technique(
                    db, rule["technique_id"], rule["name"], rule["tactic"]
                )
                if tech not in alert.mitre_techniques:
                    alert.mitre_techniques.append(tech)
                    mapped_techniques.append(tech)
                break # Move to next rule on first match to avoid duplicate links per technique

    db.commit()
    db.refresh(alert)
    return mapped_techniques

def calculate_case_score(db: Session, case_id: int) -> int:
    """
    Calculates the Case severity score using the tactic-weighted formula:
    Case Score = Max(Alert Base Severity) + Max(MITRE Tactic Weight)
    Also auto-escalates case severity based on score thresholds.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return 0

    if not case.alerts:
        case.score = 0
        db.commit()
        return 0

    # 1. Base Severity (highest base score of any alert linked to the case)
    max_base = 1
    for alert in case.alerts:
        sev_val = SEVERITY_BASE.get((alert.severity or "low").lower(), 1)
        if sev_val > max_base:
            max_base = sev_val

    # 2. MITRE Tactics Weights
    max_tactic_weight = 0
    for alert in case.alerts:
        for tech in alert.mitre_techniques:
            weight = TACTIC_WEIGHTS.get(tech.tactic, 0)
            if weight > max_tactic_weight:
                max_tactic_weight = weight

    # 3. Final Dynamic Score
    final_score = max_base + max_tactic_weight
    case.score = final_score

    # 4. Severity Escalation thresholds
    if final_score >= 12:
        case.severity = "critical"
    elif final_score >= 8:
        case.severity = "high"
    elif final_score >= 5:
        case.severity = "medium"
    else:
        case.severity = "low"

    db.commit()
    db.refresh(case)
    print(f"[SCORING] Calculated Case ID {case.id} Score: {case.score}, Adjusted Severity: {case.severity}")
    return final_score
