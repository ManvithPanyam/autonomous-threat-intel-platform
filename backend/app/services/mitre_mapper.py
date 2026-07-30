from app.data.mitre_mappings import MITRE_LOOKUP

FALLBACK_KEYWORDS = {
    "powershell": "suspicious_powershell",
    "smb": "lateral_movement_smb",
    "beacon": "outbound_beacon_c2",
    "login": "failed_login_burst",
    "exfil": "data_exfil_large_transfer",
}


def map_to_mitre(alert_signature: str, alert_description: str = "") -> dict:
    key = alert_signature if alert_signature in MITRE_LOOKUP else None

    if not key:
        desc_lower = (alert_description or "").lower()
        for keyword, mapped_key in FALLBACK_KEYWORDS.items():
            if keyword in desc_lower:
                key = mapped_key
                break

    if not key:
        key = "unmapped"

    technique_id, technique_name, base_severity = MITRE_LOOKUP[key]
    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "base_severity": base_severity,
        "matched_via": (
            "lookup"
            if key == alert_signature
            else "fallback"
            if key != "unmapped"
            else "default"
        ),
    }
