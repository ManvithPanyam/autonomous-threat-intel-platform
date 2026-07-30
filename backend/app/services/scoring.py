def calculate_severity_score(
    base_severity: int,
    vt_summary_score: int | None,
    abuseipdb_summary_score: int | None,
) -> dict:
    vt_normalized = min((vt_summary_score or 0) / 70 * 100, 100)
    abuse_normalized = abuseipdb_summary_score or 0

    technique_component = base_severity * 0.4
    vt_component = vt_normalized * 0.3
    abuse_component = abuse_normalized * 0.3

    total = round(technique_component + vt_component + abuse_component)

    if total >= 80:
        tier = "Critical"
    elif total >= 60:
        tier = "High"
    elif total >= 35:
        tier = "Medium"
    else:
        tier = "Low"

    explanation = (
        f"Technique base severity contributed {round(technique_component)} pts. "
        f"VirusTotal detections contributed {round(vt_component)} pts "
        f"({vt_summary_score or 0} engines flagged). "
        f"AbuseIPDB confidence contributed {round(abuse_component)} pts "
        f"({abuse_normalized}% confidence)."
    )

    return {
        "score": total,
        "tier": tier,
        "explanation": explanation,
    }
