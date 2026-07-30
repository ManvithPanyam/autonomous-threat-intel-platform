from typing import Any

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) AI Analyst specializing in threat intelligence synthesis.
Your task is to analyze security case data and produce a clear, concise, analyst-facing markdown incident summary.

STRICT GUIDELINES:
1. Target ~150-250 words. Be specific, data-driven, and explainable. Avoid generic boilerplate.
2. Structure your summary using the following markdown format:
   - **Executive Summary**: What happened (correlating alert activity and context).
   - **Risk & Severity Rationale**: Why it is scored the way it is (explicitly citing MITRE ATT&CK technique and IOC reputation findings).
   - **Recommended Response Actions**: Exactly 2 to 3 recommended Human-in-the-Loop containment actions from the supported set: `Block IP`, `Host Isolation`, `Auto-Ticket`.
3. HUMAN-IN-THE-LOOP (HITL) RULE: NEVER claim an action was executed or taken. These are ONLY proposed options for analyst review and approval.
"""

def build_case_prompt(case_data: dict[str, Any]) -> str:
    case_meta = f"""CASE METADATA:
- Case ID: {case_data.get('id')}
- Status: {case_data.get('status')}
- Created At: {case_data.get('created_at')}
- Severity Score: {case_data.get('severity_score')} / 100
- Severity Tier: {case_data.get('severity_tier')}
- Severity Rationale: {case_data.get('severity_explanation')}
"""

    mitre_meta = f"""MITRE ATT&CK MAPPING:
- Technique ID: {case_data.get('technique_id', 'N/A')}
- Technique Name: {case_data.get('technique_name', 'N/A')}
- Matched Via: {case_data.get('matched_via', 'N/A')}
"""

    alerts = case_data.get("alerts", [])
    alerts_str_list = []
    for a in alerts:
        alerts_str_list.append(
            f"  * Title: {a.get('title')} | Source: {a.get('source')} | Event Type: {a.get('event_type', 'N/A')} | Desc: {a.get('description')}"
        )
    alerts_meta = "LINKED ALERTS:\n" + ("\n".join(alerts_str_list) if alerts_str_list else "  * None")

    iocs = case_data.get("iocs", [])
    iocs_str_list = []
    for i in iocs:
        iocs_str_list.append(
            f"  * Indicator: {i.get('indicator')} ({i.get('indicator_type')}) | Provider: {i.get('source')} | Reputation Score: {i.get('reputation_score')} | Status: {i.get('status')}"
        )
    iocs_meta = "\nINDICATORS OF COMPROMISE & ENRICHMENTS:\n" + ("\n".join(iocs_str_list) if iocs_str_list else "  * None")

    user_prompt = f"{case_meta}\n{mitre_meta}\n{alerts_meta}\n{iocs_meta}\n\nPlease generate the analyst incident summary based on the guidelines above."
    return user_prompt
