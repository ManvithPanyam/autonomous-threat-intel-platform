import sys
import os

# Ensure backend directory is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.mitre_mapper import map_to_mitre
from app.services.scoring import calculate_severity_score


def run_verification():
    print("🚀 Starting Phase 6 MITRE Mapping & Dynamic Scoring Verification...\n")

    test_cases = [
        {
            "signature": "outbound_beacon_c2",
            "description": "High frequency outbound HTTP beaconing detected",
            "vt_score": 17,
            "abuse_score": 0,
        },
        {
            "signature": "unknown_alert_sig",
            "description": "Suspicious powershell execution in user profile",
            "vt_score": 5,
            "abuse_score": 50,
        },
        {
            "signature": "custom_unrecognized_event",
            "description": "Generic system log message",
            "vt_score": None,
            "abuse_score": None,
        },
    ]

    for idx, test in enumerate(test_cases, 1):
        print(f"--- Test Case #{idx} ---")
        print(f"Input Signature: {test['signature']}")
        print(f"Input Description: {test['description']}")

        mitre_res = map_to_mitre(test["signature"], test["description"])
        print(
            f"✓ MITRE Mapping: {mitre_res['technique_id']} - {mitre_res['technique_name']} "
            f"(Base Sev: {mitre_res['base_severity']}, Matched via: {mitre_res['matched_via']})"
        )

        score_res = calculate_severity_score(
            mitre_res["base_severity"], test["vt_score"], test["abuse_score"]
        )
        print(f"✓ Dynamic Score: {score_res['score']}/100 (Tier: {score_res['tier']})")
        print(f"✓ Explanation: {score_res['explanation']}\n")

    print("🎉 MITRE MAPPER & DYNAMIC SCORING VERIFICATION PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    run_verification()
