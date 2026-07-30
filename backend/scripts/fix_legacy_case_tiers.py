import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal
from app.models.case import Case
from app.services.scoring import calculate_severity_score


def fix_legacy_case_tiers():
    db = SessionLocal()
    try:
        cases = db.query(Case).all()
        updated_count = 0

        for c in cases:
            score_val = c.severity_score if c.severity_score is not None else (c.score or 0)
            if score_val >= 80:
                expected_tier = "Critical"
            elif score_val >= 60:
                expected_tier = "High"
            elif score_val >= 35:
                expected_tier = "Medium"
            else:
                expected_tier = "Low"

            if c.severity_tier != expected_tier or c.severity_score is None:
                print(f"[FIX] Updating Case #{c.id}: score={score_val}, old_tier='{c.severity_tier}' -> new_tier='{expected_tier}'")
                c.severity_score = score_val
                c.severity_tier = expected_tier
                updated_count += 1

        db.commit()
        print(f"[SUCCESS] Updated {updated_count} legacy case records in PostgreSQL database.")
    finally:
        db.close()


if __name__ == "__main__":
    fix_legacy_case_tiers()
