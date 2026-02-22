# app/security/self_healer.py

import os
from datetime import datetime, timedelta


def self_heal(user, alerts, db):

    actions = []

    # Lock account
    if "BRUTE_FORCE" in alerts:
        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        actions.append("ACCOUNT_LOCKED")

    # Force token reset
    if "HIGH_RISK" in alerts:
        user.token_version += 1
        actions.append("TOKEN_RESET")

    # Reduce trust score
    if "DATA_EXFIL" in alerts:
        user.trust_score -= 20
        actions.append("TRUST_REDUCED")

    db.commit()

    return actions