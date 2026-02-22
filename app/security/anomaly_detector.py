# app/security/anomaly_detector.py

from datetime import datetime, timedelta


def detect_anomaly(user, risk, action):
    alerts = []

    # Too many failed logins
    if user.failed_attempts >= 3:
        alerts.append("BRUTE_FORCE")

    # High risk activity
    if risk == "HIGH":
        alerts.append("HIGH_RISK")

    # New device
    if user.last_login:
        now = datetime.utcnow()
        if now - user.last_login < timedelta(minutes=5):
            alerts.append("RAPID_ACTIVITY")

    # Suspicious download
    if action == "download" and risk == "HIGH":
        alerts.append("DATA_EXFIL")

    return alerts