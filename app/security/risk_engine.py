from datetime import datetime


# ---------------- RISK ENGINE ----------------

def calculate_risk(
    user,
    ip_address,
    device_hash,
    action,
    file_size=0,
    file_type=None
):
    score = 0

    # ---------------- TIME RISK ----------------
    hour = datetime.utcnow().hour

    if hour < 6 or hour > 22:
        score += 2   # night activity


    # ---------------- DEVICE RISK ----------------
    if user.device_hash and user.device_hash != device_hash:
        score += 3   # new device


    # ---------------- IP RISK ----------------
    if user.last_ip and user.last_ip != ip_address:
        score += 2   # new location


    # ---------------- BEHAVIOR RISK ----------------
    if user.failed_attempts > 3:
        score += 3


    # ---------------- FILE RISK ----------------
    if file_size > 5 * 1024 * 1024:
        score += 2   # large file

    risky_types = ["exe", "bat", "sh"]

    if file_type in risky_types:
        score += 4


    # ---------------- ACTION RISK ----------------
    if action == "login":
        score += 1

    if action == "download":
        score += 1


    # ---------------- CLASSIFICATION ----------------
    if score <= 2:
        return "MEDIUM"

    elif score <= 5:
        return "MEDIUM"

    else:
        return "HIGH"