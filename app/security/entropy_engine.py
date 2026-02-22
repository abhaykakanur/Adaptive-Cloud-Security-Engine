import math
from collections import Counter
from datetime import datetime

# Store recent security actions
SECURITY_EVENTS = []

MAX_EVENTS = 100
ENTROPY_THRESHOLD = 1.5   # Below this = too predictable


def log_event(event_type: str):
    """
    Log security-related events
    """
    global SECURITY_EVENTS

    SECURITY_EVENTS.append({
        "type": event_type,
        "time": datetime.utcnow()
    })

    if len(SECURITY_EVENTS) > MAX_EVENTS:
        SECURITY_EVENTS.pop(0)


def calculate_entropy():
    """
    Calculate Shannon entropy of security events
    """
    if len(SECURITY_EVENTS) < 10:
        return 3.0  # Not enough data → assume safe

    types = [e["type"] for e in SECURITY_EVENTS]
    counts = Counter(types)

    total = len(types)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def is_system_predictable():
    """
    Check if entropy is too low
    """
    entropy = calculate_entropy()

    print("[ENTROPY]", entropy)

    return entropy < ENTROPY_THRESHOLD