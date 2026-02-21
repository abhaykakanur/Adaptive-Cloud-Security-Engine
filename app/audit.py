from datetime import datetime
import os

LOG_FILE = "audit.log"


def log_event(user: str, action: str, filename: str):

    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"[{time}] | {user} | {action} | {filename}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log)