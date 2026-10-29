"""Generate safe synthetic authentication events for the SIEM demo."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT = Path("sample_logs/auth_events.jsonl")


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = []

    # Five failures followed by a successful login from the same documentation-only IP.
    for i in range(5):
        events.append({
            "timestamp": (now - timedelta(minutes=4, seconds=40 - i * 50)).isoformat().replace("+00:00", "Z"),
            "event_type": "failed_login",
            "source_ip": "192.0.2.10",
            "username": "analyst",
            "details": "Invalid password (synthetic demo event)",
        })

    events.append({
        "timestamp": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "event_type": "successful_login",
        "source_ip": "192.0.2.10",
        "username": "analyst",
        "details": "Successful authentication (synthetic demo event)",
    })

    events.append({
        "timestamp": (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
        "event_type": "privileged_command",
        "source_ip": "192.0.2.25",
        "username": "admin",
        "details": "sudo systemctl restart ssh (synthetic demo event)",
    })

    # A benign-looking successful login to show normal events in the dashboard.
    events.append({
        "timestamp": (now - timedelta(minutes=8)).isoformat().replace("+00:00", "Z"),
        "event_type": "successful_login",
        "source_ip": "192.0.2.30",
        "username": "student",
        "details": "Normal successful login (synthetic demo event)",
    })

    events.sort(key=lambda event: event["timestamp"])
    with OUTPUT.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    print(f"Wrote {len(events)} synthetic events to {OUTPUT}")


if __name__ == "__main__":
    main()
