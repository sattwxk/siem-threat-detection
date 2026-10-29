
import argparse
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path("siem.db")
BRUTE_FORCE_THRESHOLD = 5
WINDOW_MINUTES = 5
VALID_TYPES = {"failed_login", "successful_login", "privileged_command"}


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp; normalize it to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone information, e.g. Z")
    return parsed.astimezone(timezone.utc)


def connect_db(db_path=DB_PATH):
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            details TEXT NOT NULL,
            event_key TEXT NOT NULL UNIQUE
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            description TEXT NOT NULL,
            alert_key TEXT NOT NULL UNIQUE
        )
    """)
    connection.commit()
    return connection


def load_jsonl(path):
    """Read JSONL events and validate required fields."""
    events = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                timestamp = parse_timestamp(raw.get("timestamp"))
                event_type = raw.get("event_type")
                source_ip = raw.get("source_ip")
                username = raw.get("username", "unknown")
                details = raw.get("details", "")
                if event_type not in VALID_TYPES:
                    raise ValueError(f"event_type must be one of {sorted(VALID_TYPES)}")
                if not isinstance(source_ip, str) or not source_ip.strip():
                    raise ValueError("source_ip must be a non-empty string")
                if not isinstance(username, str) or not isinstance(details, str):
                    raise ValueError("username and details must be strings")
                normalized = {
                    "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                    "event_type": event_type,
                    "source_ip": source_ip.strip(),
                    "username": username.strip() or "unknown",
                    "details": details.strip(),
                }
                normalized["event_key"] = json.dumps(normalized, sort_keys=True)
                events.append(normalized)
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                raise ValueError(f"Invalid event on line {line_number}: {exc}") from exc
    return sorted(events, key=lambda event: event["timestamp"])



def detect_alerts(events):
    """Detect brute force, post-failure success, and privileged commands."""
    alerts = []
    parsed = [(event, parse_timestamp(event["timestamp"])) for event in events]
    parsed.sort(key=lambda pair: pair[1])

    failures = [
        (event, timestamp)
        for event, timestamp in parsed
        if event["event_type"] == "failed_login"
    ]

    for event, timestamp in parsed:
        if event["event_type"] == "failed_login":
            matching = [
                failed_event
                for failed_event, failed_time in failures
                if failed_event["source_ip"] == event["source_ip"]
                and timestamp - timedelta(minutes=WINDOW_MINUTES)
                < failed_time <= timestamp
            ]

            if len(matching) == BRUTE_FORCE_THRESHOLD:
                alert = {
                    "timestamp": event["timestamp"],
                    "severity": "High",
                    "rule_name": "Possible Brute-Force Login",
                    "source_ip": event["source_ip"],
                    "username": event["username"],
                    "description": (
                        f"{len(matching)} failed logins from "
                        f"{event['source_ip']} within {WINDOW_MINUTES} minutes."
                    ),
                }
                alert["alert_key"] = json.dumps(
                    [alert["rule_name"], alert["source_ip"], alert["timestamp"]],
                    sort_keys=True,
                )
                alerts.append(alert)

        elif event["event_type"] == "successful_login":
            previous_failures = [
                failed_event
                for failed_event, failed_time in failures
                if failed_event["source_ip"] == event["source_ip"]
                and timestamp - timedelta(minutes=WINDOW_MINUTES)
                < failed_time < timestamp
            ]

            if len(previous_failures) >= BRUTE_FORCE_THRESHOLD:
                alert = {
                    "timestamp": event["timestamp"],
                    "severity": "High",
                    "rule_name": "Success After Repeated Failures",
                    "source_ip": event["source_ip"],
                    "username": event["username"],
                    "description": (
                        f"Successful login from {event['source_ip']} after "
                        f"{len(previous_failures)} failures in the preceding "
                        f"{WINDOW_MINUTES} minutes."
                    ),
                }
                alert["alert_key"] = json.dumps(
                    [alert["rule_name"], alert["source_ip"], alert["timestamp"]],
                    sort_keys=True,
                )
                alerts.append(alert)

        elif event["event_type"] == "privileged_command":
            alert = {
                "timestamp": event["timestamp"],
                "severity": "Medium",
                "rule_name": "Privileged Command Observed",
                "source_ip": event["source_ip"],
                "username": event["username"],
                "description": (
                    f"Review privileged activity: "
                    f"{event['details'] or 'No details provided'}"
                ),
            }
            alert["alert_key"] = json.dumps(
                [alert["rule_name"], alert["source_ip"], alert["timestamp"]],
                sort_keys=True,
            )
            alerts.append(alert)

    return alerts


def ingest_file(path, db_path=DB_PATH):
    events = load_jsonl(path)
    inserted_events = 0
    inserted_alerts = 0

    connection = connect_db(db_path)
    try:
        with connection:
            for event in events:
                cursor = connection.execute("""
                    INSERT OR IGNORE INTO events
                    (timestamp, event_type, source_ip, username, details, event_key)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event["timestamp"], event["event_type"], event["source_ip"],
                    event["username"], event["details"], event["event_key"]
                ))
                inserted_events += cursor.rowcount

            # Run detection against all stored events, including older imports.
            rows = connection.execute("""
                SELECT timestamp, event_type, source_ip, username, details, event_key
                FROM events
                ORDER BY timestamp
            """).fetchall()

            all_events = []
            for row in rows:
                all_events.append({
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "source_ip": row["source_ip"],
                    "username": row["username"],
                    "details": row["details"],
                    "event_key": row["event_key"],
                })

            alerts = detect_alerts(all_events)

            for alert in alerts:
                cursor = connection.execute("""
                    INSERT OR IGNORE INTO alerts
                    (timestamp, severity, rule_name, source_ip, username, description, alert_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert["timestamp"], alert["severity"], alert["rule_name"],
                    alert["source_ip"], alert["username"], alert["description"],
                    alert["alert_key"]
                ))
                inserted_alerts += cursor.rowcount

    finally:
        connection.close()

    return inserted_events, inserted_alerts


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM JSONL log ingester")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ingest_parser = subparsers.add_parser("ingest", help="Ingest a JSONL log file and run detections")
    ingest_parser.add_argument("path", help="Path to a JSONL events file")
    ingest_parser.add_argument("--db", default=str(DB_PATH), help="SQLite database path")
    args = parser.parse_args()

    if args.command == "ingest":
        try:
            event_count, alert_count = ingest_file(args.path, args.db)
            print(f"New events stored: {event_count}")
            print(f"New alerts stored: {alert_count}")
            print(f"Database: {args.db}")
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise SystemExit(f"Error: {exc}") from exc


if __name__ == "__main__":
    main()
