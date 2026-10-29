import tempfile
import unittest
from pathlib import Path

from siem import detect_alerts, ingest_file, load_jsonl


class DetectionTests(unittest.TestCase):
    def make_event(self, minute, event_type, ip="192.0.2.10", user="analyst", details="test"):
        return {
            "timestamp": f"2026-10-29T10:{minute:02d}:00Z",
            "event_type": event_type,
            "source_ip": ip,
            "username": user,
            "details": details,
        }

    def test_five_failures_trigger_brute_force_alert(self):
        events = [self.make_event(i, "failed_login") for i in range(0, 5)]
        alerts = detect_alerts(events)
        self.assertTrue(any(a["rule_name"] == "Possible Brute-Force Login" for a in alerts))

    def test_success_after_five_failures_triggers_alert(self):
        events = [self.make_event(i, "failed_login") for i in range(0, 5)]
        success = self.make_event(4, "successful_login")
        success["timestamp"] = "2026-10-29T10:04:30Z"
        events.append(success)
        alerts = detect_alerts(events)
        self.assertTrue(any(a["rule_name"] == "Success After Repeated Failures" for a in alerts))

    def test_failures_from_different_ips_do_not_combine(self):
        events = [
            self.make_event(0, "failed_login", "192.0.2.10"),
            self.make_event(1, "failed_login", "192.0.2.11"),
            self.make_event(2, "failed_login", "192.0.2.10"),
            self.make_event(3, "failed_login", "192.0.2.11"),
        ]
        alerts = detect_alerts(events)
        self.assertFalse(any(a["rule_name"] == "Possible Brute-Force Login" for a in alerts))

    def test_privileged_command_is_flagged(self):
        events = [self.make_event(1, "privileged_command", details="sudo systemctl restart ssh")]
        alerts = detect_alerts(events)
        self.assertEqual(alerts[0]["severity"], "Medium")
        self.assertEqual(alerts[0]["rule_name"], "Privileged Command Observed")

    def test_ingest_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "events.jsonl"
            log.write_text(
                '{"timestamp":"2026-10-29T10:00:00Z","event_type":"failed_login","source_ip":"192.0.2.10","username":"a","details":"bad"}\n',
                encoding="utf-8",
            )
            db = root / "test.db"
            self.assertEqual(ingest_file(log, db), (1, 0))
            self.assertEqual(ingest_file(log, db), (0, 0))

    def test_loader_rejects_timezone_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "bad.jsonl"
            log.write_text(
                '{"timestamp":"2026-10-29T10:00:00","event_type":"failed_login","source_ip":"192.0.2.10","username":"a","details":"bad"}\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_jsonl(log)


if __name__ == "__main__":
    unittest.main()
