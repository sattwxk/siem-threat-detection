import tempfile
import unittest
from pathlib import Path

from siem import detect_alerts, ingest_file, load_jsonl


class DetectionTests(unittest.TestCase):
    def make_event(self, minute, event_type, ip="192.0.2.10", user="analyst",
                   details="test", second=0):
        return {
            "timestamp": f"2026-10-29T10:{minute:02d}:{second:02d}Z",
            "event_type": event_type,
            "source_ip": ip,
            "username": user,
            "details": details,
        }

    def write_log(self, directory, lines, name="events.jsonl"):
        path = Path(directory) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    # ---------- existing tests ----------

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

    # ---------- new: regression tests for the bugs found in review ----------

    def test_same_second_burst_triggers_one_alert(self):
        events = [self.make_event(0, "failed_login") for _ in range(6)]
        alerts = detect_alerts(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_name"], "Possible Brute-Force Login")

    def test_slow_sustained_attack_alerts_once_per_window(self):
        # one failure per minute for 8 minutes, all within a single 5-minute alert window
        events = [self.make_event(m, "failed_login") for m in range(0, 8)]
        brute = [a for a in detect_alerts(events)
                 if a["rule_name"] == "Possible Brute-Force Login"]
        self.assertEqual(len(brute), 1)

    def test_failures_exactly_five_minutes_apart_do_not_combine(self):
        events = [self.make_event(m, "failed_login") for m in (0, 1, 2, 3, 5)]
        alerts = detect_alerts(events)
        self.assertFalse(any(a["rule_name"] == "Possible Brute-Force Login" for a in alerts))

    def test_success_after_four_failures_does_not_alert(self):
        events = [self.make_event(i, "failed_login") for i in range(0, 4)]
        events.append(self.make_event(4, "successful_login"))
        alerts = detect_alerts(events)
        self.assertFalse(any(a["rule_name"] == "Success After Repeated Failures" for a in alerts))

    def test_two_privileged_commands_same_second_make_two_alerts(self):
        events = [
            self.make_event(0, "privileged_command", details="sudo a"),
            self.make_event(0, "privileged_command", details="sudo b"),
        ]
        alerts = detect_alerts(events)
        self.assertEqual(len({a["alert_key"] for a in alerts}), 2)

    def test_identical_events_in_same_second_are_all_stored(self):
        line = ('{"timestamp":"2026-10-29T10:00:00Z","event_type":"failed_login",'
                '"source_ip":"192.0.2.10","username":"a","details":"bad"}')
        with tempfile.TemporaryDirectory() as tmp:
            log = self.write_log(tmp, [line] * 6)
            db = Path(tmp) / "test.db"
            self.assertEqual(ingest_file(log, db), (6, 1))  # 6 events, 1 brute-force alert
            self.assertEqual(ingest_file(log, db), (0, 0))  # still idempotent

    def test_loader_rejects_invalid_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self.write_log(tmp, [
                '{"timestamp":"2026-10-29T10:00:00Z","event_type":"failed_login","source_ip":"not-an-ip","username":"a","details":"bad"}'
            ], name="bad_ip.jsonl")
            with self.assertRaises(ValueError):
                load_jsonl(log)


if __name__ == "__main__":
    unittest.main()