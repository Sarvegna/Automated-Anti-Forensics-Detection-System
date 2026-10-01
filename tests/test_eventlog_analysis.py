import sys
import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.eventlog_analysis import (
    analyze_event_log,
    LOG_CLEARED_EVENT_ID,
    AUDIT_POLICY_CHANGED_EVENT_ID,
    EVENT_LOG_SERVICE_SHUTDOWN_EVENT_ID,
    GAP_THRESHOLD_MINUTES,
)
from core.evtx_reader import read_evtx_file
from core.risk_scoring import calculate_risk_score


class TestEventLogAnalysis(unittest.TestCase):

    def setUp(self):
        self.base_time = datetime(2026, 8, 2, 9, 0, 0)

    def test_normal_events_no_anomaly(self):
        # 4624, 4672, 4798, 5379, 5799 provide context and must NOT trigger anti-forensics findings
        context_events = [
            {"event_id": 4624, "timestamp": self.base_time, "source": "Security", "message": "Logon"},
            {"event_id": 4672, "timestamp": self.base_time + timedelta(minutes=5), "source": "Security", "message": "Special privileges assigned"},
            {"event_id": 4798, "timestamp": self.base_time + timedelta(minutes=10), "source": "Security", "message": "Local group enumerated"},
            {"event_id": 5379, "timestamp": self.base_time + timedelta(minutes=15), "source": "Security", "message": "Credential read"},
            {"event_id": 5799, "timestamp": self.base_time + timedelta(minutes=20), "source": "Security", "message": "Service ticket requested"},
        ]
        result = analyze_event_log(context_events)
        self.assertFalse(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 0)
        self.assertEqual(result["total_events_analyzed"], 5)

    def test_event_4907_does_not_become_4719_or_1100(self):
        # Event ID 4907 (Object auditing settings changed) must NOT generate 4719 or 1100
        events = [
            {
                "event_id": 4907,
                "record_id": 1001,
                "channel": "Security",
                "timestamp": self.base_time,
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "Auditing settings on object were changed."
            }
        ]
        result = analyze_event_log(events)
        self.assertFalse(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 0)
        self.assertEqual(result["total_events_analyzed"], 1)
        self.assertEqual(result["event_id_counts"].get(4907), 1)

    def test_event_1100_service_shutdown(self):
        events = [
            {"event_id": 1100, "record_id": 501, "channel": "Security", "timestamp": self.base_time, "source": "EventLog", "message": "The Event Log service was stopped"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 1)
        ind = result["indicators"][0]
        self.assertEqual(ind["type"], "Event Log Service Shutdown")
        self.assertEqual(ind["event_id"], 1100)
        self.assertEqual(ind["record_id"], 501)
        self.assertEqual(ind["channel"], "Security")
        self.assertEqual(ind["severity"], "HIGH")
        self.assertEqual(ind["points"], 20)

    def test_event_1102_log_cleared(self):
        events = [
            {"event_id": 1102, "record_id": 601, "channel": "Security", "timestamp": self.base_time, "source": "Security", "message": "The audit log was cleared"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 1)
        ind = result["indicators"][0]
        self.assertEqual(ind["type"], "Log Cleared")
        self.assertEqual(ind["event_id"], 1102)
        self.assertEqual(ind["record_id"], 601)
        self.assertEqual(ind["severity"], "HIGH")
        self.assertEqual(ind["points"], 25)

    def test_event_4719_audit_policy_changed(self):
        events = [
            {"event_id": 4719, "record_id": 701, "channel": "Security", "timestamp": self.base_time, "source": "Security", "message": "Audit policy was changed"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 1)
        ind = result["indicators"][0]
        self.assertEqual(ind["type"], "Audit Policy Changed")
        self.assertEqual(ind["event_id"], 4719)
        self.assertEqual(ind["record_id"], 701)
        self.assertEqual(ind["severity"], "HIGH")
        self.assertEqual(ind["points"], 20)

    def test_timeline_gap_detection(self):
        events = [
            {"event_id": 4624, "record_id": 101, "timestamp": self.base_time, "source": "Security", "message": "Logon"},
            {"event_id": 4624, "record_id": 102, "timestamp": self.base_time + timedelta(minutes=45), "source": "Security", "message": "Logon"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 1)
        ind = result["indicators"][0]
        self.assertEqual(ind["type"], "Timeline Gap")
        self.assertEqual(ind["severity"], "MEDIUM")
        self.assertEqual(ind["source"], "Windows Event Log")
        self.assertEqual(ind["gap_minutes"], 45.0)
        self.assertEqual(ind["points"], 15)
        self.assertEqual(ind["from_record_id"], 101)
        self.assertEqual(ind["to_record_id"], 102)

    def test_four_1100_occurrences_all_preserved(self):
        events = [
            {"event_id": 1100, "record_id": 201, "timestamp": self.base_time, "source": "Microsoft-Windows-Eventlog", "message": "Shutdown 1"},
            {"event_id": 1100, "record_id": 202, "timestamp": self.base_time + timedelta(minutes=5), "source": "Microsoft-Windows-Eventlog", "message": "Shutdown 2"},
            {"event_id": 1100, "record_id": 203, "timestamp": self.base_time + timedelta(minutes=10), "source": "Microsoft-Windows-Eventlog", "message": "Shutdown 3"},
            {"event_id": 1100, "record_id": 204, "timestamp": self.base_time + timedelta(minutes=15), "source": "Microsoft-Windows-Eventlog", "message": "Shutdown 4"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 4)
        for i, ind in enumerate(result["indicators"]):
            self.assertEqual(ind["type"], "Event Log Service Shutdown")
            self.assertEqual(ind["event_id"], 1100)
            self.assertEqual(ind["record_id"], 201 + i)

    def test_one_finding_per_matching_event(self):
        events = [
            {"event_id": 1102, "timestamp": self.base_time, "source": "Security", "message": "Cleared 1"},
            {"event_id": 1102, "timestamp": self.base_time + timedelta(minutes=2), "source": "Security", "message": "Cleared 2"},
            {"event_id": 4719, "timestamp": self.base_time + timedelta(minutes=4), "source": "Security", "message": "Policy 1"},
        ]
        result = analyze_event_log(events)
        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(len(result["indicators"]), 3)
        self.assertEqual(result["indicators"][0]["type"], "Log Cleared")
        self.assertEqual(result["indicators"][1]["type"], "Log Cleared")
        self.assertEqual(result["indicators"][2]["type"], "Audit Policy Changed")

    def test_parser_preserves_numeric_event_id_and_event_data(self):
        xml = """<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
            <System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>
            <EventID>4907</EventID><EventRecordID>42</EventRecordID>
            <TimeCreated SystemTime=\"2026-08-02T09:00:00.0000000Z\"/>
            <Channel>Security</Channel><Computer>HOST01</Computer></System>
            <EventData><Data Name=\"ObjectName\">C:\\Sensitive</Data></EventData></Event>"""

        class FakeRecord:
            def xml(self):
                return xml

            def record_num(self):
                return 999

        class FakeEvtx:
            def __init__(self, _file_path):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def records(self):
                return [FakeRecord()]

        with patch("core.evtx_reader.Evtx", FakeEvtx):
            events = read_evtx_file("fixture.evtx")

        self.assertEqual(events[0]["event_id"], 4907)
        self.assertEqual(events[0]["record_id"], 42)
        self.assertEqual(events[0]["event_data"], {"ObjectName": "C:\\Sensitive"})
        self.assertIn("ObjectName=C:\\Sensitive", events[0]["message"])
        self.assertNotIn("Real event extracted from", events[0]["message"])
        self.assertFalse(analyze_event_log(events)["anomaly_detected"])

    def test_repeated_event_and_gap_occurrences_score_base_weights_once(self):
        events = [
            {"event_id": 1100, "record_id": 201 + index,
             "timestamp": self.base_time + timedelta(minutes=index * 5),
             "source": "Microsoft-Windows-Eventlog", "message": f"Shutdown {index + 1}"}
            for index in range(4)
        ]
        events.extend(
            {"event_id": 4624, "record_id": 205 + index,
             "timestamp": self.base_time + timedelta(minutes=55 + index * 40),
             "source": "Microsoft-Windows-Security-Auditing", "message": "Normal logon"}
            for index in range(5)
        )

        result = analyze_event_log(events)
        self.assertEqual(sum(ind["type"] == "Event Log Service Shutdown" for ind in result["indicators"]), 4)
        self.assertEqual(sum(ind["type"] == "Timeline Gap" for ind in result["indicators"]), 5)

        risk_result = calculate_risk_score(eventlog_result=result)
        self.assertEqual(risk_result["score"], 35)
        contributions = {item["type"]: item for item in risk_result["contributing_indicators"]}
        self.assertEqual(contributions["Event Log Service Shutdown (Event Log)"]["occurrences"], 4)
        self.assertEqual(contributions["Timeline Gap (Event Log)"]["occurrences"], 5)

    def test_final_risk_score_is_bounded_to_100(self):
        timestamp_result = {
            "anomaly_detected": True,
            "indicators": [
                {"type": "Modified Before Created", "explanation": "x"},
                {"type": "Accessed Before Created", "explanation": "x"},
                {"type": "Future Timestamp", "explanation": "x"},
                {"type": "Accessed Before Modified", "explanation": "x"},
            ],
        }
        eventlog_result = {
            "anomaly_detected": True,
            "indicators": [
                {"type": "Log Cleared", "explanation": "x"},
                {"type": "Audit Policy Changed", "explanation": "x"},
                {"type": "Event Log Service Shutdown", "explanation": "x"},
                {"type": "Timeline Gap", "explanation": "x"},
            ],
        }
        risk_result = calculate_risk_score(
            timestamp_result=timestamp_result,
            eventlog_result=eventlog_result,
            hidden_file_result={"anomaly_detected": True, "explanation": "x"},
        )
        self.assertEqual(risk_result["score"], 100)
        self.assertGreaterEqual(risk_result["score"], 0)
        self.assertLessEqual(risk_result["score"], 100)

    def test_empty_and_invalid_events(self):
        self.assertEqual(analyze_event_log([])["indicators"], [])
        self.assertEqual(analyze_event_log(None)["indicators"], [])
        invalid = [
            "not_a_dict",
            {"event_id": "not_int", "timestamp": self.base_time},
            {"event_id": 1102, "timestamp": "not_datetime"}
        ]
        self.assertEqual(analyze_event_log(invalid)["indicators"], [])


if __name__ == "__main__":
    # Test Case 1: Normal event log — no anomalies
    normal_events = [
        {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 0, 0), "source": "Security", "message": "Successful logon"},
        {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Successful logon"},
        {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 10, 0), "source": "Security", "message": "Successful logon"},
    ]

    result = analyze_event_log(normal_events)
    print("Test 1 - Normal log:")
    print("  Anomaly detected:", result["anomaly_detected"])
    print("  Indicators found:", len(result["indicators"]))
    print()

    # Test Case 2: Suspicious event log — contains 1100, 1102, 4719, and a timeline gap
    suspicious_events = [
        {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 0, 0), "source": "Security", "message": "Successful logon"},
        {"event_id": 1100, "timestamp": datetime(2026, 8, 2, 9, 4, 0), "source": "EventLog", "message": "The Windows Event Log service was stopped"},
        {"event_id": 4719, "timestamp": datetime(2026, 8, 2, 9, 5, 0), "source": "Security", "message": "Audit policy changed"},
        {"event_id": 1102, "timestamp": datetime(2026, 8, 2, 9, 6, 0), "source": "Security", "message": "The audit log was cleared"},
        # Big gap here - next event is 45 minutes later
        {"event_id": 4624, "timestamp": datetime(2026, 8, 2, 9, 51, 0), "source": "Security", "message": "Successful logon"},
    ]

    result = analyze_event_log(suspicious_events)
    print("Test 2 - Suspicious log:")
    print("  Anomaly detected:", result["anomaly_detected"])
    print("  Indicators found:", len(result["indicators"]))
    for indicator in result["indicators"]:
        print("   -", indicator["type"], ":", indicator["explanation"])
    print()

    print("Running unit tests:")
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

