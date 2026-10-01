import unittest
from datetime import datetime, timedelta

from core.gap_detection import find_timeline_gaps


class TestFindTimelineGaps(unittest.TestCase):

    def setUp(self):
        self.base_time = datetime(2026, 8, 30, 10, 0, 0)

    def test_detects_gap_above_threshold(self):
        events = [
            {"timestamp": self.base_time},
            {"timestamp": self.base_time + timedelta(minutes=45)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Timeline Gap")
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_does_not_detect_gap_below_threshold(self):
        events = [
            {"timestamp": self.base_time},
            {"timestamp": self.base_time + timedelta(minutes=15)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 0)

    def test_events_are_sorted_before_analysis(self):
        events = [
            {"timestamp": self.base_time + timedelta(minutes=45)},
            {"timestamp": self.base_time},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_supports_custom_timestamp_key(self):
        visits = [
            {"visit_time": self.base_time},
            {"visit_time": self.base_time + timedelta(minutes=40)},
        ]

        result = find_timeline_gaps(
            visits,
            threshold_minutes=30,
            timestamp_key="visit_time"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 40)

    def test_empty_events(self):
        result = find_timeline_gaps(
            [],
            threshold_minutes=30
        )

        self.assertEqual(result, [])

    def test_single_event(self):
        events = [
            {"timestamp": self.base_time}
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(result, [])

    def test_ignores_missing_timestamp(self):
        events = [
            {"timestamp": self.base_time},
            {"event_id": 1102},
            {"timestamp": self.base_time + timedelta(minutes=45)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_ignores_none_timestamp(self):
        events = [
            {"timestamp": self.base_time},
            {"timestamp": None},
            {"timestamp": self.base_time + timedelta(minutes=45)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_ignores_invalid_timestamp_type(self):
        events = [
            {"timestamp": self.base_time},
            {"timestamp": "invalid timestamp"},
            {"timestamp": self.base_time + timedelta(minutes=45)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_ignores_non_dictionary_event(self):
        events = [
            {"timestamp": self.base_time},
            None,
            {"timestamp": self.base_time + timedelta(minutes=45)},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["gap_minutes"], 45)

    def test_all_invalid_timestamps(self):
        events = [
            {"timestamp": None},
            {"timestamp": "invalid"},
            {"event_id": 1102},
        ]

        result = find_timeline_gaps(
            events,
            threshold_minutes=30
        )

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
