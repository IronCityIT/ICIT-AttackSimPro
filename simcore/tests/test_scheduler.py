"""Tests for the cron parser, next-run computation, and scheduling plan."""

import unittest
from datetime import datetime, timezone

from simcore.scheduler import CronSchedule, ScheduleEntry, plan


class TestCron(unittest.TestCase):
    def test_parse_wildcards(self):
        c = CronSchedule.parse("*/15 * * * *")
        self.assertIn(0, c.minute)
        self.assertIn(15, c.minute)
        self.assertNotIn(7, c.minute)

    def test_next_run_hourly(self):
        c = CronSchedule.parse("0 * * * *")
        after = datetime(2026, 6, 1, 10, 30, tzinfo=timezone.utc)
        nxt = c.next_run(after)
        self.assertEqual((nxt.hour, nxt.minute), (11, 0))

    def test_next_run_daily(self):
        c = CronSchedule.parse("30 2 * * *")
        after = datetime(2026, 6, 1, 3, 0, tzinfo=timezone.utc)
        nxt = c.next_run(after)
        self.assertEqual((nxt.day, nxt.hour, nxt.minute), (2, 2, 30))

    def test_day_of_week(self):
        # Sunday = 0. 2026-06-07 is a Sunday.
        c = CronSchedule.parse("0 9 * * 0")
        after = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)  # a Monday
        nxt = c.next_run(after)
        self.assertEqual(nxt.weekday(), 6)  # Python Sunday == 6

    def test_bad_field_count(self):
        with self.assertRaises(ValueError):
            CronSchedule.parse("* * *")

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            CronSchedule.parse("99 * * * *")


class TestPlan(unittest.TestCase):
    def test_plan_and_disabled(self):
        entries = [
            ScheduleEntry(name="nightly", cron="0 2 * * *", targets=["http://127.0.0.1:9101"],
                          group="standard"),
            ScheduleEntry(name="off", cron="0 2 * * *", targets=["x"], enabled=False),
        ]
        now = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
        result = plan(entries, now=now)
        self.assertTrue(result[0]["next_run"])
        self.assertFalse(result[1]["enabled"])
        self.assertIsNone(result[1]["next_run"])


if __name__ == "__main__":
    unittest.main()
