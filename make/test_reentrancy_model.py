#!/usr/bin/env python3
"""Abstract E4/E6 state-machine checks for lease / IN_FLIGHT / release."""

from __future__ import annotations

import unittest


class FlightState:
    def __init__(self) -> None:
        self.active = False
        self.in_flight = 0
        self.entry = 0
        self.map_users = 0

    def lease(self, entry: int) -> bool:
        if self.active or entry == 0:
            return False
        self.entry = entry
        self.active = True
        self.map_users += 1
        return True

    def try_run(self) -> bool:
        if not self.active or self.entry == 0:
            return False
        if self.in_flight != 0:
            return False  # reentrancy rejected
        self.in_flight += 1
        return True

    def end_run(self) -> None:
        assert self.in_flight > 0
        self.in_flight -= 1

    def release(self) -> bool:
        if not self.active:
            return False
        if self.in_flight != 0:
            return False  # must drain first
        self.active = False
        self.entry = 0
        self.map_users = max(0, self.map_users - 1)
        return True


class ReentrancyTests(unittest.TestCase):
    def test_reject_nested_flight(self) -> None:
        s = FlightState()
        self.assertTrue(s.lease(0x40380200))
        self.assertTrue(s.try_run())
        self.assertFalse(s.try_run())
        s.end_run()
        self.assertTrue(s.try_run())
        s.end_run()

    def test_release_waits_for_drain(self) -> None:
        s = FlightState()
        self.assertTrue(s.lease(0x40380200))
        self.assertTrue(s.try_run())
        self.assertFalse(s.release())
        s.end_run()
        self.assertTrue(s.release())
        self.assertEqual(s.map_users, 0)
        self.assertEqual(s.entry, 0)

    def test_inactive_run_rejected(self) -> None:
        s = FlightState()
        self.assertFalse(s.try_run())


if __name__ == "__main__":
    unittest.main()
