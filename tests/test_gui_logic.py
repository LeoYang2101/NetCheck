"""Tests for netcheck_gui pure logic: target validation (AC7) and quality scoring.

Importing netcheck_gui pulls in PySide6 but constructs no QApplication at import
time, so these run headless.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import netcheck_gui as gui  # noqa: E402
import netmetrics  # noqa: E402


class TestValidateTarget(unittest.TestCase):
    def test_empty_is_general(self):
        ok, host, port, err = gui.validate_target("   ")
        self.assertTrue(ok)
        self.assertIsNone(host)
        self.assertIsNone(port)

    def test_plain_domain(self):
        ok, host, port, _ = gui.validate_target("example.com")
        self.assertTrue(ok)
        self.assertEqual(host, "example.com")
        self.assertIsNone(port)

    def test_ipv4(self):
        ok, host, port, _ = gui.validate_target("1.1.1.1")
        self.assertTrue(ok)
        self.assertEqual(host, "1.1.1.1")

    def test_host_port(self):
        ok, host, port, _ = gui.validate_target("example.com:443")
        self.assertTrue(ok)
        self.assertEqual(port, 443)

    def test_bad_port(self):
        ok, *_ , err = gui.validate_target("example.com:abc")
        self.assertFalse(ok)

    def test_port_out_of_range(self):
        ok, *_, err = gui.validate_target("example.com:70000")
        self.assertFalse(ok)

    def test_injection_attempt_rejected(self):
        # AC8-adjacent: shell metacharacters must fail validation, never reach ping.
        for bad in ("example.com; ls", "a && calc", "$(reboot)", "a|b", "`id`"):
            ok, *_ = gui.validate_target(bad)
            self.assertFalse(ok, f"{bad!r} should be rejected")

    def test_ipv6_rejected_gracefully(self):
        ok, *_, err = gui.validate_target("::1")
        self.assertFalse(ok)
        self.assertIn("IPv6", err)

    def test_malformed_dotted_ip_rejected(self):
        # BUG-2: all-numeric dotted input is an IP typo, not a hostname — reject
        # inline with an IP-range message instead of falling through to DNS.
        for bad in ("999.999.999.999", "256.1.1.1"):
            ok, host, port, err = gui.validate_target(bad)
            self.assertFalse(ok, f"{bad!r} should be rejected")
            self.assertIn("IP", err)

    def test_short_numeric_dotted_rejected(self):
        ok, *_, err = gui.validate_target("1.2.3")
        self.assertFalse(ok)

    def test_valid_ip_still_accepted(self):
        ok, host, *_ = gui.validate_target("255.255.255.0")
        self.assertTrue(ok)
        self.assertEqual(host, "255.255.255.0")


class TestComputeQuality(unittest.TestCase):
    def _stats(self, ok=True, loss=0.0, avg=20.0, jitter=2.0):
        s = netmetrics.PingStats(host="h", ok=ok)
        s.loss_pct = loss
        s.rtt_avg = avg
        s.jitter = jitter
        return s

    def test_perfect_is_good(self):
        score, level, _ = gui.compute_quality(self._stats())
        self.assertEqual(level, "good")
        self.assertGreaterEqual(score, 80)

    def test_high_loss_is_poor(self):
        score, level, _ = gui.compute_quality(self._stats(loss=20.0))
        self.assertEqual(level, "poor")

    def test_high_latency_drops_score(self):
        good = gui.compute_quality(self._stats(avg=20.0))[0]
        slow = gui.compute_quality(self._stats(avg=200.0))[0]
        self.assertLess(slow, good)

    def test_offline_is_zero(self):
        score, level, _ = gui.compute_quality(self._stats(ok=False))
        self.assertEqual(score, 0)
        self.assertEqual(level, "poor")


if __name__ == "__main__":
    unittest.main(verbosity=2)
