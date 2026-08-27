"""Offline unit tests for netmetrics parsing/derivation logic."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netmetrics  # noqa: E402

WIN_PING = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=12ms TTL=57
Reply from 1.1.1.1: bytes=32 time=13ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 13ms, Average = 8ms
"""

UNIX_PING = """
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=13.1 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=11.8 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=12.0 ms

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 11.8/12.3/13.1/0.5 ms
"""

# Real Simplified-Chinese Windows `ping` output (full-width commas, 时间/已发送
# tokens). This is the exact shape that broke BUG-1 in the field — regression guard.
CN_WIN_PING = """
正在 Ping 1.1.1.1 具有 32 字节的数据:
来自 1.1.1.1 的回复: 字节=32 时间=12ms TTL=57
来自 1.1.1.1 的回复: 字节=32 时间=13ms TTL=57
来自 1.1.1.1 的回复: 字节=32 时间<1ms TTL=57
请求超时。

1.1.1.1 的 Ping 统计信息:
    数据包: 已发送 = 4，已接收 = 3，丢失 = 1 (25% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 1ms，最长 = 13ms，平均 = 8ms
"""


class TestParsePingWindows(unittest.TestCase):
    def setUp(self):
        self.p = netmetrics.parse_ping_summary(WIN_PING, is_windows=True)

    def test_counts(self):
        self.assertEqual(self.p["sent"], 4)
        self.assertEqual(self.p["received"], 3)

    def test_loss(self):
        self.assertAlmostEqual(self.p["loss_pct"], 25.0)

    def test_rtts(self):
        self.assertEqual(self.p["rtts"], [12.0, 13.0, 1.0])


class TestParsePingUnix(unittest.TestCase):
    def setUp(self):
        self.p = netmetrics.parse_ping_summary(UNIX_PING, is_windows=False)

    def test_counts_and_loss(self):
        self.assertEqual(self.p["sent"], 4)
        self.assertEqual(self.p["received"], 4)
        self.assertAlmostEqual(self.p["loss_pct"], 0.0)

    def test_rtts(self):
        self.assertEqual(self.p["rtts"], [12.3, 13.1, 11.8, 12.0])


class TestParsePingChineseWindows(unittest.TestCase):
    """Regression for BUG-1: Chinese-locale Windows ping must parse correctly."""

    def setUp(self):
        self.p = netmetrics.parse_ping_summary(CN_WIN_PING, is_windows=True)

    def test_counts(self):
        self.assertEqual(self.p["sent"], 4)
        self.assertEqual(self.p["received"], 3)

    def test_loss(self):
        self.assertAlmostEqual(self.p["loss_pct"], 25.0)

    def test_rtts(self):
        self.assertEqual(self.p["rtts"], [12.0, 13.0, 1.0])

    def test_not_reported_as_offline(self):
        # The exact real-world failure: a healthy host must not read as 100% loss.
        self.assertLess(self.p["loss_pct"], 100.0)
        self.assertGreater(self.p["received"], 0)


class TestJitter(unittest.TestCase):
    def test_none_for_single(self):
        self.assertIsNone(netmetrics._jitter([10.0]))

    def test_computed(self):
        # diffs: |12-10|=2, |11-12|=1 -> mean 1.5
        self.assertAlmostEqual(netmetrics._jitter([10.0, 12.0, 11.0]), 1.5)


class TestParseGeo(unittest.TestCase):
    def test_success(self):
        raw = b'{"status":"success","country":"\\u4e2d\\u56fd","regionName":"Beijing","city":"Beijing","isp":"Chinanet","query":"1.2.3.4"}'
        g = netmetrics.parse_geo(raw)
        self.assertTrue(g.ok)
        self.assertEqual(g.ip, "1.2.3.4")
        self.assertEqual(g.isp, "Chinanet")
        self.assertIn("Beijing", g.location())

    def test_failure_status(self):
        raw = b'{"status":"fail","message":"reserved range"}'
        g = netmetrics.parse_geo(raw)
        self.assertFalse(g.ok)
        self.assertIn("reserved", g.detail)

    def test_bad_json(self):
        g = netmetrics.parse_geo(b"not json")
        self.assertFalse(g.ok)


class TestStabilityRating(unittest.TestCase):
    def test_good(self):
        self.assertEqual(netmetrics.stability_rating(0.0, 5.0)[0], "good")

    def test_fair_by_loss(self):
        self.assertEqual(netmetrics.stability_rating(3.0, 5.0)[0], "fair")

    def test_poor_by_loss(self):
        self.assertEqual(netmetrics.stability_rating(10.0, 5.0)[0], "poor")

    def test_poor_by_jitter(self):
        self.assertEqual(netmetrics.stability_rating(0.0, 80.0)[0], "poor")

    def test_unknown(self):
        self.assertEqual(netmetrics.stability_rating(None, None)[0], "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
