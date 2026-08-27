"""Unit tests for netcheck. Run: python -m pytest tests/  (or python tests/test_netcheck.py)

These focus on the pure/parsing/formatting logic and the checks that can run
offline (loopback), so the suite is deterministic and needs no internet.
"""
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netcheck  # noqa: E402


class TestTargetParse(unittest.TestCase):
    def test_bare_host(self):
        t = netcheck.Target.parse("example.com")
        self.assertIsNone(t.scheme)
        self.assertEqual(t.host, "example.com")
        self.assertIsNone(t.port)

    def test_host_with_port(self):
        t = netcheck.Target.parse("1.1.1.1:53")
        self.assertEqual(t.host, "1.1.1.1")
        self.assertEqual(t.port, 53)

    def test_https_url_defaults_port_443(self):
        t = netcheck.Target.parse("https://api.github.com")
        self.assertEqual(t.scheme, "https")
        self.assertEqual(t.host, "api.github.com")
        self.assertEqual(t.port, 443)

    def test_http_url_with_path_strips_path(self):
        t = netcheck.Target.parse("http://example.com/some/path")
        self.assertEqual(t.scheme, "http")
        self.assertEqual(t.host, "example.com")
        self.assertEqual(t.port, 80)

    def test_url_with_explicit_port(self):
        t = netcheck.Target.parse("http://example.com:8080")
        self.assertEqual(t.host, "example.com")
        self.assertEqual(t.port, 8080)


class TestPingRttParse(unittest.TestCase):
    def test_unix_format(self):
        out = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
        self.assertEqual(netcheck._parse_ping_rtt(out), 12.3)

    def test_windows_format(self):
        out = "Reply from 1.1.1.1: bytes=32 time=12ms TTL=57"
        self.assertEqual(netcheck._parse_ping_rtt(out), 12.0)

    def test_windows_sub_millisecond(self):
        out = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64"
        self.assertEqual(netcheck._parse_ping_rtt(out), 1.0)

    def test_no_match(self):
        self.assertIsNone(netcheck._parse_ping_rtt("Request timed out."))


class TestDnsLiteralIp(unittest.TestCase):
    def test_literal_ip_skips_lookup(self):
        r = netcheck.check_dns("127.0.0.1", timeout=1)
        self.assertTrue(r.ok)
        self.assertIn("literal IP", r.detail)


class TestTcpCheckLoopback(unittest.TestCase):
    def setUp(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self._stop = False

        def accept_loop():
            self.srv.settimeout(0.5)
            while not self._stop:
                try:
                    c, _ = self.srv.accept()
                    c.close()
                except socket.timeout:
                    continue
                except OSError:
                    break

        self.thread = threading.Thread(target=accept_loop, daemon=True)
        self.thread.start()

    def tearDown(self):
        self._stop = True
        self.srv.close()
        self.thread.join(timeout=2)

    def test_open_port(self):
        r = netcheck.check_tcp("127.0.0.1", self.port, timeout=2)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail, "open")
        self.assertIsNotNone(r.latency_ms)

    def test_closed_port(self):
        # Bind a socket to grab a free port, close it, then probe it (unused).
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        r = netcheck.check_tcp("127.0.0.1", closed_port, timeout=1)
        self.assertFalse(r.ok)


class TestPayloadAndLocalIp(unittest.TestCase):
    def test_build_payload_all_ok(self):
        rep = netcheck.TargetReport(target="x")
        rep.checks.append(netcheck.CheckResult("DNS", True, "ok"))
        payload = netcheck.build_payload({"local_ip": "1.2.3.4", "public_ip": "5.6.7.8"}, [rep])
        self.assertTrue(payload["all_ok"])
        self.assertEqual(payload["targets"][0]["target"], "x")

    def test_build_payload_with_failure(self):
        rep = netcheck.TargetReport(target="x")
        rep.checks.append(netcheck.CheckResult("DNS", False, "fail"))
        payload = netcheck.build_payload({"local_ip": "?", "public_ip": "?"}, [rep])
        self.assertFalse(payload["all_ok"])

    def test_local_ip_returns_string(self):
        ip = netcheck.local_ip()
        self.assertIsInstance(ip, str)
        self.assertTrue(len(ip) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
