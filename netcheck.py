#!/usr/bin/env python3
"""netcheck — a zero-dependency network diagnostics CLI.

Runs a set of connectivity checks against one or more targets and prints a
readable summary. Standard library only, so it runs anywhere Python 3.8+ is.

Checks per target:
  - DNS resolution (hostname -> IP addresses)
  - Ping / reachability (system ping, with a TCP-connect fallback)
  - TCP port open/closed (when a port is given, e.g. host:443)
  - HTTP(S) health (status code + latency, when a URL or web port is implied)

Plus host-level checks:
  - Local IP address
  - Public (egress) IP address

Usage:
  python netcheck.py                       # check a default set of targets
  python netcheck.py example.com           # DNS + ping + common web ports
  python netcheck.py example.com:443       # DNS + ping + TCP 443 + HTTPS
  python netcheck.py 1.1.1.1:53 github.com https://api.github.com
  python netcheck.py --json example.com    # machine-readable JSON output
  python netcheck.py --timeout 3 host      # per-check timeout in seconds

Exit code is 0 when every check passed, 1 when any check failed.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Optional

DEFAULT_TARGETS = ["github.com", "1.1.1.1:53", "https://www.google.com"]
COMMON_WEB_PORTS = (80, 443)

# ----- terminal colors (auto-disabled when not a tty) -------------------------


class C:
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for name in ("GREEN", "RED", "YELLOW", "DIM", "BOLD", "RESET"):
            setattr(cls, name, "")


def _supports_unicode() -> bool:
    """True when stdout can encode the tick glyphs (e.g. Windows GBK cannot)."""
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "✓✗".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# Chosen once at import based on the console's real encoding.
PASS_MARK, FAIL_MARK = ("✓", "✗") if _supports_unicode() else ("+", "x")


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    latency_ms: Optional[float] = None


@dataclass
class TargetReport:
    target: str
    checks: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)


# ----- target parsing ---------------------------------------------------------


@dataclass
class Target:
    raw: str
    scheme: Optional[str]  # "http" / "https" / None
    host: str
    port: Optional[int]

    @classmethod
    def parse(cls, raw: str) -> "Target":
        scheme = None
        host = raw.strip()
        port = None
        if "://" in host:
            scheme, host = host.split("://", 1)
            scheme = scheme.lower()
            host = host.split("/", 1)[0]  # strip any path
        # host may still carry :port (but not for bare IPv6 — kept simple here)
        if host.count(":") == 1:
            h, p = host.rsplit(":", 1)
            if p.isdigit():
                host, port = h, int(p)
        if port is None and scheme == "https":
            port = 443
        if port is None and scheme == "http":
            port = 80
        return cls(raw=raw, scheme=scheme, host=host, port=port)


# ----- individual checks ------------------------------------------------------


def check_dns(host: str, timeout: float) -> CheckResult:
    # Skip DNS when the host is already a literal IP address.
    try:
        socket.inet_aton(host)
        return CheckResult("DNS", True, f"{host} (literal IP, no lookup)")
    except OSError:
        pass
    socket.setdefaulttimeout(timeout)
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None)
        latency = (time.perf_counter() - start) * 1000
        ips = sorted({i[4][0] for i in infos})
        return CheckResult("DNS", True, ", ".join(ips), latency)
    except socket.gaierror as e:
        return CheckResult("DNS", False, f"resolution failed: {e}")
    except Exception as e:  # noqa: BLE001
        return CheckResult("DNS", False, f"error: {e}")
    finally:
        socket.setdefaulttimeout(None)


def check_ping(host: str, timeout: float) -> CheckResult:
    """Use the system ping; fall back to a TCP connect if ICMP is blocked."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    # ping timeout: Windows -w is milliseconds, Unix -W is seconds.
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(int(max(1, timeout)))
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, host]
    try:
        start = time.perf_counter()
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
            text=True,
        )
        elapsed = (time.perf_counter() - start) * 1000
        if proc.returncode == 0:
            rtt = _parse_ping_rtt(proc.stdout)
            return CheckResult("PING", True, "reachable", rtt if rtt else elapsed)
        return CheckResult("PING", False, "no reply (host may block ICMP)")
    except FileNotFoundError:
        return CheckResult("PING", False, "ping command not available")
    except subprocess.TimeoutExpired:
        return CheckResult("PING", False, "timed out")
    except Exception as e:  # noqa: BLE001
        return CheckResult("PING", False, f"error: {e}")


def _parse_ping_rtt(output: str) -> Optional[float]:
    # Matches "time=12.3 ms" (Unix) and "time=12ms" / "time<1ms" (Windows).
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", output)
    if m:
        return float(m.group(1))
    return None


def check_tcp(host: str, port: int, timeout: float) -> CheckResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000
            return CheckResult(f"TCP:{port}", True, "open", latency)
    except socket.timeout:
        return CheckResult(f"TCP:{port}", False, "timed out")
    except ConnectionRefusedError:
        return CheckResult(f"TCP:{port}", False, "refused")
    except OSError as e:
        return CheckResult(f"TCP:{port}", False, f"unreachable: {e}")


def check_http(url: str, timeout: float) -> CheckResult:
    name = "HTTPS" if url.startswith("https") else "HTTP"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "netcheck/1.0"})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            latency = (time.perf_counter() - start) * 1000
            code = resp.getcode()
            ok = code < 400
            return CheckResult(name, ok, f"HTTP {code}", latency)
    except urllib.error.HTTPError as e:
        # Server responded, just with an error status — that is still "reachable".
        latency = (time.perf_counter() - start) * 1000
        return CheckResult(name, e.code < 500, f"HTTP {e.code}", latency)
    except urllib.error.URLError as e:
        return CheckResult(name, False, f"failed: {e.reason}")
    except Exception as e:  # noqa: BLE001
        return CheckResult(name, False, f"error: {e}")


# ----- host-level checks ------------------------------------------------------


def local_ip() -> str:
    try:
        # No packets are actually sent for a UDP connect; it just picks a route.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "unknown"


def public_ip(timeout: float) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netcheck/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip
        except Exception:  # noqa: BLE001
            continue
    return "unavailable (no outbound HTTPS?)"


# ----- orchestration ----------------------------------------------------------


def run_target(target: Target, timeout: float) -> TargetReport:
    report = TargetReport(target=target.raw)
    report.checks.append(check_dns(target.host, timeout))
    report.checks.append(check_ping(target.host, timeout))

    if target.port is not None:
        report.checks.append(check_tcp(target.host, target.port, timeout))
    elif target.scheme is None:
        # Bare hostname: probe common web ports so the tool is useful by default.
        for p in COMMON_WEB_PORTS:
            report.checks.append(check_tcp(target.host, p, timeout))

    if target.scheme in ("http", "https"):
        report.checks.append(check_http(target.raw, timeout))
    elif target.scheme is None and target.port in (80, 443):
        proto = "https" if target.port == 443 else "http"
        report.checks.append(check_http(f"{proto}://{target.host}", timeout))

    return report


def _fmt_latency(ms: Optional[float]) -> str:
    if ms is None:
        return ""
    return f"{C.DIM}({ms:.0f} ms){C.RESET}"


def print_human(host_info: dict, reports: list) -> None:
    print(f"{C.BOLD}netcheck report{C.RESET}")
    print(f"  local IP : {host_info['local_ip']}")
    print(f"  public IP: {host_info['public_ip']}")
    print()
    for r in reports:
        header = f"{C.BOLD}{r.target}{C.RESET}"
        status = f"{C.GREEN}OK{C.RESET}" if r.ok else f"{C.RED}ISSUES{C.RESET}"
        print(f"{header}  [{status}]")
        for c in r.checks:
            mark = f"{C.GREEN}{PASS_MARK}{C.RESET}" if c.ok else f"{C.RED}{FAIL_MARK}{C.RESET}"
            line = f"  {mark} {c.name:<9} {c.detail}"
            lat = _fmt_latency(c.latency_ms)
            if lat:
                line += f" {lat}"
            print(line)
        print()


def build_payload(host_info: dict, reports: list) -> dict:
    return {
        "host": host_info,
        "targets": [
            {
                "target": r.target,
                "ok": r.ok,
                "checks": [asdict(c) for c in r.checks],
            }
            for r in reports
        ],
        "all_ok": all(r.ok for r in reports),
    }


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dependency network diagnostics tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="hosts/URLs to check, e.g. example.com  1.1.1.1:53  https://api.github.com",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="per-check timeout in seconds (default 5)"
    )
    parser.add_argument("--json", action="store_true", help="output machine-readable JSON")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args(argv)

    if args.no_color or args.json or not sys.stdout.isatty():
        C.disable()

    targets = args.targets or DEFAULT_TARGETS
    parsed = [Target.parse(t) for t in targets]

    host_info = {
        "local_ip": local_ip(),
        "public_ip": public_ip(args.timeout),
    }
    reports = [run_target(t, args.timeout) for t in parsed]

    if args.json:
        print(json.dumps(build_payload(host_info, reports), indent=2))
    else:
        print_human(host_info, reports)

    return 0 if all(r.ok for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
