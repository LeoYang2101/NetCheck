"""netmetrics — extra network metrics for the NetCheck GUI (P0 F2/F5).

Builds on netcheck.py (DNS/ping/TCP/HTTP primitives). Adds:
  - ping_stats(): multi-ping latency + packet-loss + jitter (F2)
  - ip_geo():     public IP + geolocation / ISP (F5)

Parsing is split into pure functions (parse_ping_summary, parse_geo) so they
can be unit-tested offline and deterministically.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PingStats:
    host: str
    ok: bool
    sent: int = 0
    received: int = 0
    loss_pct: float = 100.0
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    jitter: Optional[float] = None  # mean abs diff between consecutive RTTs
    detail: str = ""
    tcp_ok: Optional[bool] = None   # TCP-connect reachability fallback (ICMP-blocked hosts)
    rtts: list = field(default_factory=list)


def _jitter(rtts: list) -> Optional[float]:
    if len(rtts) < 2:
        return None
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    return sum(diffs) / len(diffs)


def parse_ping_summary(output: str, is_windows: bool) -> dict:
    """Extract sent/received/loss and per-reply RTTs from `ping` output.

    Locale-independent: matches both English and Simplified-Chinese Windows
    output (中文 Windows prints `时间=12ms` / `已发送 = 4，已接收 = 4，丢失 = 0`
    with full-width commas, which the English-only patterns missed → BUG-1).
    Returns a dict; missing values are left as None. Kept pure for testing.
    """
    result = {"sent": None, "received": None, "loss_pct": None, "rtts": []}

    # Per-reply RTTs: English "time=12ms"/"time<1ms", Chinese "时间=12ms"/"时间<1ms".
    result["rtts"] = [
        float(m) for m in re.findall(r"(?:time|时间)[=<]\s*([\d.]+)\s*ms", output)
    ]

    if is_windows:
        # English: "Sent = 4, Received = 3, Lost = 1"
        # Chinese: "已发送 = 4，已接收 = 3，丢失 = 1"  (full-width comma / spaces vary)
        m = re.search(
            r"(?:Sent|已发送)\s*=\s*(\d+)\D+?(?:Received|已接收)\s*=\s*(\d+)", output
        )
        if m:
            sent, recv = int(m.group(1)), int(m.group(2))
            result["sent"], result["received"] = sent, recv
            result["loss_pct"] = (sent - recv) / sent * 100 if sent else 100.0
    else:
        m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", output)
        if m:
            sent, recv = int(m.group(1)), int(m.group(2))
            result["sent"], result["received"] = sent, recv
            result["loss_pct"] = (sent - recv) / sent * 100 if sent else 100.0
        lm = re.search(r"(\d+)%\s+packet loss", output)
        if lm and result["loss_pct"] is None:
            result["loss_pct"] = float(lm.group(1))
    return result


def ping_stats(host: str, count: int = 4, timeout: float = 3.0) -> PingStats:
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(int(max(1, timeout)))
    cmd = ["ping", count_flag, str(count), timeout_flag, timeout_val, host]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout * count + 5, text=True,
        )
    except FileNotFoundError:
        return PingStats(host, False, detail="ping 命令不可用")
    except subprocess.TimeoutExpired:
        return PingStats(host, False, detail="超时无响应")
    except Exception as e:  # noqa: BLE001
        return PingStats(host, False, detail=f"错误: {e}")

    parsed = parse_ping_summary(proc.stdout, is_windows)
    rtts = parsed["rtts"]
    sent = parsed["sent"] or count
    received = parsed["received"]
    if received is None:
        received = len(rtts)
    loss = parsed["loss_pct"]
    if loss is None:
        loss = (sent - received) / sent * 100 if sent else 100.0

    stats = PingStats(
        host=host,
        ok=received > 0,
        sent=sent,
        received=received,
        loss_pct=round(loss, 1),
        rtts=rtts,
    )
    if rtts:
        stats.rtt_min = round(min(rtts), 1)
        stats.rtt_max = round(max(rtts), 1)
        stats.rtt_avg = round(sum(rtts) / len(rtts), 1)
        j = _jitter(rtts)
        stats.jitter = round(j, 1) if j is not None else None
    if stats.ok:
        stats.detail = f"{received}/{sent} 回复，丢包 {stats.loss_pct}%"
    else:
        stats.detail = "无回复（可能屏蔽 ICMP 或不可达）"
    return stats


def check_connectivity(host: str, port: int = 443, count: int = 4,
                       timeout: float = 3.0) -> PingStats:
    """Ping-based latency/loss stats, with a TCP-connect reachability fallback.

    Many hosts (e.g. github.com) drop ICMP, so ping alone reports them offline
    even when they serve traffic. When ping gets no reply we probe `host:port`
    over TCP and record it in `tcp_ok`, so the connectivity card can distinguish
    "ICMP blocked but reachable" from "truly down" (BUG-1 附带项).
    """
    stats = ping_stats(host, count=count, timeout=timeout)
    if not stats.ok:
        import netcheck  # lazy import avoids any import cycle
        try:
            tcp = netcheck.check_tcp(host, port, timeout=timeout)
            stats.tcp_ok = bool(tcp.ok)
            if tcp.ok:
                stats.detail = f"ICMP 无回复，但 TCP {port} 可达（可能屏蔽 ICMP）"
        except Exception as e:  # noqa: BLE001 — fallback must never crash the check
            stats.tcp_ok = False
            stats.detail = f"{stats.detail}；TCP 探测失败: {e}"
    return stats


@dataclass
class GeoInfo:
    ok: bool
    ip: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    detail: str = ""

    def location(self) -> str:
        parts = [p for p in (self.country, self.region, self.city) if p]
        return " / ".join(parts) if parts else "未知"


def parse_geo(raw: bytes) -> GeoInfo:
    """Parse an ip-api.com JSON response. Pure, for testing."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        return GeoInfo(False, detail=f"解析失败: {e}")
    if data.get("status") != "success":
        return GeoInfo(False, detail=data.get("message", "查询失败"))
    return GeoInfo(
        ok=True,
        ip=data.get("query", ""),
        country=data.get("country", ""),
        region=data.get("regionName", ""),
        city=data.get("city", ""),
        isp=data.get("isp", ""),
    )


def ip_geo(timeout: float = 5.0) -> GeoInfo:
    url = "http://ip-api.com/json/?lang=zh-CN&fields=status,message,country,regionName,city,isp,query"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "netcheck/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return parse_geo(resp.read())
    except Exception as e:  # noqa: BLE001
        return GeoInfo(False, detail=f"无法获取归属地: {e}")


def stability_rating(loss_pct: Optional[float], jitter: Optional[float]) -> tuple:
    """Return (level, label) where level in {good, fair, poor, unknown}.

    Thresholds align with the design spec (loss 0 优 / <2 一般 / >=2 差).
    """
    if loss_pct is None:
        return ("unknown", "未知")
    if loss_pct >= 5 or (jitter is not None and jitter > 50):
        return ("poor", "差")
    if loss_pct >= 2 or (jitter is not None and jitter > 20):
        return ("fair", "一般")
    return ("good", "优")
