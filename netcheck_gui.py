#!/usr/bin/env python3
"""NetCheck — cross-platform network check desktop GUI (PySide6).

P0 / F1–F7 MVP. Reuses the framework-agnostic detection core:
  - netcheck.py   : DNS / TCP / HTTP / local IP primitives
  - netmetrics.py : ping latency+loss+jitter, public IP + geolocation, stability

Design (per UX spec): single window, three zones —
  top bar (title · target input · refresh · theme) /
  overview strip (quality · online · public IP+geo · last check) /
  metric card grid — plus a bottom bar (copy report).

Checks run on a QThreadPool (QRunnable) and stream results back to the UI thread
via signals, so the window never freezes (AC6). Target input is validated before
use (AC7); the ping core uses argv-array subprocess calls, never shell strings,
so `; ls` / `&& calc` style input cannot execute (AC8).

Run:  python netcheck_gui.py
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys
import time
import traceback

from PySide6.QtCore import Qt, QObject, QRunnable, QThreadPool, Signal, QTimer
from PySide6.QtGui import QFont, QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFrame, QSizePolicy, QScrollArea,
)

import netcheck
import netmetrics

# App icon lives in assets/, bundled into the exe via --add-data (see build docs).
ICON_REL = os.path.join("assets", "icon.ico")


def resource_path(rel: str) -> str:
    """Resolve a bundled resource path from source *or* a PyInstaller onefile.

    PyInstaller unpacks bundled data to a temp dir exposed as sys._MEIPASS; from
    source we fall back to this file's directory so setWindowIcon finds the .ico
    in both cases.
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


# ----- input validation (AC7) -------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(text: str):
    """Return (ok, host, port, error). Empty text is valid (means general check)."""
    text = text.strip()
    if not text:
        return True, None, None, ""
    host, port = text, None
    if text.count(":") == 1:
        h, p = text.rsplit(":", 1)
        if not p.isdigit():
            return False, None, None, "端口必须是数字"
        port = int(p)
        if not (1 <= port <= 65535):
            return False, None, None, "端口需在 1–65535 之间"
        host = h
    elif text.count(":") > 1:
        return False, None, None, "格式无效（IPv6 暂不支持，请用 域名/IPv4[:端口]）"
    if not host:
        return False, None, None, "主机名不能为空"
    try:
        ipaddress.ip_address(host)
        return True, host, port, ""
    except ValueError:
        pass
    # Dotted all-numeric input was meant as an IP; since ip_address() rejected it,
    # it's a malformed IP (octet out of range / wrong shape), not a hostname — so
    # report it precisely instead of letting it fall through to a DNS failure (BUG-2).
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return False, None, None, "IP 地址无效（每段应为 0–255）"
    if re.fullmatch(r"[\d.]+", host):
        return False, None, None, "IP 地址格式无效"
    if _HOSTNAME_RE.match(host):
        return True, host, port, ""
    return False, None, None, "主机名格式无效"


# ----- quality scoring --------------------------------------------------------


def compute_quality(stats: "netmetrics.PingStats"):
    """Aggregate latency + loss into a 0–100 score and a rating."""
    if stats is None or not stats.ok:
        return 0, "poor", "差"
    score = 100.0
    score -= min(stats.loss_pct, 100) * 4          # loss dominates
    if stats.rtt_avg is not None:
        if stats.rtt_avg > 150:
            score -= 30
        elif stats.rtt_avg > 50:
            score -= 12
    if stats.jitter is not None and stats.jitter > 30:
        score -= 10
    score = max(0, min(100, round(score)))
    if score >= 80:
        return score, "good", "优"
    if score >= 55:
        return score, "fair", "一般"
    return score, "poor", "差"


# ----- worker (QThreadPool) ---------------------------------------------------


class WorkerSignals(QObject):
    result = Signal(str, object)   # (card_key, payload)
    error = Signal(str, str)       # (card_key, message)


class CheckTask(QRunnable):
    def __init__(self, key, fn):
        super().__init__()
        self.key = key
        self.fn = fn
        self.signals = WorkerSignals()

    def run(self):
        try:
            self.signals.result.emit(self.key, self.fn())
        except Exception as e:  # noqa: BLE001 — never let a worker crash the app (AC1)
            traceback.print_exc()
            self.signals.error.emit(self.key, str(e))


# ----- status tokens ----------------------------------------------------------

STATUS_COLORS = {
    "good": "#1a9d55", "fair": "#c88a04", "poor": "#d33a3a",
    "idle": "#8a8f98", "running": "#5b8def", "na": "#8a8f98",
}
STATUS_ICON = {
    "good": "✓", "fair": "!", "poor": "✕",
    "idle": "·", "running": "⟳", "na": "—",
}


# ----- metric card ------------------------------------------------------------


class MetricCard(QFrame):
    def __init__(self, key, title):
        super().__init__()
        self.key = key
        self.setObjectName("card")
        self.setMinimumWidth(250)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)

        self.title_lbl = QLabel(title)
        self.title_lbl.setObjectName("cardTitle")
        self.value_lbl = QLabel("—")
        self.value_lbl.setObjectName("cardValue")
        vf = QFont()
        vf.setPointSize(16)
        vf.setBold(True)
        self.value_lbl.setFont(vf)
        self.status_lbl = QLabel("未检测")
        self.status_lbl.setObjectName("cardStatus")
        self.detail_lbl = QLabel("")
        self.detail_lbl.setObjectName("cardDetail")
        self.detail_lbl.setWordWrap(True)

        lay.addWidget(self.title_lbl)
        lay.addWidget(self.value_lbl)
        lay.addWidget(self.status_lbl)
        lay.addWidget(self.detail_lbl)
        self.set_state("idle", "—", "未检测", "")

    def set_state(self, level, value, status, detail):
        color = STATUS_COLORS.get(level, "#8a8f98")
        icon = STATUS_ICON.get(level, "·")
        self.value_lbl.setText(str(value))
        self.status_lbl.setText(f"{icon} {status}")
        self.status_lbl.setStyleSheet(f"color: {color}; font-weight: 600;")
        self.detail_lbl.setText(detail or "")
        self.setProperty("level", level)
        # re-polish so the QSS border color picks up the new level
        self.style().unpolish(self)
        self.style().polish(self)


# ----- main window ------------------------------------------------------------

LIGHT_QSS = """
QMainWindow, QWidget#central { background: #f4f5f7; }
QLabel#appTitle { font-size: 18px; font-weight: 700; color: #1c1e21; }
QLabel#overviewItem { color: #3a3d42; font-size: 13px; }
QFrame#card { background: #ffffff; border: 1px solid #e3e6ea; border-radius: 12px; }
QFrame#card[level="good"] { border-left: 4px solid #1a9d55; }
QFrame#card[level="fair"] { border-left: 4px solid #c88a04; }
QFrame#card[level="poor"] { border-left: 4px solid #d33a3a; }
QFrame#card[level="running"] { border-left: 4px solid #5b8def; }
QLabel#cardTitle { color: #6b7076; font-size: 12px; }
QLabel#cardValue { color: #1c1e21; }
QLabel#cardDetail { color: #6b7076; font-size: 11px; }
QLineEdit { padding: 6px 10px; border: 1px solid #cfd3d8; border-radius: 8px; background: #fff; }
QPushButton { padding: 7px 16px; border-radius: 8px; background: #2f6fed; color: #fff; font-weight: 600; }
QPushButton:hover { background: #285fd0; }
QPushButton:disabled { background: #a9c0f2; }
QPushButton#ghost { background: #e7eaef; color: #1c1e21; }
QPushButton#ghost:hover { background: #dbdfe6; }
"""

DARK_QSS = """
QMainWindow, QWidget#central { background: #1b1d21; }
QLabel#appTitle { font-size: 18px; font-weight: 700; color: #f0f1f3; }
QLabel#overviewItem { color: #c3c7cd; font-size: 13px; }
QFrame#card { background: #26292e; border: 1px solid #33373d; border-radius: 12px; }
QFrame#card[level="good"] { border-left: 4px solid #2bbd6b; }
QFrame#card[level="fair"] { border-left: 4px solid #e0a419; }
QFrame#card[level="poor"] { border-left: 4px solid #e85d5d; }
QFrame#card[level="running"] { border-left: 4px solid #5b8def; }
QLabel#cardTitle { color: #9aa0a8; font-size: 12px; }
QLabel#cardValue { color: #f0f1f3; }
QLabel#cardDetail { color: #9aa0a8; font-size: 11px; }
QLineEdit { padding: 6px 10px; border: 1px solid #3a3f46; border-radius: 8px; background: #303439; color: #f0f1f3; }
QPushButton { padding: 7px 16px; border-radius: 8px; background: #3b7bf0; color: #fff; font-weight: 600; }
QPushButton:hover { background: #4a86f2; }
QPushButton:disabled { background: #35435f; color: #9aa0a8; }
QPushButton#ghost { background: #33373d; color: #f0f1f3; }
QPushButton#ghost:hover { background: #3d424a; }
"""

# Default probe targets for a "general" (no input) check.
DEFAULT_PING = "1.1.1.1"
DEFAULT_DNS = "www.baidu.com"


class NetCheckWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetCheck · 网络检查工具")
        self.setWindowIcon(QIcon(resource_path(ICON_REL)))
        self.resize(880, 620)
        self.pool = QThreadPool.globalInstance()
        self._pending = 0
        self._dark = False
        self._last_report = {}

        central = QWidget()
        central.setObjectName("central")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(18, 16, 18, 14)
        root.setSpacing(12)

        root.addLayout(self._build_topbar())
        root.addWidget(self._build_overview())
        root.addWidget(self._build_cards(), 1)
        root.addLayout(self._build_bottombar())

        self.apply_theme()

    # -- UI construction --
    def _build_topbar(self):
        bar = QHBoxLayout()
        title = QLabel("NetCheck")
        title.setObjectName("appTitle")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("域名 / IP[:端口]（留空=检查本机网络）")
        self.target_input.returnPressed.connect(self.run_checks)
        self.refresh_btn = QPushButton("⟳ 刷新")
        self.refresh_btn.clicked.connect(self.run_checks)
        self.theme_btn = QPushButton("🌓 主题")
        self.theme_btn.setObjectName("ghost")
        self.theme_btn.clicked.connect(self.toggle_theme)
        bar.addWidget(title)
        bar.addSpacing(12)
        bar.addWidget(self.target_input, 1)
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.theme_btn)
        return bar

    def _build_overview(self):
        frame = QFrame()
        frame.setObjectName("card")
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(14, 10, 14, 10)
        self.ov_status = QLabel("● 待检测")
        self.ov_status.setObjectName("overviewItem")
        self.ov_ip = QLabel("公网 IP：—")
        self.ov_ip.setObjectName("overviewItem")
        self.ov_time = QLabel("上次检查：—")
        self.ov_time.setObjectName("overviewItem")
        lay.addWidget(self.ov_status)
        lay.addStretch(1)
        lay.addWidget(self.ov_ip)
        lay.addStretch(1)
        lay.addWidget(self.ov_time)
        return frame

    def _build_cards(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        holder = QWidget()
        self.grid = QGridLayout(holder)
        self.grid.setSpacing(12)
        self.grid.setContentsMargins(0, 0, 0, 0)

        self.cards = {}
        specs = [
            ("connectivity", "连通性"),
            ("latency", "延迟"),
            ("loss", "丢包率"),
            ("dns", "DNS 解析"),
            ("port", "端口访问"),
            ("stability", "稳定性 / 抖动"),
            ("geo", "公网 IP / 归属地"),
            ("quality", "网络质量评分"),
        ]
        cols = 3
        for i, (key, title) in enumerate(specs):
            card = MetricCard(key, title)
            self.cards[key] = card
            self.grid.addWidget(card, i // cols, i % cols)
        for c in range(cols):
            self.grid.setColumnStretch(c, 1)
        scroll.setWidget(holder)
        return scroll

    def _build_bottombar(self):
        bar = QHBoxLayout()
        self.status_line = QLabel("就绪。点击「刷新」开始检查。")
        self.status_line.setObjectName("overviewItem")
        self.copy_btn = QPushButton("复制报告")
        self.copy_btn.setObjectName("ghost")
        self.copy_btn.clicked.connect(self.copy_report)
        bar.addWidget(self.status_line, 1)
        bar.addWidget(self.copy_btn)
        return bar

    # -- theming --
    def apply_theme(self):
        self.setStyleSheet(DARK_QSS if self._dark else LIGHT_QSS)

    def toggle_theme(self):
        self._dark = not self._dark
        self.apply_theme()

    # -- run checks --
    def run_checks(self):
        # Guard against re-entry while a pass is running: the refresh button is
        # disabled, but returnPressed in the input would otherwise bypass it (BUG-3).
        if not self.refresh_btn.isEnabled():
            return
        ok, host, port, err = validate_target(self.target_input.text())
        if not ok:
            self.status_line.setText(f"⚠ 输入无效：{err}")
            self.target_input.setStyleSheet("border: 1px solid #d33a3a;")
            return
        self.target_input.setStyleSheet("")

        general = host is None
        ping_host = host or DEFAULT_PING
        dns_host = host if (host and not _is_ip(host)) else DEFAULT_DNS

        # Reset applicable cards to "running".
        for key, card in self.cards.items():
            if key == "port" and general:
                card.set_state("na", "—", "不适用", "填入 host:端口 后可用")
                continue
            card.set_state("running", "…", "检测中", "")

        tasks = [
            ("latency", lambda h=ping_host, p=(port or 443):
                netmetrics.check_connectivity(h, port=p, count=4, timeout=3.0)),
            ("dns", lambda h=dns_host: netcheck.check_dns(h, timeout=5.0)),
            ("geo", lambda: netmetrics.ip_geo(timeout=6.0)),
        ]
        if not general and port is not None:
            tasks.append(("port", lambda h=host, p=port: netcheck.check_tcp(h, p, timeout=5.0)))
        elif not general:
            tasks.append(("port_web", lambda h=host: netcheck.check_tcp(h, 443, timeout=5.0)))

        self._pending = len(tasks) + 1  # +1 for the latency-derived cards bundle
        self.refresh_btn.setEnabled(False)
        self.status_line.setText("检查中…")

        for key, fn in tasks:
            task = CheckTask(key, fn)
            task.signals.result.connect(self.on_result)
            task.signals.error.connect(self.on_error)
            self.pool.start(task)

        self.ov_time.setText("上次检查：" + time.strftime("%H:%M:%S"))

    # -- result handlers (main thread) --
    def on_result(self, key, payload):
        if key == "latency":
            self._apply_ping(payload)
        elif key == "dns":
            self._apply_dns(payload)
        elif key == "geo":
            self._apply_geo(payload)
        elif key in ("port", "port_web"):
            self._apply_port(payload, key == "port_web")
        self._tick_done()

    def on_error(self, key, message):
        card = self.cards.get(key if key != "port_web" else "port")
        if card:
            card.set_state("poor", "错误", "失败", message)
        self._tick_done()

    def _apply_ping(self, s):
        self._last_report["ping"] = s
        # connectivity — ICMP first, then TCP-reachability fallback (ICMP-blocked hosts)
        if s.ok:
            self.cards["connectivity"].set_state("good", "已连接", "正常", s.detail)
            self.ov_status.setText("● 在线")
        elif getattr(s, "tcp_ok", None):
            self.cards["connectivity"].set_state("fair", "可达 (TCP)", "ICMP 受限", s.detail)
            self.ov_status.setText("● 在线（ICMP 受限）")
        else:
            self.cards["connectivity"].set_state("poor", "不通", "失败", s.detail)
            self.ov_status.setText("● 离线 / 受限")
        # latency
        if s.ok and s.rtt_avg is not None:
            lvl = "good" if s.rtt_avg < 50 else "fair" if s.rtt_avg <= 150 else "poor"
            self.cards["latency"].set_state(
                lvl, f"{s.rtt_avg} ms", {"good": "优", "fair": "一般", "poor": "差"}[lvl],
                f"最小 {s.rtt_min} / 最大 {s.rtt_max} ms",
            )
        else:
            self.cards["latency"].set_state("poor", "—", "无数据", s.detail)
        # loss
        loss = s.loss_pct
        lvl = "good" if loss == 0 else "fair" if loss < 2 else "poor"
        self.cards["loss"].set_state(
            lvl, f"{loss}%", {"good": "优", "fair": "一般", "poor": "差"}[lvl],
            f"{s.received}/{s.sent} 回复",
        )
        # stability / jitter
        slevel, slabel = netmetrics.stability_rating(s.loss_pct, s.jitter)
        jd = f"抖动 {s.jitter} ms" if s.jitter is not None else "抖动 —"
        self.cards["stability"].set_state(slevel, slabel, slabel, jd)
        # quality
        score, qlevel, qlabel = compute_quality(s)
        self.cards["quality"].set_state(qlevel, f"{score}", qlabel, "综合延迟+丢包评估")

    def _apply_dns(self, r):
        self._last_report["dns"] = r
        if r.ok:
            lat = f"{r.latency_ms:.0f} ms · " if r.latency_ms else ""
            self.cards["dns"].set_state("good", "正常", "成功", f"{lat}{r.detail}")
        else:
            self.cards["dns"].set_state("poor", "失败", "失败", r.detail)

    def _apply_geo(self, g):
        self._last_report["geo"] = g
        if g.ok:
            self.cards["geo"].set_state("good", g.ip or "已获取", "成功",
                                        f"{g.location()} · {g.isp}")
            self.ov_ip.setText(f"公网 IP：{g.ip}（{g.location()}）")
        else:
            self.cards["geo"].set_state("fair", "不可用", "警告", g.detail)
            self.ov_ip.setText("公网 IP：不可用")

    def _apply_port(self, r, is_web):
        self._last_report["port"] = r
        suffix = "（默认探测 443）" if is_web else ""
        if r.ok:
            self.cards["port"].set_state("good", "开放", "成功", f"{r.detail}{suffix}")
        else:
            self.cards["port"].set_state("poor", "关闭", "失败", f"{r.detail}{suffix}")

    def _tick_done(self):
        self._pending -= 1
        if self._pending <= 1:
            self.refresh_btn.setEnabled(True)
            self.status_line.setText("检查完成。")

    # -- report --
    def build_report_text(self):
        lines = [f"NetCheck 报告 · {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        tgt = self.target_input.text().strip() or "(本机网络)"
        lines.append(f"目标：{tgt}")
        lines.append("-" * 36)
        for key, card in self.cards.items():
            lines.append(f"{card.title_lbl.text():<12} {card.value_lbl.text():<10} "
                         f"{card.status_lbl.text()}  {card.detail_lbl.text()}")
        return "\n".join(lines)

    def copy_report(self):
        QGuiApplication.clipboard().setText(self.build_report_text())
        self.status_line.setText("报告已复制到剪贴板。")


def _selftest(out_path: str) -> int:
    """Headless diagnostic: run the real detection code paths (the same ones the
    refresh button drives) and write a JSON summary. No Qt window is created, so
    this works under the windowed/frozen exe where stdout is detached — evidence
    lands in a file. Exercises subprocess ping + locale-agnostic parsing, DNS, TCP
    and geo, which is exactly what freezing can break (hidden imports, bootloader
    subprocess). Exit 0 iff connectivity to the default host came back healthy.
    """
    import json
    report = {"frozen": bool(getattr(sys, "frozen", False))}
    try:
        s = netmetrics.check_connectivity("1.1.1.1", port=443, count=4, timeout=3.0)
        report["ping"] = {
            "ok": s.ok, "loss_pct": s.loss_pct, "rtt_avg": s.rtt_avg,
            "tcp_ok": getattr(s, "tcp_ok", None), "detail": s.detail,
        }
        report["dns"] = {"ok": netcheck.check_dns("github.com", timeout=5.0).ok}
        report["tcp_github_443"] = {"ok": netcheck.check_tcp("github.com", 443, timeout=5.0).ok}
        healthy = bool(s.ok and (s.loss_pct or 0) < 100)
        report["healthy"] = healthy
    except Exception as e:  # noqa: BLE001
        report["error"] = repr(e)
        healthy = False
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return 0 if report.get("healthy") else 1


def main():
    # Hidden diagnostic hook: `NetCheck.exe --selftest [out.json]` runs detection
    # headless and exits, without opening the window. Used to smoke-test the frozen
    # build; harmless in normal use since it requires an explicit flag.
    if "--selftest" in sys.argv:
        idx = sys.argv.index("--selftest")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "netcheck_selftest.json"
        return _selftest(out)
    # Windows: distinct AppUserModelID so the taskbar shows our icon and groups
    # the app under its own identity instead of the generic python.exe host.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("com.netcheck.app")
        except Exception:  # noqa: BLE001 — cosmetic only, never block startup
            pass
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path(ICON_REL)))
    win = NetCheckWindow()
    win.show()
    return app.exec()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    sys.exit(main())
