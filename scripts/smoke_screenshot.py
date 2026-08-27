"""Headless smoke test + screenshot capture for NetCheck.

Runs under the Qt 'offscreen' platform: builds the window, fires a real check
pass, pumps the event loop until workers finish, then saves a PNG of the
rendered window. Verifies the whole pipeline (UI + threads + engine) without a
display. Usage: python scripts/smoke_screenshot.py [target] [out.png]
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QTimer, QEventLoop  # noqa: E402
from PySide6.QtGui import QFont, QFontDatabase  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import netcheck_gui as gui  # noqa: E402

# Offscreen QPA loads *no* system fonts (families() == 0), so CJK glyphs render
# as tofu unless we load a font file explicitly. Real Windows uses the native
# font engine and needs none of this — this is purely for headless screenshots.
_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\msyh.ttc",      # Microsoft YaHei
    r"C:\Windows\Fonts\simhei.ttf",    # SimHei
    r"C:\Windows\Fonts\simsun.ttc",    # SimSun
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
]


def _load_cjk_font(app):
    loaded = None
    for path in _FONT_CANDIDATES:
        if not os.path.exists(path):
            continue
        fid = QFontDatabase.addApplicationFont(path)
        if fid < 0:
            continue
        fams = QFontDatabase.applicationFontFamilies(fid)
        if fams and loaded is None:
            app.setFont(QFont(fams[0], 10))
            loaded = fams[0]
    # Also register a symbol font so ✓/✕/⟳ glyphs aren't tofu (Qt falls back
    # across all registered application fonts).
    for sym in (r"C:\Windows\Fonts\seguisym.ttf", r"C:\Windows\Fonts\segoeui.ttf"):
        if os.path.exists(sym):
            QFontDatabase.addApplicationFont(sym)
            break
    return loaded


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    out = sys.argv[2] if len(sys.argv) > 2 else "netcheck_screenshot.png"

    app = QApplication(sys.argv)
    loaded_font = _load_cjk_font(app)
    win = gui.NetCheckWindow()
    if target:
        win.target_input.setText(target)
    win.resize(900, 640)
    win.show()

    # Let the window lay out, then trigger a real check pass.
    app.processEvents()
    win.run_checks()

    # Pump the event loop until all workers report back (or timeout).
    loop = QEventLoop()
    done = {"v": False}

    def poll():
        if win._pending <= 1:
            done["v"] = True
            loop.quit()

    timer = QTimer()
    timer.timeout.connect(poll)
    timer.start(200)
    QTimer.singleShot(20000, loop.quit)  # hard cap 20s
    loop.exec()

    app.processEvents()
    pix = win.grab()
    ok = pix.save(out, "PNG")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    print(f"workers_finished={done['v']} screenshot_saved={ok} path={out} font={loaded_font}")
    print("--- report ---")
    print(win.build_report_text())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
