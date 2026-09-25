"""
SentinelX – Cybersecurity Suite  |  PySide6 Entry Point.

Professional cybersecurity application with splash screen,
branding, and polished startup experience.
"""

import sys
import os

# Force UTF-8 console output (prevents colorama/cp1252 crash with Unicode)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure the project root is on the path so ``modules`` imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon

from ui.theme import apply_theme


def _get_icon_path() -> str:
    """Resolve the application icon path (works for dev and PyInstaller)."""
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "assets", "sentinelx.ico")


def main() -> None:
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelX – Cybersecurity Suite")
    app.setOrganizationName("SentinelX")
    app.setApplicationVersion("2.0.0")

    # Apply global dark theme
    apply_theme(app)

    # Set application icon
    icon_path = _get_icon_path()
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # ── Show Splash Screen ───────────────────────────────────────────
    from ui.splash_screen import SplashScreen

    splash = SplashScreen()
    splash.show()
    app.processEvents()

    # ── Prepare Main Window (created after splash finishes) ──────────
    # Use a mutable container so the reference survives in the closure
    state = {"window": None}

    def _on_splash_done():
        """Called when splash fade-out finishes."""
        # Stop splash animations cleanly
        try:
            splash._shield._glow_anim.stop()
        except Exception:
            pass
        splash.close()

        from ui.main_window import MainWindow

        state["window"] = MainWindow()

        # Set icon on main window too
        if os.path.exists(icon_path):
            state["window"].setWindowIcon(QIcon(icon_path))

        state["window"].show()

        # Trigger entry animations after window is visible
        QTimer.singleShot(100, state["window"].play_entry_animation)

    # Override the splash's finish handler
    splash._on_finished = _on_splash_done

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
