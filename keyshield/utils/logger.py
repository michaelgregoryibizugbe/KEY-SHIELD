"""Security Logger v3.0 — robust path handling, Windows color support."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone

from .helpers import get_data_dir


LOG_DIR = os.path.join(get_data_dir(), "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except OSError:
    LOG_DIR = os.path.join(os.getcwd(), "logs")
    os.makedirs(LOG_DIR, exist_ok=True)


def _supports_color() -> bool:
    """Check if terminal supports ANSI colors."""
    if os.name == "nt":
        # Enable ANSI on Windows 10+
        try:
            os.system("")  # Enable VT100 processing
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[41m\033[37m",
    }
    RESET = "\033[0m"

    def __init__(self):
        super().__init__()
        self.use_color = _supports_color()

    def format(self, record):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        msg = f"[{ts}] [{record.levelname:<8}] {record.getMessage()}"
        if self.use_color:
            color = self.COLORS.get(record.levelname, self.RESET)
            msg = f"{color}{msg}{self.RESET}"
        return msg


class SecurityLogger:
    def __init__(self, name: str = "KeyShield"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(ColorFormatter())
            self.logger.addHandler(ch)

            try:
                fh = RotatingFileHandler(
                    os.path.join(LOG_DIR, "keyshield.log"),
                    maxBytes=5 * 1024 * 1024, backupCount=3,
                )
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                ))
                self.logger.addHandler(fh)
            except OSError:
                pass  # Can't write log file — continue with console only

    def info(self, msg): self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg, exc_info=False): self.logger.error(msg, exc_info=exc_info)
    def debug(self, msg): self.logger.debug(msg)
    def critical(self, msg): self.logger.critical(msg)
