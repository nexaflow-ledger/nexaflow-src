"""
Structured logging configuration for NexaFlow.

Supports two output formats:
  - **human** – coloured, single-line, readable
  - **json**  – newline-delimited JSON for log aggregators

Usage:
    from nexaflow_core.logging_config import setup_logging
    setup_logging(level="DEBUG", fmt="json", log_file="nexaflow.log")
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class _JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, default=str)


class _HumanFormatter(logging.Formatter):
    """Coloured, concise single-line format."""

    COLOURS = {
        "DEBUG": "\033[36m",     # cyan
        "INFO": "\033[32m",      # green
        "WARNING": "\033[33m",   # yellow
        "ERROR": "\033[31m",     # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelname, "")
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        return (
            f"{colour}{ts} [{record.levelname:<7}]{self.RESET} "
            f"{record.name}: {record.getMessage()}"
        )


def setup_logging(
    level: str = "INFO",
    fmt: str = "human",
    log_file: Optional[str] = None,
) -> None:
    """
    Configure the root logger for the entire application.

    Parameters
    ----------
    level : str
        One of DEBUG, INFO, WARNING, ERROR, CRITICAL.
    fmt : str
        ``"human"`` for coloured single-line output, ``"json"`` for
        newline-delimited JSON.
    log_file : str, optional
        If provided, logs are *also* written to this file (always in JSON
        format for machine parsing).
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove any existing handlers (avoid duplicates on reload)
    root.handlers.clear()

    # --- Console handler ---
    console = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        console.setFormatter(_JSONFormatter())
    else:
        console.setFormatter(_HumanFormatter())
    root.addHandler(console)

    # --- Optional file handler ---
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(path))
        fh.setFormatter(_JSONFormatter())  # always JSON for files
        root.addHandler(fh)
