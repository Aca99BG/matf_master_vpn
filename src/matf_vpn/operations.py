"""Operational logging and reconnect supervision."""

from datetime import datetime, timezone
import json
import logging
import sys
import time
from typing import Callable, Optional, TextIO


STANDARD_LOG_RECORD_FIELDS = set(logging.makeLogRecord({}).__dict__)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                timezone.utc,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field, value in record.__dict__.items():
            if field not in STANDARD_LOG_RECORD_FIELDS and field != "message":
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def configure_logging(
    json_output: bool = False,
    stream: Optional[TextIO] = None,
) -> None:
    handler = logging.StreamHandler(stream or sys.stderr)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def run_with_reconnect(
    run_once: Callable[[], None],
    reconnect_delay: float,
    logger: logging.Logger,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    if reconnect_delay < 0:
        raise ValueError("reconnect_delay must not be negative")

    attempt = 0
    while True:
        try:
            run_once()
            return
        except OSError as error:
            attempt += 1
            logger.warning(
                "VPN session failed; reconnecting",
                extra={
                    "event": "reconnect_scheduled",
                    "attempt": attempt,
                    "delay_seconds": reconnect_delay,
                    "error_type": type(error).__name__,
                    "error": str(error),
                },
            )
            sleep(reconnect_delay)
