from io import StringIO
import json
import logging
import unittest
from unittest.mock import Mock

from matf_vpn.operations import configure_logging, run_with_reconnect


class StructuredLoggingTest(unittest.TestCase):
    def tearDown(self) -> None:
        logging.getLogger().handlers.clear()

    def test_emits_json_event_fields(self) -> None:
        stream = StringIO()
        configure_logging(json_output=True, stream=stream)

        logging.getLogger("matf_vpn.test").info(
            "connected",
            extra={"event": "session_established", "session_id": 42},
        )

        record = json.loads(stream.getvalue())
        self.assertEqual(record["level"], "INFO")
        self.assertEqual(record["event"], "session_established")
        self.assertEqual(record["session_id"], 42)
        self.assertIn("timestamp", record)


class ReconnectSupervisorTest(unittest.TestCase):
    def test_retries_transient_failure_then_returns(self) -> None:
        action = Mock(side_effect=[TimeoutError("peer unavailable"), None])
        sleep = Mock()
        logger = Mock()

        run_with_reconnect(action, 1.5, logger, sleep=sleep)

        self.assertEqual(action.call_count, 2)
        sleep.assert_called_once_with(1.5)
        logger.warning.assert_called_once()

    def test_does_not_retry_programming_error(self) -> None:
        action = Mock(side_effect=ValueError("invalid configuration"))

        with self.assertRaisesRegex(ValueError, "invalid configuration"):
            run_with_reconnect(action, 1.0, Mock(), sleep=Mock())


if __name__ == "__main__":
    unittest.main()