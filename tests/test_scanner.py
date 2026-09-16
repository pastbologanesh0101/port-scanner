"""Unit tests for scanner.py

These tests spin up real local TCP listener sockets on ephemeral ports
(bound to 127.0.0.1) inside the test process, then verify the scanner's
behavior against them. All sockets are closed in tearDown.
"""

import socket
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import (  # noqa: E402
    get_service_name,
    parse_ports,
    scan_port,
    scan_target,
)


class BaseScannerTest(unittest.TestCase):
    """Helper base class that manages listener sockets."""

    def setUp(self):
        self._listeners = []

    def tearDown(self):
        for sock in self._listeners:
            try:
                sock.close()
            except OSError:
                pass
        self._listeners = []

    def make_listener(self, backlog=1):
        """Create and return (sock, port) for a 127.0.0.1 listener."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(backlog)
        self._listeners.append(sock)
        return sock, sock.getsockname()[1]

    def find_closed_port(self):
        """Bind a socket, grab its port, then close it immediately so
        nothing is listening there (very likely closed/refused)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port


class TestOpenPortDetection(BaseScannerTest):
    def test_single_open_port_reported_open(self):
        _, port = self.make_listener()
        result = scan_port("127.0.0.1", port, timeout=1.0, grab=False)
        self.assertTrue(result.open)
        self.assertEqual(result.port, port)

    def test_scan_target_reports_multiple_open_ports(self):
        _, port_a = self.make_listener()
        _, port_b = self.make_listener()
        results = scan_target(
            "127.0.0.1", [port_a, port_b], timeout=1.0, grab_banners=False
        )
        open_ports = {r.port for r in results if r.open}
        self.assertEqual(open_ports, {port_a, port_b})


class TestClosedPortDetection(BaseScannerTest):
    def test_closed_port_reported_closed(self):
        closed_port = self.find_closed_port()
        result = scan_port("127.0.0.1", closed_port, timeout=1.0, grab=False)
        self.assertFalse(result.open)

    def test_mixed_open_and_closed_ports(self):
        _, open_port = self.make_listener()
        closed_port = self.find_closed_port()
        results = scan_target(
            "127.0.0.1", [open_port, closed_port], timeout=1.0, grab_banners=False
        )
        by_port = {r.port: r.open for r in results}
        self.assertTrue(by_port[open_port])
        self.assertFalse(by_port[closed_port])


class TestPortParsing(BaseScannerTest):
    def test_parse_range_syntax(self):
        self.assertEqual(parse_ports("20-25"), [20, 21, 22, 23, 24, 25])

    def test_parse_comma_list_syntax(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_parse_mixed_range_and_list(self):
        self.assertEqual(parse_ports("22,80,1000-1002"), [22, 80, 1000, 1001, 1002])

    def test_parse_deduplicates_and_sorts(self):
        self.assertEqual(parse_ports("80,22,80,22-24"), [22, 23, 24, 80])

    def test_parse_invalid_range_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("100-50")

    def test_parse_out_of_bounds_port_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")


class TestServiceMap(BaseScannerTest):
    def test_well_known_ports_map_common_services(self):
        self.assertEqual(get_service_name(22), "ssh")
        self.assertEqual(get_service_name(80), "http")
        self.assertEqual(get_service_name(443), "https")
        self.assertEqual(get_service_name(21), "ftp")

    def test_unknown_high_port_falls_back_gracefully(self):
        # 59999 is not in our curated map and unlikely to be registered
        # with the OS service database, so it should fall back cleanly
        # instead of raising.
        name = get_service_name(59999)
        self.assertIsInstance(name, str)
        self.assertTrue(len(name) > 0)


class TestTimeoutBehavior(BaseScannerTest):
    def test_scan_respects_timeout_on_nonresponsive_listener(self):
        """A listener that accepts but never sends data must not cause
        the banner grab / scan to hang beyond the given timeout."""
        sock, port = self.make_listener()

        start = time.time()
        result = scan_port("127.0.0.1", port, timeout=0.3, grab=True)
        elapsed = time.time() - start

        self.assertTrue(result.open)
        self.assertIsNone(result.banner)
        # Should complete quickly, well under a generous upper bound,
        # proving the banner grab timeout was honored rather than hanging.
        self.assertLess(elapsed, 3.0)

    def test_closed_port_scan_does_not_hang(self):
        closed_port = self.find_closed_port()
        start = time.time()
        result = scan_port("127.0.0.1", closed_port, timeout=0.5, grab=True)
        elapsed = time.time() - start
        self.assertFalse(result.open)
        self.assertLess(elapsed, 3.0)


if __name__ == "__main__":
    unittest.main()
