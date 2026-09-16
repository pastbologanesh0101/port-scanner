#!/usr/bin/env python3
"""Port Scanner

A pure-Python, multithreaded TCP connect port scanner with basic
service identification (well-known-ports map + best-effort banner grab).

Intended for scanning hosts and networks you own or are explicitly
authorized to test. Do not use this against systems without permission.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional


# A small map of well-known ports to service names. Not exhaustive, but
# covers the ports most commonly seen open on general-purpose hosts.
WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "smtp-submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "dev-http",
    3268: "ldap-gc",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-http",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5985: "wsman",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


def get_service_name(port: int) -> str:
    """Return a best-guess service name for a port number.

    Falls back to the standard library's socket.getservbyport when the
    port isn't in our curated map, and finally to "unknown".
    """
    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error):
        return "unknown"


@dataclass
class ScanResult:
    port: int
    open: bool
    service: str = "unknown"
    banner: Optional[str] = None


def grab_banner(sock: socket.socket, timeout: float) -> Optional[str]:
    """Best-effort banner grab on an already-connected socket.

    Never raises: on any timeout/error, returns None. Uses a short
    timeout so a silent service never causes the scan to hang.
    """
    try:
        sock.settimeout(timeout)
        data = sock.recv(64)
        if not data:
            return None
        return data.decode(errors="replace").strip() or None
    except (socket.timeout, OSError):
        return None


def scan_port(host: str, port: int, timeout: float, grab: bool = True) -> ScanResult:
    """Attempt a TCP connect to host:port and report the result.

    Uses plain socket.connect_ex (a "TCP connect scan") which requires
    no raw sockets or elevated privileges.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return ScanResult(port=port, open=False)

        service = get_service_name(port)
        banner = None
        if grab:
            # Give the banner grab a small slice of the overall timeout
            # so a non-responsive service doesn't stall the scan.
            banner_timeout = min(timeout, 0.5)
            banner = grab_banner(sock, banner_timeout)
        return ScanResult(port=port, open=True, service=service, banner=banner)
    except (socket.timeout, OSError):
        return ScanResult(port=port, open=False)
    finally:
        sock.close()


def parse_ports(spec: str) -> List[int]:
    """Parse a port specification into a sorted list of unique ports.

    Supports:
      - a range:      "1-1024"
      - a comma list: "22,80,443"
      - a mix:        "22,80,1000-1010"
    """
    ports: set[int] = set()
    spec = spec.strip()
    if not spec:
        raise ValueError("empty port specification")

    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, _, end_str = chunk.partition("-")
            start, end = int(start_str), int(end_str)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {chunk}")
            ports.add(port)

    return sorted(ports)


def scan_target(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    max_workers: int = 100,
    grab_banners: bool = True,
) -> List[ScanResult]:
    """Scan `ports` on `host` concurrently using a thread pool.

    Returns only the results (open and closed) in ascending port order.
    """
    ports = list(ports)
    results: List[ScanResult] = []

    workers = max(1, min(max_workers, len(ports) or 1))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banners): port
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.port)
    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "Multithreaded TCP connect port scanner with basic service "
            "identification. Only scan hosts/networks you own or are "
            "explicitly authorized to test."
        ),
    )
    parser.add_argument("host", help="Target host (e.g. 127.0.0.1 or example.com)")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range (1-1024) or comma list (22,80,443). Default: 1-1024",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Max concurrent threads (default: 100)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner grabbing",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror as exc:
        print(f"Error: could not resolve host '{args.host}': {exc}", file=sys.stderr)
        return 2

    print(f"Scanning {args.host} ({target_ip}) - {len(ports)} port(s)")
    print(
        "NOTE: only scan hosts/networks you own or are explicitly "
        "authorized to test.\n"
    )

    start = time.time()
    results = scan_target(
        target_ip,
        ports,
        timeout=args.timeout,
        max_workers=args.workers,
        grab_banners=not args.no_banner,
    )
    duration = time.time() - start

    open_results = [r for r in results if r.open]
    if open_results:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}BANNER")
        for r in open_results:
            banner = r.banner or ""
            print(f"{r.port:<10}{'open':<10}{r.service:<15}{banner}")
    else:
        print("No open ports found.")

    print(
        f"\nScan complete: {len(open_results)} open / {len(ports)} scanned "
        f"in {duration:.2f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
