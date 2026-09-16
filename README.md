# Port Scanner

A small, pure-Python multithreaded TCP connect port scanner with basic
service identification. No raw sockets, no root/administrator privileges
required — just `socket.connect_ex` and a thread pool.

> **Authorized use only.** This tool is meant for scanning hosts and
> networks **you own or are explicitly authorized to test** (e.g. your
> own machine, lab VMs, or systems you have written permission to
> assess). Scanning systems without authorization may be illegal in
> your jurisdiction. The examples below only ever target `127.0.0.1`
> (localhost).

## Features

- TCP connect scan over a port range (`1-1024`) or an explicit list
  (`22,80,443`), or a mix of both (`22,80,1000-1010`).
- Concurrent scanning via a configurable thread pool.
- Configurable per-connection timeout so scans never hang on
  unresponsive hosts.
- Best-effort service name guessing via a curated well-known-ports map
  (falling back to the OS service database).
- Optional lightweight banner grab: reads a few bytes from the open
  socket (short timeout, best-effort, never blocks the scan).
- Pure standard library — no third-party dependencies.

## Requirements

- Python 3.11+

## Usage

```bash
# Scan the default range (1-1024) on localhost
python scanner.py 127.0.0.1

# Scan a specific range
python scanner.py 127.0.0.1 --ports 1-1024

# Scan an explicit list of ports
python scanner.py 127.0.0.1 --ports 22,80,443

# Mix ranges and individual ports
python scanner.py 127.0.0.1 --ports 22,80,1000-1010

# Tune timeout and concurrency
python scanner.py 127.0.0.1 --ports 1-2048 --timeout 0.5 --workers 200

# Disable banner grabbing
python scanner.py 127.0.0.1 --ports 1-1024 --no-banner
```

### Example output

```
$ python scanner.py 127.0.0.1 --ports 22,80,443,8080
Scanning 127.0.0.1 (127.0.0.1) - 4 port(s)
NOTE: only scan hosts/networks you own or are explicitly authorized to test.

PORT      STATE     SERVICE        BANNER
22        open      ssh            SSH-2.0-OpenSSH_9.6

Scan complete: 1 open / 4 scanned in 0.12s
```

## CLI options

| Option        | Default   | Description                                   |
|---------------|-----------|------------------------------------------------|
| `host`        | required  | Target hostname or IP address                 |
| `--ports`     | `1-1024`  | Port range and/or comma-separated list         |
| `--timeout`   | `1.0`     | Per-connection timeout in seconds              |
| `--workers`   | `100`     | Max concurrent threads                         |
| `--no-banner` | off       | Disable best-effort banner grabbing            |

## Running tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover -s tests -v
```

Tests bind real listener sockets on ephemeral `127.0.0.1` ports within
the test process to verify open/closed detection, port-range parsing,
the service-name map, and timeout behavior — no network access or
external hosts required.

## How it works

The scanner performs a classic **TCP connect scan**: for each target
port it attempts a full TCP handshake via `socket.connect_ex()`. A
successful connection means the port is open; a connection error or
refusal means it's closed or filtered. This is the same fundamental
technique used by tools like `nmap -sT`, implemented here in pure
Python for learning and lightweight auditing purposes.

## License

MIT — see [LICENSE](LICENSE).
