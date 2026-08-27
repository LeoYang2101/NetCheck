# netcheck

A zero-dependency command-line network diagnostics tool. Python 3.8+, standard
library only — no `pip install`, runs on Windows / macOS / Linux.

Given one or more targets, it runs a batch of connectivity checks and prints a
readable pass/fail summary (with latencies), plus your local and public IP.

## Checks

Per target:
- **DNS** — resolves a hostname to its IP addresses (skipped for literal IPs)
- **PING** — reachability + round-trip time via the system `ping`
- **TCP:<port>** — whether a TCP port is open (e.g. `host:443`)
- **HTTP / HTTPS** — status code + latency for URLs

Host-level:
- **local IP** — this machine's LAN address
- **public IP** — your outbound/egress address

## Usage

```bash
# Check a default set of targets (github.com, 1.1.1.1:53, google)
python netcheck.py

# A bare hostname → DNS + ping + common web ports (80, 443)
python netcheck.py example.com

# Specific port → DNS + ping + that TCP port
python netcheck.py example.com:443

# Mix hosts, host:port, and URLs freely
python netcheck.py 1.1.1.1:53 github.com https://api.github.com

# Machine-readable output for scripts/monitoring
python netcheck.py --json example.com

# Options
python netcheck.py --timeout 3 host     # per-check timeout (seconds, default 5)
python netcheck.py --no-color host      # disable ANSI colors
```

Exit code is **0** when every check passed, **1** when any check failed — handy
in CI or a cron health check.

## Example

```
netcheck report
  local IP : 192.168.1.20
  public IP: 203.0.113.45

github.com:443  [OK]
  + DNS       20.205.243.166 (43 ms)
  + PING      reachable (26 ms)
  + TCP:443   open (20 ms)
  + HTTPS     HTTP 200 (192 ms)
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite (15 tests) covers target parsing, ping-output parsing (Unix + Windows
formats), literal-IP DNS shortcut, TCP checks against a loopback server, and
payload building — all offline and deterministic.

## Notes

- A failed **PING** with other checks OK usually just means the host blocks ICMP
  (common for cloud/CDN hosts) — TCP/HTTP are the more reliable signals.
- On consoles that can't render Unicode (e.g. Windows GBK), the ✓/✗ marks fall
  back to `+`/`x` automatically.
