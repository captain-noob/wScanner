# wScanner

A fast, concurrent web port scanner and HTTP reconnaissance tool written in Go.

## Features

- **Port Scanning** — Concurrent TCP port probing with configurable timeouts and rate limiting
- **HTTP Probing** — Automatic scheme detection (HTTP/HTTPS), response headers, page titles, redirects
- **Header Recon** — Detects web servers, frameworks, WAFs, CDNs, CMSs via response headers
- **Directory Fuzzing** — Path discovery with built-in wordlist and 403 bypass techniques
- **Wildcard Detection** — Filters false positives across all HTTP status ranges (2xx–5xx)
- **DNS Enrichment** — CNAME and PTR (reverse DNS) lookups for each target
- **SSL Certificate Info** — Extracts Common Name (CN) and Subject Alternative Names (SANs)
- **Cloudflare Detection** — Identifies Cloudflare IPs and optionally skips them (`-force-cf` to override)
- **Resume Support** — Interrupted scans can be resumed from the last completed phase
- **Structured Error Logging** — All errors logged to `error.log` with timestamps and context
- **Retry Logic** — Exponential backoff on transport-level failures (configurable via `-retries`)
- **Sorted Output** — Results sorted by status code (2xx first)
- **HTML Report** — Clean, interactive report with filtering and search
- **CSV Export** — Machine-readable output
- **Self-Update** — Update to the latest release directly from the CLI

## Usage

```bash
# Single target
wScanner -host 10.0.0.1

# Multiple targets from file
wScanner -input targets.txt

# With options
wScanner -host 10.0.0.1 -timeout 10 -csv -output my_scan -path custom_wordlist.txt

# Increase concurrency and rate limit
wScanner -input targets.txt -c 2048 -rps 500

# Resume an interrupted scan (same -output folder)
wScanner -input targets.txt -output my_scan

# Force scan Cloudflare IPs
wScanner -host cdn.example.com -force-cf

# Self-update to latest release
wScanner -update
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | — | Single target to scan |
| `-input` | — | File with targets (one per line) |
| `-timeout` | `15` | Request timeout in seconds |
| `-c` | `0` | Max concurrent workers (0 = auto, capped at 1024) |
| `-rps` | `0` | Max requests per second (0 = unlimited) |
| `-retries` | `2` | Retries for failed HTTP requests (transport errors only) |
| `-output` | auto | Custom output folder name |
| `-csv` | `false` | Generate CSV results |
| `-stdout` | `true` | Print results to standard output |
| `-path` | — | Custom wordlist for directory fuzzing |
| `-ports-file` | `ports.txt` | Custom ports file |
| `-force-cf` | `false` | Force scanning Cloudflare IPs |
| `-v` | `false` | Verbose output |
| `-local` | `false` | Skip internet check |
| `-update-config` | `false` | Re-download config files |
| `-update` | `false` | Self-update to the latest GitHub release |

## Output Files

Each scan produces an output folder with the following files:

| File | Description |
|------|-------------|
| `output_report.html` | Interactive HTML report with filters and search |
| `output_urls.txt` | Plain list of discovered URLs |
| `validated.txt` | Endpoints returning valid 2xx/3xx responses |
| `fuzzing.txt` | Path fuzzing results grouped by target |
| `rechecked_ports.txt` | Ports re-checked after returning no initial data |
| `open_ports_initial.txt` | Raw open ports from the initial scan |
| `cloudflare_ips.txt` | Cloudflare IPs detected during scanning |
| `error.log` | Structured error log with timestamps and context |
| `results.csv` | CSV export (when `-csv` is used) |
| `.resume.json` | Resume state file (deleted on successful completion) |

## Resume Functionality

If a scan is interrupted (e.g., Ctrl+C), it can be resumed by re-running the same command with the same `-output` folder:

```bash
# Start a scan
wScanner -input targets.txt -output my_scan

# (interrupted...)

# Resume from where it left off
wScanner -input targets.txt -output my_scan
```

The scanner tracks 7 phases: port scan → scheme detection → HTTP probe → recheck → fuzzing → enrichment → done. Completed phases are skipped on resume. The `.resume.json` file is automatically removed once the scan finishes successfully.

> **Note:** Resume only works when `-output` is explicitly specified. Auto-timestamped folders always start fresh.

## Build

```bash
go build .
```

Cross-compile for all platforms (Linux, macOS, Windows — amd64 & arm64):
```bash
chmod +x build.sh && ./build.sh
```

> **Note:** On Linux you can check your process limit with `ulimit -u` before running large scans.