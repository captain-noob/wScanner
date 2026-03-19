# wScanner

A fast, concurrent web port scanner and HTTP reconnaissance tool written in Go.

## Features

- **Port Scanning** — Concurrent TCP port probing with configurable timeouts
- **HTTP Probing** — Automatic scheme detection, response headers, page titles, redirects
- **Header Recon** — Detects web servers, frameworks, WAFs, CDNs, CMSs via response headers
- **Directory Fuzzing** — Path discovery with built-in wordlist (auto-downloaded)
- **403 Bypass** — Automatically attempts 31 bypass techniques (header injection, method switching, path mutation)
- **HTML Report** — Clean, interactive report with filtering and search
- **CSV Export** — Machine-readable output
- **Self-Update** — Update to the latest release directly from the CLI

## Usage

```bash
# Single target
wScanner -host 10.0.0.1

# Multiple targets
wScanner -input targets.txt

# With options
wScanner -host 10.0.0.1 -timeout 10 -csv -output my_scan -path custom_wordlist.txt

# Increase concurrency (default auto-detected, capped at 1024)
wScanner -input targets.txt -rps 2048

# Self-update to latest release
wScanner -update
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | — | Single target to scan |
| `-input` | — | File with targets (one per line) |
| `-timeout` | `15` | Request timeout in seconds |
| `-rps` | `0` | Concurrency limit (0 = auto, max 1024) |
| `-output` | auto | Custom output folder name |
| `-csv` | `false` | Generate CSV results |
| `-stdout` | `true` | Print results to standard output |
| `-path` | — | Custom wordlist for directory fuzzing |
| `-ports-file` | `ports.txt` | Custom ports file |
| `-v` | `false` | Verbose output |
| `-local` | `false` | Skip internet check |
| `-update-config` | `false` | Re-download config files |
| `-update` | `false` | Self-update to the latest GitHub release |

## Build

```bash
go build .
```

Cross-compile for all platforms (Linux, macOS, Windows — amd64 & arm64):
```bash
chmod +x build.sh && ./build.sh
```

> **Note:** On Linux you can check your process limit with `ulimit -u` before running large scans.