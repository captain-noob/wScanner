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

## Usage

```bash
# Single target
wScanner -host 10.0.0.1

# Multiple targets
wScanner -input targets.txt

# With options
wScanner -host 10.0.0.1 -timeout 10 -csv -output my_scan -path custom_wordlist.txt
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | — | Single target to scan |
| `-input` | — | File with targets (one per line) |
| `-timeout` | `15` | Request timeout in seconds |
| `-rps` | `0` | Max concurrent requests (0 = auto) |
| `-output` | auto | Custom output folder name |
| `-csv` | `false` | Generate CSV results |
| `-path` | — | Custom wordlist for directory fuzzing |
| `-ports-file` | `ports.txt` | Custom ports file |
| `-v` | `false` | Verbose output |
| `-local` | `false` | Skip internet check |
| `-update-config` | `false` | Re-download config files |

## Build

```bash
go build .
```

Cross-compile for multiple platforms:
```bash
chmod +x build.sh && ./build.sh
```
