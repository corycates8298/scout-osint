# Scout OSINT

**Unified OSINT intelligence gathering CLI** — one command, all tools, parallel execution.

Auto-detects target type (username, email, domain, IP, phone, file, person, company) and runs the right tools in parallel, merging results into a single report.

## Features

- **8 target types** with auto-detection
- **20+ integrated tools** (Sherlock, Maigret, Holehe, theHarvester, Amass, Nmap, Shodan, GHunt, and more)
- **Parallel execution** — 6 workers by default
- **Stealth mode** — passive-only, no direct target contact
- **Structured reports** — JSON + text, with extracted findings (accounts, emails, IPs)
- **Smart summary** — deduped findings, hit counts, wall time

## Installation

### Prerequisites (macOS)

```bash
# Core tools via Homebrew
brew install sherlock amass nmap exiftool

# Python environment
python3 -m venv ~/osint/venv
source ~/osint/venv/bin/activate
pip install -r requirements.txt
```

### Install scout-osint

```bash
pip install -e .
```

## Usage

```bash
# Auto-detect target type
scout-osint johndoe
scout-osint user@gmail.com
scout-osint example.com
scout-osint 8.8.8.8
scout-osint "+1-555-0123"
scout-osint photo.jpg
scout-osint "John Doe"
scout-osint "Acme Corp Inc"

# Force target type
scout-osint -t company "Buff City Soap"

# Full mode (all tools, including slow ones)
scout-osint --full user@gmail.com

# Stealth mode (passive only — no port scans, no HTTP to target)
scout-osint --stealth example.com

# JSON output (pipe to jq or other tools)
scout-osint --json johndoe | jq '.findings.accounts_found'

# Don't save report to disk
scout-osint --no-save johndoe
```

## Target Types

| Type | Auto-detects | Tools Used |
|------|-------------|------------|
| `username` | Any single word | Sherlock, Maigret, Socialscan |
| `email` | contains `@` | Holehe, GHunt, Ignorant, WHOIS, H8mail, Socialscan |
| `domain` | `word.tld` pattern | theHarvester, Amass, WHOIS, DNS, WebTech, SSL, Wayback |
| `phone` | digits with `+/-/()` | Ignorant, carrier checks |
| `ip` | `x.x.x.x` | IPWhois, GeoIP, Shodan, Nmap, Reverse DNS |
| `file` | existing file path | ExifTool, strings, hashes, GPS |
| `person` | "First Last" | Username variants + email variants + multi-tool sweep |
| `company` | multi-word + suffix | Domain guess + WHOIS + employees + tech stack |

## Reports

Reports auto-save to `~/osint/reports/` as both JSON and text:

```
~/osint/reports/
├── johndoe_20260516_143022.json
├── johndoe_20260516_143022.txt
├── example_com_20260516_143100.json
└── example_com_20260516_143100.txt
```

## Flags

| Flag | Description |
|------|-------------|
| `-t TYPE` | Force target type |
| `--full` | Run all tools including slow/deep ones |
| `--stealth` | Passive only — no direct target contact |
| `--json` | Raw JSON output |
| `--no-save` | Don't save report files |
| `--workers N` | Parallel workers (default: 6) |

## License

MIT
