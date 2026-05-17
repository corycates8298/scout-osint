# Scout OSINT

**Unified OSINT intelligence gathering CLI** — one command, all tools, parallel execution.

Auto-detects target type (username, email, domain, IP, phone, file, person, company) and runs the right tools in parallel, deduplicates results, and diffs against previous scans.

## v3.0 — What's New

- **Modular architecture** — each target type in its own module
- **Input sanitization** — shell injection hardened (blocks `;`, `|`, `$()`, backticks)
- **Result deduplication** — cross-tool correlation, platform extraction
- **Scan diffing** — auto-compares with previous scan, shows added/removed accounts
- **Smarter detection** — "Buff City Soap" correctly detected as company (not person)
- **Multi-TLD company guessing** — tries `.com`, `.io`, `.co`, `.org`, `.net`
- **API key management** — `~/.scout-osint/keys.yaml`
- **55 unit tests** — detectors, sanitization, dedup, diffing, all tool modules

## Installation

### Prerequisites (macOS)

```bash
brew install sherlock amass nmap exiftool

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
scout-osint johndoe                    # username (auto-detected)
scout-osint user@gmail.com             # email
scout-osint example.com                # domain
scout-osint 8.8.8.8                    # IP
scout-osint "+1-555-0123"              # phone
scout-osint photo.jpg                  # file
scout-osint "John Doe"                 # person
scout-osint "Buff City Soap"           # company (auto-detected)

scout-osint -t company "Buff City Soap"   # force type
scout-osint --full user@gmail.com         # all tools including slow ones
scout-osint --stealth example.com         # passive only
scout-osint --json johndoe | jq           # structured output
scout-osint --keys                        # show/configure API keys
```

## Target Types

| Type | Auto-detects | Tools |
|------|-------------|-------|
| `username` | Single word | Sherlock, Maigret, Socialscan |
| `email` | `user@domain` | Holehe, GHunt, Ignorant, WHOIS, H8mail |
| `domain` | `word.tld` | theHarvester, Amass, WHOIS, DNS, WebTech, SSL, Wayback |
| `phone` | digits with `+/-/()` | Ignorant, Socialscan |
| `ip` | `x.x.x.x` | IPWhois, GeoIP, Shodan, Nmap |
| `file` | existing file path | ExifTool, strings, hashes, GPS |
| `person` | "First Last" | Username/email variant generation + multi-tool sweep |
| `company` | business name/keywords | Multi-TLD domain guess, WHOIS, CrossLinked, tech stack |

## Hardening

### Input Sanitization
All user input is validated before passing to shell commands. Blocked characters: `;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>`, `!`, `~`, newlines. Additionally, all arguments are shell-quoted.

### Result Deduplication
When Sherlock and Maigret both find the same GitHub profile, it's reported once. URLs are normalized (strip www, trailing slash, scheme) before comparison. Platforms are extracted and listed in the summary.

### Scan Diffing
Every scan is saved to `~/osint/reports/`. When you scan a target again, Scout automatically compares with the previous scan and shows:
- **+ New** — accounts/profiles that appeared since last scan
- **- Gone** — accounts that disappeared

### API Keys
Configure at `~/.scout-osint/keys.yaml`:
```yaml
shodan: YOUR_KEY
censys_id: YOUR_ID
censys_secret: YOUR_SECRET
virustotal: YOUR_KEY
```
Or via environment variables: `SHODAN_API_KEY`, `CENSYS_API_ID`, etc.

## Architecture

```
scout_osint/
├── cli.py          # Main entry point, parallel orchestration
├── detectors.py    # Target type auto-detection (200+ first names, company keywords)
├── sanitize.py     # Shell injection prevention
├── reporting.py    # JSON + text report generation
├── dedup.py        # Cross-tool result deduplication
├── history.py      # Scan diffing (compare over time)
├── keys.py         # API key management
└── tools/
    ├── username.py # Sherlock, Maigret, Socialscan
    ├── email.py    # Holehe, GHunt, Ignorant, H8mail, WHOIS
    ├── domain.py   # theHarvester, Amass, WebTech, Wayback
    ├── ip.py       # IPWhois, Shodan, Nmap, GeoIP
    ├── phone.py    # Ignorant, carrier checks
    ├── file.py     # ExifTool, strings, hashes
    ├── person.py   # Variant generation + sweep
    └── company.py  # Multi-TLD domain guess + full recon
```

## Tests

```bash
python3 tests/test_scout.py
# 55/55 passed (100%)
```

## License

MIT
