#!/usr/bin/env python3
"""
Scout OSINT v2.0 — Unified OSINT orchestrator for Scout (M4 MacBook)
Detects target type and runs the right tools in parallel, then merges results.

Usage:
    scout-osint <target>                  # auto-detect type
    scout-osint -t username <target>      # force type
    scout-osint -t email <target>
    scout-osint -t domain <target>
    scout-osint -t phone <target>
    scout-osint -t ip <target>
    scout-osint -t file <target>
    scout-osint -t person "First Last"
    scout-osint -t company "Company Name"
    scout-osint --full <target>           # run ALL tools, even slow ones
    scout-osint --stealth <target>        # passive-only, no direct contact with target
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

OSINT_DIR = Path.home() / "osint"
REPORTS_DIR = OSINT_DIR / "reports"
VENV_ACTIVATE = f"source {OSINT_DIR}/venv/bin/activate"
VENV_PYTHON = str(OSINT_DIR / "venv/bin/python3")

# ANSI colors
class C:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════════╗
  ║           🔍 Scout OSINT v2.0                ║
  ║      Unified Intelligence Gathering           ║
  ║  8 target types · 20+ tools · parallel exec   ║
  ╚═══════════════════════════════════════════════╝{C.RESET}
""")


def detect_type(target):
    """Auto-detect target type."""
    if os.path.isfile(target):
        return "file"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        return "email"
    if re.match(r'^\+?[\d\s\-().]{7,}$', target):
        return "phone"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target):
        return "domain"
    if " " in target and any(w[0].isupper() for w in target.split() if w):
        # Capitalized multi-word — could be person or company
        # Heuristic: if it ends in Inc, LLC, Corp, etc. → company
        company_suffixes = ['inc', 'llc', 'corp', 'ltd', 'co', 'company', 'group', 'solutions', 'technologies']
        if any(target.lower().endswith(s) for s in company_suffixes):
            return "company"
        return "person"
    if " " in target:
        return "person"
    return "username"


def run_tool(name, cmd, timeout=120):
    """Run a tool and capture output."""
    start = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        output = result.stdout.strip()
        errors = result.stderr.strip()
        if not output and errors:
            output = errors
        return {
            "tool": name,
            "status": "success" if result.returncode == 0 else "partial",
            "output": output,
            "elapsed": round(elapsed, 1),
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": name,
            "status": "timeout",
            "output": f"Timed out after {timeout}s",
            "elapsed": timeout,
        }
    except Exception as e:
        return {
            "tool": name,
            "status": "error",
            "output": str(e),
            "elapsed": round(time.time() - start, 1),
        }


def venv_cmd(tool_cmd):
    """Wrap a command to run inside the OSINT venv."""
    return f"bash -c '{VENV_ACTIVATE} && {tool_cmd}'"


def python_inline(code):
    """Run inline Python in the venv."""
    escaped = code.replace("'", "'\\''")
    return f"bash -c '{VENV_ACTIVATE} && python3 -c \"{escaped}\"'"


# ── Tool runners by target type ──────────────────────────────────

def tools_for_username(target, full=False, stealth=False):
    """Tools to run for a username target."""
    jobs = {
        "Sherlock": f"sherlock {target} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {target} --no-color --timeout 30 2>/dev/null"),
        "Socialscan": f"socialscan {target} 2>/dev/null",
    }
    if full:
        jobs["Maigret (full DB)"] = venv_cmd(f"maigret {target} -a --no-color --timeout 60 2>/dev/null")
    return jobs


def tools_for_email(target, full=False, stealth=False):
    """Tools to run for an email target."""
    username = target.split("@")[0]
    domain = target.split("@")[1]

    jobs = {
        "Holehe": venv_cmd(f"holehe {target} --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {target} 2>/dev/null",
        "Ignorant (phone links)": venv_cmd(f"ignorant {target} 2>/dev/null"),
        "GHunt (Google)": venv_cmd(f"ghunt email {target} 2>/dev/null"),
        "WHOIS (domain)": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{domain}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "Email Validation": venv_cmd(f"python3 -c \"from email_validator import validate_email; r=validate_email('{target}', check_deliverability=True); print(f'Valid: {{r.email}}'); print(f'MX: {{r.mx}}' if hasattr(r,'mx') else '')\" 2>/dev/null"),
    }

    if full:
        jobs["Sherlock (username)"] = f"sherlock {username} --print-found --no-color 2>/dev/null"
        jobs["Maigret (username)"] = venv_cmd(f"maigret {username} --no-color --timeout 30 2>/dev/null")
        jobs["theHarvester"] = venv_cmd(
            f"theHarvester -d {domain} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"
        )
        jobs["H8mail (breach check)"] = venv_cmd(f"h8mail -t {target} 2>/dev/null")
        jobs["Wayback (domain)"] = venv_cmd(
            f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{domain}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null"
        )

    return jobs


def tools_for_domain(target, full=False, stealth=False):
    """Tools to run for a domain target."""
    jobs = {
        "WHOIS": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{target}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "theHarvester": venv_cmd(
            f"theHarvester -d {target} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"
        ),
        "Amass (passive)": f"timeout 60 amass enum -passive -d {target} 2>/dev/null",
        "DNS Records": f"nslookup -type=ANY {target} 2>/dev/null; echo '---MX---'; nslookup -type=MX {target} 2>/dev/null; echo '---TXT---'; nslookup -type=TXT {target} 2>/dev/null",
        "WebTech": venv_cmd(f"webtech -u https://{target} 2>/dev/null"),
        "Wayback Machine": venv_cmd(
            f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{target}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<15]\" 2>/dev/null"
        ),
    }

    if not stealth:
        jobs["SSL Cert"] = f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -30"
        jobs["HTTP Headers"] = f"curl -sI https://{target} 2>/dev/null | head -25"

    if full:
        jobs["Amass (active)"] = f"timeout 120 amass enum -active -d {target} 2>/dev/null"
        jobs["Nmap (top ports)"] = f"nmap -sT --top-ports 100 -T4 {target} 2>/dev/null"
        jobs["BuiltWith"] = venv_cmd(f"python3 -c \"import builtwith; import json; r=builtwith.parse('https://{target}'); print(json.dumps(r, indent=2))\" 2>/dev/null")
        jobs["CrossLinked (LinkedIn)"] = venv_cmd(f"crosslinked -f '{{first}}.{{last}}@{target}' '{target}' 2>/dev/null")

    return jobs


def tools_for_phone(target, full=False, stealth=False):
    """Tools to run for a phone number target."""
    clean = re.sub(r'[^\d+]', '', target)
    jobs = {
        "Ignorant": venv_cmd(f"ignorant {clean} 2>/dev/null"),
        "Holehe (if email-able)": venv_cmd(f"holehe {clean}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {clean} 2>/dev/null",
    }
    if full:
        jobs["Sherlock (number)"] = f"sherlock {clean} --print-found --no-color 2>/dev/null"
    return jobs


def tools_for_ip(target, full=False, stealth=False):
    """Tools to run for an IP address target."""
    jobs = {
        "IPWhois": venv_cmd(f"python3 -c \"from ipwhois import IPWhois; import json; w=IPWhois('{target}'); r=w.lookup_rdap(); print(json.dumps(r, indent=2, default=str))\" 2>/dev/null"),
        "Reverse DNS": f"nslookup {target} 2>/dev/null",
        "GeoIP (ipinfo.io)": f"curl -s https://ipinfo.io/{target}/json 2>/dev/null",
        "Shodan (host)": venv_cmd(f"shodan host {target} 2>/dev/null"),
    }

    if not stealth:
        jobs["Nmap (quick)"] = f"nmap -sT -T4 --top-ports 50 {target} 2>/dev/null"

    if full:
        jobs["Nmap (full)"] = f"nmap -sT -sV -T4 --top-ports 1000 {target} 2>/dev/null"
        jobs["Traceroute"] = f"traceroute -m 15 {target} 2>/dev/null"

    return jobs


def tools_for_file(target, full=False, stealth=False):
    """Tools to run for a file target."""
    jobs = {
        "ExifTool (full)": f"exiftool -G1 -s {target}",
        "ExifTool (JSON)": f"exiftool -json -G1 {target}",
        "File type": f"file -b {target}",
        "Strings (emails/URLs)": f"strings {target} 2>/dev/null | grep -iE '(https?://|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}})' | sort -u | head -30",
    }
    if full:
        jobs["Strings (all interesting)"] = f"strings {target} 2>/dev/null | grep -iE '(password|secret|key|token|admin|root|user|login|api)' | sort -u | head -30"
        jobs["Hashes"] = f"echo 'MD5:' && md5 -q {target} 2>/dev/null; echo 'SHA1:' && shasum -a 1 {target} 2>/dev/null | cut -d' ' -f1; echo 'SHA256:' && shasum -a 256 {target} 2>/dev/null | cut -d' ' -f1"
        # Check if image — extract GPS
        jobs["GPS coordinates"] = f"exiftool -gpslatitude -gpslongitude -gpsposition -n {target} 2>/dev/null"
    return jobs


def tools_for_person(target, full=False, stealth=False):
    """Tools to run for a person name — generates username/email variants."""
    parts = target.lower().split()
    if len(parts) < 2:
        parts = [parts[0], ""]
    first, last = parts[0], parts[-1]

    usernames = list(set(filter(None, [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{last}{first}",
        f"{first}{last[0]}" if last else None,
    ])))

    emails = [
        f"{first}{last}@gmail.com",
        f"{first}.{last}@gmail.com",
        f"{first}{last}@yahoo.com",
        f"{first}.{last}@outlook.com",
        f"{first[0]}{last}@gmail.com",
    ]

    print(f"{C.DIM}  Username variants: {', '.join(usernames)}{C.RESET}")
    print(f"{C.DIM}  Email variants: {', '.join(emails[:3])}...{C.RESET}")

    primary = f"{first}{last}" if last else first
    jobs = {
        "Sherlock": f"sherlock {primary} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {primary} --no-color --timeout 30 2>/dev/null"),
        "Socialscan (usernames)": f"socialscan {' '.join(usernames)} 2>/dev/null",
        "Holehe (gmail)": venv_cmd(f"holehe {first}{last}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Holehe (yahoo)": venv_cmd(f"holehe {first}{last}@yahoo.com --no-color --no-clear 2>/dev/null"),
    }

    if full:
        jobs["Sherlock (alt)"] = f"sherlock {first}_{last} --print-found --no-color 2>/dev/null"
        jobs["Maigret (alt)"] = venv_cmd(f"maigret {first[0]}{last} --no-color --timeout 30 2>/dev/null")
        jobs["Holehe (outlook)"] = venv_cmd(f"holehe {first}.{last}@outlook.com --no-color --no-clear 2>/dev/null")
        jobs["GHunt (gmail)"] = venv_cmd(f"ghunt email {first}{last}@gmail.com 2>/dev/null")
        jobs["CrossLinked (LinkedIn)"] = venv_cmd(f"crosslinked -f '{{first}} {{last}}' '{first} {last}' 2>/dev/null")

    return jobs


def tools_for_company(target, full=False, stealth=False):
    """Tools to run for a company name."""
    # Try to derive a domain from the company name
    domain_guess = target.lower().replace(" ", "").replace(",", "").replace(".", "")
    domain_guess = re.sub(r'(inc|llc|corp|ltd|co|company|group|solutions|technologies)$', '', domain_guess)
    domain_guess = f"{domain_guess}.com"

    print(f"{C.DIM}  Guessed domain: {domain_guess}{C.RESET}")

    jobs = {
        "WHOIS (guessed domain)": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{domain_guess}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "theHarvester": venv_cmd(
            f"theHarvester -d {domain_guess} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"
        ),
        "DNS": f"nslookup {domain_guess} 2>/dev/null",
        "WebTech": venv_cmd(f"webtech -u https://{domain_guess} 2>/dev/null"),
        "HTTP Headers": f"curl -sI https://{domain_guess} 2>/dev/null | head -20",
        "SSL Cert": f"echo | openssl s_client -connect {domain_guess}:443 -servername {domain_guess} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null",
    }

    if full:
        jobs["CrossLinked (employees)"] = venv_cmd(f"crosslinked -f '{{first}}.{{last}}@{domain_guess}' '{target}' 2>/dev/null")
        jobs["Amass"] = f"timeout 60 amass enum -passive -d {domain_guess} 2>/dev/null"
        jobs["Wayback"] = venv_cmd(
            f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{domain_guess}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null"
        )
        jobs["BuiltWith"] = venv_cmd(f"python3 -c \"import builtwith; import json; r=builtwith.parse('https://{domain_guess}'); print(json.dumps(r, indent=2))\" 2>/dev/null")

    return jobs


TOOL_MAP = {
    "username": tools_for_username,
    "email": tools_for_email,
    "domain": tools_for_domain,
    "phone": tools_for_phone,
    "ip": tools_for_ip,
    "file": tools_for_file,
    "person": tools_for_person,
    "company": tools_for_company,
}


# ── Result formatting ────────────────────────────────────────────

def print_result(result):
    """Pretty-print a single tool result."""
    status_icon = {
        "success": f"{C.GREEN}✓{C.RESET}",
        "partial": f"{C.YELLOW}~{C.RESET}",
        "timeout": f"{C.RED}⏱{C.RESET}",
        "error": f"{C.RED}✗{C.RESET}",
    }
    icon = status_icon.get(result["status"], "?")
    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"{icon} {C.BOLD}{C.BLUE}{result['tool']}{C.RESET} {C.DIM}({result['elapsed']}s){C.RESET}")
    print(f"{'─' * 60}")

    output = result["output"]
    if not output:
        print(f"  {C.DIM}(no output){C.RESET}")
    else:
        lines = output.split("\n")
        if len(lines) > 80:
            print("\n".join(lines[:60]))
            print(f"\n  {C.DIM}... ({len(lines) - 60} more lines in report){C.RESET}")
        else:
            print(output)


def save_report(target, target_type, results):
    """Save full report to JSON + text."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w.-]', '_', target)
    base = REPORTS_DIR / f"{safe_target}_{ts}"

    report = {
        "target": target,
        "type": target_type,
        "timestamp": datetime.now().isoformat(),
        "tools_run": len(results),
        "results": results,
    }

    # JSON report
    json_path = base.with_suffix(".json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # Text report
    txt_path = base.with_suffix(".txt")
    with open(txt_path, "w") as f:
        f.write(f"Scout OSINT Report v2.0\n{'=' * 50}\n")
        f.write(f"Target: {target}\n")
        f.write(f"Type: {target_type}\n")
        f.write(f"Time: {report['timestamp']}\n")
        f.write(f"Tools: {len(results)}\n\n")
        for r in results:
            f.write(f"\n{'=' * 50}\n")
            f.write(f"[{r['status'].upper()}] {r['tool']} ({r['elapsed']}s)\n")
            f.write(f"{'─' * 50}\n")
            f.write(r["output"] + "\n")

    return json_path, txt_path


# ── Summary extractor ────────────────────────────────────────────

def extract_findings(results):
    """Extract structured findings from raw output."""
    findings = {
        "accounts_found": [],
        "emails_found": [],
        "domains_found": [],
        "ips_found": [],
        "other": [],
    }

    for r in results:
        output = r["output"]
        for line in output.split("\n"):
            # URLs from Sherlock/Maigret
            url_match = re.search(r'https?://[^\s\]"]+', line)
            if url_match and ("[+]" in line or "Found" in line.lower()):
                findings["accounts_found"].append(url_match.group(0))
            # Emails
            email_match = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            findings["emails_found"].extend(email_match)
            # IPs
            ip_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            findings["ips_found"].extend(ip_match)

    # Deduplicate
    findings["accounts_found"] = list(dict.fromkeys(findings["accounts_found"]))
    findings["emails_found"] = list(dict.fromkeys(findings["emails_found"]))
    findings["ips_found"] = list(dict.fromkeys(findings["ips_found"]))

    return findings


def summarize(target, target_type, results):
    """Extract key findings across all tools."""
    findings = extract_findings(results)

    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SUMMARY — {target} ({target_type}){C.RESET}")
    print(f"{'═' * 60}")

    total = len(results)
    success = sum(1 for r in results if r["status"] in ("success", "partial"))
    timeout = sum(1 for r in results if r["status"] == "timeout")

    print(f"  Tools: {total} run | {success} returned data | {timeout} timed out")

    if findings["accounts_found"]:
        print(f"\n  {C.GREEN}{C.BOLD}Accounts/Profiles ({len(findings['accounts_found'])}):{C.RESET}")
        for url in findings["accounts_found"][:20]:
            print(f"    {C.GREEN}→{C.RESET} {url}")
        if len(findings["accounts_found"]) > 20:
            print(f"    {C.DIM}... +{len(findings['accounts_found']) - 20} more in report{C.RESET}")

    if findings["emails_found"]:
        unique_emails = [e for e in findings["emails_found"] if e != target and 'github.com' not in e][:10]
        if unique_emails:
            print(f"\n  {C.YELLOW}{C.BOLD}Emails found ({len(unique_emails)}):{C.RESET}")
            for email in unique_emails:
                print(f"    {C.YELLOW}→{C.RESET} {email}")

    if findings["ips_found"]:
        unique_ips = list(dict.fromkeys(findings["ips_found"]))[:10]
        if unique_ips:
            print(f"\n  {C.BLUE}{C.BOLD}IPs found ({len(unique_ips)}):{C.RESET}")
            for ip in unique_ips:
                print(f"    {C.BLUE}→{C.RESET} {ip}")

    elapsed_total = sum(r["elapsed"] for r in results)
    elapsed_max = max(r["elapsed"] for r in results)
    print(f"\n  Wall time: {round(elapsed_max, 1)}s (parallel) | CPU time: {round(elapsed_total, 1)}s")
    print(f"{'═' * 60}\n")

    return findings


# ── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scout OSINT v2.0 — Unified intelligence gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Target types (auto-detected or use -t):
  username    Social media, forums, sites (Sherlock + Maigret + Socialscan)
  email       Registrations, breaches, Google, domain (Holehe + GHunt + H8mail)
  domain      Subdomains, emails, tech stack, SSL, WHOIS (Amass + theHarvester + WebTech)
  phone       Phone number lookups (Ignorant + carrier checks)
  ip          GeoIP, WHOIS, Shodan, port scan (IPWhois + Nmap + Shodan)
  file        Metadata, GPS, hashes, embedded strings (ExifTool + strings)
  person      "First Last" — generates variants, multi-tool sweep
  company     "Company Name" — domain guess, employees, tech stack, history
        """,
    )
    parser.add_argument("target", help="Target to investigate")
    parser.add_argument("-t", "--type", choices=TOOL_MAP.keys(), help="Force target type")
    parser.add_argument("--full", action="store_true", help="Run ALL tools including slow ones")
    parser.add_argument("--stealth", action="store_true", help="Passive-only, no direct target contact")
    parser.add_argument("--no-save", action="store_true", help="Don't save report to disk")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    parser.add_argument("--workers", type=int, default=6, help="Max parallel workers (default: 6)")

    args = parser.parse_args()

    if not args.json:
        banner()

    target = args.target
    target_type = args.type or detect_type(target)

    if not args.json:
        print(f"  {C.BOLD}Target:{C.RESET}  {target}")
        print(f"  {C.BOLD}Type:{C.RESET}    {target_type}")
        mode_parts = []
        if args.full:
            mode_parts.append("Full")
        if args.stealth:
            mode_parts.append("Stealth")
        if not mode_parts:
            mode_parts.append("Standard")
        print(f"  {C.BOLD}Mode:{C.RESET}    {' + '.join(mode_parts)}")
        print()

    # Get tool jobs for this target type
    tool_func = TOOL_MAP[target_type]
    jobs = tool_func(target, full=args.full, stealth=args.stealth)

    if not args.json:
        print(f"  {C.DIM}Running {len(jobs)} tools in parallel (workers={args.workers})...{C.RESET}\n")

    # Run all tools in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(run_tool, name, cmd, timeout=180): name
            for name, cmd in jobs.items()
        }
        for future in as_completed(futures):
            result = future.result()
            if not args.json:
                print_result(result)
            results.append(result)

    # JSON-only output
    if args.json:
        output = {
            "target": target,
            "type": target_type,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "findings": extract_findings(results),
        }
        print(json.dumps(output, indent=2))
        return

    # Summary
    findings = summarize(target, target_type, results)

    # Save report
    if not args.no_save:
        json_path, txt_path = save_report(target, target_type, results)
        print(f"  {C.GREEN}Reports saved:{C.RESET}")
        print(f"    {json_path}")
        print(f"    {txt_path}")
        print()


if __name__ == "__main__":
    main()
