#!/usr/bin/env python3
"""
Scout OSINT v3.0 — Unified OSINT orchestrator.
Detects target type and runs the right tools in parallel, then merges results.

Usage:
    scout-osint <target>                  # auto-detect type
    scout-osint -t username <target>      # force type
    scout-osint --full <target>           # run ALL tools, even slow ones
    scout-osint --stealth <target>        # passive-only
    scout-osint diff <target>             # show what changed since last scan
    scout-osint keys                      # show configured API keys
"""

import argparse
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from .detectors import detect_type
from .sanitize import sanitize_target, shell_quote
from .reporting import extract_findings, save_report
from .dedup import deduplicate_findings
from .history import get_previous_scan, diff_scans, print_diff
from .keys import configured_keys, create_default_config, has_key
from .tools import username, email, domain, ip, phone, file, person, company

OSINT_DIR = Path.home() / "osint"
REPORTS_DIR = OSINT_DIR / "reports"
VENV_ACTIVATE = f"source {OSINT_DIR}/venv/bin/activate"

__version__ = "3.0.0"


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
  ║           Scout OSINT v{__version__}                ║
  ║      Unified Intelligence Gathering           ║
  ║  8 target types · 20+ tools · parallel exec   ║
  ╚═══════════════════════════════════════════════╝{C.RESET}
""")


def venv_cmd(tool_cmd):
    """Wrap a command to run inside the OSINT venv."""
    return f"bash -c '{VENV_ACTIVATE} && {tool_cmd}'"


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


def print_result(result):
    """Pretty-print a single tool result."""
    status_icon = {
        "success": f"{C.GREEN}+{C.RESET}",
        "partial": f"{C.YELLOW}~{C.RESET}",
        "timeout": f"{C.RED}T{C.RESET}",
        "error": f"{C.RED}x{C.RESET}",
    }
    icon = status_icon.get(result["status"], "?")
    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{icon} {C.BOLD}{C.BLUE}{result['tool']}{C.RESET} {C.DIM}({result['elapsed']}s){C.RESET}")
    print(f"{'-' * 60}")

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


def summarize(target, target_type, results):
    """Extract key findings across all tools, deduplicated."""
    raw_findings = extract_findings(results)
    findings = deduplicate_findings(raw_findings)

    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SUMMARY — {target} ({target_type}){C.RESET}")
    print(f"{'=' * 60}")

    total = len(results)
    success = sum(1 for r in results if r["status"] in ("success", "partial"))
    timeout = sum(1 for r in results if r["status"] == "timeout")

    print(f"  Tools: {total} run | {success} returned data | {timeout} timed out")

    stats = findings["stats"]
    if stats["accounts_raw"] != stats["accounts_deduped"]:
        print(f"  {C.DIM}Dedup: {stats['accounts_raw']} raw accounts → {stats['accounts_deduped']} unique{C.RESET}")

    if findings["accounts_found"]:
        print(f"\n  {C.GREEN}{C.BOLD}Accounts/Profiles ({len(findings['accounts_found'])}):{C.RESET}")
        for url in findings["accounts_found"][:20]:
            print(f"    {C.GREEN}>{C.RESET} {url}")
        if len(findings["accounts_found"]) > 20:
            print(f"    {C.DIM}... +{len(findings['accounts_found']) - 20} more in report{C.RESET}")

    if findings.get("platforms"):
        print(f"\n  {C.CYAN}{C.BOLD}Platforms ({len(findings['platforms'])}):{C.RESET} {', '.join(sorted(findings['platforms']))}")

    if findings["emails_found"]:
        unique_emails = [e for e in findings["emails_found"] if e != target and 'github.com' not in e][:10]
        if unique_emails:
            print(f"\n  {C.YELLOW}{C.BOLD}Emails ({len(unique_emails)}):{C.RESET}")
            for em in unique_emails:
                print(f"    {C.YELLOW}>{C.RESET} {em}")

    if findings["ips_found"]:
        print(f"\n  {C.BLUE}{C.BOLD}IPs ({len(findings['ips_found'])}):{C.RESET}")
        for ip_addr in findings["ips_found"][:10]:
            print(f"    {C.BLUE}>{C.RESET} {ip_addr}")

    elapsed_total = sum(r["elapsed"] for r in results)
    elapsed_max = max(r["elapsed"] for r in results) if results else 0
    print(f"\n  Wall time: {round(elapsed_max, 1)}s (parallel) | CPU time: {round(elapsed_total, 1)}s")
    print(f"{'=' * 60}\n")

    return findings


# ── Tool dispatch map ────────────────────────────────────────────

TOOL_MODULES = {
    "username": username,
    "email": email,
    "domain": domain,
    "phone": phone,
    "ip": ip,
    "file": file,
    "person": person,
    "company": company,
}


def get_jobs(target_type, target, full=False, stealth=False):
    """Get tool jobs from the appropriate module."""
    mod = TOOL_MODULES[target_type]
    result = mod.get_jobs(target, full=full, stealth=stealth, venv_cmd=venv_cmd)
    # Company module returns (jobs, domains) tuple
    if isinstance(result, tuple):
        return result[0], result[1]
    return result, None


# ── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"Scout OSINT v{__version__} — Unified intelligence gathering",
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
  company     "Company Name" — multi-TLD domain guess, employees, tech stack
        """,
    )
    parser.add_argument("target", nargs="?", help="Target to investigate")
    parser.add_argument("-t", "--type", choices=TOOL_MODULES.keys(), help="Force target type")
    parser.add_argument("--full", action="store_true", help="Run ALL tools including slow ones")
    parser.add_argument("--stealth", action="store_true", help="Passive-only, no direct target contact")
    parser.add_argument("--no-save", action="store_true", help="Don't save report to disk")
    parser.add_argument("--json", action="store_true", help="Output raw JSON only")
    parser.add_argument("--workers", type=int, default=6, help="Max parallel workers (default: 6)")
    parser.add_argument("--keys", action="store_true", help="Show configured API keys")
    parser.add_argument("--diff", action="store_true", help="Show changes since last scan of this target")
    parser.add_argument("--version", action="version", version=f"scout-osint {__version__}")

    args = parser.parse_args()

    # Keys command
    if args.keys:
        keys = configured_keys()
        if keys:
            print(f"  Configured API keys: {', '.join(keys)}")
        else:
            print(f"  No API keys configured.")
            created = create_default_config()
            if created:
                print(f"  Created template: ~/.scout-osint/keys.yaml")
            else:
                print(f"  Edit: ~/.scout-osint/keys.yaml")
        return

    if not args.target:
        parser.print_help()
        return

    # Sanitize input
    try:
        target = sanitize_target(args.target)
    except ValueError as e:
        print(f"  {C.RED}Error: {e}{C.RESET}")
        return

    if not args.json:
        banner()

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

        # Show API key status
        keys = configured_keys()
        if keys:
            print(f"  {C.BOLD}Keys:{C.RESET}    {', '.join(keys)}")

        print()

    # Get tool jobs from module
    jobs, extra_info = get_jobs(target_type, target, full=args.full, stealth=args.stealth)

    # Show extra info (like guessed domains for company)
    if extra_info and not args.json:
        if target_type == "company":
            print(f"  {C.DIM}Guessed domains: {', '.join(extra_info[:5])}{C.RESET}")

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
        raw_findings = extract_findings(results)
        findings = deduplicate_findings(raw_findings)
        output = {
            "target": target,
            "type": target_type,
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "findings": findings,
        }
        print(json.dumps(output, indent=2))
        return

    # Summary with dedup
    findings = summarize(target, target_type, results)

    # Scan diff (compare with previous)
    if args.diff or True:  # Always show diff if previous scan exists
        prev = get_previous_scan(target)
        if prev:
            current_report = {
                "target": target,
                "type": target_type,
                "timestamp": datetime.now().isoformat(),
                "results": results,
            }
            diff_result = diff_scans(prev, current_report)
            if diff_result:
                print_diff(diff_result)

    # Save report
    if not args.no_save:
        report_data = {
            "target": target,
            "type": target_type,
            "timestamp": datetime.now().isoformat(),
            "tools_run": len(results),
            "results": results,
            "findings": findings,
        }
        json_path, txt_path = save_report(target, target_type, results, str(REPORTS_DIR))
        print(f"  {C.GREEN}Reports saved:{C.RESET}")
        print(f"    {json_path}")
        print(f"    {txt_path}")
        print()


if __name__ == "__main__":
    main()
