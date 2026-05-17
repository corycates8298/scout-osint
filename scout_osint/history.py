"""Scan history and diffing — compare runs over time."""
import json
from datetime import datetime
from pathlib import Path


HISTORY_DIR = Path.home() / "osint" / "reports"


def get_previous_scan(target, current_timestamp=None):
    """Find the most recent previous scan for a target."""
    safe_target = target.replace(" ", "_").replace("@", "_")
    pattern = f"{safe_target}*.json"
    matches = sorted(HISTORY_DIR.glob(pattern), reverse=True)

    for match in matches:
        # Skip the current scan if timestamp provided
        if current_timestamp and current_timestamp in match.name:
            continue
        try:
            with open(match) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
    return None


def diff_scans(old_scan, new_scan):
    """
    Compare two scan results and return what changed.
    Returns: dict with added, removed, unchanged counts.
    """
    if not old_scan:
        return None

    def get_accounts(scan):
        accounts = set()
        for r in scan.get("results", []):
            output = r.get("output", "")
            import re
            for line in output.split("\n"):
                url_match = re.search(r'https?://[^\s\]"]+', line)
                if url_match and ("[+]" in line or "Found" in line.lower()):
                    accounts.add(url_match.group(0).rstrip("/").lower())
        return accounts

    old_accounts = get_accounts(old_scan)
    new_accounts = get_accounts(new_scan)

    added = new_accounts - old_accounts
    removed = old_accounts - new_accounts
    unchanged = old_accounts & new_accounts

    return {
        "previous_scan": old_scan.get("timestamp", "unknown"),
        "added": sorted(added),
        "removed": sorted(removed),
        "unchanged_count": len(unchanged),
        "total_old": len(old_accounts),
        "total_new": len(new_accounts),
    }


def print_diff(diff_result, colors=True):
    """Pretty-print a scan diff."""
    if not diff_result:
        return

    G = "\033[92m" if colors else ""
    R = "\033[91m" if colors else ""
    D = "\033[2m" if colors else ""
    B = "\033[1m" if colors else ""
    X = "\033[0m" if colors else ""

    print(f"\n  {B}Scan Diff{X} {D}(vs {diff_result['previous_scan']}){X}")
    print(f"  {'─' * 50}")

    if diff_result["added"]:
        print(f"  {G}{B}+ New ({len(diff_result['added'])}):{X}")
        for url in diff_result["added"][:15]:
            print(f"    {G}+ {url}{X}")
        if len(diff_result["added"]) > 15:
            print(f"    {D}... +{len(diff_result['added']) - 15} more{X}")

    if diff_result["removed"]:
        print(f"  {R}{B}- Gone ({len(diff_result['removed'])}):{X}")
        for url in diff_result["removed"][:15]:
            print(f"    {R}- {url}{X}")

    print(f"  {D}Unchanged: {diff_result['unchanged_count']} | Old: {diff_result['total_old']} | New: {diff_result['total_new']}{X}")
