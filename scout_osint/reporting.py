"""Report generation — JSON + text output."""
import json
import re
from datetime import datetime
from pathlib import Path


def extract_findings(results):
    """Extract structured findings from raw tool output."""
    findings = {
        "accounts_found": [],
        "emails_found": [],
        "domains_found": [],
        "ips_found": [],
    }

    for r in results:
        output = r["output"]
        for line in output.split("\n"):
            url_match = re.search(r'https?://[^\s\]"]+', line)
            if url_match and ("[+]" in line or "Found" in line.lower()):
                findings["accounts_found"].append(url_match.group(0))
            email_match = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            findings["emails_found"].extend(email_match)
            ip_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            findings["ips_found"].extend(ip_match)

    findings["accounts_found"] = list(dict.fromkeys(findings["accounts_found"]))
    findings["emails_found"] = list(dict.fromkeys(findings["emails_found"]))
    findings["ips_found"] = list(dict.fromkeys(findings["ips_found"]))

    return findings


def save_report(target, target_type, results, reports_dir):
    """Save full report to JSON + text files."""
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w.-]', '_', target)
    base = reports_dir / f"{safe_target}_{ts}"

    report = {
        "target": target,
        "type": target_type,
        "timestamp": datetime.now().isoformat(),
        "tools_run": len(results),
        "results": results,
        "findings": extract_findings(results),
    }

    json_path = base.with_suffix(".json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    txt_path = base.with_suffix(".txt")
    with open(txt_path, "w") as f:
        f.write(f"Scout OSINT Report v2.0\n{'=' * 50}\n")
        f.write(f"Target: {target}\nType: {target_type}\n")
        f.write(f"Time: {report['timestamp']}\nTools: {len(results)}\n\n")
        for r in results:
            f.write(f"\n{'=' * 50}\n")
            f.write(f"[{r['status'].upper()}] {r['tool']} ({r['elapsed']}s)\n")
            f.write(f"{'─' * 50}\n{r['output']}\n")

    return json_path, txt_path
