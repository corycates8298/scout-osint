"""Company OSINT tools — multi-TLD domain guess, WHOIS, employees, tech stack."""
import re
from ..sanitize import shell_quote, sanitize_for_python_string


def guess_domains(company_name):
    """Generate likely domain names from a company name."""
    base = company_name.lower().replace(" ", "").replace(",", "").replace(".", "")
    base = re.sub(r'(inc|llc|corp|ltd|co|company|group|solutions|technologies|enterprises|associates|partners)$', '', base)

    # Also try with hyphens/spaces preserved differently
    hyphenated = company_name.lower().replace(" ", "-").replace(",", "")
    hyphenated = re.sub(r'-(inc|llc|corp|ltd|co|company|group|solutions|technologies)$', '', hyphenated)

    domains = []
    for variant in [base, hyphenated]:
        for tld in [".com", ".io", ".co", ".org", ".net"]:
            d = f"{variant}{tld}"
            if d not in domains:
                domains.append(d)
    return domains


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    domains = guess_domains(target)
    primary = domains[0]
    safe_primary = sanitize_for_python_string(primary)
    safe_target = shell_quote(target)

    jobs = {
        "WHOIS": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{safe_primary}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "theHarvester": venv_cmd(f"theHarvester -d {primary} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"),
        "DNS": f"nslookup {primary} 2>/dev/null",
        "WebTech": venv_cmd(f"webtech -u https://{primary} 2>/dev/null"),
        "HTTP Headers": f"curl -sI https://{primary} 2>/dev/null | head -20",
        "SSL Cert": f"echo | openssl s_client -connect {primary}:443 -servername {primary} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null",
    }

    # Try alternate TLDs
    for alt in domains[1:4]:
        jobs[f"DNS ({alt})"] = f"nslookup {alt} 2>/dev/null"

    if full:
        jobs["CrossLinked (employees)"] = venv_cmd(f"crosslinked -f '{{{{first}}}}.{{{{last}}}}@{primary}' {safe_target} 2>/dev/null")
        jobs["Amass"] = f"timeout 60 amass enum -passive -d {primary} 2>/dev/null"
        jobs["Wayback"] = venv_cmd(f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{safe_primary}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null")
        jobs["BuiltWith"] = venv_cmd(f"python3 -c \"import builtwith; import json; r=builtwith.parse('https://{safe_primary}'); print(json.dumps(r, indent=2))\" 2>/dev/null")

    return jobs, domains
