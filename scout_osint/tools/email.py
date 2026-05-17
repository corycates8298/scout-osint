"""Email OSINT tools — Holehe, GHunt, Ignorant, H8mail, WHOIS."""
from ..sanitize import shell_quote, sanitize_for_python_string


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    username = target.split("@")[0]
    domain_part = target.split("@")[1]
    safe = shell_quote(target)
    safe_user = shell_quote(username)
    safe_domain = sanitize_for_python_string(domain_part)

    jobs = {
        "Holehe": venv_cmd(f"holehe {safe} --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {safe} 2>/dev/null",
        "Ignorant (phone links)": venv_cmd(f"ignorant {safe} 2>/dev/null"),
        "GHunt (Google)": venv_cmd(f"ghunt email {safe} 2>/dev/null"),
        "WHOIS (domain)": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{safe_domain}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "Email Validation": venv_cmd(f"python3 -c \"from email_validator import validate_email; r=validate_email('{sanitize_for_python_string(target)}', check_deliverability=True); print(f'Valid: {{r.email}}')\" 2>/dev/null"),
    }

    if full:
        jobs["Sherlock (username)"] = f"sherlock {safe_user} --print-found --no-color 2>/dev/null"
        jobs["Maigret (username)"] = venv_cmd(f"maigret {safe_user} --no-color --timeout 30 2>/dev/null")
        jobs["theHarvester"] = venv_cmd(f"theHarvester -d {domain_part} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null")
        jobs["H8mail (breach check)"] = venv_cmd(f"h8mail -t {safe} 2>/dev/null")
        jobs["Wayback (domain)"] = venv_cmd(f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{safe_domain}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null")

    return jobs
