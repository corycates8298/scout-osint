"""Email OSINT tools — Holehe, GHunt, Ignorant, H8mail, WHOIS."""


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    username = target.split("@")[0]
    domain = target.split("@")[1]

    jobs = {
        "Holehe": venv_cmd(f"holehe {target} --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {target} 2>/dev/null",
        "Ignorant (phone links)": venv_cmd(f"ignorant {target} 2>/dev/null"),
        "GHunt (Google)": venv_cmd(f"ghunt email {target} 2>/dev/null"),
        "WHOIS (domain)": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{domain}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "Email Validation": venv_cmd(f"python3 -c \"from email_validator import validate_email; r=validate_email('{target}', check_deliverability=True); print(f'Valid: {{r.email}}')\" 2>/dev/null"),
    }

    if full:
        jobs["Sherlock (username)"] = f"sherlock {username} --print-found --no-color 2>/dev/null"
        jobs["Maigret (username)"] = venv_cmd(f"maigret {username} --no-color --timeout 30 2>/dev/null")
        jobs["theHarvester"] = venv_cmd(f"theHarvester -d {domain} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null")
        jobs["H8mail (breach check)"] = venv_cmd(f"h8mail -t {target} 2>/dev/null")
        jobs["Wayback (domain)"] = venv_cmd(f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{domain}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null")

    return jobs
