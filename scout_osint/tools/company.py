"""Company OSINT tools — domain guess, WHOIS, employees, tech stack."""
import re


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    domain_guess = target.lower().replace(" ", "").replace(",", "").replace(".", "")
    domain_guess = re.sub(r'(inc|llc|corp|ltd|co|company|group|solutions|technologies)$', '', domain_guess)
    domain_guess = f"{domain_guess}.com"

    jobs = {
        "WHOIS": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{domain_guess}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "theHarvester": venv_cmd(f"theHarvester -d {domain_guess} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"),
        "DNS": f"nslookup {domain_guess} 2>/dev/null",
        "WebTech": venv_cmd(f"webtech -u https://{domain_guess} 2>/dev/null"),
        "HTTP Headers": f"curl -sI https://{domain_guess} 2>/dev/null | head -20",
        "SSL Cert": f"echo | openssl s_client -connect {domain_guess}:443 -servername {domain_guess} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null",
    }

    if full:
        jobs["CrossLinked (employees)"] = venv_cmd(f"crosslinked -f '{{{{first}}}}.{{{{last}}}}@{domain_guess}' '{target}' 2>/dev/null")
        jobs["Amass"] = f"timeout 60 amass enum -passive -d {domain_guess} 2>/dev/null"
        jobs["Wayback"] = venv_cmd(f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{domain_guess}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<10]\" 2>/dev/null")
        jobs["BuiltWith"] = venv_cmd(f"python3 -c \"import builtwith; import json; r=builtwith.parse('https://{domain_guess}'); print(json.dumps(r, indent=2))\" 2>/dev/null")

    return jobs
