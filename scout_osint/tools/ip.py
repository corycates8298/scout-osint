"""IP address OSINT tools — IPWhois, GeoIP, Shodan, Nmap."""
from ..sanitize import sanitize_for_python_string


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    safe_py = sanitize_for_python_string(target)

    jobs = {
        "IPWhois": venv_cmd(f"python3 -c \"from ipwhois import IPWhois; import json; w=IPWhois('{safe_py}'); r=w.lookup_rdap(); print(json.dumps(r, indent=2, default=str))\" 2>/dev/null"),
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
