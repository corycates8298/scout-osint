"""Domain OSINT tools — theHarvester, Amass, WHOIS, DNS, WebTech, SSL, Wayback."""


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    jobs = {
        "WHOIS": venv_cmd(f"python3 -c \"import whois; import json; w=whois.whois('{target}'); print(json.dumps(dict(w), indent=2, default=str))\" 2>/dev/null"),
        "theHarvester": venv_cmd(f"theHarvester -d {target} -b crtsh,dnsdumpster,rapiddns -l 200 2>/dev/null"),
        "Amass (passive)": f"timeout 60 amass enum -passive -d {target} 2>/dev/null",
        "DNS Records": f"nslookup -type=ANY {target} 2>/dev/null; echo '---MX---'; nslookup -type=MX {target} 2>/dev/null; echo '---TXT---'; nslookup -type=TXT {target} 2>/dev/null",
        "WebTech": venv_cmd(f"webtech -u https://{target} 2>/dev/null"),
        "Wayback Machine": venv_cmd(f"python3 -c \"from waybackpy import WaybackMachineCDXServerAPI; cdx=WaybackMachineCDXServerAPI('{target}'); [print(s.archive_url) for i,s in enumerate(cdx.snapshots()) if i<15]\" 2>/dev/null"),
    }

    if not stealth:
        jobs["SSL Cert"] = f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -30"
        jobs["HTTP Headers"] = f"curl -sI https://{target} 2>/dev/null | head -25"

    if full:
        jobs["Amass (active)"] = f"timeout 120 amass enum -active -d {target} 2>/dev/null"
        jobs["Nmap (top ports)"] = f"nmap -sT --top-ports 100 -T4 {target} 2>/dev/null"
        jobs["BuiltWith"] = venv_cmd(f"python3 -c \"import builtwith; import json; r=builtwith.parse('https://{target}'); print(json.dumps(r, indent=2))\" 2>/dev/null")
        jobs["CrossLinked (LinkedIn)"] = venv_cmd(f"crosslinked -f '{{{{first}}}}.{{{{last}}}}@{target}' '{target}' 2>/dev/null")

    return jobs
