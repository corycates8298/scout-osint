"""Phone number OSINT tools — Ignorant, carrier checks."""
import re
from ..sanitize import shell_quote


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    clean = re.sub(r'[^\d+]', '', target)
    safe = shell_quote(clean)
    jobs = {
        "Ignorant": venv_cmd(f"ignorant {safe} 2>/dev/null"),
        "Holehe (gmail guess)": venv_cmd(f"holehe {clean}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {safe} 2>/dev/null",
    }
    if full:
        jobs["Sherlock (number)"] = f"sherlock {safe} --print-found --no-color 2>/dev/null"
    return jobs
