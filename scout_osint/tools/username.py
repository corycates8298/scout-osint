"""Username OSINT tools — Sherlock, Maigret, Socialscan."""
from ..sanitize import shell_quote


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    safe = shell_quote(target)
    jobs = {
        "Sherlock": f"sherlock {safe} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {safe} --no-color --timeout 30 2>/dev/null"),
        "Socialscan": f"socialscan {safe} 2>/dev/null",
    }
    if full:
        jobs["Maigret (full DB)"] = venv_cmd(f"maigret {safe} -a --no-color --timeout 60 2>/dev/null")
    return jobs
