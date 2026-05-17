"""Phone number OSINT tools — Ignorant, carrier checks."""
import re


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    clean = re.sub(r'[^\d+]', '', target)
    jobs = {
        "Ignorant": venv_cmd(f"ignorant {clean} 2>/dev/null"),
        "Holehe (gmail guess)": venv_cmd(f"holehe {clean}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Socialscan": f"socialscan {clean} 2>/dev/null",
    }
    if full:
        jobs["Sherlock (number)"] = f"sherlock {clean} --print-found --no-color 2>/dev/null"
    return jobs
