"""Username OSINT tools — Sherlock, Maigret, Socialscan."""


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    jobs = {
        "Sherlock": f"sherlock {target} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {target} --no-color --timeout 30 2>/dev/null"),
        "Socialscan": f"socialscan {target} 2>/dev/null",
    }
    if full:
        jobs["Maigret (full DB)"] = venv_cmd(f"maigret {target} -a --no-color --timeout 60 2>/dev/null")
    return jobs
