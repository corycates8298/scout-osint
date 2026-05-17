"""Person OSINT tools — generates username/email variants, multi-tool sweep."""
from ..sanitize import shell_quote


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    parts = target.lower().split()
    if len(parts) < 2:
        parts = [parts[0], ""]
    first, last = parts[0], parts[-1]

    usernames = list(set(filter(None, [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{last}{first}",
        f"{first}{last[0]}" if last else None,
    ])))

    primary = f"{first}{last}" if last else first
    safe_primary = shell_quote(primary)

    jobs = {
        "Sherlock": f"sherlock {safe_primary} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {safe_primary} --no-color --timeout 30 2>/dev/null"),
        "Socialscan (usernames)": f"socialscan {' '.join(shell_quote(u) for u in usernames)} 2>/dev/null",
        "Holehe (gmail)": venv_cmd(f"holehe {first}{last}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Holehe (yahoo)": venv_cmd(f"holehe {first}{last}@yahoo.com --no-color --no-clear 2>/dev/null"),
    }

    if full:
        alt = shell_quote(f"{first}_{last}")
        alt2 = shell_quote(f"{first[0]}{last}")
        jobs["Sherlock (alt)"] = f"sherlock {alt} --print-found --no-color 2>/dev/null"
        jobs["Maigret (alt)"] = venv_cmd(f"maigret {alt2} --no-color --timeout 30 2>/dev/null")
        jobs["Holehe (outlook)"] = venv_cmd(f"holehe {first}.{last}@outlook.com --no-color --no-clear 2>/dev/null")
        jobs["GHunt (gmail)"] = venv_cmd(f"ghunt email {first}{last}@gmail.com 2>/dev/null")
        jobs["CrossLinked (LinkedIn)"] = venv_cmd(f"crosslinked -f '{{{{first}}}} {{{{last}}}}' {shell_quote(f'{first} {last}')} 2>/dev/null")

    return jobs
