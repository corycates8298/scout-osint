"""Person OSINT tools — generates username/email variants, multi-tool sweep."""


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
    jobs = {
        "Sherlock": f"sherlock {primary} --print-found --no-color 2>/dev/null",
        "Maigret": venv_cmd(f"maigret {primary} --no-color --timeout 30 2>/dev/null"),
        "Socialscan (usernames)": f"socialscan {' '.join(usernames)} 2>/dev/null",
        "Holehe (gmail)": venv_cmd(f"holehe {first}{last}@gmail.com --no-color --no-clear 2>/dev/null"),
        "Holehe (yahoo)": venv_cmd(f"holehe {first}{last}@yahoo.com --no-color --no-clear 2>/dev/null"),
    }

    if full:
        jobs["Sherlock (alt)"] = f"sherlock {first}_{last} --print-found --no-color 2>/dev/null"
        jobs["Maigret (alt)"] = venv_cmd(f"maigret {first[0]}{last} --no-color --timeout 30 2>/dev/null")
        jobs["Holehe (outlook)"] = venv_cmd(f"holehe {first}.{last}@outlook.com --no-color --no-clear 2>/dev/null")
        jobs["GHunt (gmail)"] = venv_cmd(f"ghunt email {first}{last}@gmail.com 2>/dev/null")
        jobs["CrossLinked (LinkedIn)"] = venv_cmd(f"crosslinked -f '{{{{first}}}} {{{{last}}}}' '{first} {last}' 2>/dev/null")

    return jobs
