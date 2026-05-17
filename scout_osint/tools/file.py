"""File OSINT tools — ExifTool, strings, hashes."""


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    jobs = {
        "ExifTool (full)": f"exiftool -G1 -s {target}",
        "ExifTool (JSON)": f"exiftool -json -G1 {target}",
        "File type": f"file -b {target}",
        "Strings (emails/URLs)": f"strings {target} 2>/dev/null | grep -iE '(https?://|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}})' | sort -u | head -30",
    }
    if full:
        jobs["Strings (secrets)"] = f"strings {target} 2>/dev/null | grep -iE '(password|secret|key|token|admin|root|user|login|api)' | sort -u | head -30"
        jobs["Hashes"] = f"echo 'MD5:' && md5 -q {target} 2>/dev/null; echo 'SHA1:' && shasum -a 1 {target} 2>/dev/null | cut -d' ' -f1; echo 'SHA256:' && shasum -a 256 {target} 2>/dev/null | cut -d' ' -f1"
        jobs["GPS coordinates"] = f"exiftool -gpslatitude -gpslongitude -gpsposition -n {target} 2>/dev/null"
    return jobs
