"""File OSINT tools — ExifTool, strings, hashes."""
from ..sanitize import shell_quote


def get_jobs(target, full=False, stealth=False, venv_cmd=None):
    safe = shell_quote(target)
    jobs = {
        "ExifTool (full)": f"exiftool -G1 -s {safe}",
        "ExifTool (JSON)": f"exiftool -json -G1 {safe}",
        "File type": f"file -b {safe}",
        "Strings (emails/URLs)": f"strings {safe} 2>/dev/null | grep -iE '(https?://|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}})' | sort -u | head -30",
    }
    if full:
        jobs["Strings (secrets)"] = f"strings {safe} 2>/dev/null | grep -iE '(password|secret|key|token|admin|root|user|login|api)' | sort -u | head -30"
        jobs["Hashes"] = f"echo 'MD5:' && md5 -q {safe} 2>/dev/null; echo 'SHA1:' && shasum -a 1 {safe} 2>/dev/null | cut -d' ' -f1; echo 'SHA256:' && shasum -a 256 {safe} 2>/dev/null | cut -d' ' -f1"
        jobs["GPS coordinates"] = f"exiftool -gpslatitude -gpslongitude -gpsposition -n {safe} 2>/dev/null"
    return jobs
