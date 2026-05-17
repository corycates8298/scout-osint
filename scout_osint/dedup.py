"""Result deduplication and cross-tool correlation."""
import re
from urllib.parse import urlparse


def normalize_url(url):
    """Normalize a URL for dedup (strip trailing slashes, www, scheme)."""
    url = url.rstrip("/")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host = host.lstrip("www.")
    path = parsed.path.rstrip("/")
    return f"{host}{path}".lower()


def extract_platform(url):
    """Extract platform name from URL."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lstrip("www.")
    # Strip TLD
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[0]
    return host


def deduplicate_findings(findings):
    """
    Deduplicate findings across tools.
    Returns findings with unique entries only, plus a correlation map.
    """
    seen_urls = {}  # normalized_url → {url, platforms, tools}
    deduped_accounts = []

    for url in findings.get("accounts_found", []):
        norm = normalize_url(url)
        if norm not in seen_urls:
            seen_urls[norm] = {
                "url": url,
                "platform": extract_platform(url),
            }
            deduped_accounts.append(url)

    # Deduplicate emails (case-insensitive)
    seen_emails = {}
    deduped_emails = []
    for email in findings.get("emails_found", []):
        lower = email.lower()
        if lower not in seen_emails:
            seen_emails[lower] = email
            deduped_emails.append(email)

    # Deduplicate IPs
    seen_ips = set()
    deduped_ips = []
    for ip in findings.get("ips_found", []):
        if ip not in seen_ips:
            seen_ips.add(ip)
            deduped_ips.append(ip)

    return {
        "accounts_found": deduped_accounts,
        "emails_found": deduped_emails,
        "ips_found": deduped_ips,
        "platforms": list(set(v["platform"] for v in seen_urls.values())),
        "stats": {
            "accounts_raw": len(findings.get("accounts_found", [])),
            "accounts_deduped": len(deduped_accounts),
            "emails_raw": len(findings.get("emails_found", [])),
            "emails_deduped": len(deduped_emails),
            "ips_raw": len(findings.get("ips_found", [])),
            "ips_deduped": len(deduped_ips),
        },
    }
