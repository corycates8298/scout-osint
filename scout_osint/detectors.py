"""Target type auto-detection."""
import os
import re


def detect_type(target):
    """Auto-detect target type from input string."""
    if os.path.isfile(target):
        return "file"
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        return "email"
    if re.match(r'^\+?[\d\s\-().]{7,}$', target):
        return "phone"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target):
        return "domain"
    if " " in target and any(w[0].isupper() for w in target.split() if w):
        company_suffixes = ['inc', 'llc', 'corp', 'ltd', 'co', 'company', 'group', 'solutions', 'technologies']
        if any(target.lower().endswith(s) for s in company_suffixes):
            return "company"
        return "person"
    if " " in target:
        return "person"
    return "username"
