"""Target type auto-detection — smarter heuristics for person vs company."""
import os
import re

# Company indicators — words that strongly suggest a business entity
COMPANY_SUFFIXES = [
    'inc', 'llc', 'corp', 'ltd', 'co', 'company', 'group', 'solutions',
    'technologies', 'enterprises', 'associates', 'partners', 'consulting',
    'services', 'industries', 'international', 'global', 'holdings',
    'capital', 'ventures', 'labs', 'studio', 'studios', 'agency',
    'foundation', 'institute',
]

COMPANY_KEYWORDS = [
    'soap', 'tech', 'software', 'systems', 'media', 'digital', 'creative',
    'design', 'health', 'care', 'foods', 'pharma', 'auto', 'motors',
    'bank', 'financial', 'insurance', 'energy', 'power', 'electric',
    'construction', 'realty', 'property', 'logistics', 'transport',
    'retail', 'wholesale', 'supply', 'network', 'cloud', 'data',
    'analytics', 'ai', 'robotics', 'bio', 'medical', 'dental',
    'fitness', 'beauty', 'cosmetics', 'brewing', 'distilling',
    'coffee', 'pizza', 'burger', 'grill', 'kitchen', 'bakery',
]

# Common first names (top 200) — if a word matches, it's likely a person
COMMON_FIRST_NAMES = {
    'james', 'john', 'robert', 'michael', 'david', 'william', 'richard',
    'joseph', 'thomas', 'charles', 'christopher', 'daniel', 'matthew',
    'anthony', 'mark', 'donald', 'steven', 'andrew', 'paul', 'joshua',
    'mary', 'patricia', 'jennifer', 'linda', 'barbara', 'elizabeth',
    'susan', 'jessica', 'sarah', 'karen', 'lisa', 'nancy', 'betty',
    'margaret', 'sandra', 'ashley', 'emily', 'donna', 'michelle',
    'dorothy', 'carol', 'amanda', 'melissa', 'deborah', 'stephanie',
    'rebecca', 'sharon', 'laura', 'cynthia', 'kathleen', 'amy', 'angela',
    'shirley', 'anna', 'brenda', 'pamela', 'emma', 'nicole', 'helen',
    'samantha', 'katherine', 'christine', 'debra', 'rachel', 'carolyn',
    'janet', 'catherine', 'maria', 'heather', 'diane', 'ruth', 'julie',
    'olivia', 'joyce', 'virginia', 'victoria', 'kelly', 'lauren', 'christina',
    'joan', 'evelyn', 'judith', 'megan', 'andrea', 'cheryl', 'hannah',
    'jacqueline', 'martha', 'gloria', 'teresa', 'ann', 'sara', 'madison',
    'frances', 'kathryn', 'janice', 'jean', 'abigail', 'alice', 'judy',
    'sophia', 'grace', 'denise', 'amber', 'doris', 'marilyn', 'danielle',
    'beverly', 'isabella', 'theresa', 'diana', 'natalie', 'brittany',
    'charlotte', 'marie', 'kayla', 'alexis', 'lori', 'cory', 'yamalia',
    'brian', 'kevin', 'jason', 'jeffrey', 'ryan', 'jacob', 'gary',
    'nicholas', 'eric', 'jonathan', 'stephen', 'larry', 'justin',
    'scott', 'brandon', 'benjamin', 'samuel', 'raymond', 'gregory',
    'frank', 'alexander', 'patrick', 'jack', 'dennis', 'jerry', 'tyler',
    'aaron', 'jose', 'adam', 'nathan', 'henry', 'peter', 'zachary',
    'douglas', 'harold', 'kyle', 'noah', 'gerald', 'ethan', 'carl',
}


def detect_type(target):
    """
    Auto-detect target type from input string.
    Uses layered heuristics for accurate person vs company detection.
    """
    # File — check first (path could look like anything)
    if os.path.isfile(target):
        return "file"

    # Email — contains @ with domain
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
        return "email"

    # IP address — check BEFORE phone (dots match phone's char class)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"

    # Phone — digits with optional formatting
    if re.match(r'^\+?[\d\s\-().]{7,}$', target):
        return "phone"

    # Domain — word.tld pattern (no spaces)
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target):
        return "domain"

    # Multi-word: person or company?
    if " " in target:
        words = target.split()
        lower_words = [w.lower() for w in words]
        lower_target = target.lower()

        # Strong company signals
        # 1. Ends with a company suffix
        if any(lower_target.endswith(s) for s in COMPANY_SUFFIXES):
            return "company"
        # 2. Contains a company keyword anywhere
        if any(kw in lower_words for kw in COMPANY_KEYWORDS):
            return "company"
        # 3. Three or more words and NO common first name → likely company
        if len(words) >= 3 and lower_words[0] not in COMMON_FIRST_NAMES:
            return "company"

        # Strong person signals
        # 1. First word is a common first name
        if lower_words[0] in COMMON_FIRST_NAMES:
            return "person"
        # 2. Exactly two capitalized words (First Last pattern)
        if len(words) == 2 and all(w[0].isupper() for w in words if w):
            return "person"

        # Default for multi-word: person (safer assumption)
        return "person"

    # Single word without dots/@ = username
    return "username"
