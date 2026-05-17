#!/usr/bin/env python3
"""Test suite for Scout OSINT v3.0."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "\033[92m+\033[0m"
FAIL = "\033[91mx\033[0m"
results = []


def test(name, condition):
    status = PASS if condition else FAIL
    results.append((name, condition))
    print(f"  {status} {name}")
    if not condition:
        import traceback
        traceback.print_exc()


def run_tests():
    print("\n  =============================================")
    print("  Scout OSINT v3.0 — Test Suite")
    print("  =============================================\n")

    # ── Detectors ──────────────────────────────────────
    print("  -- Detectors --")
    from scout_osint.detectors import detect_type

    test("Email detected", detect_type("user@gmail.com") == "email")
    test("Domain detected", detect_type("example.com") == "domain")
    test("IP detected", detect_type("8.8.8.8") == "ip")
    test("Phone detected", detect_type("+1-555-0123") == "phone")
    test("Username detected (single word)", detect_type("johndoe") == "username")
    test("Person detected (two names)", detect_type("John Doe") == "person")
    test("Person detected (first name match)", detect_type("Cory Cates") == "person")
    test("Company detected (suffix)", detect_type("Acme Corp") == "company")
    test("Company detected (keyword 'soap')", detect_type("Buff City Soap") == "company")
    test("Company detected (keyword 'tech')", detect_type("Global Tech") == "company")
    test("Company detected (3+ words no name)", detect_type("Red Bull Racing") == "company")
    test("Person not company (Yamalia Cates)", detect_type("Yamalia Cates") == "person")
    test("Company detected (LLC)", detect_type("Truvera Solutions LLC") == "company")

    # ── Sanitization ───────────────────────────────────
    print("\n  -- Sanitization --")
    from scout_osint.sanitize import sanitize_target, shell_quote

    test("Clean target passes", sanitize_target("user@gmail.com") == "user@gmail.com")
    test("Domain passes", sanitize_target("example.com") == "example.com")
    test("Person name passes", sanitize_target("John Doe") == "John Doe")

    # Dangerous inputs
    try:
        sanitize_target("user; rm -rf /")
        test("Semicolon blocked", False)
    except ValueError:
        test("Semicolon blocked", True)

    try:
        sanitize_target("user | cat /etc/passwd")
        test("Pipe blocked", False)
    except ValueError:
        test("Pipe blocked", True)

    try:
        sanitize_target("user$(whoami)")
        test("Command substitution blocked", False)
    except ValueError:
        test("Command substitution blocked", True)

    try:
        sanitize_target("user`id`")
        test("Backtick blocked", False)
    except ValueError:
        test("Backtick blocked", True)

    test("Shell quote wraps in single quotes", shell_quote("test") == "'test'")
    test("Shell quote escapes inner quotes", "\\'" in shell_quote("it's"))

    # ── Dedup ──────────────────────────────────────────
    print("\n  -- Deduplication --")
    from scout_osint.dedup import deduplicate_findings, normalize_url

    test("URL normalization strips trailing slash",
         normalize_url("https://github.com/user/") == normalize_url("https://github.com/user"))
    test("URL normalization strips www",
         normalize_url("https://www.github.com/user") == normalize_url("https://github.com/user"))

    findings = {
        "accounts_found": [
            "https://github.com/user",
            "https://www.github.com/user/",
            "https://twitter.com/user",
            "https://twitter.com/user",
        ],
        "emails_found": ["a@b.com", "A@B.COM", "c@d.com"],
        "ips_found": ["1.1.1.1", "1.1.1.1", "8.8.8.8"],
    }
    deduped = deduplicate_findings(findings)
    test("Accounts deduped (4 raw -> 2 unique)", deduped["stats"]["accounts_deduped"] == 2)
    test("Emails deduped (case insensitive)", deduped["stats"]["emails_deduped"] == 2)
    test("IPs deduped", deduped["stats"]["ips_deduped"] == 2)
    test("Platforms extracted", set(deduped["platforms"]) == {"github", "twitter"})

    # ── History/Diff ───────────────────────────────────
    print("\n  -- Scan Diffing --")
    from scout_osint.history import diff_scans

    old = {"results": [{"output": "[+] Found: https://github.com/user\n[+] Found: https://twitter.com/user"}]}
    new = {"results": [{"output": "[+] Found: https://github.com/user\n[+] Found: https://linkedin.com/in/user"}]}
    diff = diff_scans(old, new)
    test("Diff finds added account", "linkedin.com/in/user" in str(diff["added"]))
    test("Diff finds removed account", "twitter.com/user" in str(diff["removed"]))
    test("Diff counts unchanged", diff["unchanged_count"] == 1)
    test("Diff handles None old scan", diff_scans(None, new) is None)

    # ── API Keys ───────────────────────────────────────
    print("\n  -- API Keys --")
    from scout_osint.keys import configured_keys, has_key

    test("configured_keys returns list", isinstance(configured_keys(), list))
    test("has_key returns bool", isinstance(has_key("shodan"), bool))

    # ── Reporting ──────────────────────────────────────
    print("\n  -- Reporting --")
    from scout_osint.reporting import extract_findings

    test_results = [
        {"output": "[+] Found: https://github.com/test\nEmail: user@test.com\nIP: 10.0.0.1"},
        {"output": "No results"},
    ]
    findings = extract_findings(test_results)
    test("Extracts accounts from [+] lines", len(findings["accounts_found"]) >= 1)
    test("Extracts emails", "user@test.com" in findings["emails_found"])
    test("Extracts IPs", "10.0.0.1" in findings["ips_found"])

    # ── Tool Modules ───────────────────────────────────
    print("\n  -- Tool Modules --")
    from scout_osint.tools import username, email, domain, ip, phone, file, person, company

    dummy_venv = lambda cmd: f"bash -c '{cmd}'"

    jobs = username.get_jobs("testuser", venv_cmd=dummy_venv)
    test("Username module returns jobs", len(jobs) >= 3)
    test("Username has Sherlock", "Sherlock" in jobs)

    jobs = email.get_jobs("test@test.com", venv_cmd=dummy_venv)
    test("Email module returns jobs", len(jobs) >= 5)
    test("Email has Holehe", "Holehe" in jobs)

    jobs = domain.get_jobs("example.com", venv_cmd=dummy_venv)
    test("Domain module returns jobs", len(jobs) >= 6)

    jobs = ip.get_jobs("1.1.1.1", venv_cmd=dummy_venv)
    test("IP module returns jobs", len(jobs) >= 4)

    jobs = phone.get_jobs("+15550123", venv_cmd=dummy_venv)
    test("Phone module returns jobs", len(jobs) >= 3)

    jobs = file.get_jobs("/tmp/test.txt", venv_cmd=dummy_venv)
    test("File module returns jobs", len(jobs) >= 3)

    jobs = person.get_jobs("John Doe", venv_cmd=dummy_venv)
    test("Person module returns jobs", len(jobs) >= 5)

    jobs, domains = company.get_jobs("Buff City Soap", venv_cmd=dummy_venv)
    test("Company module returns jobs", len(jobs) >= 6)
    test("Company guesses multiple TLDs", len(domains) >= 5)
    test("Company includes .com", "buffcitysoap.com" in domains)
    test("Company includes .io", "buffcitysoap.io" in domains)

    # ── Full mode adds tools ───────────────────────────
    print("\n  -- Full Mode --")
    jobs_std = username.get_jobs("test", venv_cmd=dummy_venv)
    jobs_full = username.get_jobs("test", full=True, venv_cmd=dummy_venv)
    test("Full mode adds more tools", len(jobs_full) > len(jobs_std))

    jobs_std = domain.get_jobs("test.com", venv_cmd=dummy_venv)
    jobs_full = domain.get_jobs("test.com", full=True, venv_cmd=dummy_venv)
    test("Domain full adds Nmap", any("Nmap" in k for k in jobs_full))

    # ── Stealth mode removes tools ─────────────────────
    print("\n  -- Stealth Mode --")
    jobs_std = domain.get_jobs("test.com", venv_cmd=dummy_venv)
    jobs_stealth = domain.get_jobs("test.com", stealth=True, venv_cmd=dummy_venv)
    test("Stealth removes SSL Cert", "SSL Cert" not in jobs_stealth)
    test("Stealth removes HTTP Headers", "HTTP Headers" not in jobs_stealth)

    jobs_std = ip.get_jobs("1.1.1.1", venv_cmd=dummy_venv)
    jobs_stealth = ip.get_jobs("1.1.1.1", stealth=True, venv_cmd=dummy_venv)
    test("Stealth removes Nmap from IP", all("Nmap" not in k for k in jobs_stealth))

    # ── Summary ────────────────────────────────────────
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n  =============================================")
    pct = passed / total * 100
    color = "\033[92m" if pct == 100 else "\033[93m" if pct >= 80 else "\033[91m"
    print(f"  {color}Results: {passed}/{total} passed ({pct:.0f}%)\033[0m")
    print(f"  =============================================\n")

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
