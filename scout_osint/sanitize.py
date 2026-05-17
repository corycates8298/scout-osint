"""Input sanitization — prevent shell injection in tool commands."""
import re


def sanitize_target(target):
    """
    Sanitize a target string for safe use in shell commands.
    Allows: alphanumeric, @, ., -, _, +, /, :, space
    Blocks: ;, |, &, $, `, (, ), {, }, <, >, !, ~, newlines
    """
    # Block dangerous shell metacharacters
    dangerous = re.compile(r'[;&|$`(){}<>!\n\r\\~]')
    if dangerous.search(target):
        raise ValueError(f"Target contains dangerous characters: {target!r}")
    # Additional check: no command substitution patterns
    if "$(" in target or "$()" in target:
        raise ValueError(f"Target contains command substitution: {target!r}")
    return target


def shell_quote(s):
    """
    Quote a string for safe use in shell commands.
    Uses single quotes with proper escaping.
    """
    return "'" + s.replace("'", "'\\''") + "'"


def sanitize_for_python_string(s):
    """Escape a string for safe use inside Python string literals in shell commands."""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')
