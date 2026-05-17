"""API key management — loads from ~/.scout-osint/keys.yaml or env vars."""
import os
from pathlib import Path

KEYS_FILE = Path.home() / ".scout-osint" / "keys.yaml"

_keys = None


def _load_keys():
    """Load API keys from config file."""
    global _keys
    if _keys is not None:
        return _keys

    _keys = {}

    # Try YAML config first
    if KEYS_FILE.exists():
        try:
            import yaml
            with open(KEYS_FILE) as f:
                _keys = yaml.safe_load(f) or {}
        except ImportError:
            # Parse simple key: value format without yaml
            with open(KEYS_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and ":" in line:
                        k, v = line.split(":", 1)
                        _keys[k.strip()] = v.strip().strip('"').strip("'")

    # Environment variables override config file
    env_map = {
        "shodan": "SHODAN_API_KEY",
        "censys_id": "CENSYS_API_ID",
        "censys_secret": "CENSYS_API_SECRET",
        "google": "GOOGLE_API_KEY",
        "hunter": "HUNTER_API_KEY",
        "virustotal": "VIRUSTOTAL_API_KEY",
    }
    for key_name, env_var in env_map.items():
        val = os.environ.get(env_var)
        if val:
            _keys[key_name] = val

    return _keys


def get_key(name):
    """Get an API key by name. Returns None if not configured."""
    keys = _load_keys()
    return keys.get(name)


def has_key(name):
    """Check if an API key is configured."""
    return get_key(name) is not None


def configured_keys():
    """Return list of configured key names."""
    keys = _load_keys()
    return [k for k, v in keys.items() if v]


def create_default_config():
    """Create a default keys.yaml template."""
    KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not KEYS_FILE.exists():
        KEYS_FILE.write_text("""# Scout OSINT API Keys
# Uncomment and fill in keys for enhanced results.

# shodan: YOUR_SHODAN_KEY
# censys_id: YOUR_CENSYS_API_ID
# censys_secret: YOUR_CENSYS_SECRET
# google: YOUR_GOOGLE_API_KEY
# hunter: YOUR_HUNTER_KEY
# virustotal: YOUR_VT_KEY
""")
        KEYS_FILE.chmod(0o600)
        return True
    return False
