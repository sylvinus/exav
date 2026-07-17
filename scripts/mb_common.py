"""Shared helpers for the MalwareBazaar corpus fetchers.

Reproducibility contract:
  * The MalwareBazaar Auth-Key is read from $MALWAREBAZAAR_API_KEY (preferred —
    matches .env.local and fuzz/fetch_mb_corpus.sh) or the legacy $MB_KEY, after
    loading a gitignored .env.local at the repo root if present. The key is NEVER
    hard-coded or committed. Get one at https://bazaar.abuse.ch/account/.
  * Samples are written under the gitignored corpus/ dir (LIVE MALWARE), never
    next to these scripts.
"""
import os
import sys

# repo root = parent of scripts/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_env_local():
    """Populate os.environ from a gitignored .env.local (KEY=VALUE lines)."""
    env = os.path.join(ROOT, ".env.local")
    if not os.path.exists(env):
        return
    for line in open(env):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def mb_key():
    """Return the MalwareBazaar Auth-Key, or exit with a clear message."""
    _load_env_local()
    key = os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("MB_KEY")
    if not key:
        sys.exit(
            "set MALWAREBAZAAR_API_KEY in .env.local or the environment "
            "(get a key at https://bazaar.abuse.ch/account/)"
        )
    return key


def corpus_dir(*parts):
    """Absolute path under the gitignored corpus/ data dir."""
    return os.path.join(ROOT, "corpus", *parts)
