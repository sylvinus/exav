"""Shared helpers for the MalwareBazaar corpus fetchers.

Reproducibility contract:
  * The MalwareBazaar Auth-Key is read from $MALWAREBAZAAR_API_KEY (preferred —
    matches .env.local and fuzz/fetch_mb_corpus.sh) or the legacy $MB_KEY, after
    loading a gitignored .env.local at the repo root if present. The key is NEVER
    hard-coded or committed. Get one at https://bazaar.abuse.ch/account/.
  * Samples are written under the gitignored corpus/ dir (LIVE MALWARE), never
    next to these scripts.
  * Each sample's full MalwareBazaar metadata (the `get_info` record — family
    `signature`, tags, `intelligence.clamav`, `yara_rules`, vendor verdicts, …)
    is saved as a sibling `<sha>.json` so the corpus is self-describing: a
    differential run can look up what each "clean" miss actually is.
"""
import json
import os
import sys
import time
import urllib.request

API = "https://mb-api.abuse.ch/api/v1/"

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


def mb_post(fields, key=None, retries=3, timeout=90):
    """POST to the MalwareBazaar API and return the raw response bytes. Retries
    transient network/HTTP errors with a short backoff."""
    key = key or mb_key()
    data = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(API, data=data, headers={"Auth-Key": key})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (attempt + 1))
    raise last


def get_info(sha256, key=None):
    """Return the MalwareBazaar `get_info` metadata record (a dict) for a sample,
    or None if the hash is unknown / the query failed. This is the full record —
    family `signature`, tags, `intelligence.clamav`, `yara_rules`, `vendor_intel`,
    `delivery_method`, hashes, etc."""
    raw = mb_post({"query": "get_info", "hash": sha256}, key)
    j = json.loads(raw)
    if j.get("query_status") != "ok":
        return None
    data = j.get("data") or []
    return data[0] if data else None


def meta_path_for(sample_path):
    """The sibling metadata path for a `<sha>.bin` sample: `<sha>.json`."""
    return os.path.splitext(sample_path)[0] + ".json"


def save_info(sample_path, key=None):
    """Fetch and write `<sha>.json` next to a `<sha>.bin` sample. Returns the
    record on success, None if unavailable. No-op if the sha can't be derived."""
    sha = os.path.splitext(os.path.basename(sample_path))[0]
    if len(sha) != 64:
        return None
    info = get_info(sha, key)
    if info is None:
        return None
    with open(meta_path_for(sample_path), "w") as f:
        json.dump(info, f, indent=2, sort_keys=True)
    return info
