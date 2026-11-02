#!/usr/bin/env python3
"""Dependency review report: the facts a release's dependency pass decides on.

    scripts/deps-review.py                 # every workspace, crates.io queried
    scripts/deps-review.py --offline       # only what the lock files say
    scripts/deps-review.py --only viewer   # one workspace
    scripts/deps-review.py --refresh       # ignore the crates.io cache

The process around it, and what each flag means, is in docs/DEPENDENCIES.md
("Lifecycle"). The hand-kept inputs are docs/dependencies.toml (vendored code,
pins, patches). Output is Markdown on stdout; nothing in the tree is changed.
Needs cargo, and network access for crates.io, GitHub and PyPI unless
--offline.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs" / "dependencies.toml"
CACHE = ROOT / "target" / "deps-review-cache.json"
UA = "exav-deps-review (https://github.com/sylvinus/exav)"

# The Cargo workspaces, each with its own lock file, and the target whose
# build is the one that ships ("host" is the machine running this).
WORKSPACES = {
    "root": ("Cargo.toml", "host"),
    "fuzz": ("fuzz/Cargo.toml", "host"),
    "unpack-wasm": ("crates/exav-unpack-wasm/Cargo.toml", "wasm32-unknown-unknown"),
    "viewer": ("crates/exav-viewer/Cargo.toml", "wasm32-unknown-unknown"),
}

# A crate whose newest release is older than this is reported as stale.
STALE_DAYS = 730
# Shipped crates with at least this many `unsafe` keywords are listed.
UNSAFE_LIST_MIN = 1
UNSAFE_TOP = 30

NOW = datetime.now(timezone.utc)


def sh(args, cwd=ROOT):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"{' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def host_triple():
    for line in sh(["rustc", "-vV"]).splitlines():
        if line.startswith("host:"):
            return line.split()[1]
    sys.exit("rustc -vV: no host line")


def metadata(manifest, features, platform):
    """`features` is True (all), False (default) or a list of features alone."""
    args = ["cargo", "metadata", "--format-version", "1", "--locked", "--manifest-path", manifest,
            "--filter-platform", host_triple() if platform == "host" else platform]
    if features is True:
        args.append("--all-features")
    elif features:
        args += ["--no-default-features", "--features", ",".join(features)]
    return json.loads(sh(args))


# ---------------------------------------------------------------- graph


class Graph:
    """The resolved packages of one workspace, split by how they are reached."""

    def __init__(self, manifest, features, platform):
        m = metadata(manifest, features, platform)
        self.pkgs = {p["id"]: p for p in m["packages"]}
        self.members = set(m["workspace_members"])
        self.edges = {}  # id -> [(dep id, kinds)]
        for n in m["resolve"]["nodes"]:
            out = []
            for d in n["deps"]:
                kinds = {k["kind"] for k in d["dep_kinds"]}
                out.append((d["pkg"], kinds))
            self.edges[n["id"]] = out
        # A proc-macro crate runs in the compiler: it and what it pulls in are
        # not in the binary, so the "normal" set stops at it.
        self.macros = {
            i for i, p in self.pkgs.items() if any("proc-macro" in t["kind"] for t in p["targets"])
        }
        # normal: what the binary links; build: what also runs at build time
        # (build scripts, proc macros); any: all of it, dev-dependencies too.
        self.normal = self._reach({None}, stop=self.macros) - self.macros
        self.build = self._reach({None, "build"})
        self.any = self._reach({None, "build", "dev"})
        self.parents = {}
        for a, deps in self.edges.items():
            for b, kinds in deps:
                if kinds & {None, "build"}:
                    self.parents.setdefault(b, set()).add(a)

    def _reach(self, kinds, stop=frozenset()):
        seen = set(self.members)
        todo = list(self.members)
        while todo:
            a = todo.pop()
            if a in stop:
                continue
            for b, ks in self.edges.get(a, []):
                if ks & kinds and b not in seen:
                    seen.add(b)
                    todo.append(b)
        return seen

    def alone(self, name):
        """The shipped crates that leave the tree if the members stop depending
        on `name` (it stays if something else in the tree needs it)."""
        seen = set(self.members)
        todo = list(self.members)
        while todo:
            a = todo.pop()
            if a in self.macros:
                continue
            for b, ks in self.edges.get(a, []):
                if None in ks and b not in seen and not (a in self.members and self.pkgs[b]["name"] == name):
                    seen.add(b)
                    todo.append(b)
        return (self.normal - seen) - self.macros

    def external(self, ids):
        return [self.pkgs[i] for i in ids if i not in self.members and self.pkgs[i]["source"]]

    def local(self, ids):
        """Path packages outside the workspace (vendored patches)."""
        return [self.pkgs[i] for i in ids if i not in self.members and not self.pkgs[i]["source"]]

    def role(self, pid):
        if pid in self.normal:
            return "shipped"
        if pid in self.build:
            return "build"
        return "dev"

    def pulled_by(self, pid):
        names = sorted({self.pkgs[p]["name"] for p in self.parents.get(pid, ())})
        return names


# ---------------------------------------------------------------- unsafe

_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_LINE = re.compile(r"//.*$", re.M)
_UNSAFE = re.compile(r"\bunsafe\b")
_FORBID = re.compile(r"#!\[(?:forbid|deny)\(\s*unsafe_code\s*\)\]")
_GATED = re.compile(r"#!\[cfg_attr\(([^\]]*?),\s*(?:forbid|deny)\(\s*unsafe_code\s*\)\s*\)\]", re.S)


def unsafe_uses(pkg):
    """(count of the `unsafe` keyword in src/ with comments stripped, how it is forbidden).

    The second is "", "forbid", or "forbid when <cfg>" for a crate that forbids
    it only under a condition (its SIMD feature off): then the count is code
    that may not be compiled in.
    """
    src = Path(pkg["manifest_path"]).parent / "src"
    n, note = 0, ""
    if not src.is_dir():
        return 0, ""
    for f in src.rglob("*.rs"):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        text = _LINE.sub("", _BLOCK.sub("", text))
        n += len(_UNSAFE.findall(text))
        if f.name in ("lib.rs", "main.rs"):
            if _FORBID.search(text):
                note = "forbid"
            elif not note and (g := _GATED.search(text)):
                note = "forbid when " + " ".join(g.group(1).split())
    return n, note


# ---------------------------------------------------------------- registries


class Net:
    def __init__(self, offline, refresh):
        self.offline = offline
        self.cache = {}
        if CACHE.exists() and not refresh:
            try:
                self.cache = json.loads(CACHE.read_text())
            except ValueError:
                self.cache = {}
        self.last = 0.0
        self.dirty = False

    def get(self, url):
        c = self.cache.get(url)
        if c and time.time() - c["at"] < 86400:
            return c["body"]
        if self.offline:
            return c["body"] if c else None
        wait = 1.1 - (time.time() - self.last)  # crates.io asks for 1 request a second
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.load(r)
        except (urllib.error.URLError, ValueError, TimeoutError) as e:
            print(f"<!-- {url}: {e} -->", file=sys.stderr)
            return c["body"] if c else None
        self.cache[url] = {"at": time.time(), "body": body}
        self.dirty = True
        return body

    def save(self):
        if self.dirty:
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            CACHE.write_text(json.dumps(self.cache))

    def crate(self, name):
        return self.get(f"https://crates.io/api/v1/crates/{name}")


def vkey(v):
    """Sort key of a version string; pre-releases sort below their release."""
    core, _, pre = v.partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in core.split("+")[0].split(".")]
    return (nums + [0, 0, 0])[:3], pre == "", pre


def breaking(a, b):
    """True when moving from a to b is a semver-breaking change."""
    x, y = vkey(a)[0], vkey(b)[0]
    if x[0] != y[0]:
        return True
    if x[0] == 0:
        return x[1] != y[1] or (x[1] == 0 and x[2] != y[2])
    return False


def parse_date(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def crate_facts(net, name, version):
    """What crates.io says about a resolved crate, or None."""
    d = net.crate(name)
    if not d or "versions" not in d:
        return None
    vs = d["versions"]
    stable = [v for v in vs if not v["yanked"] and "-" not in v["num"]]
    latest = max(stable, key=lambda v: vkey(v["num"]), default=None)
    mine = next((v for v in vs if v["num"] == version), None)
    year_ago = NOW.timestamp() - 365 * 86400
    return {
        "latest": latest["num"] if latest else None,
        "latest_date": parse_date(latest["created_at"]) if latest else None,
        "latest_msrv": latest.get("rust_version") if latest else None,
        "yanked": bool(mine and mine["yanked"]),
        "date": parse_date(mine["created_at"]) if mine else None,
        "releases_year": sum(1 for v in vs if parse_date(v["created_at"]).timestamp() > year_ago),
        "repository": d["crate"].get("repository"),
    }


def member_text(crate_dir):
    """Every Rust source of a workspace member, to look names up in."""
    parts = []
    for f in crate_dir.rglob("*.rs"):
        if "target" in f.relative_to(crate_dir).parts or "node_modules" in f.parts:
            continue
        try:
            parts.append(f.read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(parts)


def msrv_of(manifest):
    t = tomllib.loads((ROOT / manifest).read_text())
    return t.get("workspace", {}).get("package", {}).get("rust-version")


def newer_msrv(req, have):
    if not req or not have:
        return False
    return vkey(req)[0] > vkey(have)[0]


# ---------------------------------------------------------------- register


def load_register():
    if not REGISTER.exists():
        sys.exit(f"{REGISTER.relative_to(ROOT)} is missing")
    return tomllib.loads(REGISTER.read_text())


def upstream_latest(net, entry):
    """The newest upstream release of a vendored source, as text."""
    kind = entry.get("track", "none")
    ref = entry.get("upstream", "")
    if kind == "crates":
        d = net.crate(ref)
        if d and "crate" in d:
            c = d["crate"]
            return f"{c['max_stable_version']} ({c['updated_at'][:10]})"
    elif kind == "github":
        d = net.get(f"https://api.github.com/repos/{ref}/releases/latest")
        if d and d.get("tag_name"):
            return f"{d['tag_name']} ({d['published_at'][:10]})"
        d = net.get(f"https://api.github.com/repos/{ref}/tags?per_page=1")
        if isinstance(d, list) and d:
            return d[0]["name"]
    elif kind == "pypi":
        d = net.get(f"https://pypi.org/pypi/{ref}/json")
        if d and "info" in d:
            return d["info"]["version"]
    return None


def declared_pins(manifests):
    """Every `=` requirement in a manifest: {(crate): {manifests}}."""
    pins = {}
    for path in manifests:
        t = tomllib.loads(path.read_text())
        tables = [t.get("dependencies", {}), t.get("dev-dependencies", {}), t.get("build-dependencies", {})]
        tables.append(t.get("workspace", {}).get("dependencies", {}))
        for tgt in t.get("target", {}).values():
            tables += [tgt.get("dependencies", {}), tgt.get("dev-dependencies", {})]
        for tab in tables:
            for key, spec in tab.items():
                req = spec if isinstance(spec, str) else spec.get("version", "")
                if isinstance(req, str) and req.startswith("="):
                    name = spec.get("package", key) if isinstance(spec, dict) else key
                    pins.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return pins


def manifest_files():
    out = []
    for p in ROOT.rglob("Cargo.toml"):
        rel = p.relative_to(ROOT).parts
        if rel[0] in ("target", "node_modules", "tmp", "corpus") or "node_modules" in rel or "target" in rel:
            continue
        if "vendor" in rel or "scripts" in rel:
            continue
        out.append(p)
    return out


def patches(manifests):
    found = {}
    for path in manifests:
        t = tomllib.loads(path.read_text())
        for reg, tab in t.get("patch", {}).items():
            for name, spec in tab.items():
                found.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return found


# ---------------------------------------------------------------- report


def table(head, rows):
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def age(d):
    if not d:
        return "?"
    days = (NOW - d).days
    return f"{days / 365:.1f}y" if days >= 365 else f"{days}d"


def report_register(net, reg):
    print("## Register\n")
    manifests = manifest_files()
    pins = declared_pins(manifests)
    registered = {p["crate"]: p for p in reg.get("pin", [])}
    rows = []
    for name in sorted(set(pins) | set(registered)):
        where = ", ".join(sorted(pins.get(name, ()))) or "-"
        if name not in registered:
            status = "**no register entry**"
        elif name not in pins:
            status = "**pin gone from the manifests**"
        else:
            status = "ok"
        rows.append((f"`{name}`", where, status))
    print("### Pins (`=` requirements)\n")
    print(table(["crate", "manifests", "register"], [r for r in rows if r[2] != "ok"] or [("all pins are in the register", "", "")]))

    print("### Patches (`[patch]`)\n")
    found = patches(manifests)
    reg_patch = {p["crate"] for p in reg.get("patch", [])}
    rows = []
    for name in sorted(set(found) | reg_patch):
        rows.append((f"`{name}`", ", ".join(sorted(found.get(name, ()))) or "-",
                     "ok" if name in found and name in reg_patch else "**mismatch with the register**"))
    print(table(["crate", "manifests", "register"], rows))

    print("### Vendored code against its upstream\n")
    rows = []
    for v in reg.get("vendored", []):
        up = upstream_latest(net, v) if v.get("track", "none") != "none" else None
        ours = v.get("version", "unrecorded")
        flag = ""
        if not Path(ROOT / v["path"]).exists():
            flag = "**path is gone**"
        elif ours == "unrecorded":
            flag = "record the upstream version"
        elif up and not up.lstrip("v").startswith(ours):
            flag = "upstream moved"
        rows.append((f"`{v['path']}`", v["upstream"], ours, up or "not tracked", v["kind"], flag))
    print(table(["where", "upstream", "vendored", "upstream now", "kind", "flag"], rows))


def report_workspace(name, manifest, platform, net):
    print(f"## Workspace `{name}`\n")
    msrv = msrv_of("Cargo.toml")
    g_def = Graph(manifest, False, platform)
    g_all = Graph(manifest, True, platform)
    ext_all = g_all.external(g_all.any)
    if manifest == "Cargo.toml":
        # What `cargo build -p exav` links: the members' features do not unify.
        out = sh(["cargo", "tree", "--locked", "-p", "exav", "-e", "normal", "--prefix", "none",
                  "--format", "{p}", "--target", host_triple() if platform == "host" else platform])
        linked = {tuple(l.split()[:2]) for l in out.splitlines() if l.strip()}
        default_ids = {i for i in g_all.normal if i not in g_all.members
                       and (g_all.pkgs[i]["name"], "v" + g_all.pkgs[i]["version"]) in linked}
    elif name == "viewer":
        # One wasm module per feature: what ships is their union, and each
        # module carries only its own crates.
        features = [f for f in tomllib.loads((ROOT / manifest).read_text())["features"] if f != "default"]
        per_module, union = [], set()
        for f in features:
            g = Graph(manifest, [f], platform)
            keys = {(p["name"], p["version"]) for p in g.external(g.normal)}
            per_module.append((f, keys))
            union |= keys
        default_ids = {i for i in g_all.normal if i not in g_all.members
                       and (g_all.pkgs[i]["name"], g_all.pkgs[i]["version"]) in union}
    else:
        default_ids = {p["id"] for p in g_def.external(g_def.normal)}

    declared = {}
    for mid in g_all.members:
        mp = g_all.pkgs[mid]
        for d in mp["dependencies"]:
            if d["source"] and d["source"].startswith("registry"):
                declared.setdefault(d["name"], set()).add((mp["name"], d["req"], d["kind"] or "normal", d["optional"]))

    facts = {p["id"]: crate_facts(net, p["name"], p["version"]) for p in ext_all}
    unsafe = {p["id"]: unsafe_uses(p) for p in ext_all + g_all.local(g_all.any)}

    role_n = {"shipped": 0, "build": 0, "dev": 0}
    for p in ext_all:
        role_n[g_all.role(p["id"])] += 1
    default_unsafe = sum(unsafe[i][0] for i in default_ids)
    all_unsafe = sum(unsafe[p["id"]][0] for p in ext_all if g_all.role(p["id"]) == "shipped")
    print(f"- {len(ext_all)} external crates with every feature on: "
          f"{role_n['shipped']} shipped, {role_n['build']} build-time only, {role_n['dev']} dev only.")
    shipped_names = {}
    for p in ext_all:
        if g_all.role(p["id"]) == "shipped":
            shipped_names.setdefault(p["name"], []).append(p["version"])
    twice = sum(1 for v in shipped_names.values() if len(v) > 1)
    print(f"- Shipped for `{platform}` with default features: {len(default_ids)} crates, "
          f"{default_unsafe} `unsafe` keywords in them; every feature on: "
          f"{sum(len(v) for v in shipped_names.values())} crates, {all_unsafe}; "
          f"{twice} crates at two versions.")
    local = [p for p in g_all.local(g_all.any) if "/vendor/" in p["manifest_path"]]
    if local:
        print("- Patched in from the tree: " + ", ".join(f"`{p['name']} {p['version']}`" for p in local) + ".")
    print()
    if name == "viewer":
        by_key = {(p["name"], p["version"]): unsafe[p["id"]][0] for p in ext_all}
        print("### Per wasm module\n")
        print(table(["module", "crates", "unsafe"],
                    [(f"`{f}`", len(k), sum(by_key.get(x, 0) for x in k)) for f, k in per_module]))

    # The name a crate is used by is its library target's, not its package's.
    lib_name = {}
    for p in g_all.pkgs.values():
        for t in p["targets"]:
            if "lib" in t["kind"] or "proc-macro" in t["kind"]:
                lib_name.setdefault(p["name"], t["name"])
    unused = []
    for mid in sorted(g_all.members):
        mp = g_all.pkgs[mid]
        text = member_text(Path(mp["manifest_path"]).parent)
        for d in mp["dependencies"]:
            if not (d["source"] and d["source"].startswith("registry")):
                continue
            ident = (d.get("rename") or lib_name.get(d["name"], d["name"])).replace("-", "_")
            if not re.search(rf"\b{re.escape(ident)}\b", text):
                unused.append((f"`{d['name']}`", mp["name"], d["kind"] or "normal"))
    print("### Declared and never named in the crate's sources\n")
    print("A crate used only through a feature of another (`getrandom` for its `js` feature) is a false positive; read the manifest.\n")
    print(table(["crate", "declared by", "kind"], unused))

    # ---- findings
    flags = []
    names = {}
    for p in ext_all:
        names.setdefault(p["name"], []).append(p["version"])
    for p in sorted(ext_all, key=lambda p: (p["name"], p["version"])):
        f = facts[p["id"]]
        u, forbid = unsafe[p["id"]]
        role = g_all.role(p["id"])
        fl = []
        if f:
            if f["yanked"]:
                fl.append("**YANKED**")
            if f["latest"] and vkey(f["latest"]) > vkey(p["version"]):
                kind = "breaking" if breaking(p["version"], f["latest"]) else "compatible"
                note = f"{kind} update to {f['latest']} ({age(f['latest_date'])} ago)"
                if newer_msrv(f["latest_msrv"], msrv):
                    note += f", needs Rust {f['latest_msrv']}"
                fl.append(note)
            if f["latest_date"] and (NOW - f["latest_date"]).days > STALE_DAYS:
                fl.append(f"stale: last release {age(f['latest_date'])} ago")
        if len(names[p["name"]]) > 1:
            fl.append("also at " + ", ".join(v for v in sorted(names[p["name"]]) if v != p["version"]))
        if fl:
            flags.append((f"`{p['name']}`", p["version"], role, ", ".join(fl)))
    print("### Findings\n")
    print(table(["crate", "locked", "role", "flags"], flags))

    print("### Direct dependencies\n")
    rows = []
    for dep in sorted(declared):
        for pid in (p["id"] for p in ext_all if p["name"] == dep):
            p = g_all.pkgs[pid]
            f = facts[pid]
            u, forbid = unsafe[pid]
            users = sorted({f"{m}{' (opt)' if o else ''}{'' if k == 'normal' else ' [' + k + ']'}"
                            for m, r, k, o in declared[dep]})
            reqs = sorted({r for m, r, k, o in declared[dep]})
            alone = g_all.alone(dep) if pid in g_all.normal else set()
            alone_unsafe = sum(unsafe[i][0] for i in alone if i in unsafe)
            rows.append((f"`{dep}`", ", ".join(f"`{r}`" for r in reqs), p["version"],
                         f["latest"] if f else "?", age(f["date"]) if f else "?",
                         f"{f['releases_year']}" if f else "?",
                         f"none ({forbid})" if forbid and not u else (f"{u} ({forbid})" if forbid else (u or "none")),
                         f"{len(alone)} / {alone_unsafe}" if alone else "-",
                         p["license"] or "?", "; ".join(users)))
    print("`alone`: crates that leave the shipped tree with it, and the `unsafe` in them.\n")
    print(table(["crate", "req", "locked", "latest", "age", "rel/yr", "unsafe", "alone", "license", "declared by"], rows))

    stats = {"crates": len(default_ids), "unsafe": default_unsafe,
             "crates_all": sum(len(v) for v in shipped_names.values()), "unsafe_all": all_unsafe,
             "twice": twice}

    print("### Most `unsafe` in the shipped tree\n")
    top = sorted(((unsafe[p["id"]][0], p) for p in ext_all if g_all.role(p["id"]) == "shipped"),
                 key=lambda t: -t[0])
    rows = []
    for u, p in top[:UNSAFE_TOP]:
        if u < UNSAFE_LIST_MIN:
            break
        note = unsafe[p["id"]][1]
        rows.append((f"`{p['name']}`", p["version"], f"{u} ({note})" if note else u,
                     "default" if p["id"] in default_ids else "feature",
                     ", ".join(g_all.pulled_by(p["id"])[:6])))
    print(table(["crate", "version", "unsafe", "in", "pulled in by"], rows))
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="use the cache and the lock files only")
    ap.add_argument("--refresh", action="store_true", help="ignore cached crates.io answers")
    ap.add_argument("--only", choices=sorted(WORKSPACES) + ["register"], help="one workspace, or the register alone")
    args = ap.parse_args()

    net = Net(args.offline, args.refresh)
    reg = load_register()
    print(f"# Dependency review, {NOW:%Y-%m-%d}\n")
    last = {r["workspace"]: r for r in reg.get("review", [])}
    if args.only in (None, "register"):
        report_register(net, reg)
    records = []
    for name, (manifest, platform) in WORKSPACES.items():
        if args.only in (None, name):
            stats = report_workspace(name, manifest, platform, net)
            before = last.get(name)
            print("### Against the last review\n")
            if before:
                print(table(["", "last review (" + before["date"] + ")", "now"], [
                    (k, before.get(k, "?"), stats[k]) for k in stats]))
            else:
                print("_no `[[review]]` entry for this workspace yet_\n")
            records.append((name, stats))
    if records and args.only != "register":
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        print("## To record in docs/dependencies.toml at the end of the late pass\n")
        print("```toml")
        for name, stats in records:
            print(f'[[review]]\nworkspace = "{name}"\ndate = "{NOW:%Y-%m-%d}"\nrelease = "{version}"')
            for k, v in stats.items():
                print(f"{k} = {v}")
            print()
        print("```")
    net.save()


if __name__ == "__main__":
    main()
