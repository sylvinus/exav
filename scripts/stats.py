#!/usr/bin/env python3
"""The figures of the site's Stats page (www/src/data/stats/).

    python3 -I scripts/stats.py release 0.0.3   # writes 0.0.3.json
    python3 -I scripts/stats.py bench           # writes bench.json
    python3 -I scripts/stats.py candidate       # the new version against the releases
    python3 -I scripts/stats.py dataset         # writes scripts/stats-dataset.txt

`release` describes one release, once its tag, its GitHub release and its npm
packages are all published:
  - lines of Rust, blank lines and comments left out, in groups: the crates'
    code, their tests (tests/, benches/, fuzz/, `#[cfg(test)]` modules), the
    other programs (examples, tools), the vendored crates, and the crates the
    `exav` binary is built from (default features, x86_64 Linux, procedural
    macros left out); the tests of vendored and other crates are left out;
  - the `unsafe` keywords in each group;
  - for `exav` and `exav-unpack`, the third-party crates each is built from,
    the ones our crates name, their lines and their `unsafe` keywords;
  - every third-party crate of what is published (the workspace and the crates
    of both npm packages, for every system and feature), the third-party
    packages of Cargo.lock, the npm packages the viewer asks for;
  - the formats of formats/registry.json; a release older than the registry
    is counted from its code against the first registry;
  - `#[test]` functions, JavaScript tests, end-to-end tests, fuzz targets;
  - the size of each binary of the release and of each .wasm of its npm
    packages.

`bench` times the exav of every release against clamscan, on this machine,
over the files of scripts/stats-dataset.txt, all with one copy of the
signatures freshclam keeps, and their peak memory: scanning the files, and
with the signatures loaded (raw, and from the .exavdb) and one small file. It replaces bench.json: the earlier releases are
measured again, so that every figure in it comes from the same run. The files,
the signatures and the binaries are copied into `--work` first, which has to
be on a local disk: from a network mount, the timings would be the mount's. A
release whose run is stopped (by the kernel, out of memory) is not run again:
it gets an estimate, its time on the files it got through scaled to the bytes
of all of them, and its memory no figure.

`candidate`, before a release, does the same for HEAD: it builds what the
release workflow builds (each binary for this machine's musl target, the WASI
module, both npm packages, whose dependencies `npm ci` has to have installed
on this machine), counts HEAD, measures its exav beside the
releases', writes it all into target/stats-candidate/ (not the site's) and
prints every figure of each release and of the new version side by side;
`compare` prints that again.

`dataset` lists those files: the MalwareBazaar samples of the corpus up to
1 MiB (the corpus has to stay in the page cache) and the files of
exav-samples' viewer/ at its latest commit. Rewriting it changes the
benchmark, so it is not part of a release.

REQUIREMENTS: git and cargo for `release`; clamscan and the corpus for
`bench`. Both download from GitHub, and `release` from npm.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import posixpath
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "www" / "src" / "data" / "stats"
DATASET = ROOT / "scripts" / "stats-dataset.txt"
CANDIDATE = ROOT / "target" / "stats-candidate"
WORK = Path.home() / ".cache" / "exav-stats"
REPO = "sylvinus/exav"
SAMPLES = "sylvinus/exav-samples"
NPM = ("@exav/unpack-wasm", "@exav/viewer")
LINUX = "x86_64-unknown-linux-musl"
GROUPS = ("code", "tests", "tools", "vendored", "dependencies")
# The binaries whose third-party crates are counted (built_from).
BINARIES = ("exav", "exav-unpack")


def run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "exav-stats"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def version_key(v):
    return tuple(int(x) for x in v.split("."))


# Rust sources

TOKEN = re.compile(
    r"""(?P<nl>\n)|(?P<ws>[^\S\n]+)|(?P<line>//[^\n]*)|(?P<block>/\*)
    |(?P<raw>[bc]?r(?P<hashes>\#*)")|(?P<str>[bc]?")|(?P<char>b?')
    |(?P<word>[A-Za-z_\u0080-\U0010ffff][0-9A-Za-z_\u0080-\U0010ffff]*)
    |(?P<num>[0-9][0-9A-Za-z_]*(?:\.[0-9][0-9A-Za-z_]*)?)|(?P<punct>.)""",
    re.X | re.S,
)
CHAR = re.compile(r"(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|[^\n])|[^\\'\n])'")
LIFETIME = re.compile(r"[A-Za-z_][0-9A-Za-z_]*")
STRING_END = re.compile(r'(?:[^"\\]|\\.)*"', re.S)
PAIRS = {"(": ")", "[": "]", "{": "}"}


def lex(text):
    """The tokens of a Rust source, comments left out, as (text, first line)."""
    toks, i, n, line = [], 0, len(text), 1
    while i < n:
        m = TOKEN.match(text, i)
        kind, start, i = m.lastgroup, i, m.end()
        if kind == "nl":
            line += 1
            continue
        if kind in ("ws", "line"):
            continue
        if kind == "block":
            depth = 1
            while i < n and depth:
                j = min((k for k in (text.find("/*", i), text.find("*/", i)) if k >= 0), default=n)
                line += text.count("\n", i, j)
                if j == n:
                    i = n
                elif text.startswith("/*", j):
                    depth, i = depth + 1, j + 2
                else:
                    depth, i = depth - 1, j + 2
            continue
        if kind == "raw":
            end = text.find('"' + m.group("hashes"), i)
            i = n if end < 0 else end + 1 + len(m.group("hashes"))
        elif kind == "str":
            e = STRING_END.match(text, i)
            i = e.end() if e else n
        elif kind == "char":
            if c := CHAR.match(text, i):
                i = c.end()
            elif text[start] == "'" and (c := LIFETIME.match(text, i)):
                i = c.end()
            elif text[start] == "b":
                i = start + 1
        tok = text[start:i]
        toks.append((tok, line))
        line += tok.count("\n")
    return toks


def closing(words, i):
    """The index of the bracket closing the one at `i`."""
    open_, close, depth = words[i], PAIRS[words[i]], 0
    for j in range(i, len(words)):
        depth += (words[j] == open_) - (words[j] == close)
        if depth == 0:
            return j
    return len(words) - 1


def cfg_test(attr):
    """`cfg(test)` or `cfg(all(test, ...))`: compiled for tests only."""
    if attr == ["cfg", "(", "test", ")"]:
        return True
    return attr[:4] == ["cfg", "(", "all", "("] and "test" in attr and not {"not", "any"} & set(attr)


class RustFile:
    """A Rust source: its code lines, those compiled for tests only, the lines
    of its `unsafe` keywords, its `#[test]` attributes, and the modules it
    declares in other files, as (name, #[path], for tests only)."""

    def __init__(self, text):
        toks = lex(text)
        words = [t for t, _ in toks]
        self.code, self.test, self.mods, self.tests = set(), set(), [], 0
        self.all_test = False
        for tok, line in toks:
            self.code.update(range(line, line + tok.count("\n") + 1))
        self.unsafe = [line for tok, line in toks if tok == "unsafe"]
        i, attrs = 0, []
        while i < len(words):
            w = words[i]
            if w == "#" and i + 1 < len(words):
                inner = words[i + 1] == "!"
                b = i + 2 if inner else i + 1
                if b < len(words) and words[b] == "[":
                    j = closing(words, b)
                    attr = words[b + 1 : j]
                    self.tests += attr == ["test"]
                    if inner:
                        self.all_test |= cfg_test(attr)
                    else:
                        attrs.append((attr, toks[i][1]))
                    i = j + 1
                    continue
            if w == "mod" and i + 2 < len(words):
                test = any(cfg_test(a) for a, _ in attrs)
                path = next((a[2].strip('"') for a, _ in attrs if a[:2] == ["path", "="] and len(a) > 2), None)
                if words[i + 2] == ";":
                    self.mods.append((words[i + 1], path, test))
                elif words[i + 2] == "{" and test:
                    first = min(line for _, line in attrs)
                    self.test.update(range(first, toks[closing(words, i + 2)][1] + 1))
            if w not in ("pub", "(", ")", "crate", "super", "self", "in"):
                attrs = []
            i += 1


def mod_path(decl, name, path, files):
    """The file of `mod name;` declared in `decl`, when it is one of `files`."""
    d = posixpath.dirname(decl)
    if path:
        found = posixpath.normpath(posixpath.join(d, path))
        return found if found in files else None
    stem = posixpath.basename(decl)[:-3]
    if stem not in ("lib", "main", "mod", "build") and posixpath.basename(d) not in (
        "tests", "benches", "examples", "bin", "fuzz_targets",
    ):
        d = posixpath.join(d, stem)
    return next((f for f in (f"{d}/{name}.rs", f"{d}/{name}/mod.rs") if f in files), None)


def count_rust(files, group_of):
    """Lines, `unsafe` keywords and `#[test]` attributes of the Rust sources
    `files` ({path: text}), by group: `group_of(path, tests)` names the group
    of a file, or of its lines compiled for tests only when `tests`, or None
    to leave them out. Also the units (first path part) with an `unsafe`."""
    parsed = {p: RustFile(t) for p, t in files.items()}
    tests_only = set()
    todo = [p for p, f in parsed.items() if f.all_test]
    todo += [m for p, f in parsed.items() for name, path, t in f.mods if t and (m := mod_path(p, name, path, parsed))]
    while todo:
        p = todo.pop()
        if p not in tests_only:
            tests_only.add(p)
            todo += [m for name, path, _ in parsed[p].mods if (m := mod_path(p, name, path, parsed))]
    lines, unsafe, tests, units = {}, {}, {}, set()
    for p, f in parsed.items():
        test = f.code if p in tests_only else f.code & f.test
        for g, ls in ((group_of(p, False), f.code - test), (group_of(p, True), test)):
            if g is None or not ls:
                continue
            n = sum(1 for line in f.unsafe if line in ls)
            lines[g] = lines.get(g, 0) + len(ls)
            unsafe[g] = unsafe.get(g, 0) + n
            if n:
                units.add(p.split("/")[0])
        if (g := group_of(p, False)) is not None:
            tests[g] = tests.get(g, 0) + f.tests
    return lines, unsafe, tests, units


def repo_group(path, tests):
    parts = path.split("/")
    if "vendor" in parts:
        rest = parts[parts.index("vendor") + 2 :]
        if tests or not rest or rest[0] in ("tests", "benches", "examples"):
            return None
        return "vendored"
    if tests or parts[0] == "fuzz":
        return "tests"
    if parts[0] == "crates" and len(parts) > 2:
        if parts[2] in ("src", "build.rs"):
            return "code"
        if parts[2] in ("tests", "benches"):
            return "tests"
    return "tools"


def dependency_group(path, tests):
    """`path` is <crate>-<version>/<path in the crate>."""
    inner = path.split("/", 1)[1]
    if tests or inner.split("/")[0] in ("tests", "benches", "examples") or inner == "build.rs":
        return None
    return "dependencies"


# A release


class Tree:
    """What the counts read of a tag, written out for cargo."""

    KEEP = re.compile(r"(\.rs|/Cargo\.toml|/Cargo\.lock|/package\.json|\.(test|spec)\.(ts|tsx|js|mjs))$")
    ALSO = ("formats/registry.json", "crates/exav-viewer/ts/core/formats.ts")

    def __init__(self, tag, into):
        self.dir = Path(into)
        self.files = {}
        blobs = {}
        for entry in filter(None, run("git", "ls-tree", "-r", "-z", tag, cwd=ROOT).split("\0")):
            meta, path = entry.split("\t", 1)
            _, kind, sha = meta.split()
            if kind == "blob" and (self.KEEP.search("/" + path) or path in self.ALSO):
                blobs[path] = sha
        cat = subprocess.Popen(["git", "cat-file", "--batch"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        for path, sha in blobs.items():
            cat.stdin.write(sha.encode() + b"\n")
            cat.stdin.flush()
            data = cat.stdout.read(int(cat.stdout.readline().split()[2]))
            cat.stdout.read(1)
            self.files[path] = data
            out = self.dir / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        cat.stdin.close()
        cat.wait()

    def text(self, path):
        return self.files[path].decode("utf-8", "replace") if path in self.files else None


def crates(tree, binary):
    """The third-party crates of the Linux `binary`, {(name, version):
    directory}, and how many of them our crates name; None when the tree has
    no such binary."""
    meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", LINUX, cwd=tree))
    members = set(meta["workspace_members"])
    ours = {(p["name"], p["version"]) for p in meta["packages"] if p["id"] in members}
    dirs = {(p["name"], p["version"]): Path(p["manifest_path"]).parent for p in meta["packages"]}
    owner = next(
        ((p, t) for p in meta["packages"] if p["id"] in members for t in p["targets"] if "bin" in t["kind"] and t["name"] == binary),
        None,
    )
    if owner is None:
        return None
    package, target = owner
    features = ["--features", ",".join(target["required-features"])] if target.get("required-features") else []
    out = run(
        "cargo", "tree", "--locked", "--target", LINUX, "-p", package["name"], *features,
        "-e", "normal,no-proc-macro", "--prefix", "depth", "-f", "{p}", cwd=tree,
    )
    stack, found, direct = [], set(), set()
    for line in out.splitlines():
        if not (m := re.match(r"(\d+)(\S+) v(\S+)", line)):
            continue
        depth, key = int(m.group(1)), (m.group(2), m.group(3))
        del stack[depth:]
        if key not in ours:
            found.add(key)
            if stack and stack[-1] in ours:
                direct.add(key)
        stack.append(key)
    return {k: dirs[k] for k in sorted(found)}, len(direct)


WORKSPACES = (".", "crates/exav-unpack-wasm", "crates/exav-viewer")


def all_crates(tree):
    """Every third-party crate of what is published, {(name, version):
    directory}: the workspace's and the two npm packages' (their own
    workspaces), for every system and feature, tests' and tools' included."""
    found = {}
    for ws in WORKSPACES:
        if not (tree / ws / "Cargo.lock").exists():
            continue
        meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked", "--all-features", cwd=tree / ws))
        for p in meta["packages"]:
            if p["source"]:
                found[(p["name"], p["version"])] = Path(p["manifest_path"]).parent
    return dict(sorted(found.items()))


def format_counts(tree, ref):
    """All the formats of formats/registry.json, those the extractor takes
    apart, those the viewer shows. A release older than the registry gets the
    entries of the first registry that its own code already handled: an
    extractor variant it had, a scanner type it named, an extension its viewer
    listed."""
    def count(formats, extracted, shown, typed):
        return {
            "registry": sum(1 for f in formats if extracted(f) or shown(f) or typed(f)),
            "extractor": sum(1 for f in formats if extracted(f) and f["unpack"].get("read") not in (None, "reported")),
            "viewer": sum(1 for f in formats if shown(f)),
        }

    if reg := tree.text("formats/registry.json"):
        formats = json.loads(reg)["formats"]
        return count(formats, lambda f: bool(f.get("unpack")), lambda f: bool(f.get("viewer")), lambda f: True)
    later = [v for v in released() if ref.startswith("v") and version_key(v) > version_key(ref[1:])]
    first = next((v for v in later if subprocess.run(
        ["git", "cat-file", "-e", f"v{v}:formats/registry.json"], cwd=ROOT, capture_output=True).returncode == 0), None)
    if first is None:
        return None
    formats = json.loads(run("git", "show", f"v{first}:formats/registry.json", cwd=ROOT))["formats"]
    enum = re.search(r"^pub enum Format \{(.*?)^\}", tree.text("crates/exav-unpack/src/lib.rs") or "", re.M | re.S)
    variants = set(re.findall(r"^    ([A-Z][A-Za-z0-9]*)", enum.group(1), re.M)) if enum else set()
    names = re.search(r"fn as_str.*?^    \}$", tree.text("crates/exav-core/src/filetype.rs") or "", re.M | re.S)
    types = set(re.findall(r'=> "([^"]+)"', names.group(0))) if names else set()
    extensions = set(re.findall(r'"(\.[a-z0-9.]+)"', tree.text("crates/exav-viewer/ts/core/formats.ts") or ""))
    return count(
        formats,
        lambda f: (f.get("unpack") or {}).get("format") in variants,
        lambda f: bool(f.get("viewer")) and any(e in extensions for e in f["ext"]),
        lambda f: (f.get("scan") or {}).get("type") in types,
    ) | {"from": first}


def js_tests(tree):
    unit = e2e = 0
    call = re.compile(r"^\s*(?:it|test)(?:\.each\(.*?\))?(?:\.(?:only|concurrent))?\(", re.M)
    for path in tree.files:
        if re.search(r"\.(test|spec)\.(ts|tsx|js|mjs)$", path):
            n = len(call.findall(tree.text(path)))
            if "/e2e/" in path:
                e2e += n
            else:
                unit += n
    return unit, e2e


def binaries(tag):
    """The size of each binary of the GitHub release by target, and of the
    WASI module."""
    api = json.loads(fetch(f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"))
    sizes, wasi = {}, None
    for asset in api["assets"]:
        name = asset["name"]
        if name.endswith(".wasm"):
            wasi = asset["size"]
        elif m := re.fullmatch(rf"(exav[a-z0-9-]*)-{re.escape(tag)}-(.+)\.(tar\.gz|zip)", name):
            data, names = fetch(asset["browser_download_url"]), (m.group(1), m.group(1) + ".exe")
            if m.group(3) == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    size = next(i.file_size for i in z.infolist() if posixpath.basename(i.filename) in names)
            else:
                with tarfile.open(fileobj=io.BytesIO(data)) as t:
                    size = next(i.size for i in t.getmembers() if i.isfile() and posixpath.basename(i.name) in names)
            sizes.setdefault(m.group(2), {})[m.group(1)] = size
    return {t: dict(sorted(b.items())) for t, b in sorted(sizes.items())}, wasi


def npm(version):
    """Each npm package of the release: its sizes, and each .wasm in it."""
    out = {}
    for name in NPM:
        try:
            meta = json.loads(fetch(f"https://registry.npmjs.org/{name}/{version}"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            raise
        data = fetch(meta["dist"]["tarball"])
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            wasm = {i.name.removeprefix("package/"): i.size for i in t.getmembers() if i.isfile() and i.name.endswith(".wasm")}
        out[name] = {"tarball": len(data), "unpacked": meta["dist"].get("unpackedSize"), "wasm": dict(sorted(wasm.items()))}
    return out


def counts(ref):
    """What the tree of `ref` holds: lines of Rust, `unsafe`, crates, formats
    and tests."""
    with tempfile.TemporaryDirectory(prefix="exav-stats-") as tmp:
        tree = Tree(ref, tmp)
        lines, unsafe, tests, _ = count_rust({p: tree.text(p) for p in tree.files if p.endswith(".rs")}, repo_group)
        built = {}
        for binary in BINARIES:
            found = crates(tree.dir, binary)
            if found is None:
                built[binary] = None
                continue
            deps, direct = found
            sources = {
                f"{name}-{ver}/{f.relative_to(d).as_posix()}": f.read_text("utf-8", "replace")
                for (name, ver), d in deps.items()
                for f in sorted(d.rglob("*.rs"))
            }
            dlines, dunsafe, _, with_unsafe = count_rust(sources, dependency_group)
            built[binary] = {
                "crates": len(deps),
                "direct": direct,
                "lines": dlines.get("dependencies", 0),
                "unsafe": dunsafe.get("dependencies", 0),
                "unsafe_crates": len(with_unsafe),
            }
        every = all_crates(tree.dir)
        lock = tree.text("Cargo.lock")
        unit, e2e = js_tests(tree)
        fuzz = (tree.text("fuzz/Cargo.toml") or "").count("[[bin]]")
        viewer = tree.text("crates/exav-viewer/package.json")
        viewer = viewer and json.loads(viewer)
        formats = format_counts(tree, ref)
    lines["dependencies"] = built["exav"]["lines"]
    return {
        "rust_lines": {g: lines.get(g, 0) for g in GROUPS},
        "unsafe": {g: unsafe.get(g, 0) for g in GROUPS if g != "dependencies"},
        "built_from": built,
        "dependencies": {
            "all": len(every),
            "lockfile": len(set(re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\nsource =', lock))),
            "viewer_npm": viewer and {
                "required": len(viewer.get("dependencies") or {}),
                "optional": len(viewer.get("peerDependencies") or {}),
            },
        },
        "formats": formats,
        "tests": {
            "rust": sum(n for g, n in tests.items() if g != "vendored"),
            "js": unit,
            "e2e": e2e,
            "fuzz_targets": fuzz,
        },
    }


def release(version):
    tag = f"v{version}"
    bins, wasi = binaries(tag)
    return {
        "version": version,
        "date": run("git", "for-each-ref", "--format=%(creatordate:short)", f"refs/tags/{tag}", cwd=ROOT).strip(),
        **counts(tag),
        "sizes": {"binaries": bins, "wasi": wasi, "npm": npm(version)},
    }


# The new version, before its release


def release_builds():
    """What the release workflow builds: each binary as (name, features), and
    the command and output of the WASI module."""
    yml = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    bins = re.findall(r"^\s+bin: (\S+)\n(?:\s+features: (\S+)\n)?", yml, re.M)
    wasi = re.search(r"run: (cargo build .*--target wasm32-wasip1.*)", yml).group(1).split()
    out = re.search(r"cp (target/wasm32-wasip1/release/\S+\.wasm)", yml).group(1)
    return bins, wasi, out


def build_candidate(target):
    """Builds what the release publishes, as the release workflow does, and
    returns its sizes."""
    bins, wasi, wasi_out = release_builds()
    # As the workflow: the checkout and the cargo home mapped to fixed names.
    env = {**os.environ, "RUSTFLAGS": run(str(ROOT / "scripts" / "build-flags.sh")).strip()}
    meta = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", cwd=ROOT))
    owner = {t["name"]: p["name"] for p in meta["packages"] for t in p["targets"] if "bin" in t["kind"]}
    sizes = {}
    for name, features in bins:
        # One binary at a time, as each upload step does: the features of one
        # do not reach the others.
        cmd = ["cargo", "build", "--release", "--locked", "--target", target, "-p", owner[name], "--bin", name]
        subprocess.run(cmd + (["--features", features] if features else []), cwd=ROOT, env=env, check=True)
        sizes[name] = (ROOT / "target" / target / "release" / name).stat().st_size
    subprocess.run(wasi, cwd=ROOT, env=env, check=True)
    packages = {}
    # With the dependencies already installed for this machine (`npm ci`):
    # installing them here would replace those of another machine that shares
    # the checkout.
    for package, path, steps in (
        ("@exav/unpack-wasm", "crates/exav-unpack-wasm", [["npm", "run", "build"]]),
        ("@exav/viewer", "crates/exav-viewer", [["npm", "run", "build:wasm"], ["npm", "run", "build"]]),
    ):
        for step in steps:
            subprocess.run(step, cwd=ROOT / path, env=env, check=True)
        packed = json.loads(run("npm", "pack", "--dry-run", "--json", "--ignore-scripts", cwd=ROOT / path))[0]
        packages[package] = {
            "tarball": packed["size"],
            "unpacked": packed["unpackedSize"],
            "wasm": {f["path"]: f["size"] for f in sorted(packed["files"], key=lambda f: f["path"]) if f["path"].endswith(".wasm")},
        }
    # What the candidate would publish holds no path of this machine.
    built = [ROOT / "target" / target / "release" / name for name in sizes] + [ROOT / wasi_out]
    built += [ROOT / "crates" / "exav-unpack-wasm" / "pkg", ROOT / "crates" / "exav-viewer" / "wasm", ROOT / "crates" / "exav-viewer" / "dist"]
    # The exceptions are those of the release workflow's gate.
    skip = [f"--except=/{f}" for f in ("docx_parser_bg.wasm", "pptx_parser_bg.wasm", "xlsx_parser_bg.wasm", "pdfjs.worker.js")]
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "check-build-paths.py"), *skip, *map(str, built)], check=True)
    return {"binaries": {target: dict(sorted(sizes.items()))}, "wasi": (ROOT / wasi_out).stat().st_size, "npm": packages}


def candidate(args):
    target = f"{host_arch()}-unknown-linux-musl"
    if target not in run("rustup", "target", "list", "--installed").split():
        sys.exit(f"stats: the release binaries are built for {target}: rustup target add {target}")
    if run("git", "status", "--porcelain", cwd=ROOT).strip():
        sys.exit("stats: the new version is HEAD: commit or set aside the changes first")
    version = re.search(r'^\[workspace\.package\]\nversion = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)
    sizes = build_candidate(target)
    figures = {"version": version, "date": time.strftime("%Y-%m-%d"), "candidate": True, **counts("HEAD"), "sizes": sizes}
    CANDIDATE.mkdir(parents=True, exist_ok=True)
    (CANDIDATE / "release.json").write_text(json.dumps(figures, indent=2) + "\n")
    measured = bench(args, (version, ROOT / "target" / target / "release" / "exav"))
    (CANDIDATE / "bench.json").write_text(json.dumps(measured, indent=2) + "\n")
    compare()


def flatten(d, prefix=""):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from flatten(v, f"{prefix}{k}.")
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            yield f"{prefix}{k}", v


def compare():
    """Prints every figure of each release and of the new version."""
    old = sorted(
        (json.loads(p.read_text()) for p in OUT.glob("*.json") if re.fullmatch(r"\d+\.\d+\.\d+\.json", p.name)),
        key=lambda r: version_key(r["version"]),
    )
    new = json.loads((CANDIDATE / "release.json").read_text())
    measured = json.loads((CANDIDATE / "bench.json").read_text())
    engines = measured["engines"]
    tables = [
        ([r["version"] for r in old] + [f"{new['version']} (new)"], [dict(flatten(r)) for r in old + [new]]),
        (
            [f"{e['name']} {e['version']}" + (" (new)" if e.get("candidate") else "") for e in engines],
            [dict(flatten({k: v for k, v in e.items() if k not in ("exit",)})) for e in engines],
        ),
    ]
    for heads, columns in tables:
        # Each figure beside its neighbours: the first ones in the order they
        # come, the rest by name.
        first = list(dict.fromkeys(k.split(".")[0] for c in columns for k in c))
        keys = sorted({k for c in columns for k in c}, key=lambda k: (first.index(k.split(".")[0]), k))
        names = [k if len(k) <= 60 else f"{k[:26]}…{k[-33:]}" for k in keys]
        width = max(map(len, names)) + 2
        sizes = [max(14, len(h)) + 2 for h in heads]
        print("\n" + " " * width + "".join(f"{h:>{w}}" for h, w in zip(heads, sizes)) + f"{'change':>10}")
        for k, label in zip(keys, names):
            vals = [c.get(k) for c in columns]
            cells = "".join(
                f"{'' if v is None else (f'{v:,}' if isinstance(v, int) else f'{v:,.2f}'):>{w}}" for v, w in zip(vals, sizes)
            )
            last, now = vals[-2] if len(vals) > 1 else None, vals[-1]
            change = f"{(now - last) / last:+.1%}" if last and now is not None else ""
            print(f"{label:<{width}}{cells}{change:>10}")


# The speed benchmark


def released():
    tags = run("git", "tag", "--list", "v*", cwd=ROOT).split()
    return sorted((t[1:] for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t)), key=version_key)


def exav_binary(work, version, target):
    path = work / "bin" / version / "exav"
    if not path.exists():
        data = fetch(f"https://github.com/{REPO}/releases/download/v{version}/exav-v{version}-{target}.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            member = next(i for i in t.getmembers() if i.isfile() and posixpath.basename(i.name) == "exav")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(t.extractfile(member).read())
        path.chmod(0o755)
    return path


def sample(commit, path):
    """A file of the samples repository."""
    return fetch(f"https://raw.githubusercontent.com/{SAMPLES}/{commit}/{urllib.parse.quote(path)}")


def excluded():
    """The samples an `exclude` line of the dataset keeps out."""
    if not DATASET.exists():
        return []
    return [line.split()[1] for line in DATASET.read_text().splitlines() if line.startswith("exclude ")]


def write_dataset(args):
    commit = json.loads(fetch(f"https://api.github.com/repos/{SAMPLES}/commits/HEAD"))["sha"]
    tree = json.loads(fetch(f"https://api.github.com/repos/{SAMPLES}/git/trees/{commit}?recursive=1"))
    corpus = Path(args.corpus)
    out = excluded()
    malware = sorted({
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in corpus.rglob("*.bin")
        if "control" not in p.relative_to(corpus).parts and p.stat().st_size <= args.max_size
    } - set(out))
    other = [
        (hashlib.sha256(sample(commit, e["path"])).hexdigest(), e["path"])
        for e in sorted(tree["tree"], key=lambda e: e["path"])
        if e["type"] == "blob" and e["path"].startswith("viewer/")
    ]
    DATASET.write_text(
        "# The files of the speed benchmark of the Stats page, by SHA-256, written\n"
        "# by `scripts/stats.py dataset`. A line with a path is that file of\n"
        f"# github.com/{SAMPLES} at the commit of the `samples` line;\n"
        "# one without is a MalwareBazaar sample, read from the corpus as\n"
        "# <sha256>.bin. An `exclude` line keeps a sample out: one that stops a\n"
        "# release, which would then have no figure.\n"
        f"samples {commit}\n"
        + "".join(f"exclude {s}\n" for s in out)
        + "".join(f"{s}\n" for s in malware)
        + "".join(f"{s} {p}\n" for s, p in other)
    )
    print(f"{len(malware)} samples of the corpus, {len(other)} files of {SAMPLES}")


def dataset(work, corpus):
    """The benchmark's files, copied once into `work` under their own names
    (exav reads some formats by extension), as (path, is malware). Each is
    checked against its SHA-256 at every run."""
    commit, entries = None, []
    for line in DATASET.read_text().splitlines():
        if line.startswith("samples "):
            commit = line.split()[1]
        elif line and not line.startswith(("#", "exclude ")):
            sha, _, path = line.partition(" ")
            entries.append((sha, path))
    found, files, missing = None, [], []
    for sha, path in entries:
        local = work / "data" / sha / (posixpath.basename(path) if path else f"{sha}.bin")
        if local.exists():
            data = local.read_bytes()
        elif path:
            data = sample(commit, path)
        else:
            if found is None:
                found = {p.stem: p for p in Path(corpus).rglob("*.bin")}
            if sha not in found:
                missing.append(sha)
                continue
            data = found[sha].read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            sys.exit(f"stats: {local} is not the file {sha} of the dataset")
        if not local.exists():
            local.parent.mkdir(parents=True, exist_ok=True)
            part = local.with_name(local.name + ".part")
            part.write_bytes(data)
            part.rename(local)
        files.append((local, not path))
    if missing:
        sys.exit(f"stats: {len(missing)} samples of the dataset are not in {corpus}, {missing[0]} first")
    return files


def oom_first():
    """Makes the engine the first process the kernel's out-of-memory killer
    stops, not one of the machine's."""
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write("1000")


def timed(cmd, out):
    """Wall seconds, CPU seconds, peak resident bytes and exit code (minus the
    signal that stopped it) of one run."""
    with open(out, "wb") as f:
        start = time.monotonic()
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, preexec_fn=oom_first)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.monotonic() - start
    p.returncode = os.waitstatus_to_exitcode(status)
    return wall, ru.ru_utime + ru.ru_stime, ru.ru_maxrss * 1024, p.returncode


def host_arch():
    return {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())


def machine():
    try:
        info = dict(l.split(":", 1) for l in run("lscpu").splitlines() if ":" in l)
    except (OSError, subprocess.CalledProcessError):
        info = {}
    cpu = info.get("Model name", "-").strip()
    if cpu == "-":
        cpu = info.get("Vendor ID", "").strip()
    mem = next(int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal:"))
    return {"cpu": cpu, "arch": platform.machine(), "cores": os.cpu_count(), "memory": mem * 1024, "kernel": platform.release()}


def bench(args, candidate=None):
    """Every release's exav against clamscan, and `candidate`, a (version,
    binary) of the new version, when given."""
    arch = host_arch()
    clamscan = shutil.which(args.clamscan) or sys.exit(f"stats: {args.clamscan} not found")
    work = Path(args.work)
    files = dataset(work, args.corpus)
    listing, one, eicar = work / "files.txt", work / "one.txt", work / "eicar.com"
    listing.write_text("".join(f"{f}\n" for f, _ in files))
    # Two halves the script normaliser does not join, so that exav's scan of
    # its own tree finds nothing here.
    half = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-"
    eicar.write_text(half + "TEST-FILE!$H+H*")
    one.write_text(f"{eicar}\n")
    # One copy of the signatures, so that freshclam cannot change them halfway.
    db = work / "db"
    shutil.rmtree(db, ignore_errors=True)
    db.mkdir()
    sigs = {}
    for f in sorted(Path(args.db).iterdir()):
        if f.suffix in (".cvd", ".cld", ".cud"):
            shutil.copy2(f, db / f.name)
            fields = f.open("rb").read(512).decode("ascii", "replace").split(":")
            sigs[f.stem] = {"version": int(fields[2]), "signatures": int(fields[3])}
    engines = [("clamscan", run(clamscan, "--version").split("/")[0].removeprefix("ClamAV ").strip(),
                [clamscan, "-d", str(db), "--no-summary"], "-f")]
    for v in args.versions or released():
        engines.append(("exav", v, [str(exav_binary(work, v, f"{arch}-unknown-linux-musl")), "-d", str(db)], "--files-from"))
    if candidate:
        engines.append(("exav", f"{candidate[0]}-new", [str(candidate[1]), "-d", str(db)], "--files-from"))
    runs = work / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    runs.mkdir()
    # The hash check read every file into the page cache; once more, so that
    # the first engine reads no disk either.
    for f, _ in files:
        f.read_bytes()

    results = []
    for name, version, cmd, flag in engines:
        label = f"{name}-{version}"
        start = [timed(cmd + [flag, str(one)], runs / f"{label}.start") for _ in range(3)]
        if " FOUND" not in (runs / f"{label}.start").read_text("utf-8", "replace"):
            sys.exit(f"stats: {label} did not find EICAR with the signatures, see {runs / label}.start")
        r = {"name": name, "version": version.removesuffix("-new"), "start": statistics.median(s[0] for s in start)}
        if version.endswith("-new"):
            r["candidate"] = True
        r["start_cpu"] = statistics.median(s[1] for s in start)
        # What it holds once the signatures are loaded, one small file scanned.
        r["memory_loaded"] = statistics.median(s[2] for s in start)
        if name == "exav":
            exavdb = work / "db.exavdb"
            builds = [timed(cmd + ["--build-db", str(exavdb)], runs / f"{label}.build") for _ in range(3)]
            if any(b[3] for b in builds):
                sys.exit(f"stats: {label} --build-db failed, see {runs / label}.build")
            r["build_exavdb"] = statistics.median(b[0] for b in builds)
            loads = [timed([cmd[0], "-d", str(exavdb), flag, str(one)], runs / f"{label}.exavdb") for _ in range(3)]
            r["start_exavdb"] = statistics.median(s[0] for s in loads)
            r["memory_exavdb"] = statistics.median(s[2] for s in loads)
            exavdb.unlink()
        results.append(r)
        built = f", build {r['build_exavdb']:.1f} s, from it {r['start_exavdb']:.1f} s" if name == "exav" else ""
        print(f"{label}: start {r['start']:.1f} s{built}", flush=True)
    sizes = {str(f): f.stat().st_size for f, _ in files}
    samples = [[] for _ in engines]
    for n in range(args.runs):
        # The engines in turn, so that a drift of the machine reaches each.
        for (name, version, cmd, flag), s, r in zip(engines, samples, results):
            if "failed" in r:
                continue
            out = runs / f"{name}-{version}.{n}.out"
            s.append(timed(cmd + [flag, str(listing)], out))
            print(f"{name} {version} run {n + 1}: {s[-1][0]:.1f} s", flush=True)
            if s[-1][3] < 0:
                # A release that does not get to the end of the files gets an
                # estimate instead: its time on the files it went through,
                # scaled to the bytes of all of them.
                lines = out.read_text("utf-8", "replace").splitlines()
                done = [line.split(": ", 1)[0] for line in lines if line.startswith(f"{work}/data/")]
                read = sum(sizes[p] for p in done if p in sizes)
                share = sum(sizes.values()) / max(read, 1)
                r["failed"] = {"signal": signal.Signals(-s[-1][3]).name, "files": len(done), "bytes": read}
                r["estimate"] = {"scan": (s[-1][0] - r["start"]) * share, "cpu": (s[-1][1] - r["start_cpu"]) * share}
                print(f"{name} {version} stopped by {r['failed']['signal']} after {len(done)} files", flush=True)
    for (name, version, _, _), r, s in zip(engines, results, samples):
        start_cpu = r.pop("start_cpu")
        if "failed" not in r:
            out = (runs / f"{name}-{version}.0.out").read_text("utf-8", "replace")
            r["scan"] = statistics.median(x[0] for x in s) - r["start"]
            r["cpu"] = statistics.median(x[1] for x in s) - start_cpu
            # The peak of the whole run: the signatures loaded, then every file.
            r["memory_scan"] = statistics.median(x[2] for x in s)
            r["found"] = sum(1 for line in out.splitlines() if line.endswith(" FOUND"))
            r["exit"] = sorted({x[3] for x in s})
        for k in ("start", "build_exavdb", "start_exavdb", "scan", "cpu"):
            if k in r:
                r[k] = round(r[k], 2)
        if "estimate" in r:
            r["estimate"] = {k: round(v, 2) for k, v in r["estimate"].items()}
    return {
        "date": time.strftime("%Y-%m-%d"),
        "machine": machine(),
        "signatures": sigs,
        "dataset": {
            "files": len(files),
            "bytes": sum(f.stat().st_size for f, _ in files),
            "malware": sum(1 for _, m in files if m),
        },
        "runs": args.runs,
        "engines": results,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("release", help="write <version>.json")
    r.add_argument("version")
    measuring = argparse.ArgumentParser(add_help=False)
    measuring.add_argument("--corpus", default=str(ROOT / "corpus" / "samples"))
    measuring.add_argument("--db", default="/var/lib/clamav")
    measuring.add_argument("--clamscan", default="clamscan")
    measuring.add_argument("--runs", type=int, default=3)
    measuring.add_argument("--versions", nargs="*", help="default: every release")
    measuring.add_argument("--work", default=str(WORK), help="a directory on a local disk (default: %(default)s)")
    sub.add_parser("bench", parents=[measuring], help="write bench.json")
    sub.add_parser("candidate", parents=[measuring], help=f"the new version against the releases, into {CANDIDATE.relative_to(ROOT)}")
    sub.add_parser("compare", help="print again what `candidate` printed")
    d = sub.add_parser("dataset", help="write scripts/stats-dataset.txt")
    d.add_argument("--corpus", default=str(ROOT / "corpus" / "samples"))
    d.add_argument("--max-size", type=int, default=1 << 20)
    args = ap.parse_args()
    if args.cmd == "dataset":
        return write_dataset(args)
    if args.cmd == "candidate":
        return candidate(args)
    if args.cmd == "compare":
        return compare()
    data, name = (release(args.version), f"{args.version}.json") if args.cmd == "release" else (bench(args), "bench.json")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")
    print(f"wrote {(OUT / name).relative_to(ROOT)}")


if __name__ == "__main__":
    main()
