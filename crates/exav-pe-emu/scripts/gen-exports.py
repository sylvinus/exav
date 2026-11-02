#!/usr/bin/env python3
# Regenerate src/exports/<dll>.txt: the export-name sets the synthetic system
# DLLs advertise, so a stub that resolves imports by hashing export names finds
# the function it looks for even when the emulator does not implement it.
#
# Source: Microsoft's own API documentation, which records for every exported
# function the DLLs that export it. Each reference page carries YAML front
# matter with `UID: NF:<header>.<Name>` (the exact exported name; ANSI and
# Unicode variants each have their own page), `api_type: DllExport` and an
# `api_location` list of DLLs. Only those three fields are read.
#
#   MicrosoftDocs/sdk-api                 (Win32 API reference)
#   MicrosoftDocs/windows-driver-docs-ddi (WDK reference; Rtl*/Zw* in ntdll)
#
# Both are (c) Microsoft Corporation, documentation licensed under CC BY 4.0.
# The attribution is in this crate's NOTICE. Nothing else is taken from them.
#
# Usage: download the two archives below (any path), then
#   gen-exports.py sdk-api.tar.gz windows-driver-docs-ddi.tar.gz
# The archives are read in place, never extracted. The commit is the pin; the
# SHA-256 is of GitHub's tar.gz for that commit as downloaded on 2026-10-18.
# GitHub does not promise byte-stable archives, so on a hash mismatch rebuild the
# archive from the pinned commit (`git archive --format=tar.gz`) and re-pin.

import hashlib
import os
import re
import sys
import tarfile

SOURCES = [
    {
        "repo": "MicrosoftDocs/sdk-api",
        "commit": "9e0d205d747b5e0f08019cc7e202112c3aa1f68c",
        "url": "https://codeload.github.com/MicrosoftDocs/sdk-api/tar.gz/"
        "9e0d205d747b5e0f08019cc7e202112c3aa1f68c",
        "sha256": "7ea18a09a9eb9dc2d50fddc8835f488bb349c6763a2e4eff1d1d3f99a4b53928",
    },
    {
        "repo": "MicrosoftDocs/windows-driver-docs-ddi",
        "commit": "7515063cea4c9e98db6a92986c5b4ddb0463fd16",
        "url": "https://codeload.github.com/MicrosoftDocs/windows-driver-docs-ddi/tar.gz/"
        "7515063cea4c9e98db6a92986c5b4ddb0463fd16",
        "sha256": "3c3fb42a76ec66aa3b7d61a78901ad1d5612220f9e89847f61ae94a5c11dc2fc",
    },
]

# The preloaded DLLs the documentation records exports for. `msvcrt.dll` is
# absent: the CRT reference does not map functions to it.
DLLS = ["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll"]

# Names added by hand, each with its justification. The documentation records
# the DLLs a function is exported from, and a few user-mode ntdll exports are
# documented only under the kernel.
ADDED = {
    "ntdll.dll": [
        # Documented in the WDK (ntifs.h, nf-ntifs-rtldecompressbuffer) with
        # api_location NtosKrnl.exe only. ntdll.dll exports it too, and
        # Alienyze resolves it there by hashing ntdll's export names; without
        # it the stub skips decompression.
        "RtlDecompressBuffer",
    ],
}

# Cap per module, so a synthetic module's export directory stays inside the
# region below its trap range (see `MAX_EXPORT_DIR` in src/win.rs).
MAX_PER_MODULE = 2000

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def front_matter(text):
    """The scalar and list fields of a page's leading `---` block."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fields, key = {}, None
    for line in text[3:end].splitlines():
        if line.startswith(" - ") and key is not None:
            fields.setdefault(key, []).append(line[3:].strip())
            continue
        m = re.match(r"([A-Za-z0-9_.-]+):\s*(.*)$", line)
        if m:
            key, value = m.group(1), m.group(2).strip()
            fields[key] = [value] if value else []
    return fields


def exports_in(archive, out):
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not member.isfile() or not member.name.endswith(".md"):
                continue
            # Reference pages only; a page is a few kilobytes, so anything far
            # larger is not one and is skipped unread.
            if member.size > 1 << 20:
                continue
            raw = tar.extractfile(member).read().decode("utf-8", "replace")
            fm = front_matter(raw)
            if not fm:
                continue
            if "DllExport" not in fm.get("api_type", []):
                continue
            # VersionHelpers.h functions are inline in the header, not exports,
            # though their pages list ntdll.dll.
            if (fm.get("req.header") or [""])[0].lower() == "versionhelpers.h":
                continue
            uid = (fm.get("UID") or [""])[0]
            if not uid.startswith("NF:") or "." not in uid:
                continue
            name = uid.rsplit(".", 1)[1]
            if not IDENT.fullmatch(name) or name not in fm.get("api_name", []):
                continue
            for loc in fm.get("api_location", []):
                dll = loc.strip().lower()
                if dll in out:
                    out[dll].add(name)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    if len(sys.argv) != len(SOURCES) + 1:
        sys.exit("usage: gen-exports.py sdk-api.tar.gz windows-driver-docs-ddi.tar.gz")
    out = {dll: set() for dll in DLLS}
    for src, path in zip(SOURCES, sys.argv[1:]):
        got = sha256(path)
        if got != src["sha256"]:
            sys.exit(f"{path}: sha256 {got}, expected {src['sha256']} ({src['repo']}@{src['commit']})")
        exports_in(path, out)
    for dll, names in ADDED.items():
        out[dll].update(names)
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "exports")
    os.makedirs(out_dir, exist_ok=True)
    for dll in DLLS:
        names = sorted(out[dll])[:MAX_PER_MODULE]
        dest = os.path.join(out_dir, dll.removesuffix(".dll") + ".txt")
        with open(dest, "w") as f:
            f.write("".join(n + "\n" for n in names))
        print(f"{dll}: {len(names)} names")


if __name__ == "__main__":
    main()
