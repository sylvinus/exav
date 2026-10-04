# CHM test fixtures

## Committed (benign)

`benign-lzx.chm` — a genuine **LZX-compressed** CHM built from original help-page
HTML written for this repo and compiled with `chmcmd` (Free Pascal's CHM
compiler). It carries **no payload**; its only purpose is to exercise the LZX
decode path (it contains the marker `EXAV-LZX-OK` inside the compressed content
section). The HTML content is released into the **public domain (CC0)**. Safe to
commit, and the always-on LZX decode oracle in `tests/chm.rs`.

`multi-frame-lzx.chm`: three generated pages (`a.html`, `b.html`, `c.html`,
each `<p>{name} {i * 7919 % 10007}</p>` for i in 0..2000 between
`<html><body>` and `</body></html>`) compiled with `chmcmd` 3.2.2. Its LZX
stream spans three 32 KiB frames and resets every two, so a page past the
first frame of an interval decodes only with the state that frame left. Public
domain (CC0).

## Gitignored (real malware — never committed)

Real in-the-wild malware `.chm` samples (single-frame LZX). They are
**gitignored** (`tests/fixtures/**/real-malware-*`) and kept locally as
`<name>.zip` (AES-256, password `infected`, see `../README.md`); the tests
read them at runtime and skip when absent, so they only add extra robustness coverage for
developers who have them locally. Provenance for re-download / VT lookup:

| file | sha256 |
|---|---|
| real-malware-lzx-1.chm | 0efbd18c77479b458078521c18bdad84852b71250122a17cb8105c10d3df38d4 |
| real-malware-lzx-2.chm | bc0fe921f3dae89df12adbd034ff58b875223dd3c3119aba6eaa023ad818d653 |
