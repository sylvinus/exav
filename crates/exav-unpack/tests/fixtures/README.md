# Test fixtures

Real containers, kept as files because most of them cannot be built in a test:
qcow2 and VMDK images, a BinHex 4.0 stream, a CPython `.pyc`, archives written by
tools that are not Rust libraries.

## `.xor` files are masked

A fixture whose whole job is to be *detected* is a fixture that gets this
repository quarantined on `git clone`, deleted by an AV-scanned CI runner, and
flagged by whatever watches a contributor's laptop. Several of these carry the
EICAR test string, and one — `upx_nrv_gamma_overflow.upx`, a fuzzer-built UPX'd
i386 ELF — matches ClamAV's generic Mirai signature.

So the ones a scanner reacts to are committed XORed with `0x5A` under a `.xor`
suffix. That removes the archive magic and the payload in one step, leaving
nothing for any engine to match, and the bytes stay one XOR away.

Nothing needs to know which is which:

* **Runtime reads** go through `exav_unpack::read_fixture(path)`, which prefers
  `<path>.xor` and falls back to the plain file. Call sites pass the plain name.
* **`include_bytes!`** names the `.xor` file directly and wraps it in
  `exav_unpack::unmask_fixture(...)`, because the path is resolved at compile
  time and cannot fall back.

To mask a new fixture, XOR it with `0x5A`, add the `.xor` suffix, and delete the
original — no code change if it is loaded through `read_fixture`.

XOR rather than the password-protected ZIP that is standard for *distributing*
samples: these fixtures are the corpus for an archive extractor, so wrapping them
in archives would make the ZIP and 7z tests depend on working ZIP and decryption
support to load their own inputs, and the `--no-default-features` build has
neither compiled in.

`scripts/release.sh` greps the tracked tree for the EICAR string on every run.
`make av-audit` scans it with `clamscan` and a signature database, which needs
both installed, so it is run when fixtures change; `docs/RELEASING.md` also
has the release build scanned over the tree.

## Real malware is never committed

Committed fixtures carry EICAR or synthetic payloads only, masked as above
when a scanner reacts to them. A few suites also run on real in-the-wild
samples (`chm/`, `lnk/`, `nsis/`, `onenote/`) when a developer has them
locally. Those are:

* named `real-malware-*`, which `.gitignore` excludes, and never committed;
* kept as `<name>.zip`: a ZIP holding the one sample, AES-256 encrypted with
  the password `infected`, the convention MalwareBazaar distributes samples in;
* listed with their sha256 in the directory's `README.md`, for re-download.

`read_fixture(path)` falls back to `<path>.zip` when neither `<path>.xor` nor
`<path>` exists and decrypts it in memory, so call sites pass the plain name.
That needs the `zip` and `decrypt` features; a build without them, like a
checkout without the samples, skips the tests that use them.

## Written by a script

`dmg/udif_lzfse.dmg` is `dmg/hfs_plus_udrw.dmg`'s disk in two LZFSE runs (sectors
0 to 8, then the rest): a UDIF image with a `koly` trailer and a block map
around the streams the `lzfse_rust` crate (an LZFSE encoder, MIT) writes, one
LZVN block and FSE blocks. `tests/suites/lzfse.rs` reads it back against the
raw image.

`tests/oracle/` holds the C wrappers and `build.sh` for the differential tests
of the LZFSE and DCL decoders against their reference sources, which are
fetched, never committed (`src/formats/lzfse.rs`, `src/formats/dcl_explode.rs`).

To add one (`pip install pyzipper`):

```python
import pyzipper
with pyzipper.AESZipFile("real-malware-x.one.zip", "w",
                         compression=pyzipper.ZIP_DEFLATED,
                         encryption=pyzipper.WZ_AES) as z:
    z.setpassword(b"infected")
    z.write("real-malware-x.one")
```

then delete the plain file and add its sha256 to the directory's README.
