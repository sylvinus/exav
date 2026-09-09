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

`scripts/release.sh` re-checks the whole tracked tree with `clamscan` when a
signature database is present, so a fixture committed in the clear is caught
before it ships.
