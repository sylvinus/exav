# Test fixtures

Containers used by the engine's integration suites, kept as files because they
cannot be built in a test.

## `.xor` files are masked

Fixtures that a scanner detects — several here carry the EICAR test string —
are committed XORed with `0x5A` under a `.xor` suffix, so this repository is not
quarantined on `git clone` or stripped by an AV-scanned CI runner.

Load them through `exav_core::unpack::read_fixture(path)`, which prefers
`<path>.xor` and falls back to the plain file; call sites pass the plain name.

The full rationale, and what to do when adding one, is in
[`crates/exav-unpack/tests/fixtures/README.md`](../../../exav-unpack/tests/fixtures/README.md).
