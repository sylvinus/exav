# delharc 0.6.1 — panic "attempt to add with overflow" in LHA header parser

Found by fuzzing exav (which builds with `overflow-checks = true`). `delharc`'s
LHA header parser performs an unchecked `u32` addition that overflows on a
crafted header, panicking (with overflow-checks on) or silently wrapping (in a
stock release build).

- **Crate:** `delharc` 0.6.1
- **Location:** `src/header/parser.rs:265` — `else if long_header_len < parser.len as u32 + first_header_len`
- **Panic:** `attempt to add with overflow`
- **Trigger:** `parser.len as u32 + first_header_len` overflows `u32`.

## Minimal reproducer (49 bytes)

```rust
use std::io::Cursor;

// Build with overflow-checks on (Cargo's default for dev/test, or
// `RUSTFLAGS="-C overflow-checks=on" cargo run --release`).
fn main() {
    let data: &[u8] = &[
        0x04, 0x00, 0x4f, 0x03, 0x24, 0xc3, 0xc3, 0xc3, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4d, 0x53, 0x43, 0x46, 0x1a, 0x03, 0x62, 0x00, 0x08,
        0x28, 0xf9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x52,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x21,
    ];
    // panics: "attempt to add with overflow" at header/parser.rs:265
    let _ = delharc::LhaDecodeReader::new(Cursor::new(data));
}
```

Hex: `04004f0324c3c3c3000000000000004d5343461a0362000828f9ffffffffffff7f00005200000000006172000000000021`

## Suggested fix
Use `checked_add`/`saturating_add` (or widen to `u64`) for
`parser.len as u32 + first_header_len` and return `LhaError::HeaderParse` on
overflow, rather than relying on wrapping.

## Notes
exav contains this via a `catch_unwind` boundary around all archive decoders,
so it is not a crash for exav users — it is reported as an unscannable member.
The raw bytes live at `fixtures/lha_delharc_overflow_min.lha`. Filed upstream at
the `delharc` repository.

---

# delharc 0.6.1 — issue 2: unbounded allocation from a header length field (memory DoS)

Found by fuzzing exav (2026-07-02). A crafted LHA header drives
`Parser::read_limit_no_checksums` (`header/parser.rs:140`) to
`buf.try_reserve_exact(limit)` where `limit` is an **attacker-controlled**
header field (`extra_header_len` / `extended_len` / `filename_len`). A 143-byte
input reserves ~3.2 GB. `try_reserve` degrades gracefully on a memory-constrained
host (returns `HeaderParse("memory allocation failed")`), but on a host with
enough RAM it succeeds and allocates the full attacker-declared size — a
memory-amplification denial of service.

- **Crate:** `delharc` 0.6.1
- **Location:** `src/header/parser.rs:140` (`read_limit_no_checksums`) and
  `:124` (`read_limit`), reached from `LhaHeader::read` (`:200`/`:232`/`:290`).
- **Behavior:** `malloc(3187671040)` from a 143-byte input; not a crash
  (graceful `try_reserve`), but unbounded memory use.
- **Repro bytes:** `fixtures/lha_delharc_oom.lha` (143 bytes).

## Suggested fix
Bound `limit` before reserving — reject a declared extended-header/filename
length that exceeds the bytes actually remaining in the reader (or a sane
absolute cap), rather than reserving the full declared size up front.

## exav mitigation
`Budget` cannot see this allocation — delharc makes it internally, before
yielding any output — and `catch_unwind` does not catch an allocation, which
aborts rather than unwinding. So the bound has to be applied before the reader
is handed the bytes.

`header_worth_reading` in `src/formats/lha.rs` refuses a header that both reaches
past the end of the archive *and* declares a size no archiver writes
(`MAX_PLAUSIBLE_HEADER`, 16 MiB). Both conditions are required. Over-declaring
alone is not grounds for refusal: this extractor is handed carved and embedded
regions, where a genuine archive's header can legitimately describe more than
the slice holds, and turning one of those into an `Unscannable` would hide a
member from the scan — worth more to an attacker than the allocation it avoids.
Requiring the size to be implausible as well keeps the check inside the region
where delharc cannot succeed either: it would allocate, read short, and fail.

The daemon's `RLIMIT_AS` remains the backstop for anything this misses.
`lha_delharc_oom.lha` is wired into `tests/suites/lha_header_bounds.rs`, which is
safe because the gate refuses it before delharc reserves.
