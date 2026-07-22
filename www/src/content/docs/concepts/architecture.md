---
title: Architecture
description: How exav is organized — the two input modes, the crate layout, and how each ClamAV signature type compiles to a distinct runtime structure.
---

exav is a small set of focused crates around a constant-memory scanning core.
This is the high-level picture; deeper implementation detail lives in the
repository's `docs/`.

## Two input modes

exav scans through one of two paths, and the difference decides what analysis is
possible:

- **Stream** (`Read`: stdin, pipes) — `scan_stream` runs the constant-memory
  pattern + hash core. Unlimited size, but structural unpacking needs seeking, so
  a pure pipe does pattern+hash only.
- **Seekable** (`Read + Seek`: local files, or an HTTP range reader over HTTP
  range GETs) — `scan_seekable` additionally drives archive extraction through
  the reader, fetching only the directory and members it actually scans.

See [Streaming & memory](/concepts/streaming-memory/) for the core.

The code is split across a handful of crates — `exav-cli` and the WASI build are
the front-ends, `exav-core` is the engine, `exav-unpack` does extraction (and
backs the standalone `exav-grep`). See
[How the crates compose](#how-the-crates-compose) below, and
[Subprojects](/subprojects/) for what each one owns.

## Not one monolithic engine

Different ClamAV signature types compile to different runtime structures — there
is deliberately **not** one giant matcher:

| Source | Runtime structure | Matching |
|---|---|---|
| `.ndb` bodies + `.ldb` literal subsignatures | a shared **Aho-Corasick automaton** keyed on a literal anchor per body | an automaton hit fans out to every body sharing that anchor; each candidate is then verified (wildcards / gaps / nibbles / alternation / offset / nocase) |
| `.ldb` PCRE subsignatures | `regex` objects compiled lazily, gated by the trigger expression | linear-time, DoS-safe regex |
| `.hsb` / `.hdb` | a size-keyed hash table | whole-file digest lookup |
| `.mdb` / `.msb` | a section-hash table | per-PE-section digest lookup |
| `.cdb` | container-metadata matchers | matched on archive members (name/size/encryption/position) |
| `.imp` | a size-constrained import-hash map | PE imphash lookup |
| `.cbc` | a [sandboxed bytecode interpreter](/concepts/bytecode-sandbox/) (no JIT) | trigger-gated programs run on extracted buffers |
| `.yar` / `.yara` | a [native YARA engine](/guides/yara/) | near-full YARA, no runtime codegen |

So the engine is really: *one Aho-Corasick automaton (fed by ndb + ldb literal
subsigs) + several cheap hash tables + lazy regex + interpreters.* Almost all of
the memory cost is the automaton — see [the database internals](/guides/prebuilt-database/).

## How the crates compose

exav is a small Cargo workspace, not one binary. Four front-ends drive one
engine: the CLI (which is also the daemon), the WASI build, the archive grep,
and the WebAssembly bindings published to npm. `exav-core` is the engine;
`exav-unpack` does extraction; `exav-update` sits to the side, feeding fresh
signatures out of band.

Every arrow points down. Nothing below calls anything above it, which is what
lets the extraction crates be taken on their own.

<svg viewBox="0 0 790 620" role="img" aria-labelledby="craten crated" style="width:100%;height:auto;max-width:790px">
  <title id="craten">exav crate dependency graph</title>
  <desc id="crated">Four front ends sit on top: exav-cli, exav-core built for
  wasm32-wasip1, exav-grep and exav-unpack-wasm. exav-cli and the wasi binary
  depend on exav-core; exav-core, exav-grep and exav-unpack-wasm all depend on
  exav-unpack, which depends on exav-pe-emu, which depends on exav-x86.
  exav-update hangs off exav-cli alone and feeds signature files out of
  band.</desc>
  <defs>
    <marker id="crate-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <text x="4" y="14" fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">FRONT ENDS</text>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="4" y="24" width="185" height="70" rx="6"/>
    <rect x="203" y="24" width="185" height="70" rx="6"/>
    <rect x="402" y="24" width="185" height="70" rx="6"/>
    <rect x="601" y="24" width="185" height="70" rx="6"/>
    <rect x="200" y="160" width="190" height="104" rx="6"/>
    <rect x="150" y="330" width="490" height="78" rx="6"/>
    <rect x="295" y="450" width="200" height="62" rx="6"/>
    <rect x="295" y="550" width="200" height="62" rx="6"/>
    <rect x="4" y="550" width="185" height="62" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14" font-weight="600" text-anchor="middle">
    <text x="96" y="48">exav-cli</text>
    <text x="295" y="48">exav-core</text>
    <text x="494" y="48">exav-grep</text>
    <text x="693" y="48">exav-unpack-wasm</text>
    <text x="295" y="188">exav-core</text>
    <text x="395" y="358">exav-unpack</text>
    <text x="395" y="474">exav-pe-emu</text>
    <text x="395" y="574">exav-x86</text>
    <text x="96" y="574">exav-update</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="96" y="66">clamscan + clamd</text>
    <text x="96" y="82">the only unsafe: libc</text>
    <text x="295" y="66">--wasi-bin</text>
    <text x="295" y="82">wasm32-wasip1</text>
    <text x="494" y="66">grep inside</text>
    <text x="494" y="82">archives</text>
    <text x="693" y="66">wasm-bindgen → npm</text>
    <text x="693" y="82">its own profile</text>
    <text x="295" y="210">typing · patterns · hashes</text>
    <text x="295" y="228">YARA · .cbc VM</text>
    <text x="395" y="380">every container format · Budget / Limits</text>
    <text x="395" y="396">#![forbid(unsafe_code)]</text>
    <text x="395" y="494">x86-32 sandbox</text>
    <text x="395" y="594">decoder</text>
    <text x="96" y="594">signatures, out of band</text>
    <text x="510" y="468" text-anchor="start">runs a packer's own stub to</text>
    <text x="510" y="484" text-anchor="start">recover the image it rebuilds</text>
    <text x="510" y="568" text-anchor="start">decode only,</text>
    <text x="510" y="584" text-anchor="start">zero dependencies</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#crate-arrow)">
    <path d="M140 94 V127 H250 V156"/>
    <path d="M295 94 V156"/>
    <path d="M295 264 V326"/>
    <path d="M494 94 V326"/>
    <path d="M693 94 V290 H590 V326"/>
    <path d="M395 408 V446"/>
    <path d="M395 512 V546"/>
    <path d="M96 94 V546"/>
  </g>
</svg>

A scan flows through it like this:

<svg viewBox="0 0 790 440" role="img" aria-labelledby="flown flowd" style="width:100%;height:auto;max-width:790px">
  <title id="flown">How a scan flows</title>
  <desc id="flowd">A file enters identify(), which types the first 4 KiB. A
  container has its members walked one at a time under a single shared Budget,
  and each member re-enters identify() bounded at max_recursion of 16. A flat
  file goes to pattern, hash and heuristic matching. Both paths end in one of
  five verdicts: Clean, Infected, LimitsExceeded, Unscannable or
  PasswordProtected.</desc>
  <defs>
    <marker id="flow-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="24" width="96" height="48" rx="6"/>
    <rect x="150" y="24" width="190" height="52" rx="6"/>
    <rect x="40" y="150" width="350" height="92" rx="6"/>
    <rect x="430" y="150" width="352" height="92" rx="6"/>
    <rect x="150" y="330" width="632" height="96" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14" font-weight="600" text-anchor="middle">
    <text x="56" y="53">file</text>
    <text x="245" y="46">identify()</text>
    <text x="215" y="180">container</text>
    <text x="606" y="180">flat</text>
    <text x="466" y="384">Clean · Infected · LimitsExceeded</text>
    <text x="466" y="410">Unscannable · PasswordProtected</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="245" y="64">types the first 4 KiB</text>
    <text x="215" y="202">walk members one at a time,</text>
    <text x="215" y="220">sharing one Budget</text>
    <text x="606" y="202">pattern + hash + heuristics</text>
    <text x="466" y="358">every scan ends in exactly one verdict</text>
    <text x="290" y="105" text-anchor="start">each member re-enters identify()</text>
    <text x="290" y="121" text-anchor="start">bounded at max_recursion (16)</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#flow-arrow)">
    <path d="M104 48 H146"/>
    <path d="M215 76 V146"/>
    <path d="M340 50 H606 V146"/>
    <path d="M215 242 V326"/>
    <path d="M606 242 V326"/>
    <path d="M280 150 V80" stroke-dasharray="4 4"/>
  </g>
</svg>

The five verdicts are the whole output vocabulary. Anything that stops a scan
early produces one of the last three rather than `Clean` — see
[Verdicts & exit codes](/reference/verdicts/).

The split is not cosmetic. Extraction touches hostile bytes first and hardest,
so it lives in its own `#![forbid(unsafe_code)]` crate with its own budget and
panic containment; a malformed archive cannot reach the engine, let alone the
host. It also means you can take one piece — a build system that needs to look
inside archives does not need a virus scanner, and a reverse engineer who wants
to unpack a packed executable needs neither.

`exav-pe-emu` sits below the extractor for the same reason. Running a packer's stub
is the one place where the scanner executes attacker-authored *control flow*
rather than parsing attacker-authored data, so it is its own crate with its own
budgets, its own `#![forbid(unsafe_code)]`, and no way to reach a syscall.

Each crate has its own page under [Subprojects](/subprojects/), with install
instructions, API, and examples.

## Recursive unpacking, bounded

The `exav-unpack` crate recursively extracts archives and structured documents
(see [Supported formats](/reference/formats/)). Every path runs under
**decompression-bomb defenses**: output-byte, ratio, file-count, recursion-depth,
and cumulative scan-byte budgets. A bomb is `LIMITS-EXCEEDED`, never `OK`; a
member with an unsupported codec or encryption is `UNSCANNABLE` /
`PASSWORD-PROTECTED`, never silently dropped — the
[never-silent invariant](/concepts/design-principles/#never-a-silent-clean) reaching all the way down.

## Content-based typing

File type is decided by **magic bytes**, never by extension — an executable
renamed `.jpg` is still typed and scanned as an executable.
