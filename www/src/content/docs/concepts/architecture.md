---
title: Architecture
description: How exav is organized, the crate layout, and how each ClamAV signature type compiles to a distinct runtime structure.
---

exav is a small set of focused crates around one scanning engine. This is the
high-level picture; implementation detail lives in the repository's `docs/`.

## Input

Every input is scanned through a seekable source (`Read + Seek`): a local file,
an HTTP range reader, or a buffered stream. Stdin, `INSTREAM` and ICAP bodies are
buffered first (in memory, then in a temporary file), because container formats
need to seek. `scan_seekable` hands the input to the one pipeline every object
takes, the input and whatever is unpacked, decoded or carved out of it, at any
size and depth. See [Streaming & memory](/concepts/streaming-memory/) for what
is held in memory and what is read as it is needed.

## How a scan flows

<svg viewBox="0 0 790 440" role="img" aria-labelledby="flown flowd" style="width:100%;height:auto;max-width:790px">
  <title id="flown">How a scan flows</title>
  <desc id="flowd">An object enters identify(), which types it from its start,
  its end, or a search of it. An archive has its members walked one at a time
  under a single shared Budget, then its own bytes matched. Anything else has
  its own bytes matched first, then what is inside it analysed: a packed or
  installer executable's payload, carved images, decoded payloads, heuristics.
  Everything found inside re-enters identify(), bounded at --max-unpack-depth of 16.
  Both paths end in OK, FOUND, or PARTIAL with its category: LIMITS-EXCEEDED,
  UNSCANNABLE or PASSWORD-PROTECTED; an input that cannot be read, even part
  way, is ERROR.</desc>
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
    <text x="56" y="53">object</text>
    <text x="245" y="46">identify()</text>
    <text x="215" y="180">archive</text>
    <text x="606" y="180">anything else</text>
    <text x="466" y="384">OK · FOUND · PARTIAL · ERROR</text>
    <text x="466" y="410">PARTIAL: LIMITS-EXCEEDED · UNSCANNABLE · PASSWORD-PROTECTED</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="245" y="64">start · end · a search</text>
    <text x="215" y="202">members one at a time, sharing</text>
    <text x="215" y="220">one Budget; then its own bytes</text>
    <text x="606" y="202">its own bytes; then what is inside:</text>
    <text x="606" y="220">payloads, carved images, heuristics</text>
    <text x="466" y="358">not fully examined is PARTIAL, never OK; input unreadable is ERROR</text>
    <text x="290" y="105" text-anchor="start">everything found inside re-enters</text>
    <text x="290" y="121" text-anchor="start">identify() · --max-unpack-depth (16)</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#flow-arrow)">
    <path d="M104 48 H146"/>
    <path d="M215 76 V146"/>
    <path d="M340 50 H606 V146"/>
    <path d="M215 242 V326"/>
    <path d="M606 242 V326"/>
    <path d="M280 150 V80" stroke-dasharray="4 4"/>
    <path d="M560 150 V64 H344" stroke-dasharray="4 4"/>
  </g>
</svg>

A file is `OK`, `FOUND`, or `PARTIAL` when it could not be fully examined, with
a category saying why: a limit (`LIMITS-EXCEEDED`), content with no decoder
(`UNSCANNABLE`) or encryption (`PASSWORD-PROTECTED`). Anything that stops a scan
early is `PARTIAL`, never `OK`. `ERROR` is exav failing rather than a fact
about the file: a path it cannot open, a database that will not load, or a
source that fails part way through a scan, whose unread bytes are not taken for
the end of the file (see [Verdicts & exit codes](/reference/verdicts/)).

### Content-based typing

File type is decided by magic bytes, not by extension: an executable renamed
`.jpg` is still typed and scanned as an executable.

### Recursive unpacking, bounded

See [Archive extraction](/concepts/archive-extraction/) for the budgets every
extraction runs under and what a member exav cannot read becomes.

## How the crates compose

exav is a small Cargo workspace, not one binary. Two front ends drive the
engine, `exav-core`: the CLI (which is also the daemon) and the WASI build. Two
more use only the extractor, `exav-unpack`: the archive grep, and the
WebAssembly bindings published to npm (built outside the workspace, with their
own profile). `exav-update`, enabled by the `http` feature, sits to the side,
feeding fresh signatures out of band.

Every arrow points down. Nothing below calls anything above it, which is what
lets the extraction crates be taken on their own.

<svg viewBox="0 0 790 620" role="img" aria-labelledby="craten crated" style="width:100%;height:auto;max-width:790px">
  <title id="craten">exav crate dependency graph</title>
  <desc id="crated">Four front ends sit on top: exav, exav-core built for
  wasm32-wasip1, exav-grep and exav-unpack-wasm. exav and the wasi binary
  depend on exav-core; exav-core, exav-grep and exav-unpack-wasm all depend on
  exav-unpack, which depends on exav-pe-emu, which depends on exav-x86.
  exav-core also depends on exav-x86 directly, for the bytecode disassembly
  API. exav-update, optional behind the http feature, hangs off exav alone and
  feeds signature files out of band.</desc>
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
    <text x="96" y="48">exav</text>
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
    <text x="295" y="66">feature wasi-bin</text>
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
    <text x="96" y="594">optional: http feature</text>
    <text x="126" y="292" text-anchor="start">bytecode disasm</text>
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
    <path d="M200 240 H120 V530 H250 V581 H291"/>
  </g>
</svg>

Extraction touches hostile bytes first and hardest, so it lives in its own
`#![forbid(unsafe_code)]` crate with its own budget and panic containment. It
also means one piece can be used alone: a build system that needs to look inside
archives does not need a virus scanner, and a reverse engineer who wants to
unpack a packed executable needs neither.

`exav-pe-emu` sits below the extractor for the same reason. Running a packer's stub
is the one place where the scanner executes attacker-authored *control flow*
rather than parsing attacker-authored data, so it is its own crate with its own
budgets, its own `#![forbid(unsafe_code)]`, and no way to reach a syscall.

Each crate has its own page under [Subprojects](/subprojects/), with install
instructions, API, and examples.

## Signature types and runtime structures

Different ClamAV signature types compile to different runtime structures rather
than one matcher:

| Source | Runtime structure | Matching |
|---|---|---|
| `.ndb` bodies + `.ldb` literal subsignatures | a set of **Aho-Corasick automata**, one per (target type, case) pair, keyed on a literal anchor per body | an automaton hit fans out to every body sharing that anchor; each candidate is then verified (wildcards / gaps / nibbles / alternation / offset / nocase) |
| `.ldb` PCRE subsignatures | regexes compiled lazily, gated by the trigger expression | linear-time `regex`; patterns with backreferences use a backtracking engine under a step bound |
| `.hsb` / `.hdb` | a size-keyed hash table | whole-file digest lookup |
| `.mdb` / `.msb` | a section-hash table | per-PE-section digest lookup |
| `.cdb` | container-metadata matchers | matched on archive members (name/size/encryption/position) |
| `.imp` | a size-constrained import-hash map | PE imphash lookup |
| `.cbc` | a [sandboxed bytecode interpreter](/concepts/bytecode-sandbox/) (no JIT) | trigger-gated programs run on extracted buffers |
| `.yar` / `.yara` | a [native YARA engine](/guides/yara/) | near-full YARA, no runtime codegen |

So the engine is a set of Aho-Corasick automata (fed by `.ndb` and `.ldb` literal
subsignatures), several cheap hash tables, lazy regexes and interpreters. Almost
all of the memory cost is the automata; see the
[prebuilt database](/guides/prebuilt-database/).

## How a body signature is matched

<svg viewBox="0 0 790 556" role="img" aria-labelledby="matn matd" style="width:100%;height:auto;max-width:790px">
  <title id="matn">From anchor hit to detection</title>
  <desc id="matd">An object's bytes, and a lowercased view of them for
  case-insensitive anchors, go through the partitions whose target fits the
  file type. One Aho-Corasick sweep reports every anchor hit as a group and an
  offset. Each hit fans out to every body sharing the anchor, and each is
  verified around the hit. A verified .ndb body is a detection. A verified .ldb
  subsignature is counted, and the logical expressions of the .ldb signatures
  whose subsignatures hit are evaluated after the sweep; a PCRE subsignature
  runs only when its trigger holds.</desc>
  <defs>
    <marker id="mat-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="24" width="240" height="56" rx="6"/>
    <rect x="300" y="24" width="482" height="56" rx="6"/>
    <rect x="300" y="120" width="482" height="56" rx="6"/>
    <rect x="300" y="216" width="482" height="76" rx="6"/>
    <rect x="8" y="340" width="370" height="76" rx="6"/>
    <rect x="412" y="340" width="370" height="76" rx="6"/>
    <rect x="412" y="460" width="370" height="84" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600" text-anchor="middle">
    <text x="128" y="48">object</text>
    <text x="541" y="48">partitions, by (target, case)</text>
    <text x="541" y="144">one Aho-Corasick sweep</text>
    <text x="541" y="240">fan out, then verify each body</text>
    <text x="193" y="364">.ndb body verified</text>
    <text x="597" y="364">.ldb subsignature verified</text>
    <text x="597" y="484">logical expression</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="128" y="66">its bytes, and a lowercased view</text>
    <text x="541" y="66">only those whose target fits the file type run</text>
    <text x="541" y="162">every anchor at once: hits as (group, offset)</text>
    <text x="541" y="260">every body sharing the anchor: prefix back, suffix</text>
    <text x="541" y="278">forward, gaps as intervals, offset, ::f word bounds</text>
    <text x="193" y="386">a detection; a normal scan stops here,</text>
    <text x="193" y="404">--all-matches keeps verifying</text>
    <text x="597" y="386">counted, with the offset of its first match</text>
    <text x="597" y="404">(byte comparisons are taken from there)</text>
    <text x="597" y="506">after the sweep, only for the signatures whose</text>
    <text x="597" y="524">subsignatures hit; a PCRE runs if its trigger holds</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#mat-arrow)">
    <path d="M248 52 H296"/>
    <path d="M541 80 V116"/>
    <path d="M541 176 V212"/>
    <path d="M420 292 V316 H193 V336"/>
    <path d="M660 292 V336"/>
    <path d="M597 416 V456"/>
  </g>
</svg>

An anchor is a literal run each body must contain; everything else in the body
(wildcards, nibbles, alternations, gaps, the offset) is checked only where an
anchor hit. Anchors are split by target type and case, so a scan runs only the
automata that can matter for the object's type, and a PE never walks the
HTML-only anchors. The automata that apply advance together over one read of
the object, whatever the number of signatures in them, so the processor waits on
their memory at the same time; case-insensitive ones read each byte lowercased.

Verification never backtracks: a body is a sequence of elements, and the
positions it can have reached after each one are kept as a set of intervals, so
a `{10-}` gap widens an interval instead of multiplying attempts. Backtracking
is left to PCRE subsignatures with lookaround or backreferences, which are not
regular and so cannot run on the linear engine: they run on a backtracking
engine under a step bound, after a linear prefilter (the pattern with its
lookarounds removed, which matches at least as much) has ruled most objects out.

### How far a check reads around a hit

<svg viewBox="0 0 790 310" role="img" aria-labelledby="lkn lkd" style="width:100%;height:auto;max-width:790px">
  <title id="lkn">How far a check reads around an anchor hit</title>
  <desc id="lkd">An object drawn as a strip of 64 KiB blocks. The sweep reads
  it in order, a chunk at a time, carrying the automaton's state across chunk
  seams. At an anchor hit, verification reads the body's prefix backward from
  the anchor and its suffix forward, as far as the body needs; a gap with no
  upper bound can reach the end of the object. A block no longer in the cache
  is read again. The cache bounds what is held, not how far a check reaches.</desc>
  <defs>
    <marker id="lk-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="16">THE OBJECT, IN 64 KIB BLOCKS</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="96" width="774" height="40" rx="4"/>
  </g>
  <g stroke="currentColor" stroke-width="1" stroke-dasharray="3 3" opacity="0.5">
    <path d="M104 96 V136"/><path d="M200 96 V136"/><path d="M296 96 V136"/>
    <path d="M392 96 V136"/><path d="M488 96 V136"/><path d="M584 96 V136"/>
    <path d="M680 96 V136"/>
  </g>
  <rect x="104" y="97" width="96" height="38" fill="currentColor" opacity="0.08"/>
  <rect x="420" y="97" width="56" height="38" fill="currentColor" opacity="0.35"/>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12" font-weight="600" text-anchor="middle">
    <text x="448" y="121">anchor</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#lk-arrow)">
    <path d="M8 60 H776"/>
    <path d="M420 160 H130"/>
    <path d="M476 160 H700"/>
    <path d="M700 196 H778" stroke-dasharray="4 4"/>
  </g>
  <g stroke="currentColor" stroke-width="1" opacity="0.5">
    <path d="M296 54 V66"/><path d="M584 54 V66"/>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="8" y="46">sweep: in order, a chunk at a time; the automaton's state carries across seams, so nothing is read twice</text>
    <text x="130" y="180">prefix: read backward from the anchor</text>
    <text x="490" y="180">suffix: read forward</text>
    <text x="490" y="214">a {n-} gap can reach the end of the object</text>
    <text x="110" y="84">not in the cache: read again</text>
    <text x="8" y="250">Offsets are checked against where the match starts: EOF-n everywhere, EP+n and Sn+n</text>
    <text x="8" y="268">only on an object held in memory. A ::f body is checked against the byte on each side.</text>
    <text x="8" y="292">Held: 8 MiB of 64 KiB blocks (the sweep reads 1 MiB chunks), least recently used dropped first.</text>
  </g>
</svg>

Neither the sweep nor a check has a window to fall out of. The automata read
the object once, in order, and their state carries from one chunk to the next,
so an anchor split across a seam is found without re-reading anything. A check
asks for the bytes it needs at their offset, before or after the hit, from
memory or, past `--max-object-bytes`, from the
[block cache](/concepts/streaming-memory/#past-it-through-a-block-cache).

Over an object not held in memory, regular expressions (PCRE subsignatures,
YARA strings) run as lazy DFAs stepped through it, forward to find where a match
ends and backward from there to find where it starts. A PCRE with lookaround
runs its lookaround-free superset that way: when that finds nothing, the PCRE
cannot match either; when it finds something, the scan is `LIMITS-EXCEEDED`
unless something else is found, as it is when a lazy DFA meets a construct it
cannot follow (a Unicode word boundary next to a non-ASCII byte).

## Reading an object not held in memory

<svg viewBox="0 0 790 392" role="img" aria-labelledby="bcn bcd" style="width:100%;height:auto;max-width:790px">
  <title id="bcn">One source, read through a block cache</title>
  <desc id="bcd">A file, an HTTP range reader or a spill file is read through a
  block cache of 64 KiB blocks holding 8 MiB. Every check asks it for bytes at
  an offset: the signature sweep a chunk at a time in order, verification and
  the container walk at any offset, the regexes stepped through, the hashes,
  typing's search and carving in one shared pass. The checks that parse an object whole run only when it fits within
  --max-object-bytes.</desc>
  <defs>
    <marker id="bc-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="16">SOURCES</text>
    <text x="520" y="16">WHAT READS IT</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="28" width="170" height="48" rx="6"/>
    <rect x="8" y="96" width="170" height="48" rx="6"/>
    <rect x="8" y="164" width="170" height="48" rx="6"/>
    <rect x="230" y="84" width="230" height="136" rx="6"/>
    <rect x="520" y="28" width="262" height="44" rx="6"/>
    <rect x="520" y="84" width="262" height="44" rx="6"/>
    <rect x="520" y="140" width="262" height="44" rx="6"/>
    <rect x="520" y="196" width="262" height="44" rx="6"/>
    <rect x="520" y="252" width="262" height="44" rx="6"/>
    <rect x="520" y="324" width="262" height="56" rx="6" stroke-dasharray="4 4"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600">
    <text x="93" y="50" text-anchor="middle">file</text>
    <text x="93" y="118" text-anchor="middle">HTTP range</text>
    <text x="93" y="186" text-anchor="middle">spill file</text>
    <text x="345" y="112" text-anchor="middle">BlockCache</text>
    <text x="532" y="48">signature sweep</text>
    <text x="532" y="104">verification</text>
    <text x="532" y="160">regexes</text>
    <text x="532" y="216">hashes · typing · carving</text>
    <text x="532" y="272">container walk</text>
    <text x="532" y="346">whole-object checks</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="93" y="66" text-anchor="middle">past --max-object-bytes</text>
    <text x="93" y="134" text-anchor="middle">a request per block</text>
    <text x="93" y="202" text-anchor="middle">a large member or view</text>
    <text x="345" y="136" text-anchor="middle">64 KiB blocks, 8 MiB held,</text>
    <text x="345" y="154" text-anchor="middle">least recently used dropped;</text>
    <text x="345" y="172" text-anchor="middle">bytes at any offset, or in</text>
    <text x="345" y="190" text-anchor="middle">1 MiB chunks in order</text>
    <text x="532" y="64">chunks in order, one pass</text>
    <text x="532" y="120">windows at any offset</text>
    <text x="532" y="176">lazy DFAs stepped through</text>
    <text x="532" y="232">one shared pass; start and end</text>
    <text x="532" y="288">headers and members, by offset</text>
    <text x="532" y="366">held whole only: PE, RAR, OLE</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#bc-arrow)">
    <path d="M178 52 H200 V120 H226"/>
    <path d="M178 120 H226"/>
    <path d="M178 188 H200 V150 H226"/>
    <path d="M460 120 H490 V50 H516"/>
    <path d="M490 106 H516"/>
    <path d="M490 120 V162 H516"/>
    <path d="M490 162 V218 H516"/>
    <path d="M490 218 V274 H516"/>
  </g>
</svg>

What the cache holds, and which checks parse an object whole and so do not run
past `--max-object-bytes`, is in
[Streaming & memory](/concepts/streaming-memory/#past-it-through-a-block-cache).

## Where the spill fits

<svg viewBox="0 0 790 330" role="img" aria-labelledby="spn spd" style="width:100%;height:auto;max-width:790px">
  <title id="spn">The two uses of spill files</title>
  <desc id="spd">Before a scan, a stream (stdin, INSTREAM, ICAP) is held in
  memory up to --spill-threshold-bytes and then in a temporary file up to
  --max-spill-bytes, and becomes a seekable source for the scan. Inside a scan,
  a streamed archive member that decodes past --max-object-bytes, and the normalised
  text views of a large text file, are written to spill files and read back
  through a block cache. A stream past its budget, or past the threshold with
  --spill-dir off, has what was held scanned; with --spill-dir off, such a
  member or view is not scanned. Either way a scan that finds nothing is
  LIMITS-EXCEEDED.</desc>
  <defs>
    <marker id="sp-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="16">BEFORE THE SCAN: A STREAM</text>
    <text x="8" y="176">INSIDE THE SCAN: WHAT IT MAKES</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="28" width="170" height="60" rx="6"/>
    <rect x="214" y="28" width="170" height="60" rx="6"/>
    <rect x="420" y="28" width="170" height="60" rx="6"/>
    <rect x="626" y="28" width="156" height="60" rx="6"/>
    <rect x="8" y="188" width="250" height="60" rx="6"/>
    <rect x="8" y="258" width="250" height="60" rx="6"/>
    <rect x="310" y="222" width="190" height="60" rx="6"/>
    <rect x="552" y="222" width="230" height="60" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600" text-anchor="middle">
    <text x="93" y="52">stdin · INSTREAM</text>
    <text x="299" y="52">RAM</text>
    <text x="505" y="52">temp file</text>
    <text x="704" y="52">the scan</text>
    <text x="133" y="212">member past the limit</text>
    <text x="133" y="282">text views, large file</text>
    <text x="405" y="246">spill file</text>
    <text x="667" y="246">scanned from there</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="93" y="72">ICAP bodies</text>
    <text x="299" y="72">--spill-threshold-bytes</text>
    <text x="505" y="72">--max-spill-bytes</text>
    <text x="704" y="72">a seekable source</text>
    <text x="133" y="232">decoded past --max-object-bytes</text>
    <text x="133" y="302">HTML, text, JS normalised</text>
    <text x="405" y="266">written as it is made</text>
    <text x="667" y="266">through a block cache</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#sp-arrow)">
    <path d="M178 58 H210"/>
    <path d="M384 58 H416"/>
    <path d="M590 58 H622"/>
    <path d="M258 218 H284 V248 H306"/>
    <path d="M258 288 H284 V256 H306"/>
    <path d="M500 252 H548"/>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="8" y="116">Past --max-spill-bytes, or past the threshold with --spill-dir off, what was held is</text>
    <text x="8" y="134">scanned and the stream is LIMITS-EXCEEDED unless that finds something.</text>
    <text x="8" y="152">--max-total-spill-bytes bounds every spill file of a process together.</text>
  </g>
</svg>

The library never writes to disk itself: the host hands a scan somewhere to
spill (the `exav` binary passes its `--spill-dir` files and budgets). Only a
member decoded as it is read can spill; one decoded whole is bounded by
`--max-object-bytes` (see [Archive members](/concepts/streaming-memory/#archive-members)).
Without a spill, a member that decodes past `--max-object-bytes` is not scanned,
the normalised views of a text file that large are skipped, and a scan that
found nothing is `LIMITS-EXCEEDED` rather than `OK`.
