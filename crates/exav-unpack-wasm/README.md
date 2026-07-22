# exav-unpack-wasm

WebAssembly bindings for [`exav-unpack`](../exav-unpack) — **memory-safe,
in-browser archive extraction** with no server round-trip and no native/C
dependencies. Because `exav-unpack` is pure Rust, the whole extractor (zip, rar,
7z, cab, arj, lha, tar, gz, xz, bz2, iso, cpio, ar, xar, ole, pdf, email, upx)
compiles to `wasm32-unknown-unknown`.

> Excluded from the workspace (it's a wasm32-target artifact, like `fuzz/`).
> Build it with its own manifest / `wasm-pack`.

## Build

```
# one-time
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# from this directory:
wasm-pack build --release --target web      # or --target bundler / nodejs
```

This emits a `pkg/` directory with the `.wasm` module + JS bindings.

**Publish from this directory with `npm publish`, never `wasm-pack publish`.**
`wasm-pack` regenerates `pkg/package.json` on every build, and that manifest
lists only the three build artifacts — no `LICENSE`, no `NOTICE`, no author.
Publishing from `pkg/` would ship a compiled module that statically links a large
permissively-licensed dependency graph with none of its required attribution.
The manifest here carries the full `files` list; `prepublishOnly` refuses to
publish if `LICENSE`, `NOTICE` or `README.md` is missing, so a publish from the
wrong directory fails rather than succeeding quietly.

### Presets

Three, and each is a complete choice rather than a starting point:

| Preset | `npm run` | Contents |
|---|---|---|
| `standard` *(default)* | `build` | Every format **except** the packer emulator |
| `full` | `build:full` | Everything, emulator included |
| `minimal` | `build:minimal` | zip, gzip, tar |

**Why the emulator is not in the default.** `pe-emu` unpacks a packed executable
by running its own stub under an x86 interpreter — the one component that
follows control flow the scanned file supplies rather than parsing data it
supplies. Its bounds are a fixed 120M-instruction budget that no caller can
lower, so a page that hits it hangs the tab, and that is not something a user
should discover from a hung tab.

**Use `full` when packed executables are part of what you are opening** and you
have somewhere to put the work: a Web Worker, or a server-side runtime where a
stalled instance costs nothing a user sees. It is the same code the CLI runs.

Any individual format also works as a feature, for a build narrower than
`minimal`:

```
wasm-pack build --release --target web -- --no-default-features --features zip,rar
```

## JavaScript API

```js
import init, { detectFormat, unpack, Archive } from "exav-unpack-wasm";

await init();

const buf = new Uint8Array(await file.arrayBuffer());

detectFormat(buf);   // -> "Zip" | "Rar" | "Arj" | ... | undefined

const members = await unpack(buf);   // rejects on unrecognised format
for (const m of members) {
  if (m.unsupported) {
    console.warn(m.name, "not extracted:", m.unsupported);
    continue;
  }
  console.log(m.name, m.bytes.length);
}
```

Hand it a `File` instead of bytes and the archive is never held whole — members
are read one at a time, straight out of the file on disk:

```js
const archive = await Archive.open(file);
for (const m of await archive.list()) {
  const entry = await archive.extract(m.index);
  console.log(entry.name, entry.bytes.length);
}
await archive.close();
```

- `detectFormat(bytes)` → the format name, or `undefined` if unrecognised.
- `unpack(bytes, passwords?, limits?)` → a promise for an array of
  `{ name, bytes: Uint8Array, data: ReadableStream, encrypted, unsupported }`.
  A member exav could not extract comes back with `unsupported` set and no data,
  rather than being dropped or handed back as raw bytes — so "the archive holds
  nothing dangerous" and "I could not read this member" stay distinguishable.
  Member names are returned **verbatim** — sanitize paths before writing them
  anywhere.
- `Archive.open(source, limits?, options?)` → an archive you can `list()` and
  `extract()` member by member. `source` is a `File`/`Blob`, a `Uint8Array`, or
  a `{ read(offset, length): Uint8Array, size: number }` object. `close()` when
  you are done with it.

### Why a `File` uses a Worker

exav's archive readers are synchronous — the same code the CLI runs, rather than
a second implementation written against async I/O, because two readers of the
same bytes are two sets of answers about them. Reading a `File` synchronously
needs `FileReaderSync`, which browsers provide only inside a Worker, so that is
where a `File` is opened. The package spawns the Worker itself and the API stays
a normal `await`.

The Worker is also what makes a decoder crash survivable. `wasm32-unknown-unknown`
is a `panic = "abort"` target, so the `catch_unwind` that turns a decoder panic
into a returned limit everywhere else in exav catches nothing here: a panic traps
the module and every later call into that instance fails. A Worker is disposable
in a way a page is not — the trap takes an instance you do not own, every pending
request is rejected with the reason rather than left unanswered, the Worker is
replaced, and the next archive opens on a fresh one. An archive opened on the old
one reports that it was replaced instead of waiting forever on a Worker that can
no longer answer.

The in-process path gets the same treatment without the isolation: a trap there
drops the module instance and rebuilds it on the next call, so one hostile
archive costs you that archive rather than the page.

Bytes already in memory take no Worker at all. If your bundler cannot resolve
`new URL("./worker.js", import.meta.url)`, pass your own:

```js
import workerUrl from "exav-unpack-wasm/worker?url";
const archive = await Archive.open(file, undefined, {
  worker: new Worker(workerUrl, { type: "module" }),
});
```

Where an archive carries an index — a ZIP's central directory, a tar's headers —
`list()` reads it and decompresses nothing, and `extract(i)` seeks straight to
the member. A single compressed stream such as gzip or xz has no index by
construction: there `list()` walks the archive, costing what `extractAll()`
costs, and the result is reused rather than walked twice.

### Limits

Both entry points take an optional limits object. Every key is optional; what
you leave out keeps the browser default.

```js
const archive = await Archive.open(file, {
  maxExtractedBytes: 64 * 1024 * 1024, // everything this archive may decompress
  maxBufferBytes: 16 * 1024 * 1024,    // the most one buffered object may hold
  maxMembers: 5000,
  maxRecursion: 4,                     // archives inside archives
  maxCompressionRatio: 200,            // decompression ratio
  allowedFormats: ["Zip", "Tar"],      // open only these; anything else is reported
});
```

`allowedFormats` narrows what a build will open **per call**, so one module can
serve a page that accepts archives and a page that does not. Names are the ones
`detectFormat` returns.

The check applies at both ends, and the two ends answer differently. An excluded
format at the **top level** never opens: `Archive.open` and `unpack` throw
`"<Format> is not in allowedFormats"`, because an archive you declined should not
become a handle you can call `list` on. An excluded format **nested inside** an
allowed one is **reported, not skipped**: the member comes back with
`unsupported` set, so your code can tell "I declined to open this" from "there
was nothing here". Those are different facts and should stay different.

**Two of the defaults are lower than the Rust library's on purpose**:
`maxExtractedBytes` is 128 MiB against the library's 1 GiB, and `maxBufferBytes`
is 32 MiB against 256 MiB. wasm32 caps the address space at 4 GiB and a browser
commonly allows far less, so the library's budgets let a page ask for more than
the tab can give. Running out is not an error you can catch: the module aborts
and takes its instance with it, so your `await` never resolves and you get no
result at all.

`maxMembers` (100000), `maxRecursion` (16) and `maxCompressionRatio` (1000) keep
the library's values — they bound counts and shapes rather than bytes, so the
address space is not what constrains them.

Raise them if the page can afford it — a desktop app in a Web Worker is not a
phone browser.
- `isVolumePart(name)` → whether a *filename* marks one part of a byte-split
  archive. Names only, so it is cheap enough to run over a whole drop.
- `joinVolumes(files)` → rejoin the split archives among files dropped together.

## Split archives

`big.7z.001`, `.002`, `.003` is one archive cut at arbitrary byte offsets. Open
any part on its own and there is no header, no directory, nothing to detect —
which is what a multi-file drop hands you. `joinVolumes` turns the group back
into files `Archive.open` can take:

```js
const sets = joinVolumes(files);           // [{ name, data, parts, incomplete }]
for (const s of sets) {
  if (s.incomplete) continue;              // see below
  const archive = await Archive.open(s.data);
}
```

`incomplete` is `null` for a set that rejoined, and otherwise a string saying
why it could not — with `data` holding the pieces that *were* present. Those are
handed back rather than dropped on purpose: their bytes belong to an archive
nothing can read any more, and letting them vanish silently is the one outcome
worth avoiding. Files that are not part of a set are simply absent from the
result; you already have them.

RAR `.partN` and ZIP `.zNN` volumes are not rejoined here. Each carries its own
headers and a member's data resumes *past* the next volume's header, so
concatenating them yields garbage that still looks like an archive.

## Notes

- **Sandboxed**: wasm is itself a sandbox, and extraction is bounded
  (decompression-bomb limits), so untrusted input is safe to feed client-side.
- **Deterministic**: extraction draws no randomness, so the module links no
  random-number source and needs no JS backend for one.
- **Size**: the raw `.wasm` is a few MB unoptimized; `wasm-pack` runs `wasm-opt`
  to shrink it considerably.
