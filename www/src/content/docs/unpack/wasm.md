---
title: "@exav/unpack-wasm"
description: exav-unpack compiled to WebAssembly with typed JavaScript bindings, so a web page opens user-supplied archives without a server round trip, a File read a piece at a time in a Worker; Node runs it in-process.
---

`exav-unpack-wasm` compiles the [exav-unpack](/unpack/rust/) library to
WebAssembly, published on npm as `@exav/unpack-wasm` with typed JavaScript
bindings, so a web app can open user-supplied archives in the browser without
sending bytes to a server. It is pure Rust with no C dependencies, the sandbox
is the browser's, and the crate has no `unsafe` of its own.

```sh
npm install @exav/unpack-wasm
```

```js
import init, { Archive } from "@exav/unpack-wasm";

await init();                               // once, before the synchronous helpers
const archive = await Archive.open(file);   // a File from a drop or <input>
for (const m of await archive.list()) {
  const entry = await archive.extract(m.index);
  console.log(entry.name, entry.bytes.length);
}
await archive.close();
```

Bytes already in memory take one call:

```js
import init, { detectFormat, unpack } from "@exav/unpack-wasm";

await init();
const buf = new Uint8Array(await file.arrayBuffer());

detectFormat(buf);                   // "Zip", "Rar", ... or undefined
for (const m of await unpack(buf)) { // rejects on an unrecognised format
  if (m.unsupported) {
    console.warn(m.name, "not extracted:", m.unsupported);
    continue;
  }
  console.log(m.name, m.bytes.length);
}
```

## How a `File` is read

The archive readers read by offset, synchronously, the same code the CLI runs,
rather than a second implementation written against async I/O. Reading a
`Blob` synchronously needs `FileReaderSync`, which browsers provide only in a
Web Worker, so a `File`/`Blob` is opened there: the package spawns the Worker
itself, the API stays a normal `await`, and the file is read a piece at a
time, never held whole. If your bundler cannot resolve
`new URL("./worker.js", import.meta.url)`, pass your own Worker:

```js
import workerUrl from "@exav/unpack-wasm/worker?url";
const archive = await Archive.open(file, undefined, {
  worker: new Worker(workerUrl, { type: "module" }),
});
```

Bytes already in memory need no Worker: a `Uint8Array`/`ArrayBuffer` runs
in-process, as does a caller-supplied `{ read(offset, length): Uint8Array, size }`
reader, whose `read` is synchronous because the readers beneath it are.

A decoder trap costs the archive, not the page. wasm32 is a `panic = "abort"`
target, so the `catch_unwind` that contains a decoder panic elsewhere in exav
catches nothing here: a panic traps the module instance for good. The instance
is discarded instead. In the Worker, pending requests are rejected with the
reason and the Worker is replaced; an archive opened on the old one reports
that it was replaced rather than waiting forever. In-process, the instance is
rebuilt on the next call.

## In Node

The package is built for the web target, where `init()` fetches the `.wasm`
file next to the module. Node's `fetch` does not read `file:` URLs, so hand
`init` the module's bytes once; every later call reuses that instance:

```js
import { readFileSync } from "node:fs";
import init, { unpack } from "@exav/unpack-wasm";

const wasm = new URL("../pkg/exav_unpack_wasm_bg.wasm", import.meta.resolve("@exav/unpack-wasm"));
await init({ module_or_path: readFileSync(wasm) });

for (const m of await unpack(readFileSync("archive.zip"))) {
  console.log(m.name, m.unsupported || m.bytes.length);
}
```

Node has no Web Worker, so a `Blob` cannot be opened there. Pass bytes, or a
synchronous reader over a file descriptor to read a large archive a piece at a
time:

```js
import { openSync, readSync, fstatSync } from "node:fs";
import { Archive } from "@exav/unpack-wasm";

// after init(), as above
const fd = openSync("big.zip", "r");
const archive = await Archive.open({
  size: fstatSync(fd).size,
  read(offset, length) {
    const buf = Buffer.alloc(length);
    const n = readSync(fd, buf, 0, length, offset);
    return new Uint8Array(buf.buffer, buf.byteOffset, n);
  },
});
console.log(archive.format(), await archive.list());
await archive.close();
```

## API

| Call | Does |
|---|---|
| `Archive.open(source, limits?, options?)` | Open a `File`/`Blob` (in the Worker), or a `Uint8Array`/`ArrayBuffer`/sync reader (in-process). |
| `archive.format()` | The detected format's name, known since `open`. |
| `archive.list(passwords?)` | Every member's metadata, decoding nothing it can avoid: where the archive carries an index (a ZIP's central directory, a tar's headers) nothing is decompressed. `uncompressedSize` is what the archive declares, or -1 where it declares none (a gzip or xz stream). A format read whole (7z, RAR) is decoded to be listed. Where a limit stops the listing, the last entry says so. |
| `archive.extract(index, passwords?)` | One member, as an `Entry`. The archive is walked up to it, skipping the members before it undecoded where the format allows. |
| `archive.extractAll(passwords?)` | Every member, under one budget for the whole archive. Where a limit stops the walk, the last entry says so. For a format read whole (7z, RAR) this is one pass, where `extract(i)` over every `i` is many. |
| `archive.close()` | Release the archive and its reader. Safe to call twice. |
| `unpack(bytes, passwords?, limits?)` | `open` + `extractAll` in one call, for bytes in memory. |
| `detectFormat(bytes)` | The format these magic bytes name, or `undefined`. Like the next two, synchronous: call `await init()` once before using it. |
| `isVolumePart(name)` | Whether a filename marks one part of a byte-split archive (`big.7z.001`). Names only, cheap enough to run over a whole drop. |
| `joinVolumes(files)` | Rejoin the split archives among files dropped together, into data `Archive.open` can take. |

An `Entry` is `{ name, bytes: Uint8Array, data: ReadableStream, encrypted,
unsupported }`. `unsupported` is empty when the member decoded, and otherwise says
why not (unsupported compression, a missing password, a limit), with the member
still reported and no data, so "the archive holds nothing dangerous" and "I
could not read this member" stay distinguishable. Member names come back
verbatim; sanitize paths before writing them anywhere.

## Limits

`Archive.open` and `unpack` take an optional limits object. Every key is
optional; what you leave out keeps the browser default.

```js
const archive = await Archive.open(file, {
  maxExtractedBytes: 64 * 1024 * 1024, // everything this archive may decompress
  maxBufferBytes: 16 * 1024 * 1024,    // the most one buffered object may hold
  maxScannedBytes: 1024 * 1024 * 1024, // cumulative bytes fed to the matcher
  maxMembers: 5000,
  maxRecursion: 4,                     // archives inside archives
  maxCompressionRatio: 200,            // decompression ratio
  allowedFormats: ["Zip", "Tar"],      // open only these; anything else is reported
});
```

Two of the defaults are lower than the Rust library's on purpose:
`maxExtractedBytes` is 128 MiB against 1 GiB, and `maxBufferBytes` 32 MiB
against 256 MiB. wasm32 caps the address space at 4 GiB and a tab often gets
far less; running out is not an error you can catch: the module aborts and
your `await` never resolves. `maxMembers` (100000), `maxRecursion` (16) and
`maxCompressionRatio` (1000) keep the library's values, since they bound counts
and shapes rather than bytes. Raise them if the page can afford it: a desktop
app in a Web Worker is not a phone browser.

`allowedFormats` narrows what one call may open, named as `detectFormat`
names them; an unknown name is ignored. An excluded format at the top level
never opens: `Archive.open` and `unpack` throw `"<Format> is not in
allowedFormats"`. One nested inside an allowed format is reported, not
skipped: the member comes back with `unsupported` set, so your code can tell
"I declined to open this" from "there was nothing here".

## Split archives

`big.7z.001`, `.002`, `.003` is one archive cut at arbitrary byte offsets. Open
any part on its own and there is nothing to detect, which is what a multi-file
drop hands you. `joinVolumes` turns the group back into files `Archive.open`
can take:

```js
const sets = joinVolumes(files);           // [{ name, data, parts, incomplete }]
for (const s of sets) {
  if (s.incomplete) continue;              // see below
  const archive = await Archive.open(s.data);
}
```

`incomplete` is `null` for a set that rejoined, and otherwise says why it could
not, with `data` holding the pieces that were present rather than dropping
them. Files that are not part of a set are absent from the result.

RAR `.partN` and ZIP `.zNN` volumes are not rejoined here: each carries its own
headers, and a member's data resumes past the next volume's header, so
concatenating them gives something that still looks like an archive but is
not. The [command](/unpack/cli/) reads those sets.

## Builds

The npm package is the `standard` build: every format except the PE packer
emulator, which the Rust library's default includes. The emulator runs a
packed executable's own stub under an x86 interpreter, the one component that
follows control flow the file supplies, with a fixed instruction budget a
caller cannot lower, so on a page it can hang the tab. Building the package
yourself (`wasm-pack`, from `crates/exav-unpack-wasm`):

| Preset | `npm run` | Contents |
|---|---|---|
| `standard` (default) | `build` | Every format except the packer emulator |
| `full` | `build:full` | Everything, emulator included: for a Web Worker or a server-side runtime where a stalled instance costs nothing a user sees |
| `minimal` | `build:minimal` | ZIP, gzip and tar |

These formats are also features one by one, for a build narrower than
`minimal` (`wasm-pack build --release --target web -- --no-default-features --features zip,rar`):
`zip`, `gzip`, `tar`, `bzip2`, `xz`, `zstd`, `lzip`, `cab`, `sevenz`, `rar`,
`arj`, `lha`, `iso`, `ole`, `pdf`, `email`, `dmg`, `upx`, `ar`, `cpio`, `xar`.
For the rest, pick a preset.

Extraction draws no randomness, so the module links no random-number source
and needs no JavaScript backend for one.
