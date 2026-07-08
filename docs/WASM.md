# WASM Sandboxed Scanning

exav can run its entire scanning engine inside a WebAssembly sandbox, letting
you load **untrusted signature databases** without giving them access to your
host. The scanner compiles to `wasm32-wasip1` — a standard WASI command — and
runs under any compatible runtime (wasmtime, wasmer, wazero, etc.) with **zero
custom host code**.

## Quick start

```sh
# 1. Build the WASM module
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 -p exav-wasm

# 2. Strip debug names (~10% smaller)
cargo install wasm-tools  # if not installed
wasm-tools strip -a target/wasm32-wasip1/release/exav_wasm.wasm \
  -o exav.wasm

# 3. Install wasmtime (if you don't have it)
# https://wasmtime.dev/

# 4. Scan a file
wasmtime \
  --dir /path/to/sigs::/db \
  --dir .::. \
  exav.wasm \
  /db malware.exe
```

The `--dir` flags mount directories into the WASM sandbox:

- `--dir /path/to/sigs::/db` — signature DB mounted at `/db` inside the module
- `--dir .::.` — current working directory mounted at `/` (so relative paths work)

## How it works

The WASM module is a plain WASI command — same as any CLI tool, but sandboxed:

1. **Startup**: reads CLI args via WASI
2. **Load signatures**: walks the mounted signature directory recursively,
   loading `.ndb`/`.ldb`/`.hdb`/`.cvd`/`.cld`/`.yar`/etc. files (including
   CVD/CLD container extraction — handled inside the module)
3. **Build database**: compiles the signature matcher (Aho-Corasick automaton)
4. **Scan files**: for each file argument, reads it from the mounted filesystem,
   runs the full scan (patterns, hashes, YARA, bytecode, structural analysis),
   and writes a JSON `ScanReport` to stdout

Progress and errors go to stderr. Results go to stdout — pipe to `jq`:

```sh
wasmtime --dir ./sigs::/db --dir .::. exav_wasm.wasm /db *.exe 2>/dev/null | jq '.verdict'
```

## Output format

Each scanned file produces one JSON object on stdout:

```json
{"verdict":"Clean","findings":[{"label":"type","detail":"PE32+ executable"}]}

{"verdict":{"Infected":{"signature":"Win.Trojan.Agent-1234","offset":4096,"method":"Pattern"}},"findings":[]}

{"verdict":{"LimitsExceeded":{"reason":"scan-size limit"}},"findings":[]}
```

`Verdict` variants: `Clean`, `Infected`, `LimitsExceeded`, `Unscannable`,
`PasswordProtected`.

## Why WASM?

### Threat model

When you load third-party signatures (community YARA rules, untrusted `.ndb`
sets, anything you didn't build yourself), the signature parser becomes part of
your attack surface. A malicious `.ndb` file could:

- Trigger a heap overflow in the parser → RCE
- Cause excessive memory allocation → DoS
- Exploit a parser bug to escape the scanner process

Running in native code, any of these compromise the host. In a WASM sandbox:

- **Memory is bounded** — the module can't access memory outside its linear
  memory instance
- **No system calls** — WASI restricts file/network access to explicitly mounted
  paths
- **Fuel limits** — wasmtime can cap instruction counts, killing runaway modules
- **No `unsafe` escape** — even if the Rust code has bugs, WASM type-checking
  prevents memory corruption from escaping the sandbox

### Why not a custom host?

An earlier design used a custom host binary (`exav-host`) that embedded the
`wasmi` WASM interpreter and called exported functions via a raw pointer ABI.
This had two problems:

1. **Trust shifts to the host** — users now had to trust both the WASM module AND the
   host binary. The host contained wasmi (less audited than wasmtime) plus
   custom pointer-manipulation code.

2. **No auditability** — the custom ABI (alloc/dealloc/load_file/scan) was
   opaque to users and hard to verify.

The new design uses a standard WASI command. Users bring their own wasmtime —
a ByteCode Alliance project, audited, used in production by Fastly, Cloudflare,
and others. The host code is wasmtime itself, not ours.

### Comparison

| | Native `exav` | Custom host (`exav-host`) | WASI command |
|---|---|---|---|
| Untrusted sigs | full host access | sandboxed, but custom host | sandboxed, no custom host |
| Runtime trust | N/A | wasmi (less audited) | wasmtime (audited, production) |
| Audit surface | entire codebase | host + wasmi + WASM | wasmtime only |
| Custom code | N/A | ~250 lines of pointer ABI | 0 lines |
| ABI | native calls | raw `extern "C"` pointers | standard WASI I/O |
| Portability | platform-specific binary | embeds WASM runtime | any WASI runtime |

## Security properties

### Memory safety

- The WASM module runs in a linear memory sandbox — no pointer escapes
- `exav-unpack` (the extraction engine) has `#![forbid(unsafe_code)]`
- `exav-core` scanning code is safe Rust
- Residual `unsafe` is in audited compression/crypto dependencies, not
  attacker-controlled parsing

### Resource limits

- **WASM linear memory**: bounded by the runtime (default 4 GiB max, typically
  much less)
- **Fuel/instructions**: wasmtime can limit total instructions per scan
- **Filesystem**: only mounted directories are accessible — the module can't
  read `/etc/passwd` or write to disk
- **Network**: no network access in WASI (unless explicitly enabled)

### Panic isolation

If the WASM module panics (e.g., on corrupt input), wasmtime catches it as a
trap — the host process is unaffected. This is the same isolation as the native
`catch_unwind` boundary, but at the WASM level.

## Building

```sh
# Requires Rust 1.85+ and the wasm32-wasip1 target
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 -p exav-wasm
```

The output is `target/wasm32-wasip1/release/exav_wasm.wasm` (~5-6 MB).

## Limitations

- **No daemon mode** — each `wasmtime run` invocation loads the DB from scratch.
  For high-throughput scanning, use the native `exav --daemon` instead.
- **No stdin streaming** — files must be on a mounted filesystem (WASI doesn't
  support the pipe-from-stdin pattern that native `exav` uses for streaming).
- **No HTTP(S) scanning** — the WASM module can't make network requests, so
  `exav://` URL targets aren't available.
- **~10-20% overhead** vs native — wasmtime JIT is fast, but the WASM
  sandboxing layer adds some cost.
- **DB loading is slower** — the full ClamAV DB build wants ~6 GiB transient
  RAM; in a WASM sandbox this is bounded by the runtime's memory limit. Use a
  prebuilt cache for large DBs.

## Alternatives

- **Native `exav`**: best performance, full features, but requires trusting the
  scanner with host access.
- **Docker container**: similar isolation to WASM but heavier — a full OS image
  vs a single `.wasm` file.
- **Browser (exav-unpack-wasm)**: the archive *extractor* (not the full scanner)
  runs in-browser via wasm-bindgen. Useful for client-side archive preview, but
  doesn't include signature scanning.
