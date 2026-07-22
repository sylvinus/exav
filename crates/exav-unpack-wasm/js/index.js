// The public entry point.
//
// The wasm module beneath this is synchronous throughout, because
// `exav_unpack::Archive` is `Read + Seek` and meeting it on its own terms is
// what lets a browser build share exav's archive readers instead of carrying a
// second set. Synchronous reads of a `File` need `FileReaderSync`, which exists
// only inside a Worker — so this file routes a `File` to a Worker and presents
// the async API a page actually wants.
//
// Bytes already in memory take no Worker at all: a `Cursor` is already
// `Read + Seek`, so that path runs in-process and the caller cannot tell the
// difference except in how fast it returns.

import init, {
  Archive as WasmArchive,
  unpack as wasmUnpack,
  detectFormat,
  joinVolumes,
  isVolumePart,
} from "../pkg/exav_unpack_wasm.js";

export { detectFormat, joinVolumes, isVolumePart };

/**
 * Instantiate the module, once.
 *
 * Memoised because `init` builds a fresh instance every call, and every method
 * below awaits it: without this, a page that extracts ten archives compiles the
 * module ten times and each `Archive` ends up pointing into a different wasm
 * memory from the one that made it.
 */
let initialized = null;
function ready(...args) {
  initialized = initialized ?? init(...args);
  return initialized;
}
export default ready;

/**
 * Run something against the in-process module, surviving a trap.
 *
 * `wasm32-unknown-unknown` is a `panic = "abort"` target — the `catch_unwind`
 * that turns a decoder panic into a returned limit everywhere else in exav
 * catches nothing here. A panic traps the module, its memory is gone, and every
 * later call into that instance fails. Left alone that makes ONE hostile
 * archive break the page for good.
 *
 * So the instance is treated as spent: dropped, rebuilt on the next call, and
 * the failure reported as this archive's failure rather than as silence.
 */
function inProcess(fn) {
  try {
    return fn();
  } catch (e) {
    // Only a TRAP poisons the instance. An ordinary `Err` from the Rust side
    // arrives here as a thrown value too — "index out of bounds", "no password"
    // — and those leave the module perfectly healthy. Treating them alike would
    // throw away a working instance on every routine error, and would report a
    // caller's own mistake as a decoder crash.
    //
    // A trap does not arrive under one name. A panic or a failed allocation
    // aborts and surfaces as `WebAssembly.RuntimeError`, but an exhausted stack
    // surfaces as a plain `RangeError` — and it leaves the module just as
    // unusable, mid-frame with Rust's invariants broken. Matching only the
    // obvious name left that one running on a poisoned instance.
    const poisoned = e instanceof WebAssembly.RuntimeError || e instanceof RangeError;
    if (!poisoned) throw e;
    initialized = null;
    throw new Error(`the decoder trapped on this archive: ${(e && e.message) || e}`);
  }
}

// ---------------------------------------------------------------------------
// Worker plumbing
// ---------------------------------------------------------------------------

let sharedWorker = null;
let nextRequestId = 1;
const pending = new Map();

function spawnWorker(override) {
  const worker =
    override ?? new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  worker.onmessage = (event) => {
    const { id, ok, value, error } = event.data;
    const waiting = pending.get(id);
    if (!waiting) return;
    pending.delete(id);
    if (ok) waiting.resolve(value);
    else waiting.reject(new Error(error));
  };
  // A Worker that dies takes every outstanding request with it. Leaving those
  // Promises unsettled would hang the caller forever with no way to find out
  // why, so they are all rejected with the reason.
  //
  // This is the containment `catch_unwind` cannot give here. A decoder panic
  // traps the module, and on a `panic = "abort"` target there is no catching
  // it in Rust — but a Worker is disposable in a way a page is not. The trap
  // takes an instance the caller does not own, every request that instance held
  // is answered with an error rather than left unanswered, and the next archive
  // opens on a fresh one.
  worker.onerror = (event) => {
    const why = new Error(
      `the decoder trapped in the archive worker: ${event.message || "unknown error"}`,
    );
    for (const [, waiting] of pending) waiting.reject(why);
    pending.clear();
    if (sharedWorker === worker) sharedWorker = null;
    worker.terminate();
  };
  return worker;
}

function call(worker, op, args, transfer = []) {
  const id = nextRequestId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, args }, transfer);
  });
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

/**
 * Present one member the way callers consume it.
 *
 * `data` is a ReadableStream, and `bytes` the same content as a Uint8Array.
 * The stream is what crosses into a page that wants to pipe the member
 * somewhere; the bytes are what everything else wants, and deriving one from
 * the other at the call site is a step every caller was repeating.
 */
function presentEntry(raw) {
  const bytes = raw.data;
  return {
    name: raw.name,
    bytes,
    get data() {
      return new Blob([bytes]).stream();
    },
    encrypted: raw.encrypted,
    unsupported: raw.unsupported,
  };
}

// ---------------------------------------------------------------------------
// Archive
// ---------------------------------------------------------------------------

/**
 * An open archive.
 *
 * Obtained from `Archive.open`. Members are listed without extracting them, and
 * extracted one at a time — for a `File` that means the archive is never held
 * in memory whole.
 */
export class Archive {
  #worker = null;
  #handle = 0;
  #local = null;
  #format = "";
  #closed = false;

  constructor(guard) {
    if (guard !== Archive) {
      throw new TypeError("use Archive.open()");
    }
  }

  /**
   * Open an archive.
   *
   * `source` is a `File`/`Blob`, which is read a piece at a time in a Worker,
   * or a `Uint8Array`/`ArrayBuffer`, which is read in-process.
   *
   * `options.worker` supplies a Worker instead of letting this module create
   * one, for bundlers that cannot resolve `new URL("./worker.js",
   * import.meta.url)`.
   */
  static async open(source, limits, options = {}) {
    const archive = new Archive(Archive);

    if (source instanceof Blob) {
      // Respawned transparently when a previous archive trapped: the caller
      // that opens the NEXT archive did nothing wrong and should not inherit
      // the last one's failure.
      sharedWorker = sharedWorker ?? spawnWorker(options.worker);
      archive.#worker = sharedWorker;
      const { handle, format } = await call(archive.#worker, "open", { source, limits });
      archive.#handle = handle;
      archive.#format = format;
      return archive;
    }

    // Everything else runs in-process: bytes are already in memory, and a
    // caller-supplied `read` is synchronous, so neither needs a Worker. What
    // counts as a valid source is decided in one place, in the wasm module —
    // duplicating that test here is how the two come to disagree.
    await ready();
    archive.#local = WasmArchive.open(
      source instanceof ArrayBuffer ? new Uint8Array(source) : source,
      limits,
    );
    archive.#format = archive.#local.format();
    return archive;
  }

  /** The detected format's name. Known since `open`, so no round trip. */
  format() {
    return this.#format;
  }

  #check() {
    if (this.#closed) throw new Error("archive is closed");
    // A trapped Worker is replaced, not reused, so an archive opened on the old
    // one no longer refers to anything. `postMessage` to a dead Worker neither
    // throws nor arrives, which would leave the caller waiting on a promise
    // that can never settle — worse than an error, because nothing ever says
    // the scan did not happen.
    if (this.#worker && this.#worker !== sharedWorker) {
      throw new Error(
        "the archive worker was replaced after a decoder trap; reopen this archive",
      );
    }
  }

  /**
   * Every member's metadata.
   *
   * Where the archive carries an index — a ZIP's central directory, a tar's
   * headers — this decompresses nothing. A single compressed stream such as
   * gzip or xz has no index by construction, so its members are only knowable
   * by walking the archive; there this takes passwords and costs what
   * `extractAll` costs. The result is held, so calling both is not two walks.
   */
  async list(passwords) {
    this.#check();
    return this.#local
      ? inProcess(() => this.#local.list(passwords))
      : call(this.#worker, "list", { handle: this.#handle, passwords });
  }

  /** Extract one member by index. */
  async extract(index, passwords) {
    this.#check();
    const raw = this.#local
      ? inProcess(() => this.#local.extract(index, passwords))
      : await call(this.#worker, "extract", { handle: this.#handle, index, passwords });
    return presentEntry(raw);
  }

  /**
   * Extract every member.
   *
   * Bounded by one budget across the whole archive, so `maxMembers`,
   * `maxExtractedBytes` and the compression-ratio guard apply to the archive
   * rather than to each member. Where a limit stops the walk, the last entry
   * says so instead of the list simply ending.
   */
  async extractAll(passwords) {
    this.#check();
    const raw = this.#local
      ? inProcess(() => this.#local.extractAll(passwords))
      : await call(this.#worker, "extractAll", { handle: this.#handle, passwords });
    return raw.map(presentEntry);
  }

  /**
   * Release the archive.
   *
   * For a `File` this frees the buffered reader inside the Worker, which would
   * otherwise live as long as the Worker does. Calling it twice is harmless.
   */
  async close() {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#local) {
      this.#local.free();
      this.#local = null;
    } else if (this.#worker) {
      await call(this.#worker, "close", { handle: this.#handle });
    }
  }
}

/**
 * Extract every member from bytes already in memory.
 *
 * The one-line form of `Archive.open` + `extractAll` for callers that have the
 * bytes and want the contents. Takes no Worker: there is nothing to stream.
 */
export async function unpack(data, passwords, limits) {
  await ready();
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return wasmUnpack(bytes, passwords, limits).map(presentEntry);
}
