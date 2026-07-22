// The Worker side of the File path.
//
// WHY THIS EXISTS: `exav_unpack::Archive` is `Read + Seek`, and the only
// synchronous way to read a `Blob` is `FileReaderSync`, which browsers expose
// only inside a Worker. Running here is what lets a `File` be read through the
// same archive code as everything else, a member at a time, without loading it
// whole. The alternative was a second set of archive readers written against
// async I/O — and a second reader is a second set of answers about the same
// bytes.
//
// This file is an RPC shim and nothing else. Every decision about archives is
// in the wasm module; the only logic here is matching replies to requests.

import init, { Archive } from "../pkg/exav_unpack_wasm.js";

/** Open archives, by handle. A handle is dead only when the caller closes it. */
const open = new Map();
let nextHandle = 1;

const ready = init();

/** Run one request, returning whatever should be sent back as `value`. */
function dispatch(op, args) {
  if (op === "open") {
    const archive = Archive.open(args.source, args.limits);
    const handle = nextHandle++;
    open.set(handle, archive);
    // The format travels back with the handle so the caller's `format()` can
    // stay synchronous, as it is for an in-memory archive.
    return { handle, format: archive.format() };
  }

  const archive = open.get(args.handle);
  if (!archive) {
    throw new Error(`archive handle ${args.handle} is not open`);
  }

  switch (op) {
    case "list":
      return archive.list(args.passwords);
    case "extract":
      return archive.extract(args.index, args.passwords);
    case "extractAll":
      return archive.extractAll(args.passwords);
    case "close":
      // `free` is wasm-bindgen's destructor. Without it the archive — and the
      // buffered reader inside it — stays live in the Worker's memory for as
      // long as the Worker does.
      archive.free();
      open.delete(args.handle);
      return null;
    default:
      throw new Error(`unknown operation: ${op}`);
  }
}

self.onmessage = async (event) => {
  const { id, op, args } = event.data;
  try {
    await ready;
    self.postMessage({ id, ok: true, value: dispatch(op, args) });
  } catch (e) {
    // An Error does not survive structured clone with its message intact in
    // every engine, and a caller that gets `{}` back cannot act on it. The
    // message is sent as a string and rebuilt on the other side.
    self.postMessage({ id, ok: false, error: String((e && e.message) || e) });
  }
};
