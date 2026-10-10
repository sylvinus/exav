// pdf.js imports this module when `${wasmUrl}openjpeg.wasm` (or `jbig2.wasm`)
// does not instantiate, calls its default export, and uses only what that
// returns: `_malloc`, `_free`, `writeArrayToMemory`, `_jp2_decode` (or
// `_jbig2_decode` and `_ccitt_decode`), then `imageData` and `errorMessages`.
// Behind them is exav-render's decoder, in the WebAssembly module embedded
// above, so that nothing else is fetched.
//
// The pointers are handles to buffers kept here: the decoder sees only a copy
// of the bytes, never an address pdf.js computed.

let compiled = null;

function wasmBytes() {
  const text = atob(WASM);
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i);
  return out;
}

export default async function createDecoder() {
  if (!compiled) {
    compiled = WebAssembly.compile(wasmBytes());
    compiled.catch(() => (compiled = null));
  }
  const module = await compiled;
  let api = null;
  // A trap (a decoder panic, or memory exhausted) leaves an instance
  // unusable: the next call gets a new one.
  const live = () => {
    if (!api) {
      const b = bindings();
      b.initSync({ module });
      api = b;
    }
    return api;
  };
  const call = (f) => {
    try {
      return f(live());
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) api = null;
      throw e;
    }
  };
  const exports = live();

  const buffers = new Map();
  let next = 8;
  const input = (ptr, size) => buffers.get(ptr)?.subarray(0, size) ?? new Uint8Array(0);
  const m = {
    imageData: null,
    _malloc(size) {
      const ptr = next;
      next += 8;
      buffers.set(ptr, new Uint8Array(size));
      return ptr;
    },
    _free(ptr) {
      buffers.delete(ptr);
    },
    writeArrayToMemory(array, ptr) {
      buffers.get(ptr)?.set(array);
    },
  };

  if (exports.decodeJpx) {
    // Returns non-zero with `errorMessages` set on failure, as OpenJPEG's does.
    m._jp2_decode = (ptr, size, numComponents, isIndexedColormap, smaskInData, reducePower) => {
      try {
        const out = call((a) => a.decodeJpx(input(ptr, size), numComponents, !!isIndexedColormap, !!smaskInData, reducePower | 0));
        m.imageData = out ? new Uint8ClampedArray(out.buffer, out.byteOffset, out.length) : null;
        return 0;
      } catch (e) {
        m.errorMessages = e instanceof Error ? e.message : String(e);
        return 1;
      }
    };
  }
  if (exports.decodeJbig2) {
    // No `imageData` is the failure, as with PDFium's.
    m._jbig2_decode = (ptr, size, width, height, globalsPtr, globalsSize) => {
      try {
        const globals = globalsSize > 0 ? input(globalsPtr, globalsSize) : new Uint8Array(0);
        const out = call((a) => a.decodeJbig2(input(ptr, size), width, height, globals));
        m.imageData = new Uint8ClampedArray(out.buffer, out.byteOffset, out.length);
      } catch {
        m.imageData = null;
      }
    };
    m._ccitt_decode = (ptr, size, width, height, k, endOfLine, encodedByteAlign, blackIs1, columns, rows) => {
      try {
        m.imageData = call((a) => a.decodeCcitt(input(ptr, size), width, height, k, !!endOfLine, !!encodedByteAlign, !!blackIs1, columns, rows));
      } catch {
        m.imageData = null;
      }
    };
  }
  return m;
}
