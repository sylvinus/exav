// exav-unpack's ZIP reader and the Office format test (exav_viewer_sniff.wasm): what the end of a file says of its central directory, and what its container says it is.
import init, { officeKinds, zipTail } from "../../wasm/exav_viewer_sniff.js";

import { serve } from "../core/worker-host.js";
import type { ZipRequest, ZipTailRead } from "./zip-engine.js";

let ready: Promise<unknown> | null = null;

serve<ZipRequest, ZipTailRead | string[]>(async (request) => {
  ready ??= init();
  await ready;
  if ("bytes" in request) return { value: officeKinds(new Uint8Array(request.bytes), new Uint8Array(request.names)) };
  const read = zipTail(new Uint8Array(request.tail), request.size);
  try {
    return { value: { found: read.found, needs: read.needs, end: read.end, names: read.names, sizes: Array.from(read.sizes) } };
  } finally {
    read.free();
  }
});
