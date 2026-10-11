// exav-render's image decoders, for the formats browsers do not draw.
import init, { decodeImage } from "../../wasm/exav_viewer_image.js";

import { serve } from "../core/worker-host.js";
import type { DecodeRequest, DecodeResult } from "./decode.js";

let ready: Promise<unknown> | null = null;

serve<DecodeRequest, DecodeResult>(async ({ bytes, maxBytes }) => {
  ready ??= init();
  await ready;
  const image = decodeImage(new Uint8Array(bytes), maxBytes);
  try {
    const rgba = image.takeRgba();
    return {
      value: { width: image.width, height: image.height, rgba: rgba.buffer as ArrayBuffer },
      transfer: [rgba.buffer as ArrayBuffer],
    };
  } finally {
    image.free();
  }
});
