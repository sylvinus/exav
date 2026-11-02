// exav-render's slides module (exav_viewer_slides.wasm): the page gets back the PPTX.
import init, { convertSlides } from "../../wasm/exav_viewer_slides.js";

import { serve } from "../core/worker-host.js";
import type { SlideRequest, SlideResult } from "./slides.js";

let ready: Promise<unknown> | null = null;

serve<SlideRequest, SlideResult>(async ({ bytes, format, maxShapes, maxMemory }) => {
  ready ??= init();
  await ready;
  const converted = convertSlides(new Uint8Array(bytes), format, maxShapes, maxMemory, Infinity);
  try {
    const pptx = converted.takePptx();
    return {
      value: { pptx: pptx.buffer as ArrayBuffer, slides: converted.slides, warnings: converted.warnings },
      transfer: [pptx.buffer as ArrayBuffer],
    };
  } finally {
    converted.free();
  }
});
