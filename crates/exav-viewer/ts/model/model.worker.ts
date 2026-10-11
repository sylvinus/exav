// IFC and STL reading runs here, so the page never sees the file's
// entities: only finished buffers come back, transferred.
import init, { parseIfc, parseStl } from "../../wasm/exav_viewer_model.js";

import { serve } from "../core/worker-host.js";
import type { ModelMeta, ModelRequest, ParsedModel } from "./engine.js";

let ready: Promise<unknown> | null = null;

serve<ModelRequest, ParsedModel>(async (r) => {
  const started = performance.now();
  ready ??= init();
  await ready;
  const model = (r.kind === "ifc" ? parseIfc : parseStl)(new Uint8Array(r.bytes), r.maxTriangles);
  try {
    const out: ParsedModel = {
      positions: model.takePositions(),
      normals: model.takeNormals(),
      indices: model.takeIndices(),
      edges: model.takeEdges(),
      colors: model.takeColors(),
      meta: JSON.parse(model.metaJson()) as ModelMeta,
      parseMs: performance.now() - started,
    };
    return {
      value: out,
      transfer: [out.positions.buffer, out.normals.buffer, out.indices.buffer, out.edges.buffer, out.colors.buffer] as ArrayBuffer[],
    };
  } finally {
    model.free();
  }
});
