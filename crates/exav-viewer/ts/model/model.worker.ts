// Model reading runs here, so the page never sees the file's entities: only
// finished buffers come back, transferred.
import init, { parseGltf, parseIfc, parseObj, parsePly, parseStl } from "../../wasm/exav_viewer_model.js";

import { serve } from "../core/worker-host.js";
import type { ModelKind, ModelMeta, ModelRequest, ParsedModel } from "./engine.js";

let ready: Promise<unknown> | null = null;

const READERS: Record<ModelKind, typeof parseIfc> = { ifc: parseIfc, stl: parseStl, obj: parseObj, ply: parsePly, gltf: parseGltf };

serve<ModelRequest, ParsedModel>(async (r) => {
  const started = performance.now();
  ready ??= init();
  await ready;
  const model = READERS[r.kind](new Uint8Array(r.bytes), r.maxTriangles);
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
