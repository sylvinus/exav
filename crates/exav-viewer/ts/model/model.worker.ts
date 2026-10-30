// Model reading runs here, so the page never sees the file's entities: only
// finished buffers come back, transferred.
import init, { gltfBuffers, parseGltf, parseGltfWith, parseIfc, parseObj, parsePly, parseStl } from "../../wasm/exav_viewer_model.js";

import { serve } from "../core/worker-host.js";
import type { ModelAnswer, ModelKind, ModelMeta, ModelRequest, ParsedModel } from "./engine.js";

let ready: Promise<unknown> | null = null;

const READERS: Record<ModelKind, typeof parseIfc> = { ifc: parseIfc, stl: parseStl, obj: parseObj, ply: parsePly, gltf: parseGltf };

serve<ModelRequest, ModelAnswer>(async (r) => {
  const started = performance.now();
  ready ??= init();
  await ready;
  const bytes = new Uint8Array(r.bytes);
  if (r.list) return { value: { buffers: JSON.parse(gltfBuffers(bytes)) as string[] } };
  let model: ReturnType<typeof parseIfc>;
  if (r.kind === "gltf" && r.files?.length) {
    const lengths = new Uint32Array(r.files.map((f) => f.bytes.byteLength));
    const joined = new Uint8Array(lengths.reduce((a, b) => a + b, 0));
    let at = 0;
    for (const f of r.files) {
      joined.set(new Uint8Array(f.bytes), at);
      at += f.bytes.byteLength;
    }
    model = parseGltfWith(bytes, r.maxTriangles, r.files.map((f) => f.name), joined, lengths);
  } else model = READERS[r.kind](bytes, r.maxTriangles);
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
