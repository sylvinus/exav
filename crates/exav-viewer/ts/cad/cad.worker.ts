// Parsing and tessellation run here, so the page never sees an entity: only
// finished vertex buffers come back, transferred rather than copied.
import init, { drawingPreview, parseDrawing, unsupportedDrawingVersion, type Document } from "../../wasm/exav_viewer_dwg.js";

import { serve } from "../core/worker-host.js";
import type { DrawingPreview, LayerInfo, LayoutInfo, ParsedDrawing, Warnings } from "./types.js";

export type CadRequest =
  /**
   * Take the file and answer its thumbnail, if it has one, before the slow
   * part: the next `parse` without bytes parses this file. A DWG of a
   * release the engine does not read is answered with its version ID
   * (`unsupported`), and not kept.
   */
  | { kind: "load"; bytes: ArrayBuffer }
  /** Parse a DWG or DXF (the bytes given, else those loaded) and draw a layout; "" is model space. */
  | {
      kind: "parse";
      bytes?: ArrayBuffer;
      layout: string;
      background: Uint8Array;
      maxPrimitives: number;
      maxDecompressedBytes: number;
    }
  /** Draw another layout of the file already parsed. */
  | { kind: "layout"; layout: string; background: Uint8Array; maxPrimitives: number };

export type CadAnswer = ParsedDrawing | { preview: DrawingPreview | null; unsupported: string | null };

let ready: Promise<unknown> | null = null;
// The parsed document outlives a request, so a layout switch costs only a
// tessellation. It is the whole entity graph, so only one is held.
let doc: Document | null = null;
// A file loaded and not parsed yet.
let loaded: Uint8Array | null = null;

function draw(d: Document, r: { layout: string; background: Uint8Array; maxPrimitives: number }, started: number) {
  const drawing = d.tessellate(r.layout, r.background, r.maxPrimitives);
  try {
    const out: ParsedDrawing = {
      strokes: drawing.takeStrokes().buffer as ArrayBuffer,
      fills: drawing.takeFills().buffer as ArrayBuffer,
      texts: drawing.takeTexts().buffer as ArrayBuffer,
      textStrings: drawing.takeTextStrings().buffer as ArrayBuffer,
      strokeTiles: drawing.takeStrokeTiles().buffer as ArrayBuffer,
      fillTiles: drawing.takeFillTiles().buffer as ArrayBuffer,
      layers: JSON.parse(drawing.layersJson()) as LayerInfo[],
      layouts: JSON.parse(d.layoutsJson()) as LayoutInfo[],
      layout: drawing.layout,
      origin: Array.from(drawing.origin()) as [number, number],
      extents: Array.from(drawing.extents()) as [number, number, number, number],
      warnings: JSON.parse(drawing.warningsJson()) as Warnings,
      maxOrder: drawing.maxOrder(),
      opaqueStrokes: drawing.opaqueStrokes(),
      opaqueFills: drawing.opaqueFills(),
      opaqueStrokeTiles: drawing.opaqueStrokeTiles(),
      opaqueFillTiles: drawing.opaqueFillTiles(),
      parseMs: performance.now() - started,
    };
    return {
      value: out,
      transfer: [out.strokes, out.fills, out.texts, out.textStrings, out.strokeTiles, out.fillTiles],
    };
  } finally {
    drawing.free();
  }
}

serve<CadRequest, CadAnswer>(async (r) => {
  const started = performance.now();
  ready ??= init();
  await ready;
  if (r.kind === "load") {
    doc?.free();
    doc = null;
    const bytes = new Uint8Array(r.bytes);
    // A release the engine does not read is said so, and not parsed.
    const unsupported = unsupportedDrawingVersion(bytes) ?? null;
    loaded = unsupported ? null : bytes;
    const p = drawingPreview(bytes);
    if (!p) return { value: { preview: null, unsupported } };
    try {
      const preview: DrawingPreview = { mime: p.mime, data: p.takeData().buffer as ArrayBuffer };
      return { value: { preview, unsupported }, transfer: [preview.data] };
    } finally {
      p.free();
    }
  }
  if (r.kind === "parse") {
    doc?.free();
    doc = null;
    const bytes = r.bytes ? new Uint8Array(r.bytes) : loaded;
    loaded = null;
    if (!bytes) throw new Error("no drawing loaded");
    doc = parseDrawing(bytes, r.maxDecompressedBytes);
    return draw(doc, r, started);
  }
  if (!doc) throw new Error("no drawing loaded");
  return draw(doc, r, started);
});
