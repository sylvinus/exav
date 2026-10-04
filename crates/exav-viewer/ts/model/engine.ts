/**
 * The IFC and STL engine: exav-render's readers in a worker
 * (`exav_viewer_model.wasm`), which sends back finished vertex buffers,
 * transferred rather than copied. Shared by `@exav/viewer/ifc` and
 * `@exav/viewer/model`.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";

/** exav-render's `DEFAULT_MAX_TRIANGLES`: about 330 MB of buffers. */
export const DEFAULT_MAX_TRIANGLES = 6_000_000;
/** A damaged file can declare counts that keep the reader busy. */
export const DEFAULT_TIMEOUT_MS = 120_000;

export interface ModelRequest {
  kind: "ifc" | "stl";
  bytes: ArrayBuffer;
  maxTriangles: number;
}

/** One class and colour's part of the buffers; offsets in vertices, indices and edge vertices. */
export interface BatchMeta {
  class: string;
  /** RGBA in 0..1 (sRGB), or null when the file gives none. */
  color: [number, number, number, number] | null;
  vertex: number;
  vertices: number;
  index: number;
  indices: number;
  edge: number;
  edges: number;
  /** Byte offset of its per-vertex RGB in `colors`, -1 for none. */
  color0: number;
}

export interface ElementMeta {
  id: number;
  globalId: string;
  class: string;
  name: string;
  /** Index into `nodes`. */
  node: number | null;
  /** [batch, first index, index count]. */
  ranges: [number, number, number][];
}

export interface ModelMeta {
  origin: [number, number, number];
  /** min xyz, max xyz, relative to `origin`. */
  bounds: [number, number, number, number, number, number] | null;
  batches: BatchMeta[];
  elements: ElementMeta[];
  nodes: { id: number; class: string; name: string; parent: number | null }[];
  warnings: { unsupported: Record<string, number>; invalid: number; booleansSkipped: number; truncated: number; damaged: boolean };
}

export interface ParsedModel {
  positions: Float32Array;
  normals: Float32Array;
  indices: Uint32Array;
  edges: Float32Array;
  colors: Uint8Array;
  meta: ModelMeta;
  parseMs: number;
}

export function createModelEngine(): WorkerHost<ModelRequest, ParsedModel> {
  return createWorkerHost<ModelRequest, ParsedModel>(() => new Worker(new URL("./model.worker.js", import.meta.url), { type: "module" }));
}

/** What is missing from the picture, for the `warnings` controller. */
export function modelWarnings(meta: ModelMeta, kind: "ifc" | "stl"): { key: string; count: number }[] {
  const w = meta.warnings;
  const unsupported = Object.values(w.unsupported).reduce((a, b) => a + b, 0);
  return [
    ...(w.truncated > 0 ? [kind === "ifc" ? { key: "model_truncated", count: w.truncated } : { key: "model_partial", count: 1 }] : []),
    ...(unsupported > 0 ? [{ key: "model_unsupported", count: unsupported }] : []),
    ...(w.damaged ? [{ key: "model_damaged", count: 1 }] : []),
  ];
}
