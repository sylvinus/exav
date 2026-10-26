// The model module as the worker calls it, and what the plugins make of its
// answer: the budget reaches the reader, the warnings name what is missing.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import init, { gltfBuffers, parseGltf, parseGltfWith, parseIfc, parseObj, parsePly, parseStl } from "../../wasm/exav_viewer_model.js";
import { modelWarnings, type ModelMeta } from "./engine.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// The house of the browser tests, as exav-render's tests keep it.
const sample = (name: string) => new Uint8Array(fs.readFileSync(path.join(root, "..", "exav-render", "tests", "fixtures", "viewer", name)));

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(root, "wasm", "exav_viewer_model_bg.wasm")) });
});

describe("the model module", () => {
  it("reads the demo house whole, and within a budget leaves elements out and says how many", () => {
    const whole = parseIfc(sample("house.ifc"), 6e6);
    const meta = JSON.parse(whole.metaJson()) as ModelMeta;
    // Four walls and a slab, twelve triangles each.
    expect(meta.elements.map((e) => e.class).sort()).toEqual(["IFCSLAB", "IFCWALL", "IFCWALL", "IFCWALL", "IFCWALL"]);
    expect(whole.takeIndices().length / 3).toBe(60);
    expect(modelWarnings(meta, "ifc")).toEqual([]);
    whole.free();

    const part = parseIfc(sample("house.ifc"), 30);
    const cut = JSON.parse(part.metaJson()) as ModelMeta;
    expect(cut.elements).toHaveLength(2);
    expect(modelWarnings(cut, "ifc")).toEqual([{ key: "model_truncated", count: 3 }]);
    part.free();
  });

  it("hands over buffers that agree with the batches", () => {
    const m = parseIfc(sample("house.ifc"), 6e6);
    const meta = JSON.parse(m.metaJson()) as ModelMeta;
    const positions = m.takePositions();
    const indices = m.takeIndices();
    for (const b of meta.batches) {
      for (const i of indices.subarray(b.index, b.index + b.indices)) expect(i).toBeLessThan(b.vertices);
    }
    expect(positions.length / 3).toBe(meta.batches.reduce((n, b) => n + b.vertices, 0));
    m.free();
  });

  it("reads an STL, and refuses what is not one", () => {
    const m = parseStl(sample("house.stl"), 6e6);
    expect(m.takeIndices().length / 3).toBe(30);
    expect(modelWarnings(JSON.parse(m.metaJson()) as ModelMeta, "stl")).toEqual([]);
    m.free();
    const part = parseStl(sample("house.stl"), 10);
    expect(modelWarnings(JSON.parse(part.metaJson()) as ModelMeta, "stl")).toEqual([{ key: "model_partial", count: 1 }]);
    part.free();
    expect(() => parseStl(new Uint8Array([1, 2, 3]), 10)).toThrow("not an STL file");
    expect(() => parseIfc(new TextEncoder().encode("%PDF-1.7"), 10)).toThrow("not a STEP file");
  });

  // A tetrahedron of volume 1/6 with a square face on top: 4 + 2 triangles.
  const obj = "g base\nv 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 2 4\nf 1 4 3\nf 2 3 4\ng top\nv 0 0 2\nv 1 0 2\nv 1 1 2\nv 0 1 2\nf 5 6 7 8\n";
  const bounds = (m: ReturnType<typeof parseObj>) => (JSON.parse(m.metaJson()) as ModelMeta).bounds;

  it("reads an OBJ with its groups as elements, a polygon as triangles", () => {
    const m = parseObj(new TextEncoder().encode(obj), 100);
    const meta = JSON.parse(m.metaJson()) as ModelMeta;
    expect(m.takeIndices().length / 3).toBe(6);
    expect(meta.elements.map((e) => e.name)).toEqual(["base", "top"]);
    expect(meta.elements.map((e) => e.ranges[0]![2])).toEqual([12, 6]);
    expect(meta.bounds).toEqual([0, 0, 0, 1, 1, 2]);
    expect(modelWarnings(meta, "obj")).toEqual([]);
    m.free();
    const part = parseObj(new TextEncoder().encode(obj), 4);
    expect(modelWarnings(JSON.parse(part.metaJson()) as ModelMeta, "obj")).toEqual([{ key: "model_partial", count: 1 }]);
    part.free();
    expect(() => parseObj(new Uint8Array([0, 1, 2]), 10)).toThrow("not an OBJ file");
    expect(bounds(parseObj(new TextEncoder().encode("v 0 0 0\nv 1 0 0\nv 0 1 0\nv nan 0 0\nf 1 2 3\nf 1 2 4\n"), 10))).toEqual([0, 0, 0, 1, 1, 0]);
  });

  it("reads a PLY and refuses a point cloud", () => {
    const ply = "ply\nformat ascii 1.0\nelement vertex 4\nproperty float x\nproperty float y\nproperty float z\nproperty uchar red\nproperty uchar green\nproperty uchar blue\nelement face 1\nproperty list uchar int vertex_indices\nend_header\n0 0 0 255 0 0\n1 0 0 0 255 0\n1 1 0 0 0 255\n0 1 0 9 9 9\n4 0 1 2 3\n";
    const m = parsePly(new TextEncoder().encode(ply), 100);
    expect(m.takeIndices().length / 3).toBe(2);
    // Six corners, each with its vertex's colour: red twice at least, the grey one in both triangles.
    const c = Array.from(m.takeColors());
    const corners = Array.from({ length: 6 }, (_, i) => c.slice(i * 3, i * 3 + 3).join(","));
    expect(corners.filter((k) => k === "255,0,0").length).toBeGreaterThanOrEqual(1);
    expect(corners.filter((k) => k === "9,9,9").length).toBeGreaterThanOrEqual(1);
    expect(new Set(corners)).toEqual(new Set(["255,0,0", "0,255,0", "0,0,255", "9,9,9"]));
    m.free();
    const cloud = "ply\nformat ascii 1.0\nelement vertex 1\nproperty float x\nproperty float y\nproperty float z\nend_header\n0 0 0\n";
    expect(() => parsePly(new TextEncoder().encode(cloud), 10)).toThrow("point cloud");
    expect(() => parsePly(new TextEncoder().encode("hello"), 10)).toThrow("not a PLY file");
  });

  it("reads a glTF with a transformed node, and refuses one that points at another file", () => {
    const f = new Float32Array([0, 0, 0, 1, 0, 0, 0, 1, 0]);
    const data = Buffer.from(f.buffer).toString("base64");
    const doc = (uri: string, node: string) =>
      JSON.stringify({
        asset: { version: "2.0" },
        buffers: [{ uri, byteLength: 36 }],
        bufferViews: [{ buffer: 0, byteLength: 36 }],
        accessors: [{ bufferView: 0, componentType: 5126, count: 3, type: "VEC3" }],
        meshes: [{ primitives: [{ attributes: { POSITION: 0 } }] }],
        nodes: [{ mesh: 0, ...JSON.parse(node) }],
        scenes: [{ nodes: [0] }],
      });
    const m = parseGltf(new TextEncoder().encode(doc(`data:application/octet-stream;base64,${data}`, '{"translation":[10,0,0],"scale":[2,2,2]}')), 10);
    expect((JSON.parse(m.metaJson()) as ModelMeta).bounds).toEqual([10, 0, 0, 12, 2, 0]);
    m.free();
    expect(() => parseGltf(new TextEncoder().encode(doc("http://example.com/a.bin", "{}")), 10)).toThrow("references external files");
    expect(() => parseGltf(new TextEncoder().encode("{}"), 10)).toThrow("not a glTF file");
  });

  it("reads a glTF whose buffer is a file it is given, by the name the document writes", () => {
    const f = new Float32Array([0, 0, 0, 1, 0, 0, 0, 1, 0]);
    const doc = new TextEncoder().encode(
      JSON.stringify({
        asset: { version: "2.0" },
        buffers: [{ uri: "tri%20one.bin", byteLength: 36 }],
        bufferViews: [{ buffer: 0, byteLength: 36 }],
        accessors: [{ bufferView: 0, componentType: 5126, count: 3, type: "VEC3" }],
        meshes: [{ primitives: [{ attributes: { POSITION: 0 } }] }],
        nodes: [{ mesh: 0, translation: [10, 0, 0] }],
        scenes: [{ nodes: [0] }],
      }),
    );
    expect(JSON.parse(gltfBuffers(doc))).toEqual(["tri%20one.bin"]);
    const bin = new Uint8Array(f.buffer);
    // Two files given: the one the document names is the second.
    const files = new Uint8Array([7, 7, 7, ...bin]);
    const m = parseGltfWith(doc, 10, ["other.bin", "tri%20one.bin"], files, new Uint32Array([3, 36]));
    expect((JSON.parse(m.metaJson()) as ModelMeta).bounds).toEqual([10, 0, 0, 11, 1, 0]);
    m.free();
    expect(() => parseGltfWith(doc, 10, ["other.bin"], files, new Uint32Array([3]))).toThrow("references external files");
    expect(() => parseGltfWith(doc, 10, ["tri%20one.bin"], files, new Uint32Array([300]))).toThrow("longer than the bytes given");
    expect(JSON.parse(gltfBuffers(new TextEncoder().encode(JSON.stringify({ asset: { version: "2.0" }, buffers: [{ uri: "data:;base64,AAAA", byteLength: 3 }] }))))).toEqual([]);
  });
});
