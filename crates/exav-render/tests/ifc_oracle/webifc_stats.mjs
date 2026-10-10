// Per-element statistics of IFC files as web-ifc meshes them, in the JSON
// lines `examples/ifc_stats.rs` prints: the oracle of tests/ifc_oracle.rs.
// web-ifc is run as a black box through its public API only.
//
// usage: node webifc_stats.mjs WEB_IFC_DIR FILE.ifc
// WEB_IFC_DIR is an installed web-ifc package (0.0.77 was used), for
// example crates/exav-viewer/node_modules/web-ifc.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const [dir, file] = process.argv.slice(2);
const require = createRequire(import.meta.url);
const WebIFC = require(path.resolve(dir, "web-ifc-api-node.js"));

const api = new WebIFC.IfcAPI();
api.SetWasmPath(path.resolve(dir) + "/", true);
await api.Init();
const model = api.OpenModel(new Uint8Array(fs.readFileSync(file)), { COORDINATE_TO_ORIGIN: false });

const out = [];
api.StreamAllMeshes(model, (mesh) => {
  const lo = [Infinity, Infinity, Infinity];
  const hi = [-Infinity, -Infinity, -Infinity];
  let area = 0;
  let volume = 0;
  let triangles = 0;
  let ref = null;
  const geoms = mesh.geometries;
  for (let g = 0; g < geoms.size(); g++) {
    const placed = geoms.get(g);
    const geometry = api.GetGeometry(model, placed.geometryExpressID);
    const v = api.GetVertexArray(geometry.GetVertexData(), geometry.GetVertexDataSize());
    const ix = api.GetIndexArray(geometry.GetIndexData(), geometry.GetIndexDataSize());
    const m = placed.flatTransformation;
    // Column-major 4x4; web-ifc's output is Y-up: back to IFC's Z-up.
    const at = (i) => {
      const x = v[i * 6];
      const y = v[i * 6 + 1];
      const z = v[i * 6 + 2];
      const p = [m[0] * x + m[4] * y + m[8] * z + m[12], m[1] * x + m[5] * y + m[9] * z + m[13], m[2] * x + m[6] * y + m[10] * z + m[14]];
      return [p[0], -p[2], p[1]];
    };
    for (let t = 0; t + 2 < ix.length; t += 3) {
      const a = at(ix[t]);
      const b = at(ix[t + 1]);
      const c = at(ix[t + 2]);
      for (const q of [a, b, c]) for (let k = 0; k < 3; k++) (lo[k] = Math.min(lo[k], q[k])), (hi[k] = Math.max(hi[k], q[k]));
      const u = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
      const w = [c[0] - a[0], c[1] - a[1], c[2] - a[2]];
      const n = [u[1] * w[2] - u[2] * w[1], u[2] * w[0] - u[0] * w[2], u[0] * w[1] - u[1] * w[0]];
      area += Math.hypot(n[0], n[1], n[2]) / 2;
      ref ??= a;
      const [p, q, r] = [a, b, c].map((s) => [s[0] - ref[0], s[1] - ref[1], s[2] - ref[2]]);
      volume += (p[0] * (q[1] * r[2] - q[2] * r[1]) + p[1] * (q[2] * r[0] - q[0] * r[2]) + p[2] * (q[0] * r[1] - q[1] * r[0])) / 6;
      triangles++;
    }
    geometry.delete();
  }
  if (triangles > 0) {
    const cls = api.GetNameFromTypeCode(api.GetLineType(model, mesh.expressID)).toUpperCase();
    out.push(JSON.stringify({ id: mesh.expressID, class: cls, triangles, min: lo, max: hi, area, volume }));
  }
});
api.CloseModel(model);
process.stdout.write(out.join("\n") + "\n");
