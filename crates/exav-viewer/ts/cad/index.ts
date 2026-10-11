/**
 * `@exav/viewer/cad`: DWG and DXF drawings on exav's own engine, a Rust
 * reader and tessellator compiled to WebAssembly (exav-render) and a WebGL2
 * renderer. No peer dependency.
 *
 * Also re-exports the renderer's helpers (`isCadSupported`, `layerColor`,
 * `GROUNDS`), which a bundle that only lists plugins does not want: it
 * imports `dwg` and `dxf` from `@exav/viewer/cad/plugin` instead.
 */
export { dwg, dxf, type CadOptions } from "./plugin.js";
export { buildLayerTree, layerIndicesIn, type LayerTreeNode, type LayerTreeOptions } from "./layer-tree.js";
export { isCadSupported, layerColor, GROUNDS } from "./view.js";
