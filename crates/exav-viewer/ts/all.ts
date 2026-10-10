/**
 * `@exav/viewer/all`: every built-in plugin, for a host that opens
 * everything. Importing it makes the host's bundler resolve every engine, so
 * every optional peer dependency must be installed; a host that opens only
 * some formats imports their plugins from their own subpaths instead.
 */
import { archive, type ArchiveOptions } from "./archive/index.js";
import { dwg, dxf, type CadOptions } from "./cad/plugin.js";
import type { FormatPlugin } from "./core/types.js";
import { ifc, type IfcOptions } from "./ifc/index.js";
import { image, type ImageOptions } from "./image/index.js";
import { audio, video } from "./media/index.js";
import { stl, type ModelOptions } from "./model/index.js";
import { csv, docx, pptx, xlsx, type OfficeOptions } from "./office/index.js";
import { pdf, type PdfOptions } from "./pdf/index.js";

export interface AllOptions {
  pdf?: PdfOptions;
  image?: ImageOptions;
  office?: OfficeOptions;
  cad?: CadOptions;
  ifc?: IfcOptions;
  model?: ModelOptions;
  archive?: ArchiveOptions;
}

export function allPlugins(o: AllOptions = {}): FormatPlugin<any>[] {
  return [
    pdf(o.pdf),
    image({ wasmDecoders: true, ...o.image }),
    dwg(o.cad),
    dxf(o.cad),
    video(),
    audio(),
    ifc(o.ifc),
    stl(o.model),
    docx(o.office),
    xlsx(o.office),
    pptx(o.office),
    csv(o.office),
    archive(o.archive),
  ];
}
