/**
 * The sandboxed frame app for some formats only: which of its files they
 * need. `dist/frame/files.json` (scripts/build-frame.mjs) says whose each
 * file is, and `../frame/engines.ts` which engines a format needs.
 */
import { BUILTIN_ORDER } from "../core/formats.js";
import type { BuiltinFormat } from "../core/types.js";
import { engineClosure, ENGINES, FRAME_FORMATS_META, shippedFormats } from "../frame/engines.js";

export interface FrameFilesManifest {
  /** The files every frame has, relative to the frame app. */
  core: string[];
  /** The files of each engine. */
  engines: Record<string, string[]>;
  /** What `licenses/README.txt` says, by package. */
  notices: { header: string[]; packages: Record<string, string[]> };
}

export interface FrameSubset {
  /** The files to publish. */
  files: Set<string>;
  /** The formats the frame then opens: those asked for, and the others of their engines. */
  formats: BuiltinFormat[];
  /** `licenses/README.txt` for these files. */
  readme: string;
}

/** The names `formats` is made of, or an error naming the one that is none. */
export function checkFrameFormats(formats: readonly string[]): BuiltinFormat[] {
  const unknown = formats.filter((f) => !(BUILTIN_ORDER as readonly string[]).includes(f));
  if (unknown.length) throw new Error(`not a format of the viewer: ${unknown.join(", ")} (${BUILTIN_ORDER.join(", ")})`);
  if (!formats.length) throw new Error("the frame needs at least one format");
  return formats as BuiltinFormat[];
}

/**
 * What the frame needs to open `formats`, and the formats it then opens.
 * With `external`, an external converter is published with it: what it
 * answers is shown by the PDF and spreadsheet engines.
 */
export function frameSubset(manifest: FrameFilesManifest, formats: readonly BuiltinFormat[], external = false): FrameSubset {
  const engines = engineClosure(formats, external);
  const files = new Set(manifest.core);
  for (const id of engines) for (const f of manifest.engines[id] ?? []) files.add(f);
  const packages = [...engines].flatMap((id) => ENGINES[id]!.notices ?? []);
  const readme = `${[...manifest.notices.header, ...[...new Set(packages)].flatMap((p) => manifest.notices.packages[p] ?? [])].join("\n")}\n`;
  return { files, formats: shippedFormats(formats, external), readme };
}

/** The page of a frame that opens only `formats`: its `<meta>` says so. */
export function pageFor(html: string, formats: readonly BuiltinFormat[]): string {
  const meta = `<meta name="${FRAME_FORMATS_META}" content="*" />`;
  if (!html.includes(meta)) throw new Error("the frame's index.html does not list the formats it opens");
  return html.replace(meta, `<meta name="${FRAME_FORMATS_META}" content="${formats.join(",")}" />`);
}
