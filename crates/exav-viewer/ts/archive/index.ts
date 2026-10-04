/**
 * `@exav/viewer/archive`: what is inside an archive, on `@exav/unpack-wasm`
 * (a peer dependency): zip, 7z, rar, and tar and its compressions (gz, bz2,
 * xz), or plain gz, bz2 and xz. Members open with whatever plugin fits them, in the
 * same viewer, an archive inside an archive included.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface ArchiveOptions {
  /** Defaults: 512 MiB extracted, 5000 members, ratio 200. */
  maxExtractedBytes?: number;
  maxMembers?: number;
  maxCompressionRatio?: number;
}

export function archive(options: ArchiveOptions = {}): FormatPlugin<ArchiveOptions> {
  return {
    id: "archive",
    match: MATCHERS.archive,
    capabilities: ["nested"],
    options,
    load: () => import("./renderer.js").then((m) => m.renderer),
  };
}

export { safeFileName } from "./names.js";
