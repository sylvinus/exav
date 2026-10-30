/**
 * `@exav/viewer/archive`: what is inside an archive, on `@exav/unpack-wasm`
 * (a peer dependency): zip, 7z, rar, tar and its compressions (gz, bz2, xz,
 * zst, lz4, lz, Z), cab, lzh, arj, ar and deb, cpio, xar and pkg, the packages
 * that are zips (jar, apk...), comic books, chm, `winmail.dat`, and the iso, dmg,
 * wim and virtual disk images. Members open with whatever plugin fits them, in the
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
