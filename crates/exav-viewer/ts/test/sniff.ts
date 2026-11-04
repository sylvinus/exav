// exav_viewer_sniff.wasm as the tests run it: the module in this process,
// where the page has it in a worker (jsdom has none). Stands in for
// `ts/office/zip-engine.ts` (`openTailReader`) and `ts/core/sniff-engine.ts`
// (`sniffInWorker`).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import init, { contentType, contentTypes as listed, inspect, officeKinds, packageKinds as listedKinds, zipOfficeKinds, zipTail } from "../../wasm/exav_viewer_sniff.js";
import type { Finding, OfficeFinding } from "../core/detect.js";
import type { PackageLimits } from "../core/types.js";
import { packNames } from "../office/pack-names.js";
import type { TailReader, ZipTailRead } from "../office/zip-engine.js";

const wasm = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "wasm", "exav_viewer_sniff_bg.wasm");
let ready: Promise<unknown> | null = null;
const started = () => (ready ??= init({ module_or_path: fs.readFileSync(wasm) }));

/** What exav's detection says of the start of a file of `size` bytes. */
export async function sniffInWorker(head: Uint8Array, size: number): Promise<string> {
  await started();
  return contentType(head, size);
}

/** What exav's readers find of a file named as format `kind` (`inspect`). */
export async function inspectInWorker(kind: string, head: Uint8Array, tail: Uint8Array, size: number, limits: PackageLimits): Promise<Finding> {
  await started();
  const found = inspect(kind, head, tail, size, limits.maxExtractedBytes, limits.maxMembers, limits.maxCompressionRatio);
  try {
    return { verdict: found.verdict as Finding["verdict"], needs: found.needs, reason: found.reason };
  } finally {
    found.free();
  }
}

/** What the members of a ZIP say it may be, from its first and last bytes (`zipOfficeKinds`). */
export async function officeInWorker(head: Uint8Array, tail: Uint8Array, size: number): Promise<OfficeFinding> {
  await started();
  const found = zipOfficeKinds(head, tail, size);
  try {
    return { needs: found.needs, kinds: found.kinds };
  } finally {
    found.free();
  }
}

/** Starts the module, for a test that then calls `zipNamesNow` or `officeKindsNow`. */
export const start = (): Promise<unknown> => started();

/** The names in the directory of a whole ZIP, as the reader lists them (none if it opens none); after `start`. */
export function zipNamesNow(bytes: Uint8Array): string[] {
  const read = zipTail(bytes, bytes.length);
  try {
    return read.found ? read.names : [];
  } finally {
    read.free();
  }
}

/** What the container of a whole file says it may be, as `officeKinds` of `ts/office/zip.ts` finds it; after `start`. */
export function officeKindsNow(bytes: Uint8Array): string[] {
  return officeKinds(bytes, packNames(bytes[0] === 0x50 && bytes[1] === 0x4b ? zipNamesNow(bytes) : []));
}

/** Every type `sniffInWorker` can give. */
export async function contentTypes(): Promise<string[]> {
  await started();
  return listed();
}

/** The formats whose ZIP directory `inspect` checks against the limits. */
export async function packageKinds(): Promise<string[]> {
  await started();
  return listedKinds();
}

export function openTailReader(): TailReader {
  return {
    async read(tail, size): Promise<ZipTailRead> {
      await started();
      const read = zipTail(tail, size);
      try {
        return { found: read.found, needs: read.needs, end: read.end, names: read.names, sizes: Array.from(read.sizes) };
      } finally {
        read.free();
      }
    },
    async kinds(bytes, names) {
      await started();
      return officeKinds(bytes, packNames(names));
    },
    close() {},
  };
}
