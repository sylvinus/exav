import { createSourceReader } from "../core/source.js";
import type { FileTree } from "../core/types.js";

/** The bytes of all the volumes of a set the viewer holds at once. */
export const MAX_VOLUME_BYTES = 1024 * 1024 * 1024;

const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const baseOf = (p: string) => p.slice(p.lastIndexOf("/") + 1);

export type Volumes =
  /** The set made whole: what `Archive.open` takes. */
  | { kind: "joined"; data: Blob | Uint8Array; parts: string[] }
  /** A part of a set with volumes missing from the files around it. */
  | { kind: "incomplete"; missing: boolean }
  /** Not a part of a set: the file is an archive on its own. */
  | null;

/**
 * The volumes of the split archive the file is one of, read from the files
 * beside it in the tree (the same folder: a set is named by its stem), and
 * made one archive. Byte-split volumes (`big.7z.001`) are a Blob of the
 * parts, which the archive reader reads where it needs; RAR and ZIP volumes
 * (`x.part1.rar`, `x.rar` and `x.r00`, `x.z01` and `x.zip`) go through the
 * decoders' joiners, in memory.
 */
export async function volumesAround(tree: FileTree, signal: AbortSignal): Promise<Volumes> {
  const dir = dirOf(tree.path);
  const beside = tree.paths.filter((p) => dirOf(p) === dir).map(baseOf);
  const unpack = await import("@exav/unpack-wasm");
  await unpack.default();
  const set = unpack.volumeSet(baseOf(tree.path), beside);
  if (!set) return null;
  if (!set.complete) return { kind: "incomplete", missing: true };
  const bytes: Uint8Array[] = [];
  let held = 0;
  for (const name of set.parts) {
    const reader = createSourceReader(await tree.open(dir ? `${dir}/${name}` : name, signal), signal);
    try {
      const part = (await reader.bytes()).slice();
      held += part.length;
      if (held > MAX_VOLUME_BYTES) return { kind: "incomplete", missing: false };
      bytes.push(part);
    } finally {
      reader.dispose();
    }
  }
  const data = set.scheme === "split" ? new Blob(bytes as BlobPart[]) : unpack.joinSet(set.scheme, bytes);
  return { kind: "joined", data, parts: set.parts };
}
