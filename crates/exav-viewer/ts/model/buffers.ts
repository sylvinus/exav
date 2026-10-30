import { createSourceReader } from "../core/source.js";
import { resolveInTree } from "../core/tree.js";
import type { FileTree } from "../core/types.js";

/** The bytes of the buffer files of a glTF held at once. */
const MAX_BUFFER_BYTES = 1024 * 1024 * 1024;

/**
 * The buffer files a glTF names (`uris`, as the document writes them:
 * relative, percent-encoded) that the tree has, by the URI that names each.
 * One it does not have is left out, and the reader says so.
 */
export async function readBuffers(tree: FileTree, uris: string[], signal: AbortSignal): Promise<{ name: string; bytes: ArrayBuffer }[]> {
  const out: { name: string; bytes: ArrayBuffer }[] = [];
  let held = 0;
  for (const uri of uris) {
    let path = uri;
    try {
      path = decodeURIComponent(uri);
    } catch {
      // A name that is not valid percent-encoding is looked for as written.
    }
    const found = resolveInTree(tree, path);
    if (found === null) continue;
    const reader = createSourceReader(await tree.open(found, signal), signal);
    try {
      const bytes = (await reader.bytes()).slice();
      held += bytes.byteLength;
      if (held > MAX_BUFFER_BYTES) break;
      out.push({ name: uri, bytes: bytes.buffer as ArrayBuffer });
    } finally {
      reader.dispose();
    }
  }
  return out;
}
