import type { FileTree } from "./types.js";

/** Case and accents the way a file system compares names: macOS stores them decomposed, Windows does not mind case. */
const key = (s: string) => s.normalize("NFC").toLowerCase();

/** The parts of a path a document wrote on its own machine: either slash, no drive, no `.`. */
function parts(reference: string): string[] {
  return reference
    .replace(/\\/g, "/")
    .replace(/^[A-Za-z]:/, "")
    .split("/")
    .filter((s) => s !== "" && s !== ".");
}

/** Leading directories two paths share. */
function shared(a: string[], b: string[]): number {
  let n = 0;
  while (n < a.length && n < b.length && key(a[n]!) === key(b[n]!)) n++;
  return n;
}

/**
 * The file of `tree` a reference found in another file names, or null. A
 * reference is written for the machine that made the file: `.\Plans\x.dwg`,
 * `C:\Projects\site\x.dwg`, `..\x`, or just `x`. It is looked for beside the
 * file, as a path from it, and else by the end of its path, down to the file's
 * name alone: the nearest of several wins. Case, accents' form and either
 * slash are not told apart. `extensions` are tried after a name that has none.
 */
export function resolveInTree(tree: Pick<FileTree, "path" | "paths">, reference: string, extensions: readonly string[] = []): string | null {
  const asked = parts(reference);
  const last = asked[asked.length - 1];
  if (last === undefined) return null;
  const variants = [asked];
  if (!last.includes(".")) for (const e of extensions) variants.push([...asked.slice(0, -1), last + e]);

  const here = tree.path.split("/").filter(Boolean);
  const where = here.slice(0, -1);
  const files = tree.paths.filter((p) => p !== tree.path).map((p) => ({ path: p, key: key(p), dir: p.split("/").filter(Boolean).slice(0, -1) }));
  const byKey = new Map(files.map((f) => [f.key, f.path]));

  for (const variant of variants) {
    // As a path from the file's own folder.
    const from = [...where];
    let outside = false;
    for (const s of variant) {
      if (s === "..") {
        if (from.pop() === undefined) outside = true;
      } else from.push(s);
    }
    if (!outside) {
      const exact = byKey.get(key(from.join("/")));
      if (exact !== undefined) return exact;
    }
    // By the end of the path, the longest first.
    const named = variant.filter((s) => s !== "..");
    for (let k = 0; k < named.length; k++) {
      const tail = key(named.slice(k).join("/"));
      const hits = files.filter((f) => f.key === tail || f.key.endsWith("/" + tail));
      if (hits.length === 0) continue;
      hits.sort((a, b) => shared(where, b.dir) - shared(where, a.dir) || a.dir.length - b.dir.length || (a.path < b.path ? -1 : 1));
      return hits[0]!.path;
    }
  }
  return null;
}
