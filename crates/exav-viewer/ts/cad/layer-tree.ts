import type { Layer } from './types.js'

/**
 * Grouping for layer lists.
 *
 * DWG layer names are flat strings; the format has no folders. Two things are
 * worth grouping on anyway:
 *
 *  - `|` is a real, format-level namespace. Layers pulled in from an external
 *    reference are named `xrefname|layername`, so that split is always correct.
 *  - `_` is convention. Offices almost universally encode a discipline prefix
 *    (`03_GO_MACONNERIE`, `15_TX_100`), and grouping on it turns a 139-entry
 *    flat list into something navigable. It is a naming habit, not a guarantee,
 *    so the tree only ever groups names that do share a prefix and never
 *    hides a layer that does not fit.
 */
export interface LayerTreeOptions {
  /**
   * Segment separators, most significant first. Default `['|', '_']`.
   * Pass `[]` for a flat list.
   */
  separators?: string[]
  /** Maximum grouping depth. Default `2`. */
  maxDepth?: number
  /** A group needs at least this many layers to form. Default `2`. */
  minGroupSize?: number
}

export type LayerTreeNode =
  | { kind: 'layer'; label: string; index: number; layer: Layer }
  | { kind: 'group'; label: string; path: string; children: LayerTreeNode[] }

interface Entry {
  index: number
  layer: Layer
  /** Name split into segments, with the separator that followed each. */
  segs: string[]
  seps: string[]
}

function tokenize(name: string, separators: string[]): { segs: string[]; seps: string[] } {
  if (separators.length === 0) return { segs: [name], seps: [] }
  const segs: string[] = []
  const seps: string[] = []
  let current = ''
  for (const ch of name) {
    if (separators.includes(ch)) {
      segs.push(current)
      seps.push(ch)
      current = ''
    } else {
      current += ch
    }
  }
  segs.push(current)
  return { segs, seps }
}

/** Rebuild the original prefix for the first `n` segments. */
function joinPrefix(e: Entry, n: number): string {
  let out = ''
  for (let i = 0; i < n; i++) {
    out += e.segs[i]
    if (i < n - 1 || i < e.seps.length) out += e.seps[i] ?? ''
  }
  return out
}

function leafLabel(e: Entry, depth: number): string {
  if (depth <= 0) return e.layer.name
  // Everything past the grouped prefix, separators included.
  const prefix = joinPrefix(e, depth)
  return e.layer.name.slice(prefix.length) || e.layer.name
}

function separatorsAtEnd(path: string, separators: string[]): boolean {
  return path.length > 0 && separators.includes(path[path.length - 1])
}

function buildLevel(
  entries: Entry[],
  depth: number,
  maxDepth: number,
  minGroupSize: number,
  separators: string[],
): LayerTreeNode[] {
  const asLeaf = (e: Entry): LayerTreeNode => ({
    kind: 'layer',
    label: leafLabel(e, depth),
    index: e.index,
    layer: e.layer,
  })

  if (depth >= maxDepth || entries.length < minGroupSize) {
    return sortNodes(entries.map(asLeaf))
  }

  // Bucket by this level's segment, preserving first-seen order.
  const buckets = new Map<string, Entry[]>()
  for (const e of entries) {
    // A name with nothing after this segment cannot be grouped further.
    const key = e.segs.length > depth + 1 ? e.segs[depth] : ''
    const list = buckets.get(key)
    if (list) list.push(e)
    else buckets.set(key, [e])
  }

  const out: LayerTreeNode[] = []
  for (const [key, list] of buckets) {
    if (key === '' || list.length < minGroupSize) {
      // Not groupable: keep these at this level, labelled in full.
      for (const e of list) out.push({ kind: 'layer', label: leafLabel(e, depth), index: e.index, layer: e.layer })
      continue
    }

    let children = buildLevel(list, depth + 1, maxDepth, minGroupSize, separators)
    let path = joinPrefix(list[0], depth + 1)

    // Collapse a group whose only child is another group, so a chain like
    // `01` > `PM` becomes one `01_PM` row instead of two expansions.
    while (children.length === 1 && children[0].kind === 'group') {
      const only = children[0]
      path = only.path
      children = only.children
    }

    // The label is the prefix without its trailing separator, which stays
    // correct however many levels were collapsed into it.
    const label = separatorsAtEnd(path, separators) ? path.slice(0, -1) : path
    out.push({ kind: 'group', label, path, children })
  }

  return sortNodes(out)
}

/**
 * Groups first, then loose layers, each alphabetically.
 *
 * Without this the ungroupable names all share one bucket and land in a single
 * block at the top, which buries the structured layers a user is looking for.
 * `numeric` keeps `15_TX_100` after `15_TX_020` rather than before it.
 */
function sortNodes(nodes: LayerTreeNode[]): LayerTreeNode[] {
  const cmp = (a: string, b: string) =>
    a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
  return nodes.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'group' ? -1 : 1
    return cmp(a.label, b.label)
  })
}

/**
 * Build a tree over a flat layer list.
 *
 * Every layer appears exactly once. Names that do not share a prefix with
 * anything else stay at the top level rather than being forced into a group.
 */
export function buildLayerTree(layers: Layer[], options: LayerTreeOptions = {}): LayerTreeNode[] {
  const separators = options.separators ?? ['|', '_']
  const maxDepth = options.maxDepth ?? 2
  const minGroupSize = options.minGroupSize ?? 2

  const entries: Entry[] = layers.map((layer, index) => ({
    index,
    layer,
    ...tokenize(layer.name, separators),
  }))

  return buildLevel(entries, 0, maxDepth, minGroupSize, separators)
}

/** Every layer index under a node, groups included. */
export function layerIndicesIn(node: LayerTreeNode): number[] {
  if (node.kind === 'layer') return [node.index]
  return node.children.flatMap(layerIndicesIn)
}
