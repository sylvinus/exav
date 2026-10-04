/**
 * Choosing which spatial buckets a view touches.
 *
 * The tessellator sorts the vertex buffers into buckets and hands over a table
 * saying where each begins and what box it covers; this turns a view rectangle
 * into the draw ranges that cover it. Measured on a site plan of 2.17M
 * strokes, a view of the middle tenth holds 3.4% of them, and without this the
 * other 96.6% are put through the vertex shader every frame only to be
 * discarded.
 *
 * Two things this must get right, both of which are ways to drop geometry that
 * was actually on screen:
 *
 * - **The test is against the bucket's own box, not its grid square.** A long
 *   line belongs to one bucket and crosses many, so the tessellator records the
 *   true extent of each bucket's contents.
 * - **The view has to be inflated first.** A stroke's quad is half its
 *   lineweight plus a pixel wider than the segment, so geometry entirely
 *   outside the view can still paint inside it. See `viewMargin`.
 */

/** Bytes per tile, matching `TILE_BYTES` in crates/exav-render/src/formats/dwg/tiles.rs. */
export const TILE_BYTES = 24

/**
 * Largest number of draw calls one pass may issue.
 *
 * Adjacent buckets merge into a single call, so this is only approached by a
 * view scattered across many separate runs. Past it the remaining buckets are
 * drawn as one range covering everything between them, which draws too much
 * rather than too little.
 */
const MAX_RANGES = 1024

export interface Tile {
  start: number
  count: number
  minX: number
  minY: number
  maxX: number
  maxY: number
}

/** A contiguous run of the buffer to draw. */
export interface Range {
  start: number
  count: number
}

export function decodeTiles(bytes: ArrayBuffer): Tile[] {
  const v = new DataView(bytes)
  const n = Math.floor(bytes.byteLength / TILE_BYTES)
  const out: Tile[] = new Array(n)
  for (let i = 0; i < n; i++) {
    const o = i * TILE_BYTES
    out[i] = {
      start: v.getUint32(o + 0, true),
      count: v.getUint32(o + 4, true),
      minX: v.getFloat32(o + 8, true),
      minY: v.getFloat32(o + 12, true),
      maxX: v.getFloat32(o + 16, true),
      maxY: v.getFloat32(o + 20, true),
    }
  }
  return out
}

/**
 * How far outside the view geometry can still paint, in local units.
 *
 * The stroke shader builds a quad from the segment expanded by
 * `max(uMinWidth, widthPx) * 0.5 + 1` framebuffer pixels, so a segment wholly
 * outside the view can reach into it by that much. Lineweight runs to 211
 * hundredths of a millimetre; in model space that is a fixed pixel width, and
 * on a paper-space sheet it is a real width on the page that grows with zoom.
 * Both are covered by taking the larger.
 */
export function viewMargin(opts: {
  /** Local units per device pixel. */
  scale: number
  /** Device pixels per 1/100 mm, the model-space convention. */
  lineScale: number
  /** Local units per 1/100 mm, or 0 outside paper space. */
  lineWorld: number
  /** Minimum stroke width in device pixels. */
  minWidthPx: number
}): number {
  // Lineweight is clamped to 211 hundredths of a millimetre by the tessellator.
  const MAX_LINEWEIGHT = 211
  // The shader chooses between the two conventions rather than taking both:
  // on a sheet a lineweight is a width on the page, in model space it is a
  // width in pixels. Taking the larger would be safe but would inflate the
  // margin nearly fourfold on a sheet at ordinary zoom.
  const widthPx =
    opts.lineWorld > 0
      ? (MAX_LINEWEIGHT * opts.lineWorld) / opts.scale
      : MAX_LINEWEIGHT * opts.lineScale
  const halfPx = Math.max(opts.minWidthPx, widthPx) * 0.5 + 1
  return halfPx * opts.scale
}

/**
 * Draw ranges covering every tile in `[from, to)` that the view can touch.
 *
 * Adjacent tiles are merged, so a view over a contiguous block of the drawing
 * costs one call rather than one per bucket.
 */
export function visibleRanges(
  tiles: Tile[],
  from: number,
  to: number,
  view: { minX: number; minY: number; maxX: number; maxY: number },
  margin: number,
): Range[] {
  const minX = view.minX - margin
  const minY = view.minY - margin
  const maxX = view.maxX + margin
  const maxY = view.maxY + margin

  const ranges: Range[] = []
  for (let i = from; i < to; i++) {
    const t = tiles[i]
    if (t.maxX < minX || t.minX > maxX || t.maxY < minY || t.minY > maxY) continue
    const last = ranges[ranges.length - 1]
    if (last && last.start + last.count === t.start) {
      last.count += t.count
    } else {
      ranges.push({ start: t.start, count: t.count })
    }
  }

  // Too fragmented to be worth the call overhead: collapse to one span from the
  // first to the last, which over-draws rather than under-draws.
  if (ranges.length > MAX_RANGES) {
    const first = ranges[0]
    const last = ranges[ranges.length - 1]
    return [{ start: first.start, count: last.start + last.count - first.start }]
  }
  return ranges
}

/** Elements the ranges cover, for diagnostics. */
export function rangeTotal(ranges: Range[]): number {
  let n = 0
  for (const r of ranges) n += r.count
  return n
}
