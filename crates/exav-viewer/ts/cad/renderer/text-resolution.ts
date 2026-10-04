/**
 * Choosing the glyph atlas resolution from the view, instead of once at load.
 *
 * An atlas rasterised at a fixed em is wrong at both ends. Fitted to a sheet,
 * CAD text is three pixels tall and a 256px page is 99% waste; zoomed into a
 * detail, the same page is magnified eightfold and the text goes soft. The size
 * only makes sense relative to how big the text is actually being drawn, which
 * is a property of the camera, not of the drawing.
 *
 * So it is recomputed as the view changes. Two things keep that from thrashing:
 * the size is quantised to powers of two, so most camera movement does not
 * cross a boundary at all, and the caller debounces, so a pinch rebuilds once
 * when it settles rather than every frame.
 *
 * This is also the first use of the two pieces of machinery the renderer will
 * need for culling: a view-change trigger with hysteresis, and a query for what
 * is visible.
 */

import { TEXT_RECORD_BYTES } from './text-layout.js'

/** The camera, as this module needs it. Local (origin-relative) coordinates. */
export interface ViewRect {
  minX: number
  minY: number
  maxX: number
  maxY: number
  /** Local units per device pixel. Smaller means zoomed further in. */
  scale: number
}

/**
 * Cap height as a fraction of em, assumed when converting a DWG text height
 * into an em size.
 *
 * The real figure belongs to the face (Arimo 0.688, Tinos 0.655, Cousine
 * 0.659), but using the smallest of them for every face errs towards a larger
 * em, which errs towards sharper. The result is quantised to a power of two
 * straight afterwards, so a few percent either way rarely changes the answer.
 */
const ASSUMED_CAP_RATIO = 0.65

/**
 * Texture budget for the glyph page, in texels.
 *
 * This, rather than a ceiling on the em, is what bounds memory. 4M texels is
 * 4 MB as R8, about 5.4 MB once mipmapped: affordable on a tablet, and enough for a few hundred glyphs at 256px or a smaller set at
 * considerably more.
 */
const TEXEL_BUDGET = 4_000_000

/**
 * Texels one cell occupies, as a multiple of em squared.
 *
 * Measured rather than derived: 87 cells at 256px em packed into 4096x689,
 * which is 32.4k texels each, or 0.49 em². Glyphs are taller than they are
 * wide and the page has padding, so this is not something to reason out from
 * first principles.
 */
const TEXELS_PER_CELL_PER_EM2 = 0.5

/** Largest em whose page for `cells` glyphs still fits the budget. */
export function affordableEm(cells: number): number {
  if (cells <= 0) return Infinity
  return Math.sqrt(TEXEL_BUDGET / (cells * TEXELS_PER_CELL_PER_EM2))
}

/**
 * The em the tallest visible run needs to be drawn without magnification.
 *
 * Runs outside the view are ignored, which is what makes zooming into a detail
 * cheap: a sheet's worth of body text stops dictating the size as soon as it
 * scrolls off. Returns 0 when no text is visible.
 */
export function neededEm(records: ArrayBuffer, view: ViewRect): number {
  if (!(view.scale > 0)) return 0
  const v = new DataView(records)
  const runs = Math.floor(records.byteLength / TEXT_RECORD_BYTES)
  let tallest = 0

  for (let i = 0; i < runs; i++) {
    const o = i * TEXT_RECORD_BYTES
    const len = v.getUint16(o + 36, true)
    if (len === 0) continue
    const height = v.getFloat32(o + 8, true)
    if (!(height > 0) || height <= tallest) continue

    // A run's reach from its anchor, generously: `len` is a byte count, so it
    // over-counts any multi-byte character, and a full height per character is
    // wider than any face. Being generous costs a rebuild that was not needed;
    // being tight drops text that was visible.
    const x = v.getFloat32(o + 0, true)
    const y = v.getFloat32(o + 4, true)
    const reach = len * height
    if (
      x + reach < view.minX ||
      x - reach > view.maxX ||
      y + reach < view.minY ||
      y - reach > view.maxY
    ) {
      continue
    }
    tallest = height
  }

  if (tallest === 0) return 0
  // DWG text height is cap height; the atlas is in ems.
  return tallest / view.scale / ASSUMED_CAP_RATIO
}

/**
 * Zoom banked ahead of what the view currently needs.
 *
 * Without it the page is rasterised at exactly the size in use, so the very
 * next zoom step magnifies it and every doubling of zoom costs a rebuild. That
 * is what a reader notices: for the moment before the rebuild lands the text is
 * drawn from a page too small for it, which is not only softer but *heavier*,
 * because hinting at a small em snaps stems to whole pixels. A blurrier, fatter
 * glyph reads as a larger one, so the correction looks like the text shrinking.
 *
 * Four means a fourfold zoom before any of that can happen, which covers
 * ordinary wheel and pinch movement. It costs sixteen times the texels of an
 * exact fit, which is why the budget above exists to cap it.
 */
const ZOOM_HEADROOM = 4

/**
 * Em to rasterise the atlas at for this view, quantised, or 0 to leave it alone.
 *
 * What the view needs rounds *up* to a power of two, so text is never
 * magnified. What the budget allows is not rounded at all: rounding a cap up
 * is not a cap (an affordable 303 became 512, a 10.75 MB page against a 4 MB
 * budget), and rounding it down forfeits most of the allowance.
 *
 * `cells` is how many distinct face-and-character pairs the page has to hold.
 */
export function targetEmFor(records: ArrayBuffer, view: ViewRect, cells: number): number {
  const needed = neededEm(records, view)
  if (needed === 0) return 0
  // What the view wants is quantised, so that ordinary movement lands on the
  // page already built. The cap is not: once the budget is what decides the
  // size, the page stops growing and there is nothing left to thrash, while
  // rounding down to a power of two would forfeit most of the allowance:
  // 40 cells can afford an em of 447 and would be handed 256.
  const wanted = 2 ** Math.ceil(Math.log2(needed * ZOOM_HEADROOM))
  return Math.min(wanted, affordableEm(cells))
}
