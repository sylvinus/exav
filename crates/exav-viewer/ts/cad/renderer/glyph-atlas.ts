/**
 * Glyph atlas built with Canvas 2D.
 *
 * Only the characters a drawing actually uses are rasterised, and only in the
 * faces it actually asks for: a typical sheet needs a hundred or so cells
 * rather than several whole fonts.
 *
 * One page holds every face, keyed by face and character together. That keeps
 * text to a single texture and a single draw call however many faces a drawing
 * mixes, which matters because a title block can name three in one paragraph.
 *
 * The atlas is white-on-opaque-black and uploaded as R8, so the red channel is
 * the coverage value. Drawing onto a transparent canvas instead would not work:
 * the browser hands back *unpremultiplied* pixels, so a half-covered edge is
 * still pure white in RGB and all the antialiasing would be thrown away.
 *
 * Stroke text never arrives here. It is drawn as geometry on the Rust side so
 * the drawing's lineweight can decide its thickness, which a rasterised glyph
 * could not honour.
 */

import { CAP_RATIO, cssFont, decodeFace, type Face } from './fonts.js'

/**
 * Smallest and largest em to rasterise at.
 *
 * The em size is what bounds how far text can be zoomed before it goes soft,
 * and it is chosen per view rather than once: see `targetEmFor` in
 * `text-resolution.ts`. A fitted sheet needs 16 and a page of a few hundred
 * kilobytes; the same drawing zoomed into a detail needs several hundred, and
 * only then pays for it.
 *
 * The ceiling is high because the budget, not the ladder, is what keeps memory
 * bounded. A drawing with a small character set can afford 1024 and stay sharp
 * past a hundredfold zoom.
 */
const MIN_EM = 16
const MAX_EM = 1024
/** Page width, capped so the page stays squarish and within reach of any GPU. */
const MAX_ATLAS_WIDTH = 4096
/** Texture limit assumed when the caller does not say. */
const DEFAULT_MAX_SIZE = 4096
/** Space between cells, so linear filtering cannot bleed one into the next. */
const PAD = 3

/**
 * Bring an em into the range the atlas will rasterise at.
 *
 * Quantising is `targetEmFor`'s job, not this one: it rounds what the view
 * needs to a power of two so that ordinary movement does not cross a boundary,
 * but leaves the budget cap exact. Rounding the cap down to a power of two too
 * threw away most of the budget: 40 cells can afford an em of 447 and were
 * given 256, using 1.3 MB of an allowance of 4.
 */
export function clampEm(em: number): number {
  if (!(em > 0)) return MIN_EM
  return Math.min(MAX_EM, Math.max(MIN_EM, Math.floor(em)))
}

/**
 * Blank border kept *inside* each cell, around the glyph's ink.
 *
 * Without it the ink sits flush against the cell edge, and a quad whose top
 * edge lands exactly on the first row of ink samples half that row and half the
 * black gap outside it, shaving the tops off letters. The rounding up of the
 * cell size leaves slack at the bottom but none at the top, so the erosion is
 * one-sided and looks like the text has been cropped.
 *
 * The quad grows by the same margin, so nothing moves: the glyph is inset in a
 * slightly larger box rather than drawn smaller.
 */
const INK_MARGIN = 1

export interface Glyph {
  /** Atlas rect, normalised to 0..1. */
  u0: number
  v0: number
  u1: number
  v1: number
  /** Quad offset from the pen position, in em units (y up from the baseline). */
  left: number
  bottom: number
  width: number
  height: number
  /** Pen advance, in em units. */
  advance: number
}

interface Cell {
  key: string
  ch: string
  faceByte: number
  x: number
  y: number
  w: number
  h: number
  inkLeft: number
  inkAscent: number
  inkDescent: number
  advance: number
}

/** One character in one face. */
export interface GlyphRequest {
  faceByte: number
  ch: string
}

function key(faceByte: number, ch: string): string {
  return `${faceByte}\u0000${ch}`
}

export class GlyphAtlas {
  readonly canvas: HTMLCanvasElement
  /** Set when the character set did not fit; those glyphs are dropped. */
  readonly overflowed: boolean

  private glyphs: Map<string, Glyph>
  /** A measuring context per face byte, kept for kerning. */
  private contexts: Map<number, CanvasRenderingContext2D>
  /** Kerning between character pairs, filled in as pairs are asked for. */
  private kerns = new Map<string, number>()

  private constructor(
    canvas: HTMLCanvasElement,
    glyphs: Map<string, Glyph>,
    overflowed: boolean,
    contexts: Map<number, CanvasRenderingContext2D>,
    private emPx: number,
  ) {
    this.canvas = canvas
    this.glyphs = glyphs
    this.overflowed = overflowed
    this.contexts = contexts
  }

  /** A rasterised cell, or undefined if the face did not have one. */
  glyph(faceByte: number, ch: string): Glyph | undefined {
    return this.glyphs.get(key(faceByte, ch))
  }

  /**
   * Cap height as a fraction of em, for turning a DWG text height into ems.
   *
   * A constant of the face, not a property of this page. Measuring it from the
   * rasterised glyphs would make it drift with the em size, and text would
   * change size every time the atlas was rebuilt at a new zoom.
   */
  capRatio(faceByte: number): number {
    return CAP_RATIO[decodeFace(faceByte).family]
  }

  /**
   * Extra advance between two characters, in em units.
   *
   * Summing per-glyph advances ignores kerning, which is what the browser
   * itself applies when it draws a string, so a measured string and a drawn
   * one disagree: right-aligned and centred text drifts. Measuring the pair
   * recovers the difference. Pairs are cached because a drawing has far fewer
   * distinct pairs than it has characters of text.
   */
  kern(faceByte: number, a: string, b: string): number {
    const k = `${faceByte}\u0000${a}${b}`
    const hit = this.kerns.get(k)
    if (hit !== undefined) return hit
    const ctx = this.contexts.get(faceByte)
    if (!ctx) return 0
    const pair = ctx.measureText(a + b).width
    const apart = ctx.measureText(a).width + ctx.measureText(b).width
    const v = (pair - apart) / this.emPx
    this.kerns.set(k, v)
    return v
  }

  /** Width of `text` in em units, kerning included. */
  measure(faceByte: number, text: string): number {
    let w = 0
    let prev = ''
    for (const ch of text) {
      w += this.glyph(faceByte, ch)?.advance ?? 0
      if (prev) w += this.kern(faceByte, prev, ch)
      prev = ch
    }
    return w
  }

  /**
   * Rasterise `requests` into an atlas page.
   *
   * The bundled faces must already be loaded and awaited; Canvas silently
   * substitutes a system font for one that is not ready, which would make the
   * result depend on the machine without any sign that it had.
   *
   * `targetEm` is the size the caller wants, from the current zoom. `maxSize`
   * is the GPU's texture limit: if the character set will not fit at the target,
   * the em is halved until it does, rather than dropping the glyphs that ran
   * past the end of the page.
   */
  static build(
    requests: Iterable<GlyphRequest>,
    maxSize = DEFAULT_MAX_SIZE,
    targetEm = 256,
  ): GlyphAtlas {
    const unique = [...requests]
    const width = Math.min(maxSize, MAX_ATLAS_WIDTH)
    let em = clampEm(targetEm)
    let atlas = GlyphAtlas.pack(unique, em, width, maxSize)
    while (atlas.overflowed && em > MIN_EM) {
      em = Math.max(MIN_EM, Math.floor(em / 2))
      atlas = GlyphAtlas.pack(unique, em, width, maxSize)
    }
    return atlas
  }

  /** Em size this page was rasterised at. */
  get em(): number {
    return this.emPx
  }

  private static pack(
    requests: GlyphRequest[],
    emPx: number,
    atlasWidth: number,
    maxHeight: number,
  ): GlyphAtlas {
    // Deduplicate and order, so an atlas is the same whatever order the runs
    // arrived in.
    const wanted = new Map<string, GlyphRequest>()
    for (const r of requests) {
      if (r.ch === '\n' || r.ch === '\r') continue
      wanted.set(key(r.faceByte, r.ch), r)
    }
    const ordered = [...wanted.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

    const contexts = new Map<number, CanvasRenderingContext2D>()
    const faces = new Map<number, Face>()
    const contextFor = (faceByte: number): CanvasRenderingContext2D | null => {
      const hit = contexts.get(faceByte)
      if (hit) return hit
      const c = document.createElement('canvas')
      c.width = 8
      c.height = 8
      const ctx = c.getContext('2d')
      if (!ctx) return null
      const face = decodeFace(faceByte)
      faces.set(faceByte, face)
      ctx.font = cssFont(emPx, face)
      ctx.textBaseline = 'alphabetic'
      ctx.textAlign = 'left'
      contexts.set(faceByte, ctx)
      return ctx
    }

    const glyphs = new Map<string, Glyph>()
    const cells: Cell[] = []
    let penX = PAD
    let penY = PAD
    let rowHeight = 0
    let overflowed = false

    // Pass 1: measure and pack, so the canvas is only as tall as it needs.
    for (const [k, req] of ordered) {
      const mctx = contextFor(req.faceByte)
      if (!mctx) continue
      const m = mctx.measureText(req.ch)
      const advance = m.width
      const inkLeft = m.actualBoundingBoxLeft ?? 0
      const inkRight = m.actualBoundingBoxRight ?? advance
      const inkAscent = m.actualBoundingBoxAscent ?? emPx
      const inkDescent = m.actualBoundingBoxDescent ?? 0
      const inkW = Math.ceil(inkLeft + inkRight)
      const inkH = Math.ceil(inkAscent + inkDescent)
      const w = inkW + INK_MARGIN * 2
      const h = inkH + INK_MARGIN * 2

      // Whitespace is judged on the ink, not the padded box, which is never
      // empty.
      if (!(inkW > 0) || !(inkH > 0)) {
        // Whitespace: advances the pen, draws nothing.
        glyphs.set(k, {
          u0: 0, v0: 0, u1: 0, v1: 0,
          left: 0, bottom: 0, width: 0, height: 0,
          advance: advance / emPx,
        })
        continue
      }

      if (penX + w + PAD > atlasWidth) {
        penX = PAD
        penY += rowHeight + PAD
        rowHeight = 0
      }
      if (penY + h + PAD > maxHeight) {
        overflowed = true
        break
      }

      cells.push({
        key: k, ch: req.ch, faceByte: req.faceByte,
        x: penX, y: penY, w, h, inkLeft, inkAscent, inkDescent, advance,
      })
      penX += w + PAD
      rowHeight = Math.max(rowHeight, h)
    }

    // How much the rasteriser's idea of a capital's height differs from the
    // face's own, at this em. Canvas hints glyphs onto the pixel grid and
    // reports whole-integer ink bounds, so a capital is not the same fraction
    // of an em at every size: Arimo's "H" measures 12/16 at a 16px em, 22/32 at
    // 32, 177/256 at 256, against a true 1409/2048. Left uncorrected the glyph
    // is drawn up to 9% too tall, and because the atlas is rasterised again as
    // the view zooms, that error changes under the reader and the text visibly
    // resizes. Scaling each glyph's box by this puts the drawn cap height back
    // on the face's own figure, which is also what makes an "H" come out
    // exactly as tall as the DWG says.
    const inkScale = new Map<number, number>()
    for (const [faceByte, mctx] of contexts) {
      const ascent = mctx.measureText('H').actualBoundingBoxAscent
      const want = CAP_RATIO[decodeFace(faceByte).family] * emPx
      inkScale.set(faceByte, ascent > 0 ? want / ascent : 1)
    }

    const height = Math.max(4, penY + rowHeight + PAD)

    const canvas = document.createElement('canvas')
    canvas.width = atlasWidth
    canvas.height = height
    const ctx = canvas.getContext('2d')!
    // Opaque black ground: coverage then lands in the red channel.
    ctx.fillStyle = '#000'
    ctx.fillRect(0, 0, atlasWidth, height)
    ctx.textBaseline = 'alphabetic'
    ctx.textAlign = 'left'
    ctx.fillStyle = '#fff'

    // Pass 2: draw, now that the final height is known. Cells are ordered by
    // face, so the font is set once per face rather than once per glyph.
    let currentFace = -1
    for (const c of cells) {
      if (c.faceByte !== currentFace) {
        ctx.font = cssFont(emPx, faces.get(c.faceByte) ?? decodeFace(c.faceByte))
        currentFace = c.faceByte
      }
      // Inset by the margin, so the ink has blank rows on every side of it.
      ctx.fillText(c.ch, c.x + INK_MARGIN + c.inkLeft, c.y + INK_MARGIN + c.inkAscent)
      // The quad covers the whole cell, margin included, so the glyph keeps its
      // place. All four scale about the pen on the baseline, so correcting the
      // rasteriser's size does not move the glyph off it. The advance is not
      // scaled: it comes back unhinted and is already exact.
      const s = inkScale.get(c.faceByte) ?? 1
      glyphs.set(c.key, {
        u0: c.x / atlasWidth,
        v0: c.y / height,
        u1: (c.x + c.w) / atlasWidth,
        v1: (c.y + c.h) / height,
        left: (-(c.inkLeft + INK_MARGIN) / emPx) * s,
        bottom: (-(c.inkDescent + INK_MARGIN) / emPx) * s,
        width: (c.w / emPx) * s,
        height: (c.h / emPx) * s,
        advance: c.advance / emPx,
      })
    }

    return new GlyphAtlas(canvas, glyphs, overflowed, contexts, emPx)
  }
}
