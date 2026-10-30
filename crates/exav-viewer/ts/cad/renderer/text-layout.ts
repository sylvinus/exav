import type { GlyphAtlas, GlyphRequest } from './glyph-atlas.js'

/** Bytes per text placement record, matching crates/exav-render/src/formats/dwg/text.rs. */
export const TEXT_RECORD_BYTES = 48
/** Bytes per glyph instance in the buffer this module produces. */
export const GLYPH_BYTES = 44

const H_LEFT = 0
const H_CENTER = 1
const H_RIGHT = 2
const H_ALIGNED = 3
const H_MIDDLE = 4
const H_FIT = 5

// Vertical alignment; 0 is the baseline.
const V_BOTTOM = 1
const V_MIDDLE = 2
const V_TOP = 3


export interface TextLayoutResult {
  /** Interleaved glyph instances, `GLYPH_BYTES` each. */
  buffer: ArrayBuffer
  glyphCount: number
  /** Runs skipped because no glyph in the run had a rasterised cell. */
  skippedRuns: number
  /**
   * The glyphs of each clip region, in glyph instances: those of clip 0
   * (none) first, then each region's, in increasing id.
   */
  clipRanges: { clip: number; start: number; count: number }[]
}

/**
 * Every character each run needs, in the face that run is drawn with.
 *
 * Keyed by both, because the same letter in two faces is two cells: a drawing
 * that mixes a sans title with a serif note needs both rasterised.
 */
export function glyphsNeeded(records: ArrayBuffer, strings: Uint8Array): GlyphRequest[] {
  const view = new DataView(records)
  const runCount = Math.floor(records.byteLength / TEXT_RECORD_BYTES)
  const decoder = new TextDecoder('utf-8')
  const seen = new Set<string>()
  const out: GlyphRequest[] = []

  for (let i = 0; i < runCount; i++) {
    const o = i * TEXT_RECORD_BYTES
    const strOffset = view.getUint32(o + 32, true)
    const strLen = view.getUint16(o + 36, true)
    if (strLen === 0) continue
    const faceByte = view.getUint8(o + 44)
    const text = decoder.decode(strings.subarray(strOffset, strOffset + strLen))
    for (const ch of text) {
      const k = `${faceByte}\u0000${ch}`
      if (seen.has(k)) continue
      seen.add(k)
      out.push({ faceByte, ch })
    }
  }
  return out
}

/** Every face byte the runs name, for deciding which files to fetch. */
export function facesUsed(records: ArrayBuffer): Set<number> {
  const view = new DataView(records)
  const runCount = Math.floor(records.byteLength / TEXT_RECORD_BYTES)
  const out = new Set<number>()
  for (let i = 0; i < runCount; i++) {
    if (view.getUint16(i * TEXT_RECORD_BYTES + 36, true) === 0) continue
    out.add(view.getUint8(i * TEXT_RECORD_BYTES + 44))
  }
  return out
}

/**
 * Turn placement records into positioned glyph quads.
 *
 * A record's frame is two vectors, `u` one cap height of advance along the
 * baseline and `v` one cap height up, which carry its rotation, width factor,
 * slant, mirroring and a block's non-uniform scale. The run is laid out in
 * cap heights and the frame places it; each instance is an origin plus two
 * edge vectors, so the shader stays a single multiply-add.
 */
export function layoutText(
  records: ArrayBuffer,
  strings: Uint8Array,
  atlas: GlyphAtlas,
): TextLayoutResult {
  const view = new DataView(records)
  const runCount = Math.floor(records.byteLength / TEXT_RECORD_BYTES)
  const decoder = new TextDecoder('utf-8')

  // First pass: count glyphs so the buffer is allocated once.
  const runs: {
    text: string
    x: number
    y: number
    ux: number
    uy: number
    vx: number
    vy: number
    rgba: number
    attr: number
    hAlign: number
    vAlign: number
    order: number
    faceByte: number
    clip: number
  }[] = []
  let glyphTotal = 0

  for (let i = 0; i < runCount; i++) {
    const o = i * TEXT_RECORD_BYTES
    const strOffset = view.getUint32(o + 32, true)
    const strLen = view.getUint16(o + 36, true)
    if (strLen === 0) continue
    const text = decoder.decode(strings.subarray(strOffset, strOffset + strLen))
    if (!text) continue

    runs.push({
      text,
      x: view.getFloat32(o + 0, true),
      y: view.getFloat32(o + 4, true),
      ux: view.getFloat32(o + 8, true),
      uy: view.getFloat32(o + 12, true),
      vx: view.getFloat32(o + 16, true),
      vy: view.getFloat32(o + 20, true),
      rgba: view.getUint32(o + 24, true),
      attr: view.getUint32(o + 28, true),
      hAlign: view.getUint8(o + 38),
      vAlign: view.getUint8(o + 39),
      order: view.getUint32(o + 40, true),
      faceByte: view.getUint8(o + 44),
      clip: view.getUint16(o + 46, true),
    })
    const faceByte = view.getUint8(o + 44)
    for (const ch of text) {
      const g = atlas.glyph(faceByte, ch)
      if (g && g.width > 0) glyphTotal++
    }
  }

  const buffer = new ArrayBuffer(glyphTotal * GLYPH_BYTES)
  const out = new DataView(buffer)
  let n = 0
  let skippedRuns = 0
  // Each clip region's runs together, so it is masked once: the depth test
  // still puts each glyph in the drawing's order.
  runs.sort((a, b) => a.clip - b.clip)
  const clipRanges: TextLayoutResult['clipRanges'] = []

  for (const run of runs) {
    const last = clipRanges[clipRanges.length - 1]
    if (!last || last.clip !== run.clip) clipRanges.push({ clip: run.clip, start: n, count: 0 })
    if (!(Math.hypot(run.vx, run.vy) > 0) || !(Math.hypot(run.ux, run.uy) > 0)) {
      skippedRuns++
      continue
    }
    // DWG text height is cap height; the atlas is in em units, and the ratio
    // between them belongs to the face this run is drawn with.
    const capsPerEm = 1 / atlas.capRatio(run.faceByte)
    const runWidth = atlas.measure(run.faceByte, run.text) * capsPerEm

    // Horizontal anchor. Aligned and Fit arrive stretched and left-aligned;
    // without their second point they fall back to centred.
    let dx = 0
    switch (run.hAlign) {
      case H_CENTER:
      case H_MIDDLE:
      case H_ALIGNED:
      case H_FIT:
        dx = -runWidth / 2
        break
      case H_RIGHT:
        dx = -runWidth
        break
      case H_LEFT:
      default:
        dx = 0
    }

    // Where the baseline sits from the anchor: Bottom puts the descenders on
    // it, Middle centres the capitals, Top their tops, and the Middle
    // alignment (TEXT's MIDDLE, unlike Middle Center) capitals and descenders
    // together. `baseline_offset` in text.rs does the same for stroke text.
    const descent = atlas.descent(run.faceByte)
    let dy = 0
    if (run.hAlign === H_MIDDLE) dy = -(1 - descent) / 2
    else if (run.vAlign === V_BOTTOM) dy = descent
    else if (run.vAlign === V_MIDDLE) dy = -0.5
    else if (run.vAlign === V_TOP) dy = -1

    let pen = dx
    let drew = false
    let prev = ''

    for (const ch of run.text) {
      const g = atlas.glyph(run.faceByte, ch)
      if (!g) continue
      // Kerning has to move the pen as well as the measured width, or the
      // glyphs stop matching the box the alignment was computed from.
      if (prev) pen += atlas.kern(run.faceByte, prev, ch) * capsPerEm
      prev = ch
      if (g.width > 0) {
        // Glyph box in cap heights, along `u` and up `v`.
        const a = pen + g.left * capsPerEm
        const b0 = dy + g.bottom * capsPerEm
        const w = g.width * capsPerEm
        const h = g.height * capsPerEm

        const b = n * GLYPH_BYTES
        out.setFloat32(b + 0, run.x + a * run.ux + b0 * run.vx, true)
        out.setFloat32(b + 4, run.y + a * run.uy + b0 * run.vy, true)
        out.setFloat32(b + 8, w * run.ux, true)
        out.setFloat32(b + 12, w * run.uy, true)
        out.setFloat32(b + 16, h * run.vx, true)
        out.setFloat32(b + 20, h * run.vy, true)
        out.setUint16(b + 24, Math.round(g.u0 * 65535), true)
        out.setUint16(b + 26, Math.round(g.v0 * 65535), true)
        out.setUint16(b + 28, Math.round(g.u1 * 65535), true)
        out.setUint16(b + 30, Math.round(g.v1 * 65535), true)
        out.setUint32(b + 32, run.rgba, true)
        out.setUint32(b + 36, run.attr, true)
        out.setUint32(b + 40, run.order, true)
        n++
        drew = true
      }
      pen += g.advance * capsPerEm
    }

    if (!drew) skippedRuns++
    clipRanges[clipRanges.length - 1]!.count = n - clipRanges[clipRanges.length - 1]!.start
  }

  return { buffer, glyphCount: n, skippedRuns, clipRanges: clipRanges.filter((r) => r.count > 0) }
}
