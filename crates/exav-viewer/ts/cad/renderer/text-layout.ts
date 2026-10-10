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

const V_BASELINE = 0
const V_BOTTOM = 1
const V_MIDDLE = 2
const V_TOP = 3


export interface TextLayoutResult {
  /** Interleaved glyph instances, `GLYPH_BYTES` each. */
  buffer: ArrayBuffer
  glyphCount: number
  /** Runs skipped because no glyph in the run had a rasterised cell. */
  skippedRuns: number
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
 * Each instance carries an origin plus two edge vectors, so rotation, width
 * factor and oblique slant all fall out of the same two vectors and the shader
 * stays a single multiply-add.
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
    height: number
    rotation: number
    widthFactor: number
    oblique: number
    rgba: number
    attr: number
    hAlign: number
    vAlign: number
    order: number
    faceByte: number
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
      height: view.getFloat32(o + 8, true),
      rotation: view.getFloat32(o + 12, true),
      widthFactor: view.getFloat32(o + 16, true),
      oblique: view.getFloat32(o + 20, true),
      rgba: view.getUint32(o + 24, true),
      attr: view.getUint32(o + 28, true),
      hAlign: view.getUint8(o + 38),
      vAlign: view.getUint8(o + 39),
      order: view.getUint32(o + 40, true),
      faceByte: view.getUint8(o + 44),
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

  for (const run of runs) {
    // DWG text height is cap height; the atlas is in em units, and the ratio
    // between them belongs to the face this run is drawn with.
    const em = run.height / atlas.capRatio(run.faceByte)
    if (!(em > 0)) {
      skippedRuns++
      continue
    }

    const widthFactor = run.widthFactor > 0 ? run.widthFactor : 1
    const advanceScale = em * widthFactor
    const runWidth = atlas.measure(run.faceByte, run.text) * advanceScale

    // Horizontal anchor. Aligned and Fit stretch between two points, which we
    // do not have here, so they fall back to centred.
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

    // Vertical anchor, measured from the baseline.
    let dy = 0
    switch (run.vAlign) {
      case V_BOTTOM:
        dy = 0
        break
      case V_MIDDLE:
        dy = -run.height / 2
        break
      case V_TOP:
        dy = -run.height
        break
      case V_BASELINE:
      default:
        dy = 0
    }

    const cos = Math.cos(run.rotation)
    const sin = Math.sin(run.rotation)
    // Oblique leans the vertical edge; positive slants to the right.
    const tanO = Math.tan(run.oblique || 0)

    let pen = dx
    let drew = false
    let prev = ''

    for (const ch of run.text) {
      const g = atlas.glyph(run.faceByte, ch)
      if (!g) continue
      // Kerning has to move the pen as well as the measured width, or the
      // glyphs stop matching the box the alignment was computed from.
      if (prev) pen += atlas.kern(run.faceByte, prev, ch) * advanceScale
      prev = ch
      if (g.width > 0) {
        // Glyph box in the run's own unrotated frame.
        const gx = pen + g.left * advanceScale
        const gy = dy + g.bottom * em
        const gw = g.width * advanceScale
        const gh = g.height * em

        // Skew shifts x by the height above the baseline.
        const skewLo = gy * tanO
        const skewHi = (gy + gh) * tanO

        // Origin is the bottom-left corner; the two edges span the quad.
        const ox = gx + skewLo
        const oy = gy
        const ex = gw
        const ey = 0
        const fx = skewHi - skewLo
        const fy = gh

        const b = n * GLYPH_BYTES
        out.setFloat32(b + 0, run.x + ox * cos - oy * sin, true)
        out.setFloat32(b + 4, run.y + ox * sin + oy * cos, true)
        out.setFloat32(b + 8, ex * cos - ey * sin, true)
        out.setFloat32(b + 12, ex * sin + ey * cos, true)
        out.setFloat32(b + 16, fx * cos - fy * sin, true)
        out.setFloat32(b + 20, fx * sin + fy * cos, true)
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
      pen += g.advance * advanceScale
    }

    if (!drew) skippedRuns++
  }

  return { buffer, glyphCount: n, skippedRuns }
}
