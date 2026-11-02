import { describe, expect, it } from 'vitest'

import type { GlyphAtlas } from './glyph-atlas'
import { GLYPH_BYTES, TEXT_RECORD_BYTES, facesUsed, glyphsNeeded, layoutText } from './text-layout'

/**
 * Build a text record the way `text::encode` in `crates/exav-render/src/formats/dwg/text.rs`
 * does, so these tests fail if the wire format changes on either side.
 */
function record(opts: {
  strOffset: number
  strLen: number
  faceByte: number
  hAlign?: number
  vAlign?: number
  clip?: number
  x?: number
  u?: [number, number]
  v?: [number, number]
}): ArrayBuffer {
  const buf = new ArrayBuffer(TEXT_RECORD_BYTES)
  const v = new DataView(buf)
  const [ux, uy] = opts.u ?? [2.5, 0]
  const [vx, vy] = opts.v ?? [0, 2.5]
  v.setFloat32(0, opts.x ?? 0, true) // x
  v.setFloat32(4, 0, true) // y
  v.setFloat32(8, ux, true)
  v.setFloat32(12, uy, true)
  v.setFloat32(16, vx, true)
  v.setFloat32(20, vy, true)
  v.setUint32(24, 0xffffffff, true) // rgba
  v.setUint32(28, 0, true) // attr
  v.setUint32(32, opts.strOffset, true)
  v.setUint16(36, opts.strLen, true)
  v.setUint8(38, opts.hAlign ?? 0)
  v.setUint8(39, opts.vAlign ?? 0)
  v.setUint32(40, 1, true) // order
  v.setUint8(44, opts.faceByte)
  v.setUint16(46, opts.clip ?? 0, true)
  return buf
}

/** An atlas whose every glyph is a unit cell, an em wide. */
const unitAtlas = {
  glyph: () => ({ width: 1, height: 1, left: 0, bottom: 0, advance: 1, u0: 0, v0: 0, u1: 1, v1: 1 }),
  capRatio: () => 1,
  descent: () => 0.25,
  measure: (_face: number, text: string) => [...text].length,
  kern: () => 0,
} as unknown as GlyphAtlas

/** The glyph instances: origin, edge along, edge up. */
function quads(laid: { buffer: ArrayBuffer; glyphCount: number }) {
  const d = new DataView(laid.buffer)
  return Array.from({ length: laid.glyphCount }, (_, i) => {
    const f = (k: number) => d.getFloat32(i * GLYPH_BYTES + k * 4, true)
    return { origin: [f(0), f(1)], along: [f(2), f(3)], up: [f(4), f(5)] }
  })
}

describe('layoutText frames', () => {
  const strings = encode('AB')

  it('mirrors a run whose frame is mirrored, about its anchor', () => {
    const laid = layoutText(record({ strOffset: 0, strLen: 2, faceByte: 0, u: [-1, 0], v: [0, 1] }), strings, unitAtlas)
    expect(quads(laid)).toEqual([
      { origin: [0, 0], along: [-1, 0], up: [0, 1] },
      { origin: [-1, 0], along: [-1, 0], up: [0, 1] },
    ])
  })

  it('stretches along the baseline only, for a block scaled in x', () => {
    const laid = layoutText(record({ strOffset: 0, strLen: 2, faceByte: 0, u: [2, 0], v: [0, 1] }), strings, unitAtlas)
    expect(quads(laid).map((q) => [q.origin[0], q.along[0], q.up[1]])).toEqual([
      [0, 2, 1],
      [2, 2, 1],
    ])
  })

  it('puts the descenders on the anchor for Bottom, and centres capitals and descenders for Middle', () => {
    const y = (hAlign: number, vAlign: number) =>
      quads(layoutText(record({ strOffset: 0, strLen: 1, faceByte: 0, hAlign, vAlign, u: [1, 0], v: [0, 1] }), strings, unitAtlas))[0]!.origin[1]
    expect(y(0, 1)).toBe(0.25)
    expect(y(0, 2)).toBe(-0.5)
    expect(y(0, 3)).toBe(-1)
    // MIDDLE: from the descenders' bottom (-0.25) to the capitals' top (1).
    expect(y(4, 0)).toBe(-0.375)
  })
})

describe('layoutText', () => {
  it('puts each clip region\'s glyphs together, unclipped first, and says where', () => {
    const strings = encode('AAABBC')
    const records = concat(
      record({ strOffset: 0, strLen: 3, faceByte: 0, clip: 2, x: 1 }),
      record({ strOffset: 3, strLen: 2, faceByte: 0, clip: 0, x: 2 }),
      record({ strOffset: 5, strLen: 1, faceByte: 0, clip: 1, x: 3 }),
    )
    const laid = layoutText(records, strings, unitAtlas)
    expect(laid.clipRanges).toEqual([
      { clip: 0, start: 0, count: 2 },
      { clip: 1, start: 2, count: 1 },
      { clip: 2, start: 3, count: 3 },
    ])
    // The glyphs in those places are those runs': the first two at x 2.
    const x = (i: number) => new DataView(laid.buffer).getFloat32(i * GLYPH_BYTES, true)
    expect([x(0), x(2), x(3)]).toEqual([2, 3, 1])
  })
})

function concat(...parts: ArrayBuffer[]): ArrayBuffer {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0))
  let at = 0
  for (const p of parts) {
    out.set(new Uint8Array(p), at)
    at += p.byteLength
  }
  return out.buffer
}

const encode = (s: string) => new TextEncoder().encode(s)

describe('glyphsNeeded', () => {
  it('asks for each character in the face its run is drawn with', () => {
    const strings = encode('ABAB')
    const records = concat(
      record({ strOffset: 0, strLen: 2, faceByte: 0 }), // "AB" sans
      record({ strOffset: 2, strLen: 2, faceByte: 4 }), // "AB" serif
    )
    const needed = glyphsNeeded(records, strings)
    expect(needed).toHaveLength(4)
    expect(needed).toContainEqual({ faceByte: 0, ch: 'A' })
    expect(needed).toContainEqual({ faceByte: 4, ch: 'A' })
  })

  it('rasterises a character once per face, not once per run', () => {
    const strings = encode('AAA')
    const records = concat(
      record({ strOffset: 0, strLen: 1, faceByte: 0 }),
      record({ strOffset: 1, strLen: 1, faceByte: 0 }),
      record({ strOffset: 2, strLen: 1, faceByte: 0 }),
    )
    expect(glyphsNeeded(records, strings)).toEqual([{ faceByte: 0, ch: 'A' }])
  })

  it('reads multi-byte characters as characters, not bytes', () => {
    // "é" is two bytes in UTF-8; asking for two cells would be wrong.
    const strings = encode('é')
    const records = record({ strOffset: 0, strLen: strings.length, faceByte: 0 })
    expect(glyphsNeeded(records, strings)).toEqual([{ faceByte: 0, ch: 'é' }])
  })

  it('skips empty runs', () => {
    const records = record({ strOffset: 0, strLen: 0, faceByte: 0 })
    expect(glyphsNeeded(records, encode(''))).toEqual([])
  })
})

describe('facesUsed', () => {
  it('reports only the faces that actually draw something', () => {
    const records = concat(
      record({ strOffset: 0, strLen: 1, faceByte: 0 }),
      record({ strOffset: 1, strLen: 1, faceByte: 6 }),
      // An empty run must not drag in a font file for a face nothing uses.
      record({ strOffset: 2, strLen: 0, faceByte: 11 }),
    )
    expect([...facesUsed(records)].sort((a, b) => a - b)).toEqual([0, 6])
  })

  it('is empty for a drawing with no text', () => {
    expect([...facesUsed(new ArrayBuffer(0))]).toEqual([])
  })

  it('reads the face from the right offset', () => {
    // A stride or offset slip would read a neighbouring field; `order` is 1
    // in these records, so getting 1 back for every face would be that bug.
    for (const faceByte of [0, 3, 7, 11]) {
      const r = record({ strOffset: 0, strLen: 1, faceByte })
      expect([...facesUsed(r)]).toEqual([faceByte])
    }
  })
})
