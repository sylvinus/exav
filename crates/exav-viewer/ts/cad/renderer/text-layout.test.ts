import { describe, expect, it } from 'vitest'

import { TEXT_RECORD_BYTES, facesUsed, glyphsNeeded } from './text-layout'

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
}): ArrayBuffer {
  const buf = new ArrayBuffer(TEXT_RECORD_BYTES)
  const v = new DataView(buf)
  v.setFloat32(0, 0, true) // x
  v.setFloat32(4, 0, true) // y
  v.setFloat32(8, 2.5, true) // height
  v.setFloat32(12, 0, true) // rotation
  v.setFloat32(16, 1, true) // widthFactor
  v.setFloat32(20, 0, true) // oblique
  v.setUint32(24, 0xffffffff, true) // rgba
  v.setUint32(28, 0, true) // attr
  v.setUint32(32, opts.strOffset, true)
  v.setUint16(36, opts.strLen, true)
  v.setUint8(38, opts.hAlign ?? 0)
  v.setUint8(39, opts.vAlign ?? 0)
  v.setUint32(40, 1, true) // order
  v.setUint8(44, opts.faceByte)
  return buf
}

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
