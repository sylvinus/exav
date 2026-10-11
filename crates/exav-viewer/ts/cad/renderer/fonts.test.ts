import { describe, expect, it } from 'vitest'

import { CAP_RATIO, FACE_COUNT, FAMILIES, cssFont, decodeFace, familiesFor } from './fonts'

/**
 * The face byte is a contract with `TrueTypeFace::to_byte` in
 * `crates/exav-render/src/formats/dwg/font.rs`, which packs `family * 4 + bold * 2 + italic`.
 * If the two sides drift, text silently renders in the wrong face, so the
 * packing is restated here rather than derived from the code under test.
 */
describe('face byte', () => {
  it('decodes every combination the wasm can send', () => {
    const seen = new Set<string>()
    for (let family = 0; family < FAMILIES.length; family++) {
      for (const bold of [false, true]) {
        for (const italic of [false, true]) {
          const byte = family * 4 + (bold ? 2 : 0) + (italic ? 1 : 0)
          const face = decodeFace(byte)
          expect(face.family).toBe(FAMILIES[family])
          expect(face.bold).toBe(bold)
          expect(face.italic).toBe(italic)
          seen.add(`${face.family}/${face.bold}/${face.italic}`)
        }
      }
    }
    expect(seen.size).toBe(FACE_COUNT)
  })

  it('covers the whole range densely, so the table needs no gaps', () => {
    const combos = new Set<string>()
    for (let b = 0; b < FACE_COUNT; b++) {
      const f = decodeFace(b)
      combos.add(`${f.family}/${f.bold}/${f.italic}`)
    }
    expect(combos.size).toBe(FACE_COUNT)
  })

  it('falls back rather than producing an undefined family', () => {
    // A byte from a newer wasm, or a corrupted record, must still draw.
    for (const b of [-1, FACE_COUNT, 255, 1000, NaN]) {
      const f = decodeFace(b)
      expect(FAMILIES).toContain(f.family)
    }
  })
})

describe('cssFont', () => {
  it('names a bundled family, never a system one', () => {
    for (let b = 0; b < FACE_COUNT; b++) {
      const css = cssFont(64, decodeFace(b))
      expect(css).toMatch(/__exav_cad_(sans|serif|mono)$/)
      // No fallback stack: falling through to a system font is the failure
      // this whole bundle exists to prevent.
      expect(css).not.toContain(',')
    }
  })

  it('spells out weight and style so a variable font is pinned', () => {
    expect(cssFont(64, { family: 'sans', bold: false, italic: false })).toBe(
      '400 64px __exav_cad_sans',
    )
    expect(cssFont(64, { family: 'sans', bold: true, italic: false })).toBe(
      '700 64px __exav_cad_sans',
    )
    expect(cssFont(32, { family: 'serif', bold: true, italic: true })).toBe(
      'italic 700 32px __exav_cad_serif',
    )
  })
})

describe('cap ratios', () => {
  /**
   * These decide how large a run is drawn (`em = height / capRatio`), so they
   * must not move. Measuring them from Canvas gave a different answer at every
   * atlas size, which made text change size whenever the atlas was rebuilt at
   * a new zoom: Arimo read 0.750 at 16px against a true 0.688.
   */
  it('match the OS/2 tables the width tables were generated from', () => {
    expect(CAP_RATIO.sans).toBeCloseTo(1409 / 2048, 6)
    expect(CAP_RATIO.serif).toBeCloseTo(1341 / 2048, 6)
    expect(CAP_RATIO.mono).toBeCloseTo(1349 / 2048, 6)
  })

  it('covers every family, with a plausible value', () => {
    for (const family of FAMILIES) {
      expect(CAP_RATIO[family]).toBeGreaterThan(0.5)
      expect(CAP_RATIO[family]).toBeLessThan(0.85)
    }
  })

  it('does not depend on bold or italic, which share a cap height', () => {
    // Every face of a family resolves to the same number, so switching weight
    // mid-paragraph cannot change the line's height.
    for (let b = 0; b < FACE_COUNT; b++) {
      expect(CAP_RATIO[decodeFace(b).family]).toBe(CAP_RATIO[decodeFace(b & ~3).family])
    }
  })
})

describe('familiesFor', () => {
  it('asks for only the families a drawing actually names', () => {
    // A drawing that is all sans must not drag in the serif or mono files.
    expect([...familiesFor([0, 1, 2, 3])]).toEqual(['sans'])
    expect([...familiesFor([8])]).toEqual(['mono'])
    expect([...familiesFor([])]).toEqual([])
  })

  it('collects each family once however many faces of it are used', () => {
    const families = familiesFor([0, 2, 4, 6, 8, 10])
    expect([...families].sort()).toEqual(['mono', 'sans', 'serif'])
  })
})
