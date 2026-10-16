import { describe, expect, it } from 'vitest'

import { convertCells, distanceField } from './sdf'

/** A `size` square grid with a solid block from `lo` to `hi` (exclusive) in both axes. */
function block(size: number, lo: number, hi: number): Uint8Array {
  const g = new Uint8Array(size * size)
  for (let y = lo; y < hi; y++) for (let x = lo; x < hi; x++) g[y * size + x] = 255
  return g
}

describe('distanceField', () => {
  const size = 21
  const field = distanceField(block(size, 5, 16), size, size, 4)
  const at = (x: number, y: number) => field[y * size + x]!

  it('is above the edge value inside, below it outside', () => {
    expect(at(10, 10)).toBeGreaterThan(128)
    expect(at(0, 10)).toBeLessThan(128)
  })

  it('measures distance in texels, 64 per spread, centre to centre', () => {
    // Texel 2 is 3 from the first ink texel, texel 7 3 from the last blank one.
    expect(at(2, 10)).toBe(128 - 48)
    expect(at(7, 10)).toBe(128 + 48)
    // So the edge value falls halfway between texels 4 and 5, on the edge.
    expect((at(4, 10) + at(5, 10)) / 2).toBe(128)
  })

  it('is Euclidean, not taxicab, off a corner', () => {
    // From texel (1, 1) the nearest ink is the corner texel (5, 5).
    expect(at(1, 1)).toBe(Math.round(128 - (Math.hypot(4, 4) / 4) * 64))
  })

  it('puts a half-covered texel on the edge', () => {
    const g = new Uint8Array(9)
    g[4] = 128
    expect(distanceField(g, 3, 3, 4)[4]).toBe(128)
  })

  it('is uniform where there is no ink', () => {
    const empty = distanceField(new Uint8Array(16), 4, 4, 2)
    expect(new Set(empty).size).toBe(1)
    expect(empty[0]).toBe(0)
  })
})

describe('convertCells', () => {
  /** An RGBA atlas 40 texels wide holding two 12 by 12 cells of ink, coverage in red. */
  function atlas() {
    const width = 40
    const px = new Uint8ClampedArray(width * 14 * 4)
    const cells = [
      { x: 1, y: 1, w: 12, h: 12 },
      { x: 20, y: 1, w: 12, h: 12 },
    ]
    for (const c of cells)
      for (let y = 3; y < 9; y++) for (let x = 3; x < 9; x++) px[((c.y + y) * width + c.x + x) * 4] = 255
    return { width, px, cells }
  }

  it('writes each cell its field in all three colour channels, and leaves the rest alone', () => {
    const { width, px, cells } = atlas()
    const before = Uint8ClampedArray.from(px)
    for (const _ of convertCells(px, width, cells, 2, Infinity)) void _
    for (const c of cells) {
      const coverage = new Uint8Array(c.w * c.h)
      for (let y = 0; y < c.h; y++) for (let x = 0; x < c.w; x++) coverage[y * c.w + x] = before[((c.y + y) * width + c.x + x) * 4]!
      const field = distanceField(coverage, c.w, c.h, 2)
      for (let y = 0; y < c.h; y++)
        for (let x = 0; x < c.w; x++) {
          const i = ((c.y + y) * width + c.x + x) * 4
          expect([px[i], px[i + 1], px[i + 2]]).toEqual([field[y * c.w + x], field[y * c.w + x], field[y * c.w + x]])
        }
    }
    // Between the cells, and in alpha, nothing changed.
    expect(px[(1 * width + 15) * 4]).toBe(before[(1 * width + 15) * 4])
    expect(px[3]).toBe(before[3])
  })

  it('yields once a slice has passed, and not before', () => {
    const { width, px, cells } = atlas()
    // Each cell takes 5 ms (the clock reads 5 ms later at every call): a slice of 8 ms ends after the second.
    const run = (sliceMs: number) => {
      let clock = 0
      const gen = convertCells(px, width, cells, 2, sliceMs, () => (clock += 5))
      let yields = 0
      while (!gen.next().done) yields++
      return yields
    }
    expect(run(Infinity)).toBe(0)
    expect(run(8)).toBe(1)
    expect(run(0)).toBe(2)
  })
})
