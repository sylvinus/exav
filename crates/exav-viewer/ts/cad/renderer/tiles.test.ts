import { describe, expect, it } from 'vitest'

import { TILE_BYTES, decodeTiles, rangeTotal, viewMargin, visibleRanges, type Tile } from './tiles'

function tile(start: number, count: number, box: [number, number, number, number]): Tile {
  return { start, count, minX: box[0], minY: box[1], maxX: box[2], maxY: box[3] }
}

/** A row of tiles, each covering its own unit square along x. */
function row(n: number): Tile[] {
  return Array.from({ length: n }, (_, i) => tile(i * 10, 10, [i, 0, i + 1, 1]))
}

const NO_MARGIN = 0

describe('decodeTiles', () => {
  it('reads the layout crates/exav-render/src/formats/dwg/tiles.rs writes', () => {
    const buf = new ArrayBuffer(TILE_BYTES)
    const v = new DataView(buf)
    v.setUint32(0, 7, true)
    v.setUint32(4, 3, true)
    v.setFloat32(8, -1.5, true)
    v.setFloat32(12, -2.5, true)
    v.setFloat32(16, 3.5, true)
    v.setFloat32(20, 4.5, true)
    expect(decodeTiles(buf)).toEqual([tile(7, 3, [-1.5, -2.5, 3.5, 4.5])])
  })

  it('is empty for an empty table', () => {
    expect(decodeTiles(new ArrayBuffer(0))).toEqual([])
  })
})

describe('visibleRanges', () => {
  it('returns only the tiles the view overlaps', () => {
    const tiles = row(10)
    const r = visibleRanges(tiles, 0, tiles.length, { minX: 3.2, minY: 0, maxX: 5.8, maxY: 1 }, NO_MARGIN)
    // Tiles 3, 4 and 5, merged because they are adjacent in the buffer.
    expect(r).toEqual([{ start: 30, count: 30 }])
  })

  it('merges adjacent tiles into one call but not separated ones', () => {
    const tiles = [
      tile(0, 10, [0, 0, 1, 1]),
      tile(10, 10, [50, 0, 51, 1]), // far away, skipped
      tile(20, 10, [1, 0, 2, 1]),
    ]
    const r = visibleRanges(tiles, 0, tiles.length, { minX: 0, minY: 0, maxX: 2, maxY: 1 }, NO_MARGIN)
    expect(r).toEqual([
      { start: 0, count: 10 },
      { start: 20, count: 10 },
    ])
  })

  it('draws nothing when the view is somewhere else entirely', () => {
    const tiles = row(10)
    const r = visibleRanges(tiles, 0, tiles.length, { minX: 500, minY: 500, maxX: 501, maxY: 501 }, NO_MARGIN)
    expect(r).toEqual([])
  })

  it('respects the half of the table it is given', () => {
    const tiles = row(10)
    const view = { minX: -1, minY: -1, maxX: 100, maxY: 100 }
    expect(rangeTotal(visibleRanges(tiles, 0, 4, view, NO_MARGIN))).toBe(40)
    expect(rangeTotal(visibleRanges(tiles, 4, 10, view, NO_MARGIN))).toBe(60)
  })

  /**
   * The margin is what keeps a thick line's edge from being clipped at the
   * border of the viewport, so a tile just outside must still be drawn.
   */
  it('includes tiles just outside the view once the margin is applied', () => {
    const tiles = [tile(0, 10, [10, 0, 11, 1])]
    const view = { minX: 0, minY: 0, maxX: 9, maxY: 1 }
    expect(visibleRanges(tiles, 0, 1, view, 0)).toEqual([])
    expect(visibleRanges(tiles, 0, 1, view, 2)).toEqual([{ start: 0, count: 10 }])
  })

  /**
   * A tile's box is the extent of its contents, which can be far larger than
   * its grid square. Testing the box is what makes a long line survive.
   */
  it('keeps a tile whose contents reach into the view from far away', () => {
    const tiles = [tile(0, 1, [-1000, -1000, 1000, 1000])]
    const r = visibleRanges(tiles, 0, 1, { minX: 0, minY: 0, maxX: 1, maxY: 1 }, NO_MARGIN)
    expect(r).toEqual([{ start: 0, count: 1 }])
  })

  it('treats a touching edge as visible rather than dropping it', () => {
    const tiles = [tile(0, 5, [1, 0, 2, 1])]
    const r = visibleRanges(tiles, 0, 1, { minX: 0, minY: 0, maxX: 1, maxY: 1 }, NO_MARGIN)
    expect(r).toEqual([{ start: 0, count: 5 }])
  })

  /**
   * Nothing may be lost: for any view, the ranges must cover every tile that
   * overlaps it, checked exhaustively against a direct scan.
   */
  it('never omits an overlapping tile, over many random views', () => {
    let seed = 12345
    const rand = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      return seed / 0x7fffffff
    }
    const tiles: Tile[] = []
    for (let i = 0; i < 200; i++) {
      const x = rand() * 100
      const y = rand() * 100
      const w = rand() * 20
      const h = rand() * 20
      tiles.push(tile(i * 4, 4, [x, y, x + w, y + h]))
    }
    for (let trial = 0; trial < 300; trial++) {
      const x = rand() * 120 - 10
      const y = rand() * 120 - 10
      const view = { minX: x, minY: y, maxX: x + rand() * 40, maxY: y + rand() * 40 }
      const margin = rand() * 3

      const covered = new Set<number>()
      for (const r of visibleRanges(tiles, 0, tiles.length, view, margin)) {
        for (let e = r.start; e < r.start + r.count; e++) covered.add(e)
      }
      for (const t of tiles) {
        const overlaps =
          t.maxX >= view.minX - margin &&
          t.minX <= view.maxX + margin &&
          t.maxY >= view.minY - margin &&
          t.minY <= view.maxY + margin
        if (!overlaps) continue
        for (let e = t.start; e < t.start + t.count; e++) {
          expect(covered.has(e)).toBe(true)
        }
      }
    }
  })

  /** Ranges must stay ordered and non-overlapping, or geometry draws twice. */
  it('produces ordered, disjoint ranges', () => {
    const tiles = row(50).filter((_, i) => i % 3 !== 1)
    const r = visibleRanges(tiles, 0, tiles.length, { minX: -1, minY: -1, maxX: 100, maxY: 100 }, 0)
    let end = -1
    for (const x of r) {
      expect(x.start).toBeGreaterThan(end)
      expect(x.count).toBeGreaterThan(0)
      end = x.start + x.count - 1
    }
  })
})

describe('viewMargin', () => {
  /**
   * Mirrors the stroke shader's quad expansion, which is
   * `max(uMinWidth, widthPx) * 0.5 + 1` framebuffer pixels. Too small and thick
   * lines get clipped at the edge of the viewport.
   */
  it('covers the widest lineweight in model space', () => {
    const scale = 0.5
    const m = viewMargin({ scale, lineScale: 0.0378, lineWorld: 0, minWidthPx: 1 })
    // 211 hundredths of a millimetre at 0.0378 px each is ~8 px, so ~5 px of
    // half-width plus slack, converted to local units.
    expect(m / scale).toBeGreaterThan(211 * 0.0378 * 0.5)
    expect(m / scale).toBeLessThan(211 * 0.0378 * 0.5 + 2)
  })

  /**
   * On a sheet a lineweight is a real width on the page, so in local units it
   * does not change with zoom. The margin must therefore not collapse towards
   * zero as the sheet is zoomed into, the way a pixel-based one would.
   */
  it('does not collapse with zoom on a paper-space sheet', () => {
    const onPage = (211 * 0.01) / 2
    let previous = Infinity
    for (const scale of [1, 0.1, 0.01, 0.001, 0.0001]) {
      const m = viewMargin({ scale, lineScale: 0.0378, lineWorld: 0.01, minWidthPx: 1 })
      // Always at least the half-width the page itself calls for.
      expect(m).toBeGreaterThanOrEqual(onPage)
      // Shrinking only by the one pixel of antialiasing room, which does scale.
      expect(m).toBeLessThanOrEqual(previous)
      previous = m
    }
    // In the limit it is exactly the width on the page.
    expect(viewMargin({ scale: 1e-9, lineScale: 0.0378, lineWorld: 0.01, minWidthPx: 1 }))
      .toBeCloseTo(onPage, 6)
  })

  /** The two conventions are a choice, not a sum: the shader uses a ternary. */
  it('uses the page width alone on a sheet, not the larger of the two', () => {
    const paper = viewMargin({ scale: 1, lineScale: 0.0378, lineWorld: 0.01, minWidthPx: 1 })
    expect(paper).toBeCloseTo((211 * 0.01) / 2 + 1, 6)
  })

  it('is never zero, so a hairline still gets its antialiasing room', () => {
    const m = viewMargin({ scale: 2, lineScale: 0, lineWorld: 0, minWidthPx: 1 })
    expect(m).toBeGreaterThan(0)
  })

  it('scales with the viewer zoom in model space', () => {
    const a = viewMargin({ scale: 1, lineScale: 0.0378, lineWorld: 0, minWidthPx: 1 })
    const b = viewMargin({ scale: 2, lineScale: 0.0378, lineWorld: 0, minWidthPx: 1 })
    expect(b).toBeCloseTo(a * 2, 6)
  })
})
