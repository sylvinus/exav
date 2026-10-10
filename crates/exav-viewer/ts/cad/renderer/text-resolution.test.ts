import { describe, expect, it } from 'vitest'

import { clampEm } from './glyph-atlas'
import { TEXT_RECORD_BYTES } from './text-layout'
import { affordableEm, neededEm, targetEmFor, type ViewRect } from './text-resolution'

/** A text record as `text::encode` writes it; only the fields this reads. */
function run(opts: { x: number; y: number; height: number; len: number }): ArrayBuffer {
  const buf = new ArrayBuffer(TEXT_RECORD_BYTES)
  const v = new DataView(buf)
  v.setFloat32(0, opts.x, true)
  v.setFloat32(4, opts.y, true)
  v.setFloat32(8, opts.height, true)
  v.setUint16(36, opts.len, true)
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

/** A view 1000 units across at one unit per pixel, centred on the origin. */
const VIEW: ViewRect = { minX: -500, minY: -500, maxX: 500, maxY: 500, scale: 1 }

describe('neededEm', () => {
  it('is zero when there is no text', () => {
    expect(neededEm(new ArrayBuffer(0), VIEW)).toBe(0)
  })

  it('is zero when every run is empty', () => {
    expect(neededEm(run({ x: 0, y: 0, height: 10, len: 0 }), VIEW)).toBe(0)
  })

  /**
   * A DWG text height is a cap height, and the atlas is in ems, so the em a run
   * needs is its on-screen cap height divided by the cap ratio.
   */
  it('converts a cap height at the current zoom into an em', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    // 10 units tall at 1 unit/px is 10px of cap, which needs ~15px of em.
    expect(neededEm(records, VIEW)).toBeCloseTo(10 / 0.65, 5)
    // Zooming in by ten scales the requirement by ten.
    expect(neededEm(records, { ...VIEW, scale: 0.1 })).toBeCloseTo(100 / 0.65, 5)
  })

  it('takes the tallest visible run, not the first or the average', () => {
    const records = concat(
      run({ x: 0, y: 0, height: 2, len: 4 }),
      run({ x: 10, y: 10, height: 20, len: 4 }),
      run({ x: -10, y: -10, height: 5, len: 4 }),
    )
    expect(neededEm(records, VIEW)).toBeCloseTo(20 / 0.65, 5)
  })

  /**
   * The point of the exercise: a sheet's worth of body text must stop dictating
   * the atlas size once it has scrolled off, or zooming into a detail would
   * keep paying for glyphs nobody can see.
   */
  it('ignores runs outside the view', () => {
    const records = concat(
      run({ x: 0, y: 0, height: 2, len: 4 }),
      // Far away and much taller; must not count.
      run({ x: 100_000, y: 0, height: 500, len: 4 }),
    )
    expect(neededEm(records, VIEW)).toBeCloseTo(2 / 0.65, 5)
  })

  it('counts a run whose anchor is outside but whose text reaches in', () => {
    // Anchored past the right edge, but 20 characters of 10-unit text reach
    // back across it.
    const records = run({ x: 560, y: 0, height: 10, len: 20 })
    expect(neededEm(records, VIEW)).toBeGreaterThan(0)
  })

  it('is zero for a degenerate scale rather than infinite', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    expect(neededEm(records, { ...VIEW, scale: 0 })).toBe(0)
    expect(neededEm(records, { ...VIEW, scale: -1 })).toBe(0)
  })

  it('ignores a run with no height', () => {
    expect(neededEm(run({ x: 0, y: 0, height: 0, len: 4 }), VIEW)).toBe(0)
  })
})

describe('affordableEm', () => {
  it('shrinks as the character set grows', () => {
    const few = affordableEm(87)
    const many = affordableEm(348)
    expect(few).toBeGreaterThan(many)
    // Four times the cells is half the em, since cost goes with em squared.
    expect(few / many).toBeCloseTo(2, 1)
  })

  it('keeps the page inside its budget', () => {
    for (const cells of [1, 87, 348, 2000]) {
      const em = affordableEm(cells)
      // The estimate the budget is built from: half an em squared per cell.
      expect(cells * 0.5 * em * em).toBeLessThanOrEqual(4_000_001)
    }
  })

  it('is unbounded when there is nothing to pack', () => {
    expect(affordableEm(0)).toBe(Infinity)
  })
})

describe('targetEmFor', () => {
  it('rounds what the view needs up, and banks headroom beyond it', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    // 10 / 0.65 is 15.4 in use; four times that is 61.5, so the page is 64.
    expect(targetEmFor(records, VIEW, 87)).toBe(64)
    // Zoomed in twofold: still inside the headroom already banked.
    expect(targetEmFor(records, { ...VIEW, scale: 0.5 }, 87)).toBe(128)
    // Far enough in that the budget, not the view, decides, and it hands over
    // exactly what it can afford rather than the power of two below.
    expect(targetEmFor(records, { ...VIEW, scale: 0.05 }, 87)).toBe(affordableEm(87))
    expect(affordableEm(87)).toBeCloseTo(303, 0)
  })

  /**
   * The point of the headroom: a fourfold zoom must not need a new page, so
   * ordinary wheel and pinch movement never repaints the text.
   */
  it('covers a fourfold zoom without wanting a different page', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    const start = targetEmFor(records, { ...VIEW, scale: 1 }, 87)
    // Anything the reader can reach within a fourfold zoom is already covered
    // by the page built for the starting view.
    for (const factor of [1, 1.5, 2, 3, 4]) {
      expect(neededEm(records, { ...VIEW, scale: 1 / factor })).toBeLessThanOrEqual(start)
    }
  })

  /**
   * And rounds the budget cap *down*, because rounding a cap up is not a cap.
   * 87 cells can afford an em of 303; taking the next power of two above that
   * gives a 10.75 MB page against a 4 MB budget, and a rebuild several times
   * slower than the one it replaced.
   */
  it('never exceeds the budget cap, and spends all of it', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    const deep = { ...VIEW, scale: 1e-4 }
    expect(neededEm(records, deep)).toBeGreaterThan(100_000)

    for (const cells of [40, 87, 174, 348]) {
      const em = targetEmFor(records, deep, cells)
      // Pinned at the cap, exactly: quantising it down to a power of two threw
      // away up to three quarters of the allowance.
      expect(em).toBe(affordableEm(cells))
      expect(cells * 0.5 * em * em).toBeCloseTo(4_000_000, -3)
    }
  })

  it('is zero when nothing is visible, so the caller leaves the page alone', () => {
    const records = run({ x: 100_000, y: 0, height: 10, len: 1 })
    expect(targetEmFor(records, VIEW, 87)).toBe(0)
  })

  it('never asks for a page bigger than the budget, at any zoom', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    for (let i = 0; i < 40; i++) {
      const scale = Math.pow(0.5, i / 2)
      for (const cells of [1, 87, 348, 2000]) {
        const em = clampEm(targetEmFor(records, { ...VIEW, scale }, cells))
        expect(cells * 0.5 * em * em).toBeLessThanOrEqual(4_000_000)
      }
    }
  })
})

describe('clampEm', () => {
  it('brings a size into the range the atlas will rasterise at', () => {
    expect(clampEm(60)).toBe(60)
    expect(clampEm(298)).toBe(298)
    expect(clampEm(1)).toBe(16)
    expect(clampEm(0)).toBe(16)
    expect(clampEm(-5)).toBe(16)
    expect(clampEm(99_999)).toBe(1024)
    expect(clampEm(Infinity)).toBe(1024)
  })
})

/**
 * Rebuilds are what a reader notices, so they have to be rare. Two things make
 * them so: the view's demand is quantised to powers of two, and the page is
 * never shrunk once grown.
 */
describe('rebuild frequency', () => {
  /** Sizes a grow-only page would pass through over a zoom sweep. */
  function rebuilds(records: ArrayBuffer, cells: number, from: number, to: number): number[] {
    const seen: number[] = []
    let em = 0
    for (let i = 0; i <= 500; i++) {
      const scale = from * Math.pow(to / from, i / 500)
      const want = clampEm(targetEmFor(records, { ...VIEW, scale }, cells))
      if (want > em) {
        em = want
        seen.push(em)
      }
    }
    return seen
  }

  it('costs a handful of rebuilds over a thousandfold zoom', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    const seen = rebuilds(records, 87, 1, 0.001)
    expect(seen.length).toBeLessThanOrEqual(8)
    expect(seen.length).toBeGreaterThan(1)
    // And it settles at the budget rather than growing without end.
    expect(seen[seen.length - 1]).toBe(clampEm(affordableEm(87)))
  })

  it('costs nothing at all on the way back out', () => {
    const records = run({ x: 0, y: 0, height: 10, len: 4 })
    // Grown to the cap by zooming in, then zoomed all the way out again.
    const em = clampEm(targetEmFor(records, { ...VIEW, scale: 0.001 }, 87))
    for (let i = 0; i <= 500; i++) {
      const scale = 0.001 * Math.pow(1000, i / 500)
      expect(clampEm(targetEmFor(records, { ...VIEW, scale }, 87))).toBeLessThanOrEqual(em)
    }
  })

  /**
   * And panning at a fixed zoom must not rebuild at all, as long as the text
   * under the view is the same height.
   */
  it('does not change while panning across text of one height', () => {
    const records = concat(
      ...Array.from({ length: 20 }, (_, i) =>
        run({ x: i * 40 - 400, y: 0, height: 10, len: 4 }),
      ),
    )
    const sizes = new Set<number>()
    for (let pan = -200; pan <= 200; pan += 10) {
      sizes.add(
        clampEm(
          targetEmFor(
            records,
            { minX: pan - 500, maxX: pan + 500, minY: -500, maxY: 500, scale: 1 },
            87,
          ),
        ),
      )
    }
    expect(sizes.size).toBe(1)
  })
})
