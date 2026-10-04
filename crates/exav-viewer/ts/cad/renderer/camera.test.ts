import { describe, expect, it } from 'vitest'
import { Camera } from './camera'

function cam(width = 800, height = 600) {
  const c = new Camera()
  c.width = width
  c.height = height
  return c
}

describe('Camera', () => {
  it('round-trips screen and local coordinates', () => {
    const c = cam()
    c.cx = 1234
    c.cy = -567
    c.scale = 0.25

    for (const [sx, sy] of [
      [0, 0],
      [400, 300],
      [799, 599],
    ]) {
      const [lx, ly] = c.toLocal(sx, sy)
      const [bx, by] = c.toScreen(lx, ly)
      expect(bx).toBeCloseTo(sx, 9)
      expect(by).toBeCloseTo(sy, 9)
    }
  })

  it('puts the view centre at the middle of the viewport', () => {
    const c = cam()
    c.cx = 10
    c.cy = 20
    c.scale = 2
    const [sx, sy] = c.toScreen(10, 20)
    expect(sx).toBeCloseTo(400)
    expect(sy).toBeCloseTo(300)
  })

  it('holds the point under the cursor fixed while zooming', () => {
    const c = cam()
    c.cx = 0
    c.cy = 0
    c.scale = 1

    // This is the invariant that makes wheel zoom feel right; if it breaks,
    // the drawing slides out from under the pointer.
    const anchor: [number, number] = [610, 145]
    const before = c.toLocal(...anchor)
    c.zoomAt(...anchor, 3.7)
    const after = c.toLocal(...anchor)

    expect(after[0]).toBeCloseTo(before[0], 6)
    expect(after[1]).toBeCloseTo(before[1], 6)
    expect(c.scale).toBeCloseTo(1 / 3.7, 9)
  })

  it('holds the anchor across repeated zooms in both directions', () => {
    const c = cam()
    c.scale = 4
    const anchor: [number, number] = [123, 456]
    const before = c.toLocal(...anchor)
    for (let i = 0; i < 20; i++) c.zoomAt(...anchor, 1.3)
    for (let i = 0; i < 20; i++) c.zoomAt(...anchor, 1 / 1.3)
    const after = c.toLocal(...anchor)
    expect(after[0]).toBeCloseTo(before[0], 4)
    expect(after[1]).toBeCloseTo(before[1], 4)
    expect(c.scale).toBeCloseTo(4, 6)
  })

  it('pans by exactly the pixel delta given', () => {
    const c = cam()
    c.scale = 0.5
    const before = c.toScreen(100, 200)
    c.panPixels(30, -12)
    const after = c.toScreen(100, 200)
    // Content follows the drag, so the feature moves with the cursor.
    expect(after[0] - before[0]).toBeCloseTo(30, 9)
    expect(after[1] - before[1]).toBeCloseTo(-12, 9)
  })

  it('fits extents inside the viewport with a margin', () => {
    const c = cam()
    const extents: [number, number, number, number] = [-50, -25, 150, 75]
    c.fit(extents, 0.05)

    expect(c.cx).toBeCloseTo(50)
    expect(c.cy).toBeCloseTo(25)

    // Every corner lands on screen.
    for (const [x, y] of [
      [extents[0], extents[1]],
      [extents[2], extents[3]],
      [extents[0], extents[3]],
      [extents[2], extents[1]],
    ]) {
      const [sx, sy] = c.toScreen(x, y)
      expect(sx).toBeGreaterThanOrEqual(0)
      expect(sx).toBeLessThanOrEqual(c.width)
      expect(sy).toBeGreaterThanOrEqual(0)
      expect(sy).toBeLessThanOrEqual(c.height)
    }
  })

  it('fits the constraining axis snugly rather than over-zooming', () => {
    const c = cam(800, 600)
    // Wide drawing: width should be the limiting dimension.
    c.fit([0, 0, 1000, 10], 0)
    expect(c.scale).toBeCloseTo(1000 / 800, 9)

    // Tall drawing: height limits instead.
    c.fit([0, 0, 10, 1000], 0)
    expect(c.scale).toBeCloseTo(1000 / 600, 9)
  })

  it('survives degenerate extents without producing NaN', () => {
    const c = cam()
    c.fit([5, 5, 5, 5])
    expect(Number.isFinite(c.scale)).toBe(true)
    expect(c.scale).toBeGreaterThan(0)
    expect(Number.isFinite(c.cx)).toBe(true)
    expect(Number.isFinite(c.cy)).toBe(true)
  })

  it('keeps y pointing up, matching gl_FragCoord', () => {
    const c = cam()
    c.scale = 1
    const low = c.toScreen(0, 0)
    const high = c.toScreen(0, 100)
    // A larger drawing y must map to a larger framebuffer y.
    expect(high[1]).toBeGreaterThan(low[1])
  })
})
