/**
 * Orthographic 2D camera.
 *
 * Coordinates are "local": world coordinates minus the drawing origin. See
 * crates/exav-render/src/formats/dwg/DESIGN.md, 4.4, for why.
 */
export class Camera {
  /** Centre of the view, in local coordinates. */
  cx = 0
  cy = 0
  /** Local units per device pixel. Larger means zoomed further out. */
  scale = 1

  /** Framebuffer size in device pixels. */
  width = 1
  height = 1

  /** Frame the given extents with a margin, as a fraction of the view. */
  fit(extents: [number, number, number, number], margin = 0.04) {
    const [minX, minY, maxX, maxY] = extents
    const w = Math.max(maxX - minX, 1e-9)
    const h = Math.max(maxY - minY, 1e-9)
    this.cx = (minX + maxX) / 2
    this.cy = (minY + maxY) / 2
    const pad = 1 + margin * 2
    this.scale = Math.max((w * pad) / this.width, (h * pad) / this.height)
  }

  /** Device pixel position (y up, origin bottom-left) for a local point. */
  toScreen(x: number, y: number): [number, number] {
    return [(x - this.cx) / this.scale + this.width / 2, (y - this.cy) / this.scale + this.height / 2]
  }

  /** Local point under a device pixel position (y up, origin bottom-left). */
  toLocal(sx: number, sy: number): [number, number] {
    return [(sx - this.width / 2) * this.scale + this.cx, (sy - this.height / 2) * this.scale + this.cy]
  }

  /** Pan by a device-pixel delta. */
  panPixels(dx: number, dy: number) {
    this.cx -= dx * this.scale
    this.cy -= dy * this.scale
  }

  /**
   * Zoom by `factor` while holding the local point under (sx, sy) fixed.
   * `factor` > 1 zooms in.
   */
  zoomAt(sx: number, sy: number, factor: number) {
    const [bx, by] = this.toLocal(sx, sy)
    this.scale /= factor
    const [ax, ay] = this.toLocal(sx, sy)
    this.cx += bx - ax
    this.cy += by - ay
  }
}
