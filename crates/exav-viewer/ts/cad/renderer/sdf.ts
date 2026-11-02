/**
 * Signed distance fields for glyph cells.
 *
 * A bitmap glyph is sharp only up to the size it was rasterised at; a page of
 * thousands of glyphs (a drawing in Chinese) cannot afford a large one, so
 * zooming in blurs its text. A distance field stores, for each texel, how far
 * it is from the glyph's edge, and the shader cuts the edge again at any
 * scale. Fields are computed from the rasterised coverage with the exact
 * Euclidean distance transform of Felzenszwalb and Huttenlocher (2012), run
 * once along columns and once along rows, the coverage of an edge texel
 * giving its sub-pixel offset.
 */

const FAR = 1e20

/**
 * Squared distance to the nearest zero of `f`, along one line, in place.
 * `v`, `z` and `d` are scratch of at least `n`, `n + 1` and `n`.
 */
function transform(f: Float64Array, n: number, v: Int32Array, z: Float64Array, d: Float64Array) {
  let k = 0
  v[0] = 0
  z[0] = -FAR
  z[1] = FAR
  for (let q = 1; q < n; q++) {
    let s = 0
    do {
      const r = v[k]!
      s = (f[q]! + q * q - (f[r]! + r * r)) / (2 * q - 2 * r)
    } while (s <= z[k]! && --k > -1)
    k++
    v[k] = q
    z[k] = s
    z[k + 1] = FAR
  }
  k = 0
  for (let q = 0; q < n; q++) {
    while (z[k + 1]! < q) k++
    const r = v[k]!
    d[q] = (q - r) * (q - r) + f[r]!
  }
  for (let q = 0; q < n; q++) f[q] = d[q]!
}

/** Both passes over a `w` by `h` grid of squared distances, in place. */
function transform2d(grid: Float64Array, w: number, h: number) {
  const n = Math.max(w, h)
  const f = new Float64Array(n)
  const d = new Float64Array(n)
  const v = new Int32Array(n)
  const z = new Float64Array(n + 1)
  for (let x = 0; x < w; x++) {
    for (let y = 0; y < h; y++) f[y] = grid[y * w + x]!
    transform(f, h, v, z, d)
    for (let y = 0; y < h; y++) grid[y * w + x] = f[y]!
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) f[x] = grid[y * w + x]!
    transform(f, w, v, z, d)
    for (let x = 0; x < w; x++) grid[y * w + x] = f[x]!
  }
}

/** A cell of an atlas, in texels. */
export interface FieldCell {
  x: number
  y: number
  w: number
  h: number
}

/**
 * Replaces the coverage in each cell's red channel (an RGBA atlas `width`
 * texels wide) with its field, in all three colour channels. A field takes
 * a while, hundreds of milliseconds for a page of text: the generator yields
 * once `sliceMs` has passed since it started or last yielded, so that a caller
 * can give the thread back before going on.
 */
export function* convertCells(
  px: Uint8ClampedArray,
  width: number,
  cells: readonly FieldCell[],
  spread: number,
  sliceMs: number,
  now: () => number = () => performance.now(),
): Generator<void> {
  let from = now()
  for (const c of cells) {
    const coverage = new Uint8Array(c.w * c.h)
    for (let y = 0; y < c.h; y++)
      for (let x = 0; x < c.w; x++) coverage[y * c.w + x] = px[((c.y + y) * width + c.x + x) * 4]!
    const field = distanceField(coverage, c.w, c.h, spread)
    for (let y = 0; y < c.h; y++)
      for (let x = 0; x < c.w; x++) {
        const i = ((c.y + y) * width + c.x + x) * 4
        px[i] = px[i + 1] = px[i + 2] = field[y * c.w + x]!
      }
    if (now() - from >= sliceMs) {
      yield
      from = now()
    }
  }
}

/**
 * The field of a cell from its coverage (0 to 255, row-major), as bytes:
 * 128 on the edge, rising inside and falling outside by 64 per `spread`
 * texels, so `spread` texels either side of the edge are represented.
 */
export function distanceField(coverage: ArrayLike<number>, w: number, h: number, spread: number): Uint8Array {
  const outside = new Float64Array(w * h)
  const inside = new Float64Array(w * h)
  for (let i = 0; i < w * h; i++) {
    const a = coverage[i]! / 255
    // A partly covered texel lies half a texel minus its coverage off the
    // edge, on the side its coverage puts it.
    outside[i] = a >= 1 ? 0 : a <= 0 ? FAR : Math.max(0, 0.5 - a) ** 2
    inside[i] = a >= 1 ? FAR : a <= 0 ? 0 : Math.max(0, a - 0.5) ** 2
  }
  transform2d(outside, w, h)
  transform2d(inside, w, h)
  const out = new Uint8Array(w * h)
  for (let i = 0; i < w * h; i++) {
    const signed = Math.sqrt(inside[i]!) - Math.sqrt(outside[i]!)
    out[i] = Math.max(0, Math.min(255, Math.round(128 + (signed / spread) * 64)))
  }
  return out
}
