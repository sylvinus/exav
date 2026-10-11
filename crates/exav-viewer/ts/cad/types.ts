/** One entry of the drawing's layer table. Array index is the layer id used by
 *  the `attr` field of every vertex. */
export interface LayerInfo {
  name: string
  /** Packed little-endian RGBA. */
  color: number
  /** Hundredths of a millimetre. 0 means hairline. */
  lineweight: number
  /** Layer was switched off in the drawing. */
  off: boolean
  /** Layer was frozen in the drawing. */
  frozen: boolean
}

/** Geometry the tessellator could not produce. All zeroes means full coverage. */
export interface Warnings {
  unknownEntities: number
  missingBlocks: number
  /** Text runs drawn. Every one uses a substituted font, never the original SHX. */
  textRuns: number
  /**
   * Glyphs of the count above drawn as stroke geometry rather than rasterised,
   * because their style names a stroke font. These take the drawing's
   * lineweight, the way AutoCAD draws SHX text.
   */
  strokeGlyphs: number
  hatchPatternsMissing: number
  hatchPatternsTruncated: number
  /**
   * Images, underlays and OLE objects whose content lives in a file the viewer
   * was not given. Only their frame is drawn.
   */
  externalReferences: number
  depthExceeded: number
  /** Entities left out once the layout reached the tessellator's budget. */
  sceneTruncated: number
  /**
   * Custom entities (ACAD_PROXY_ENTITY, an application's own types) saved
   * without proxy graphics, or with empty ones: only the application that made
   * them can show them.
   */
  proxyWithoutGraphics: number
}

/** The thumbnail a drawing was saved with: a PNG or a BMP file. */
export interface DrawingPreview {
  mime: string
  data: ArrayBuffer
}

/** One of the drawing's tabs: model space, or a paper-space sheet. */
export interface LayoutInfo {
  name: string
  isModel: boolean
}

/** A tessellated drawing, as it crosses the worker boundary. */
export interface ParsedDrawing {
  /** Interleaved stroke instances, `STROKE_BYTES` each. */
  strokes: ArrayBuffer
  /** Interleaved fill vertices, `FILL_BYTES` each. */
  fills: ArrayBuffer
  /** Text placement records, `TEXT_RECORD_BYTES` each. */
  texts: ArrayBuffer
  /** UTF-8 blob the text records index into. */
  textStrings: ArrayBuffer
  layers: LayerInfo[]
  /** The drawing's tabs, model space first. */
  layouts: LayoutInfo[]
  /** Which tab these buffers hold. Empty means model space. */
  layout: string
  /** World-space origin the vertex buffers are relative to. */
  origin: [number, number]
  /** [minX, minY, maxX, maxY], relative to `origin`. */
  extents: [number, number, number, number]
  warnings: Warnings
  /** Highest draw-order index, for normalising depth. */
  maxOrder: number
  /**
   * Leading strokes and fill vertices that are opaque. Everything after them
   * is translucent and is drawn without writing depth, so what lies behind
   * still blends through.
   */
  opaqueStrokes: number
  opaqueFills: number
  /**
   * Spatial buckets over `strokes`, so a view can skip what it does not touch:
   * `u32 start, count | f32 minX, minY, maxX, maxY`, 24 bytes each. The box is
   * the true extent of the bucket's contents in the same origin-relative frame
   * as the vertex buffers, and can reach outside its own grid square because a
   * long line belongs to one bucket and crosses many.
   */
  strokeTiles: ArrayBuffer
  /** The same over `fills`, with `start` and `count` counted in vertices. */
  fillTiles: ArrayBuffer
  /**
   * Leading entries of each table that cover the opaque half. The two halves
   * are separate passes, so their buckets must not be interleaved.
   */
  opaqueStrokeTiles: number
  opaqueFillTiles: number
  /** Milliseconds spent in the worker. */
  parseMs: number
}

/** A layer as exposed to the host, including its live visibility. */
export interface Layer extends LayerInfo {
  visible: boolean
}

export const STROKE_BYTES = 28
export const FILL_BYTES = 20
