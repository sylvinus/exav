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
   * Xref inserts, images, underlays and OLE objects whose content lives in a
   * file the viewer was not given. An xref's path is drawn where it is
   * inserted, the others' frames.
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
  /** What `unknownEntities` counts, by DXF type (at most 16 types). */
  notDrawn: Record<string, number>
  /** The files external references name: xrefs, images, underlays (at most 16). */
  externalFiles: string[]
}

/** What a tab is drawn on, beyond its geometry. */
export interface Sheet {
  /**
   * Millimetres per drawing unit, which a lineweight on a layout is a width
   * in: 25.4 for a sheet in inches. 0 for model space, where a lineweight is
   * a width on the screen.
   */
  mmPerUnit: number
  /** `$LWDISPLAY`: the drawing is shown with its lineweights. */
  lineweights: boolean
  /** A layout's paper, `[minX, minY, maxX, maxY]` relative to `origin`; null in model space. */
  paper: [number, number, number, number] | null
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
  /**
   * The regions text runs are clipped to, which a record's clip id numbers
   * from 1: for each, `u32` triangle count, then `f32 x, y` per corner.
   */
  clips: ArrayBuffer
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
  sheet: Sheet
  /** Highest draw-order index, for normalising depth. */
  maxOrder: number
  /**
   * Leading strokes and fill vertices that are opaque. Everything after them
   * is translucent, in draw order, and is drawn after all of them.
   */
  opaqueStrokes: number
  opaqueFills: number
  /**
   * Tiles over `strokes`, so a view can skip what it does not touch: `u32
   * start, count | f32 minX, minY, maxX, maxY`, 24 bytes each. The opaque
   * half's are spatial buckets, the translucent half's runs of it in draw
   * order. The box is the true extent of the tile's contents in the same
   * origin-relative frame as the vertex buffers, and can reach outside its
   * own grid square because a long line belongs to one bucket and crosses
   * many.
   */
  strokeTiles: ArrayBuffer
  /** The same over `fills`, with `start` and `count` counted in vertices. */
  fillTiles: ArrayBuffer
  /**
   * Leading entries of each table that cover the opaque half. The two halves
   * are separate passes, so their tiles must not be interleaved.
   */
  opaqueStrokeTiles: number
  opaqueFillTiles: number
  /**
   * The translucent pass in draw order: `u32 kind (1 fills, 0 strokes),
   * first tile, end tile` per run, indices into that kind's table.
   */
  translucentRuns: ArrayBuffer
  /** Milliseconds spent in the worker. */
  parseMs: number
}

/** A layer as exposed to the host, including its live visibility. */
export interface Layer extends LayerInfo {
  visible: boolean
}

/** `f32 x0, y0, x1, y1 | u32 rgba, attr, order | f32 bulge` (scene.rs). */
export const STROKE_BYTES = 32
export const FILL_BYTES = 20
