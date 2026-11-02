import { tileCamera } from '../raster.js'
import { Camera } from './camera.js'
import { GlyphAtlas, clampEm, type GlyphRequest } from './glyph-atlas.js'
import { CLIP_FRAG, CLIP_VERT, FILL_FRAG, FILL_VERT, STROKE_FRAG, STROKE_VERT, TEXT_FRAG, TEXT_VERT } from './shaders.js'
import { GLYPH_BYTES, glyphsNeeded, layoutText } from './text-layout.js'
import { cappedByBudget, targetEmFor } from './text-resolution.js'
import {
  decodeRuns,
  decodeTiles,
  rangeTotal,
  viewMargin,
  visibleRanges,
  wholeTiles,
  type Range,
  type Run,
  type Tile,
} from './tiles.js'
import { FILL_BYTES, STROKE_BYTES, type ParsedDrawing } from '../types.js'

/** Device pixels per 1/100 mm at 100% zoom, before `lineweightScale`. */
const PX_PER_HUNDREDTH_MM = 0.0378
/** Width of the layer visibility texture; `layerVisible` in shaders.ts indexes by it. */
const LAYER_ROW = 256
/** `uStrokePass` in shaders.ts: every pixel, the fully covered core, the fringe. */
const STROKE_WHOLE = 0
const STROKE_CORES = 1
const STROKE_FRINGES = 2
/** `uTextPass` in shaders.ts: every glyph pixel, those at least half covered, the others. */
const TEXT_WHOLE = 0
const TEXT_CORES = 1
const TEXT_EDGES = 2

function compile(gl: WebGL2RenderingContext, type: number, src: string): WebGLShader {
  const sh = gl.createShader(type)!
  gl.shaderSource(sh, src)
  gl.compileShader(sh)
  if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
    const log = gl.getShaderInfoLog(sh)
    gl.deleteShader(sh)
    throw new Error(`shader compile failed: ${log}`)
  }
  return sh
}

function link(gl: WebGL2RenderingContext, vs: string, fs: string): WebGLProgram {
  const p = gl.createProgram()!
  const v = compile(gl, gl.VERTEX_SHADER, vs)
  const f = compile(gl, gl.FRAGMENT_SHADER, fs)
  gl.attachShader(p, v)
  gl.attachShader(p, f)
  gl.linkProgram(p)
  gl.deleteShader(v)
  gl.deleteShader(f)
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    const log = gl.getProgramInfoLog(p)
    gl.deleteProgram(p)
    throw new Error(`program link failed: ${log}`)
  }
  return p
}

type Uniforms = Record<string, WebGLUniformLocation | null>

function uniforms(gl: WebGL2RenderingContext, p: WebGLProgram, names: string[]): Uniforms {
  const out: Uniforms = {}
  for (const n of names) out[n] = gl.getUniformLocation(p, n)
  return out
}

/**
 * WebGL2 renderer for tessellated CAD geometry.
 *
 * Three pipelines (strokes, fills, text), all reading the same
 * layer-visibility texture, so toggling a layer is a small texture upload
 * rather than a buffer rebuild.
 */
export class Renderer {
  readonly camera = new Camera()

  private gl: WebGL2RenderingContext
  private strokeProg: WebGLProgram
  private fillProg: WebGLProgram
  private textProg: WebGLProgram
  private strokeU: Uniforms
  private fillU: Uniforms
  private textU: Uniforms

  private quadBuf: WebGLBuffer
  private unitQuadBuf: WebGLBuffer
  private strokeBuf: WebGLBuffer | null = null
  private fillBuf: WebGLBuffer | null = null
  private textBuf: WebGLBuffer | null = null
  private strokeVao: WebGLVertexArrayObject | null = null
  private fillVao: WebGLVertexArrayObject | null = null
  private textVao: WebGLVertexArrayObject | null = null
  private atlasTex: WebGLTexture | null = null
  glyphCount = 0
  /** Glyph instances by clip region, 0 (none) first; see text-layout.ts. */
  private glyphRanges: { clip: number; start: number; count: number }[] = []

  // Clip regions: their triangles in one buffer, and each region's vertices in it.
  private clipProg: WebGLProgram
  private clipU: Uniforms
  private clipBuf: WebGLBuffer | null = null
  private clipVao: WebGLVertexArrayObject | null = null
  private clipRegions: { first: number; count: number }[] = []

  // Kept so the atlas can be rasterised again at a different size when the
  // zoom changes. See `text-resolution.ts`.
  private textRecords: ArrayBuffer | null = null
  private textStrings: Uint8Array | null = null
  private glyphRequests: GlyphRequest[] = []
  /** Em the current atlas was rasterised at, or 0 when there is none. */
  private atlasEm = 0
  /** The atlas holds distance fields: the budget capped its em. */
  private atlasSdf = false
  /** Pending debounced check, so a pinch rebuilds once when it settles. */
  private textResolutionTimer = 0
  /** A page is being made by `refreshText`. */
  private refreshing = false
  /** Counts the drawings whose text was set, to tell a page made for an earlier one. */
  private textDrawing = 0

  private layerTex: WebGLTexture
  private layerVis = new Uint8Array(LAYER_ROW)

  private strokeCount = 0
  private fillCount = 0
  private maxOrder = 1

  // Spatial buckets, so a view only draws what it touches. See tiles.ts.
  private strokeTiles: Tile[] = []
  private fillTiles: Tile[] = []
  /** Leading tiles of each table that cover the opaque half. */
  private opaqueStrokeTiles = 0
  private opaqueFillTiles = 0
  /** The translucent tiles, fills and strokes, in draw order. */
  private translucentRuns: Run[] = []
  /** What the last frame actually submitted, for diagnostics. */
  drawnStrokes = 0
  drawnFills = 0
  /** Geometry draw calls the last frame issued, one per contiguous run. */
  drawCalls = 0

  background: [number, number, number] = [1, 1, 1]
  /** "drawing" follows the drawing's `$LWDISPLAY`; the others override it. */
  lineweights: 'drawing' | 'always' | 'never' = 'drawing'
  /** Everything in ink, as monochrome.ctb plots it. */
  monochrome = false
  /** The drawing on screen is a paper-space sheet, not model space. */
  paperSpace = false
  lineweightScale = 1
  /** From the drawing: its lineweights are shown, and a sheet's millimetres per unit. */
  private drawingLineweights = true
  private mmPerUnit = 1
  /** A layout's paper, drawn under it (`drawPaper`); null in model space. */
  private paper: [number, number, number, number] | null = null
  /** Runs whose glyphs could not be rasterised, from the last setDrawing(). */
  skippedTextRuns = 0

  /** A renderer for one picture (see the constructor). */
  private readonly picture: boolean
  /** Device pixels per CSS pixel that line widths are drawn for; null follows the window. */
  pixelRatio: number | null = null
  /** Factor on the widths that are on a sheet (`lineWorld`); see `lineweightFactors` in ../raster.ts. */
  paperWidthScale = 1
  /** The ground's opacity: 0 draws on transparency, and then no sheet or surround is drawn. */
  backgroundAlpha = 1
  /** A picture drawn in tiles: the view of the whole picture, and where the tile drawn is in it (from the bottom left). */
  private whole: { cx: number; cy: number; scale: number; width: number; height: number } | null = null
  private tileOrigin: [number, number] = [0, 0]

  private frame = 0
  private disposed = false
  /** The camera of the last frame drawn: what the canvas shows. */
  readonly drawn = { cx: 0, cy: 0, scale: 1, width: 1, height: 1 }
  /** Called after each frame is drawn, with `drawn` up to date. */
  onDraw: (() => void) | null = null
  /** First stroke the per-instance attributes currently point at. */
  private strokeInstanceOffset = 0

  /**
   * Point the stroke pipeline's per-instance attributes at `first`.
   *
   * drawArraysInstanced has no first-instance parameter, so drawing a slice of
   * the buffer means moving the attribute offsets instead.
   */
  private setStrokeInstanceOffset(first: number) {
    if (this.strokeInstanceOffset === first || !this.strokeBuf) return
    this.strokeInstanceOffset = first
    const gl = this.gl
    const base = first * STROKE_BYTES
    gl.bindBuffer(gl.ARRAY_BUFFER, this.strokeBuf)
    gl.vertexAttribPointer(1, 2, gl.FLOAT, false, STROKE_BYTES, base)
    gl.vertexAttribPointer(2, 2, gl.FLOAT, false, STROKE_BYTES, base + 8)
    gl.vertexAttribPointer(3, 4, gl.UNSIGNED_BYTE, true, STROKE_BYTES, base + 16)
    gl.vertexAttribIPointer(4, 1, gl.UNSIGNED_INT, STROKE_BYTES, base + 20)
    gl.vertexAttribIPointer(5, 1, gl.UNSIGNED_INT, STROKE_BYTES, base + 24)
    gl.vertexAttribPointer(6, 1, gl.FLOAT, false, STROKE_BYTES, base + 28)
  }

  /**
   * With `picture`, a renderer for one picture of the drawing (an export) on
   * a canvas of its own: nothing is drawn until `paint`, the camera is set by
   * the caller, and the context has an alpha channel when `alpha` is true
   * (premultiplied, as the browser composites it).
   */
  constructor(
    private canvas: HTMLCanvasElement | OffscreenCanvas,
    picture?: { alpha: boolean },
  ) {
    this.picture = picture !== undefined
    const gl = (canvas as HTMLCanvasElement).getContext('webgl2', {
      alpha: picture?.alpha ?? false,
      premultipliedAlpha: true,
      antialias: false,
      depth: true,
      // Clip regions mask the text that crosses them.
      stencil: true,
      desynchronized: !picture,
      powerPreference: 'high-performance',
      preserveDrawingBuffer: false,
    })
    if (!gl) throw new Error('WebGL2 is required and is not available in this browser')
    this.gl = gl

    this.strokeProg = link(gl, STROKE_VERT, STROKE_FRAG)
    this.fillProg = link(gl, FILL_VERT, FILL_FRAG)
    this.textProg = link(gl, TEXT_VERT, TEXT_FRAG)
    this.clipProg = link(gl, CLIP_VERT, CLIP_FRAG)
    this.clipU = uniforms(gl, this.clipProg, ['uCenter', 'uScale', 'uViewport'])
    const common = ['uCenter', 'uScale', 'uViewport', 'uLayerVis', 'uBgLuma', 'uMaxOrder', 'uMono']
    this.strokeU = uniforms(gl, this.strokeProg, [
      ...common,
      'uLineScale',
      'uMinWidth',
      'uLineWorld',
      'uStrokePass',
    ])
    this.fillU = uniforms(gl, this.fillProg, [...common, 'uBackground'])
    this.textU = uniforms(gl, this.textProg, [...common, 'uAtlas', 'uTextPass', 'uSdf'])

    // Unit quad as a triangle strip, shared by every stroke instance.
    this.quadBuf = gl.createBuffer()!
    gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf)
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
      gl.STATIC_DRAW,
    )

    // Glyph quads span 0..1 rather than -1..1, so the instance origin is the
    // corner rather than the centre.
    this.unitQuadBuf = gl.createBuffer()!
    gl.bindBuffer(gl.ARRAY_BUFFER, this.unitQuadBuf)
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([0, 0, 1, 0, 0, 1, 1, 1]), gl.STATIC_DRAW)

    this.layerTex = gl.createTexture()!
    gl.bindTexture(gl.TEXTURE_2D, this.layerTex)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
    this.uploadLayerVisibility()

    // Draw order is resolved by depth rather than by submission order, so the
    // fill and stroke passes can stay batched while still letting a later
    // entity cover an earlier one.
    gl.enable(gl.DEPTH_TEST)
    gl.depthFunc(gl.LESS)
    gl.depthMask(true)
    gl.enable(gl.BLEND)
    gl.blendFuncSeparate(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA, gl.ONE, gl.ONE_MINUS_SRC_ALPHA)
  }

  /**
   * Throw on the first GL error, naming where it happened.
   *
   * Only called on load, never per frame: `getError` flushes the pipeline, and
   * a silent `INVALID_OPERATION` here means an attribute the shader declares is
   * missing from the vertex array, which draws nothing and is easy to miss.
   */
  private check(label: string) {
    const e = this.gl.getError()
    if (e !== this.gl.NO_ERROR) throw new Error(`GL error 0x${e.toString(16)} at ${label}`)
  }

  /**
   * Replace the scene. Buffers are uploaded once and then only read. With
   * `fit` false the camera stays where it is: the same layout drawn again
   * (another ground) keeps the user's view.
   */
  setDrawing(d: ParsedDrawing, visible: boolean[], fit = true) {
    const gl = this.gl
    this.strokeCount = d.strokes.byteLength / STROKE_BYTES
    this.fillCount = d.fills.byteLength / FILL_BYTES
    const opaqueStrokes = Math.min(d.opaqueStrokes, this.strokeCount)
    const opaqueFills = Math.min(d.opaqueFills, this.fillCount)
    this.strokeTiles = d.strokeTiles ? decodeTiles(d.strokeTiles) : []
    this.fillTiles = d.fillTiles ? decodeTiles(d.fillTiles) : []
    this.opaqueStrokeTiles = Math.min(d.opaqueStrokeTiles ?? 0, this.strokeTiles.length)
    this.opaqueFillTiles = Math.min(d.opaqueFillTiles ?? 0, this.fillTiles.length)
    if (this.strokeTiles.length === 0) {
      this.strokeTiles = wholeTiles(this.strokeCount, opaqueStrokes)
      this.opaqueStrokeTiles = opaqueStrokes > 0 ? 1 : 0
    }
    if (this.fillTiles.length === 0) {
      this.fillTiles = wholeTiles(this.fillCount, opaqueFills)
      this.opaqueFillTiles = opaqueFills > 0 ? 1 : 0
    }
    this.translucentRuns = d.translucentRuns ? decodeRuns(d.translucentRuns) : []
    if (this.translucentRuns.length === 0) {
      // Without the tessellator's order: the fills, then the strokes.
      for (const [fills, from, to] of [
        [true, this.opaqueFillTiles, this.fillTiles.length],
        [false, this.opaqueStrokeTiles, this.strokeTiles.length],
      ] as const) {
        if (to > from) this.translucentRuns.push({ fills, from, to })
      }
    }
    // A run past its table is a damaged answer: drawn as far as the table goes.
    for (const r of this.translucentRuns) {
      const n = (r.fills ? this.fillTiles : this.strokeTiles).length
      r.to = Math.min(r.to, n)
      r.from = Math.min(r.from, r.to)
    }
    this.paperSpace = d.layout !== ''
    this.drawingLineweights = d.sheet?.lineweights ?? true
    this.mmPerUnit = d.sheet?.mmPerUnit > 0 ? d.sheet.mmPerUnit : 1
    this.paper = d.sheet?.paper ?? null
    this.maxOrder = Math.max(1, d.maxOrder)
    this.setClips(d.clips)

    if (this.strokeVao) gl.deleteVertexArray(this.strokeVao)
    if (this.fillVao) gl.deleteVertexArray(this.fillVao)
    if (this.strokeBuf) gl.deleteBuffer(this.strokeBuf)
    if (this.fillBuf) gl.deleteBuffer(this.fillBuf)

    // Strokes: static quad at divisor 0, per-segment data at divisor 1.
    this.strokeVao = gl.createVertexArray()
    gl.bindVertexArray(this.strokeVao)

    gl.bindBuffer(gl.ARRAY_BUFFER, this.quadBuf)
    gl.enableVertexAttribArray(0)
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)

    this.strokeBuf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, this.strokeBuf)
    gl.bufferData(gl.ARRAY_BUFFER, d.strokes, gl.STATIC_DRAW)
    // f32 x0,y0 | f32 x1,y1 | ubyte4 rgba | uint32 attr | uint32 order | f32 bulge
    gl.enableVertexAttribArray(1)
    gl.vertexAttribPointer(1, 2, gl.FLOAT, false, STROKE_BYTES, 0)
    gl.vertexAttribDivisor(1, 1)
    gl.enableVertexAttribArray(2)
    gl.vertexAttribPointer(2, 2, gl.FLOAT, false, STROKE_BYTES, 8)
    gl.vertexAttribDivisor(2, 1)
    gl.enableVertexAttribArray(3)
    gl.vertexAttribPointer(3, 4, gl.UNSIGNED_BYTE, true, STROKE_BYTES, 16)
    gl.vertexAttribDivisor(3, 1)
    gl.enableVertexAttribArray(4)
    gl.vertexAttribIPointer(4, 1, gl.UNSIGNED_INT, STROKE_BYTES, 20)
    gl.vertexAttribDivisor(4, 1)
    gl.enableVertexAttribArray(5)
    gl.vertexAttribIPointer(5, 1, gl.UNSIGNED_INT, STROKE_BYTES, 24)
    gl.vertexAttribDivisor(5, 1)
    gl.enableVertexAttribArray(6)
    gl.vertexAttribPointer(6, 1, gl.FLOAT, false, STROKE_BYTES, 28)
    gl.vertexAttribDivisor(6, 1)

    this.strokeInstanceOffset = 0

    // Fills: plain triangle list.
    this.fillVao = gl.createVertexArray()
    gl.bindVertexArray(this.fillVao)
    this.fillBuf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, this.fillBuf)
    gl.bufferData(gl.ARRAY_BUFFER, d.fills, gl.STATIC_DRAW)
    gl.enableVertexAttribArray(0)
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, FILL_BYTES, 0)
    gl.enableVertexAttribArray(1)
    gl.vertexAttribPointer(1, 4, gl.UNSIGNED_BYTE, true, FILL_BYTES, 8)
    gl.enableVertexAttribArray(2)
    gl.vertexAttribIPointer(2, 1, gl.UNSIGNED_INT, FILL_BYTES, 12)
    gl.enableVertexAttribArray(3)
    gl.vertexAttribIPointer(3, 1, gl.UNSIGNED_INT, FILL_BYTES, 16)

    this.check('setDrawing:fillVao')

    // Frame the drawing before the text is rasterised, because the atlas
    // resolution is chosen from the view. Doing it afterwards would size the
    // first page against whatever the camera happened to be showing before.
    this.resize()
    if (fit) this.camera.fit(d.extents)
    this.camera.limit(d.extents)

    this.buildTextPipeline(d)
    this.check('setDrawing:textVao')

    gl.bindVertexArray(null)

    this.check('setDrawing:buffers')
    this.setLayerVisibility(visible)
    this.check('setDrawing:layers')
    this.requestDraw()
  }

  /**
   * Take the drawing's text and rasterise it at a size suited to the view.
   *
   * The records and strings are kept, because the atlas is rebuilt whenever the
   * zoom changes enough to want a different resolution. They are small next to
   * the geometry: 750 KB of records for a site plan's 15,642 runs.
   */
  private buildTextPipeline(d: ParsedDrawing) {
    this.textDrawing++
    this.releaseText()
    this.textRecords = null
    this.textStrings = null
    this.glyphRequests = []
    this.atlasEm = 0
    this.atlasSdf = false

    const strings = new Uint8Array(d.textStrings)
    if (d.texts.byteLength === 0 || strings.length === 0) return

    this.textRecords = d.texts
    this.textStrings = strings
    this.glyphRequests = glyphsNeeded(d.texts, strings)
    const target = this.targetEm()
    this.rebuildText(target.em, target.sdf)
  }

  /** Upload the clip regions: per region a `u32` triangle count, then its corners. */
  private setClips(clips: ArrayBuffer | undefined) {
    const gl = this.gl
    if (this.clipVao) gl.deleteVertexArray(this.clipVao)
    if (this.clipBuf) gl.deleteBuffer(this.clipBuf)
    this.clipVao = null
    this.clipBuf = null
    this.clipRegions = []
    if (!clips || clips.byteLength === 0) return
    const view = new DataView(clips)
    const corners: number[] = []
    for (let at = 0; at + 4 <= clips.byteLength; ) {
      const triangles = view.getUint32(at, true)
      at += 4
      const vertices = Math.min(triangles * 3, Math.floor((clips.byteLength - at) / 8))
      this.clipRegions.push({ first: corners.length / 2, count: vertices })
      for (let i = 0; i < vertices; i++, at += 8) corners.push(view.getFloat32(at, true), view.getFloat32(at + 4, true))
    }
    this.clipVao = gl.createVertexArray()
    gl.bindVertexArray(this.clipVao)
    this.clipBuf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, this.clipBuf)
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(corners), gl.STATIC_DRAW)
    gl.enableVertexAttribArray(0)
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)
    gl.bindVertexArray(null)
  }

  /** Point the glyph instance attributes at instance `first`: instancing has no first-instance argument. */
  private setTextInstanceOffset(first: number) {
    const gl = this.gl
    const base = first * GLYPH_BYTES
    gl.bindBuffer(gl.ARRAY_BUFFER, this.textBuf)
    gl.vertexAttribPointer(1, 2, gl.FLOAT, false, GLYPH_BYTES, base)
    gl.vertexAttribPointer(2, 2, gl.FLOAT, false, GLYPH_BYTES, base + 8)
    gl.vertexAttribPointer(3, 2, gl.FLOAT, false, GLYPH_BYTES, base + 16)
    gl.vertexAttribPointer(4, 4, gl.UNSIGNED_SHORT, true, GLYPH_BYTES, base + 24)
    gl.vertexAttribPointer(5, 4, gl.UNSIGNED_BYTE, true, GLYPH_BYTES, base + 32)
    gl.vertexAttribIPointer(6, 1, gl.UNSIGNED_INT, GLYPH_BYTES, base + 36)
    gl.vertexAttribIPointer(7, 1, gl.UNSIGNED_INT, GLYPH_BYTES, base + 40)
  }

  /** Drop the GPU objects the text pipeline owns. */
  private releaseText() {
    const gl = this.gl
    if (this.textVao) gl.deleteVertexArray(this.textVao)
    if (this.textBuf) gl.deleteBuffer(this.textBuf)
    if (this.atlasTex) gl.deleteTexture(this.atlasTex)
    this.textVao = null
    this.textBuf = null
    this.atlasTex = null
    this.glyphCount = 0
  }

  /** The view rectangle in local coordinates. */
  private viewRect(): { minX: number; minY: number; maxX: number; maxY: number } {
    const cam = this.camera
    const [minX, minY] = cam.toLocal(0, 0)
    const [maxX, maxY] = cam.toLocal(cam.width, cam.height)
    return { minX, minY, maxX, maxY }
  }

  /**
   * How far outside the view geometry can still paint, in local units.
   *
   * Mirrors the quad expansion in the stroke vertex shader. Getting this too
   * small clips the edges of thick lines at the border of the viewport, which
   * is the failure a bounding-box test invites.
   */
  private cullMargin(): number {
    const dpr = this.dpr()
    return viewMargin({
      scale: this.camera.scale,
      lineScale: this.lineScale(dpr),
      lineWorld: this.lineWorld(),
      minWidthPx: dpr,
    })
  }

  /** Device pixels per CSS pixel: the window's, at most 2, unless a picture sets its own. */
  private dpr(): number {
    return this.pixelRatio ?? Math.min(window.devicePixelRatio || 1, 2)
  }

  private showLineweights(): boolean {
    return this.lineweights === 'always' || (this.lineweights === 'drawing' && this.drawingLineweights)
  }

  /** Device pixels per hundredth of a millimetre, in model space. */
  private lineScale(dpr: number): number {
    return this.showLineweights() ? PX_PER_HUNDREDTH_MM * this.lineweightScale * dpr : 0
  }

  /**
   * Drawing units per hundredth of a millimetre on a sheet, where a
   * lineweight is a width on the page and grows with zoom: a hundredth of a
   * unit on a sheet in millimetres, 1/2540 on one in inches.
   */
  private lineWorld(): number {
    return this.showLineweights() && this.paperSpace ? (0.01 * this.lineweightScale * this.paperWidthScale) / this.mmPerUnit : 0
  }

  private strokeRanges(from: number, to: number): Range[] {
    return visibleRanges(this.strokeTiles, from, to, this.viewRect(), this.cullMargin())
  }

  private fillRanges(from: number, to: number): Range[] {
    return visibleRanges(this.fillTiles, from, to, this.viewRect(), this.cullMargin())
  }

  /** The atlas em this view wants, quantised, and whether the budget caps it. */
  private targetEm(): { em: number; sdf: boolean } {
    if (!this.textRecords) return { em: 0, sdf: false }
    const cam = this.camera
    const [minX, minY] = cam.toLocal(0, 0)
    const [maxX, maxY] = cam.toLocal(cam.width, cam.height)
    const view = { minX, minY, maxX, maxY, scale: cam.scale }
    const cells = this.glyphRequests.length
    return {
      em: clampEm(targetEmFor(this.textRecords, view, cells)),
      sdf: cappedByBudget(this.textRecords, view, cells),
    }
  }

  /**
   * Rasterise the atlas at `em` and lay the text out against it.
   *
   * Glyph *positions* do not depend on the em: the atlas reports its metrics in
   * em units, so a run occupies the same box whatever resolution it was
   * rasterised at. Only the texture and the UVs change, which is what makes
   * this safe to do mid-session.
   */
  private rebuildText(em: number, sdf: boolean) {
    const gl = this.gl
    this.releaseText()
    this.skippedTextRuns = 0
    if (!this.textRecords || !this.textStrings || this.glyphRequests.length === 0) return

    // The caller has already loaded and awaited the faces these runs name.
    // Rasterising before they are ready would silently fall back to a system
    // font, which is the machine-dependence the bundle exists to remove.
    this.installText(
      GlyphAtlas.build(this.glyphRequests, gl.getParameter(gl.MAX_TEXTURE_SIZE) as number, em, sdf),
    )
  }

  /** Lay the text out against `atlas` and put both on the GPU. The old text is gone: see `releaseText`. */
  private installText(atlas: GlyphAtlas) {
    const gl = this.gl
    if (!this.textRecords || !this.textStrings) return
    this.atlasEm = atlas.em
    this.atlasSdf = atlas.sdf
    const laid = layoutText(this.textRecords, this.textStrings, atlas)
    this.skippedTextRuns = laid.skippedRuns
    if (laid.glyphCount === 0) return

    this.atlasTex = gl.createTexture()
    gl.bindTexture(gl.TEXTURE_2D, this.atlasTex)
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1)
    // White glyphs on opaque black (glyph-atlas.ts): the red channel is the coverage.
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, gl.RED, gl.UNSIGNED_BYTE, atlas.canvas)
    gl.generateMipmap(gl.TEXTURE_2D)
    // The texture holds it now: the canvas's pixels are freed rather than left to the collector.
    atlas.canvas.width = 0
    atlas.canvas.height = 0
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)

    this.textVao = gl.createVertexArray()
    gl.bindVertexArray(this.textVao)

    gl.bindBuffer(gl.ARRAY_BUFFER, this.unitQuadBuf)
    gl.enableVertexAttribArray(0)
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)

    this.textBuf = gl.createBuffer()
    gl.bindBuffer(gl.ARRAY_BUFFER, this.textBuf)
    gl.bufferData(gl.ARRAY_BUFFER, laid.buffer, gl.STATIC_DRAW)
    // f32 origin | f32 edgeX | f32 edgeY | ushort4 uv | ubyte4 rgba | uint attr
    gl.enableVertexAttribArray(1)
    gl.vertexAttribPointer(1, 2, gl.FLOAT, false, GLYPH_BYTES, 0)
    gl.vertexAttribDivisor(1, 1)
    gl.enableVertexAttribArray(2)
    gl.vertexAttribPointer(2, 2, gl.FLOAT, false, GLYPH_BYTES, 8)
    gl.vertexAttribDivisor(2, 1)
    gl.enableVertexAttribArray(3)
    gl.vertexAttribPointer(3, 2, gl.FLOAT, false, GLYPH_BYTES, 16)
    gl.vertexAttribDivisor(3, 1)
    gl.enableVertexAttribArray(4)
    gl.vertexAttribPointer(4, 4, gl.UNSIGNED_SHORT, true, GLYPH_BYTES, 24)
    gl.vertexAttribDivisor(4, 1)
    gl.enableVertexAttribArray(5)
    gl.vertexAttribPointer(5, 4, gl.UNSIGNED_BYTE, true, GLYPH_BYTES, 32)
    gl.vertexAttribDivisor(5, 1)
    gl.enableVertexAttribArray(6)
    gl.vertexAttribIPointer(6, 1, gl.UNSIGNED_INT, GLYPH_BYTES, 36)
    gl.vertexAttribDivisor(6, 1)
    gl.enableVertexAttribArray(7)
    gl.vertexAttribIPointer(7, 1, gl.UNSIGNED_INT, GLYPH_BYTES, 40)
    gl.vertexAttribDivisor(7, 1)

    this.glyphCount = laid.glyphCount
    this.glyphRanges = laid.clipRanges
  }

  /**
   * Upload the whole visibility vector, as rows of 256: a layer id is 16
   * bits, and one row of 65,536 would pass the texture size limit of most
   * GPUs (4096 on some).
   */
  setLayerVisibility(visible: boolean[]) {
    const rows = Math.max(1, Math.ceil(visible.length / LAYER_ROW))
    this.layerVis = new Uint8Array(LAYER_ROW * rows)
    for (let i = 0; i < visible.length; i++) this.layerVis[i] = visible[i] ? 255 : 0
    this.uploadLayerVisibility()
    this.requestDraw()
  }

  private uploadLayerVisibility() {
    const gl = this.gl
    gl.bindTexture(gl.TEXTURE_2D, this.layerTex)
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1)
    gl.texImage2D(
      gl.TEXTURE_2D,
      0,
      gl.R8,
      LAYER_ROW,
      this.layerVis.length / LAYER_ROW,
      0,
      gl.RED,
      gl.UNSIGNED_BYTE,
      this.layerVis,
    )
  }

  /** Match the framebuffer to the element's CSS size. Returns true if changed. */
  resize(): boolean {
    // A picture's canvas is sized by whoever draws it.
    if (this.picture) return false
    const canvas = this.canvas as HTMLCanvasElement
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = Math.max(1, Math.round(canvas.clientWidth * dpr))
    const h = Math.max(1, Math.round(canvas.clientHeight * dpr))
    // A renderer made again on a canvas already sized (after a lost context)
    // still has to give its camera that size.
    if (canvas.width === w && canvas.height === h && this.camera.width === w && this.camera.height === h) {
      return false
    }
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w
      canvas.height = h
    }
    this.camera.width = w
    this.camera.height = h
    return true
  }

  requestDraw() {
    if (this.disposed || this.picture) return
    this.scheduleTextResolutionCheck()
    this.scheduleFrame()
  }

  /**
   * Time the view must hold still before the atlas is rasterised again.
   *
   * Long enough that a pinch or a wheel spin rebuilds once at the end rather
   * than at every step, short enough not to be noticed as a delay before text
   * sharpens.
   */
  private static readonly TEXT_SETTLE_MS = 140

  /**
   * Re-check the atlas resolution once the view has stopped moving.
   *
   * Quantising to powers of two, and banking `ZOOM_HEADROOM` beyond what the
   * view needs, does most of the work: ordinary panning and zooming do not
   * cross a boundary, so this usually decides to do nothing. The debounce
   * covers a gesture that sweeps across several boundaries at once.
   *
   * The page only ever grows. Shrinking it would be free memory but a visible
   * repaint, and it would come exactly when the reader zooms out, which is when
   * they are least interested in the text changing under them. The budget in
   * `text-resolution.ts` already caps how far it can grow, so the high-water
   * mark is bounded; a new drawing or layout starts again from nothing.
   */
  private scheduleTextResolutionCheck() {
    if (!this.textRecords) return
    clearTimeout(this.textResolutionTimer)
    this.textResolutionTimer = setTimeout(() => void this.refreshText(), Renderer.TEXT_SETTLE_MS) as unknown as number
  }

  /**
   * The page rasterised again for the view, if it wants a bigger one. The
   * distance fields it may hold take longer than a frame, so the page is made
   * a slice at a time (`GlyphAtlas.buildAsync`) while the old one stays on
   * screen, and swapped in when done.
   */
  private async refreshText() {
    if (this.disposed || !this.textRecords || this.glyphRequests.length === 0 || this.refreshing) return
    const want = this.targetEm()
    // 0 means nothing is on screen to size against; leave the page alone
    // rather than rebuild it twice while panning across empty paper. A
    // page the budget caps is rebuilt once more, as distance fields.
    if (want.em === 0 || (want.em <= this.atlasEm && (!want.sdf || this.atlasSdf))) return
    const drawing = this.textDrawing
    this.refreshing = true
    let atlas: GlyphAtlas
    try {
      atlas = await GlyphAtlas.buildAsync(
        this.glyphRequests,
        this.gl.getParameter(this.gl.MAX_TEXTURE_SIZE) as number,
        want.em,
        want.sdf,
        () => new Promise((resolve) => setTimeout(resolve)),
      )
    } finally {
      this.refreshing = false
    }
    if (this.disposed) return
    // A page for a drawing that was replaced meanwhile is of no use.
    if (drawing === this.textDrawing) {
      this.releaseText()
      this.installText(atlas)
      this.scheduleFrame()
    }
    // The view may have moved on while the page was made.
    this.scheduleTextResolutionCheck()
  }

  private scheduleFrame() {
    if (this.frame) return
    this.frame = requestAnimationFrame(() => {
      this.frame = 0
      this.draw()
    })
  }

  /** Draws now, for a picture: the canvas then holds it until the caller takes it. */
  paint() {
    this.draw()
  }

  /** The GPU took the context away (a reset): what it holds is gone. */
  isLost(): boolean {
    return this.gl.isContextLost()
  }

  /** The drawing buffer's size, which a canvas the GPU cannot hold gets less of. */
  drawingBufferSize(): [number, number] {
    return [this.gl.drawingBufferWidth, this.gl.drawingBufferHeight]
  }

  /** The largest drawing buffer, texture and viewport the GPU has. */
  limits(): { texture: number; renderbuffer: number; viewport: [number, number] } {
    const gl = this.gl
    const view = gl.getParameter(gl.MAX_VIEWPORT_DIMS) as Int32Array
    return {
      texture: gl.getParameter(gl.MAX_TEXTURE_SIZE) as number,
      renderbuffer: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE) as number,
      viewport: [view[0]!, view[1]!],
    }
  }

  /**
   * A picture: the view of the whole picture (`cx`, `cy`, `scale` in local
   * coordinates, `width` and `height` its pixels), before the drawing is set
   * (the glyph atlas is sized from it).
   */
  setPictureView(whole: { cx: number; cy: number; scale: number; width: number; height: number }) {
    this.whole = { ...whole }
    this.showTile({ x: 0, y: 0, width: whole.width, height: whole.height })
  }

  /** Aim the camera at a tile of the picture (pixels from its bottom left, as GL counts them). */
  showTile(tile: { x: number; y: number; width: number; height: number }) {
    if (!this.whole) return
    Object.assign(this.camera, tileCamera(this.whole, tile))
    this.tileOrigin = [tile.x, tile.y]
  }

  private draw() {
    if (this.disposed) return
    const gl = this.gl
    const cam = this.camera
    // Reset here rather than in each branch, so an empty buffer reports zero
    // instead of whatever the last frame with geometry submitted.
    this.drawnStrokes = 0
    this.drawnFills = 0
    this.drawCalls = 0

    gl.viewport(0, 0, cam.width, cam.height)
    // Premultiplied, as a context with an alpha channel holds it.
    const a = this.backgroundAlpha
    gl.clearColor(this.background[0] * a, this.background[1] * a, this.background[2] * a, a)
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT)
    if (this.paper && a === 1) this.drawPaper(this.paper)

    // Drives the shader's contrast fix, which flips whichever of black or
    // white would otherwise vanish into the background.
    const bgLuma =
      0.2126 * this.background[0] + 0.7152 * this.background[1] + 0.0722 * this.background[2]

    gl.activeTexture(gl.TEXTURE0)
    gl.bindTexture(gl.TEXTURE_2D, this.layerTex)

    const setCommon = (u: Uniforms) => {
      gl.uniform2f(u.uCenter, cam.cx, cam.cy)
      gl.uniform1f(u.uScale, cam.scale)
      gl.uniform2f(u.uViewport, cam.width, cam.height)
      gl.uniform1i(u.uLayerVis, 0)
      gl.uniform1f(u.uBgLuma, bgLuma)
      gl.uniform1f(u.uMaxOrder, this.maxOrder)
      gl.uniform1i(u.uMono, this.monochrome ? 1 : 0)
    }

    const fills = this.fillCount > 0 && this.fillVao !== null
    const strokes = this.strokeCount > 0 && this.strokeVao !== null
    const text = this.glyphCount > 0 && this.textVao !== null && this.atlasTex !== null
    if (fills) {
      gl.useProgram(this.fillProg)
      setCommon(this.fillU)
      gl.uniform3f(this.fillU.uBackground, ...this.background)
    }
    if (strokes) {
      gl.useProgram(this.strokeProg)
      setCommon(this.strokeU)
      const dpr = this.dpr()
      gl.uniform1f(this.strokeU.uLineScale, this.lineScale(dpr))
      gl.uniform1f(this.strokeU.uMinWidth, dpr)
      gl.uniform1f(this.strokeU.uLineWorld, this.lineWorld())
    }
    if (text) {
      gl.useProgram(this.textProg)
      setCommon(this.textU)
      gl.uniform1i(this.textU.uAtlas, 1)
    }

    // The opaque halves first, fills under the linework that bounds them,
    // then the translucent halves in draw order, blending over whatever lies
    // behind. Both write depth: an entity's own overlaps (two segments at a
    // vertex) are then drawn once instead of blending twice.
    if (fills) this.drawFills(this.fillRanges(0, this.opaqueFillTiles))
    // Opaque strokes in two passes: every fully covered core, then the
    // anti-aliased fringes. A fringe drawn with the cores would write depth
    // over what lies behind it before that was drawn, leaving a halo of
    // background around a line crossing another, and a seam where a
    // polyline's segments meet.
    if (strokes) {
      const opaque = this.strokeRanges(0, this.opaqueStrokeTiles)
      this.drawStrokes(opaque, STROKE_CORES)
      this.drawStrokes(opaque, STROKE_FRINGES)
      this.drawnStrokes -= rangeTotal(opaque)
    }
    const translucent = this.translucentRuns.some((r) => r.to > r.from)
    // Text behind translucent geometry has to be there before it, and its
    // edges blended over it after: the glyphs' solid cores now, their edges
    // last, so each pixel of a glyph is still drawn once.
    if (text && translucent) this.drawText(TEXT_CORES)
    for (const r of this.translucentRuns) {
      if (r.fills && fills) this.drawFills(this.fillRanges(r.from, r.to))
      if (!r.fills && strokes) this.drawStrokes(this.strokeRanges(r.from, r.to))
    }
    if (text) this.drawText(translucent ? TEXT_EDGES : TEXT_WHOLE)

    gl.bindVertexArray(null)
    Object.assign(this.drawn, { cx: cam.cx, cy: cam.cy, scale: cam.scale, width: cam.width, height: cam.height })
    this.onDraw?.()
  }

  /**
   * A layout's paper, as AutoCAD shows it: the sheet in the ground's colour
   * on a surround a shade away from it, with a shadow. Cleared through the
   * scissor, so nothing is drawn: the geometry goes on top. The edges are
   * placed in the pixels of the whole picture and cut to the tile after, so
   * that every tile puts them on the same pixel.
   */
  private drawPaper([minX, minY, maxX, maxY]: [number, number, number, number]) {
    const gl = this.gl
    const view = this.whole ? Object.assign(new Camera(), this.whole) : this.camera
    const [ox, oy] = this.tileOrigin
    const [x0, y0] = view.toScreen(minX, minY)
    const [x1, y1] = view.toScreen(maxX, maxY)
    const [r, g, b] = this.background
    const light = 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.5
    const shade = (k: number) => (light ? [r * k, g * k, b * k] : [r + (1 - r) * (1 - k), g + (1 - g) * (1 - k), b + (1 - b) * (1 - k)])
    const clear = ([cr, cg, cb]: number[], ax: number, ay: number, bx: number, by: number) => {
      const left = Math.max(0, Math.floor(ax) - ox)
      const bottom = Math.max(0, Math.floor(ay) - oy)
      const right = Math.min(this.camera.width, Math.ceil(bx) - ox)
      const top = Math.min(this.camera.height, Math.ceil(by) - oy)
      if (right <= left || top <= bottom) return
      gl.scissor(left, bottom, right - left, top - bottom)
      gl.clearColor(cr!, cg!, cb!, 1)
      gl.clear(gl.COLOR_BUFFER_BIT)
    }
    gl.enable(gl.SCISSOR_TEST)
    clear(shade(0.88), 0, 0, view.width, view.height)
    const d = Math.max(2, Math.round(Math.min(view.width, view.height) / 200))
    clear(shade(0.7), x0 + d, y0 - d, x1 + d, y1 - d)
    clear([r, g, b], x0, y0, x1, y1)
    gl.disable(gl.SCISSOR_TEST)
  }

  private drawFills(ranges: Range[]) {
    const gl = this.gl
    gl.useProgram(this.fillProg)
    gl.bindVertexArray(this.fillVao)
    for (const r of ranges) gl.drawArrays(gl.TRIANGLES, r.start, r.count)
    this.drawnFills += rangeTotal(ranges)
    this.drawCalls += ranges.length
  }

  private drawStrokes(ranges: Range[], pass = STROKE_WHOLE) {
    const gl = this.gl
    gl.useProgram(this.strokeProg)
    gl.uniform1i(this.strokeU.uStrokePass, pass)
    gl.bindVertexArray(this.strokeVao)
    // Instancing has no first-instance argument, so each range is reached by
    // re-pointing the per-instance attributes at its start.
    for (const r of ranges) {
      this.setStrokeInstanceOffset(r.start)
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, r.count)
    }
    this.setStrokeInstanceOffset(0)
    this.drawnStrokes += rangeTotal(ranges)
    this.drawCalls += ranges.length
  }

  /** The glyphs, or the part of each `pass` names; depth places each run where the drawing puts it. */
  private drawText(pass: number) {
    const gl = this.gl
    const cam = this.camera
    gl.useProgram(this.textProg)
    gl.uniform1i(this.textU.uTextPass, pass)
    gl.uniform1i(this.textU.uSdf, this.atlasSdf ? 1 : 0)
    gl.activeTexture(gl.TEXTURE1)
    gl.bindTexture(gl.TEXTURE_2D, this.atlasTex)
    gl.bindVertexArray(this.textVao)
    const clipped = this.glyphRanges.some((r) => r.clip > 0)
    if (!clipped) {
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.glyphCount)
    } else {
      // Each clip region into the stencil, then its runs where it is.
      for (const r of this.glyphRanges) {
        const region = this.clipRegions[r.clip - 1]
        if (r.clip > 0) {
          if (!region || !this.clipVao) continue
          gl.enable(gl.STENCIL_TEST)
          gl.clear(gl.STENCIL_BUFFER_BIT)
          gl.stencilFunc(gl.ALWAYS, 1, 0xff)
          gl.stencilOp(gl.KEEP, gl.KEEP, gl.REPLACE)
          gl.colorMask(false, false, false, false)
          gl.depthMask(false)
          gl.disable(gl.DEPTH_TEST)
          gl.useProgram(this.clipProg)
          gl.uniform2f(this.clipU.uCenter, cam.cx, cam.cy)
          gl.uniform1f(this.clipU.uScale, cam.scale)
          gl.uniform2f(this.clipU.uViewport, cam.width, cam.height)
          gl.bindVertexArray(this.clipVao)
          gl.drawArrays(gl.TRIANGLES, region.first, region.count)
          gl.colorMask(true, true, true, true)
          gl.depthMask(true)
          gl.enable(gl.DEPTH_TEST)
          gl.stencilFunc(gl.EQUAL, 1, 0xff)
          gl.stencilOp(gl.KEEP, gl.KEEP, gl.KEEP)
          gl.useProgram(this.textProg)
          gl.bindVertexArray(this.textVao)
        }
        this.setTextInstanceOffset(r.start)
        gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, r.count)
        if (r.clip > 0) gl.disable(gl.STENCIL_TEST)
      }
      this.setTextInstanceOffset(0)
    }
    gl.activeTexture(gl.TEXTURE0)
  }

  /** Gives the context back to the browser now, which holds only a few: after `dispose`, for a canvas about to be dropped. */
  loseContext() {
    this.gl.getExtension('WEBGL_lose_context')?.loseContext()
  }

  dispose() {
    this.disposed = true
    if (this.frame) cancelAnimationFrame(this.frame)
    clearTimeout(this.textResolutionTimer)
    this.textRecords = null
    this.textStrings = null
    this.glyphRequests = []
    const gl = this.gl
    if (this.strokeVao) gl.deleteVertexArray(this.strokeVao)
    if (this.fillVao) gl.deleteVertexArray(this.fillVao)
    if (this.textVao) gl.deleteVertexArray(this.textVao)
    if (this.strokeBuf) gl.deleteBuffer(this.strokeBuf)
    if (this.fillBuf) gl.deleteBuffer(this.fillBuf)
    if (this.textBuf) gl.deleteBuffer(this.textBuf)
    if (this.atlasTex) gl.deleteTexture(this.atlasTex)
    gl.deleteBuffer(this.quadBuf)
    gl.deleteBuffer(this.unitQuadBuf)
    gl.deleteTexture(this.layerTex)
    gl.deleteProgram(this.strokeProg)
    gl.deleteProgram(this.fillProg)
    gl.deleteProgram(this.textProg)
    if (this.clipVao) gl.deleteVertexArray(this.clipVao)
    if (this.clipBuf) gl.deleteBuffer(this.clipBuf)
    gl.deleteProgram(this.clipProg)
  }
}
