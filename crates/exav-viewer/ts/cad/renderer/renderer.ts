import { Camera } from './camera.js'
import { GlyphAtlas, clampEm, type GlyphRequest } from './glyph-atlas.js'
import { FILL_FRAG, FILL_VERT, STROKE_FRAG, STROKE_VERT, TEXT_FRAG, TEXT_VERT } from './shaders.js'
import { GLYPH_BYTES, glyphsNeeded, layoutText } from './text-layout.js'
import { targetEmFor } from './text-resolution.js'
import { decodeTiles, rangeTotal, viewMargin, visibleRanges, type Range, type Tile } from './tiles.js'
import { FILL_BYTES, STROKE_BYTES, type ParsedDrawing } from '../types.js'

/** Device pixels per 1/100 mm at 100% zoom, before `lineweightScale`. */
const PX_PER_HUNDREDTH_MM = 0.0378
/** Width of the layer visibility texture; `layerVisible` in shaders.ts indexes by it. */
const LAYER_ROW = 256

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

  // Kept so the atlas can be rasterised again at a different size when the
  // zoom changes. See `text-resolution.ts`.
  private textRecords: ArrayBuffer | null = null
  private textStrings: Uint8Array | null = null
  private glyphRequests: GlyphRequest[] = []
  /** Em the current atlas was rasterised at, or 0 when there is none. */
  private atlasEm = 0
  /** Pending debounced check, so a pinch rebuilds once when it settles. */
  private textResolutionTimer = 0

  private layerTex: WebGLTexture
  private layerVis = new Uint8Array(LAYER_ROW)

  private strokeCount = 0
  private fillCount = 0
  /** Leading, opaque part of each buffer; the rest draws without depth writes. */
  private opaqueStrokes = 0
  private opaqueFills = 0
  private maxOrder = 1

  // Spatial buckets, so a view only draws what it touches. See tiles.ts.
  private strokeTiles: Tile[] = []
  private fillTiles: Tile[] = []
  /** Leading tiles of each table that cover the opaque half. */
  private opaqueStrokeTiles = 0
  private opaqueFillTiles = 0
  /** What the last frame actually submitted, for diagnostics. */
  drawnStrokes = 0
  drawnFills = 0
  /** Geometry draw calls the last frame issued, one per contiguous run. */
  drawCalls = 0

  background: [number, number, number] = [1, 1, 1]
  lineweights = true
  /** The drawing on screen is a paper-space sheet, not model space. */
  paperSpace = false
  lineweightScale = 1
  /** Runs whose glyphs could not be rasterised, from the last setDrawing(). */
  skippedTextRuns = 0

  private frame = 0
  private disposed = false
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
  }

  constructor(private canvas: HTMLCanvasElement) {
    const gl = canvas.getContext('webgl2', {
      alpha: false,
      antialias: false,
      depth: true,
      stencil: false,
      desynchronized: true,
      powerPreference: 'high-performance',
      preserveDrawingBuffer: false,
    })
    if (!gl) throw new Error('WebGL2 is required and is not available in this browser')
    this.gl = gl

    this.strokeProg = link(gl, STROKE_VERT, STROKE_FRAG)
    this.fillProg = link(gl, FILL_VERT, FILL_FRAG)
    this.textProg = link(gl, TEXT_VERT, TEXT_FRAG)
    const common = ['uCenter', 'uScale', 'uViewport', 'uLayerVis', 'uBgLuma', 'uMaxOrder']
    this.strokeU = uniforms(gl, this.strokeProg, [
      ...common,
      'uLineScale',
      'uMinWidth',
      'uLineWorld',
    ])
    this.fillU = uniforms(gl, this.fillProg, [...common, 'uBackground'])
    this.textU = uniforms(gl, this.textProg, [...common, 'uAtlas'])

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
    this.opaqueStrokes = Math.min(d.opaqueStrokes, this.strokeCount)
    this.opaqueFills = Math.min(d.opaqueFills, this.fillCount)
    this.strokeTiles = d.strokeTiles ? decodeTiles(d.strokeTiles) : []
    this.fillTiles = d.fillTiles ? decodeTiles(d.fillTiles) : []
    this.opaqueStrokeTiles = Math.min(d.opaqueStrokeTiles ?? 0, this.strokeTiles.length)
    this.opaqueFillTiles = Math.min(d.opaqueFillTiles ?? 0, this.fillTiles.length)
    this.paperSpace = d.layout !== ''
    this.maxOrder = Math.max(1, d.maxOrder)

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
    // f32 x0,y0 | f32 x1,y1 | ubyte4 rgba | uint32 attr
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
    this.releaseText()
    this.textRecords = null
    this.textStrings = null
    this.glyphRequests = []
    this.atlasEm = 0

    const strings = new Uint8Array(d.textStrings)
    if (d.texts.byteLength === 0 || strings.length === 0) return

    this.textRecords = d.texts
    this.textStrings = strings
    this.glyphRequests = glyphsNeeded(d.texts, strings)
    this.rebuildText(this.targetEm())
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
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    return viewMargin({
      scale: this.camera.scale,
      lineScale: this.lineweights ? PX_PER_HUNDREDTH_MM * this.lineweightScale * dpr : 0,
      lineWorld: this.lineweights && this.paperSpace ? 0.01 * this.lineweightScale : 0,
      minWidthPx: dpr,
    })
  }

  private strokeRanges(from: number, to: number): Range[] {
    if (this.strokeTiles.length === 0) {
      // No table: draw the half outright, which is what the buffer says.
      const start = from === 0 ? 0 : this.opaqueStrokes
      const count = from === 0 ? this.opaqueStrokes : this.strokeCount - this.opaqueStrokes
      return count > 0 ? [{ start, count }] : []
    }
    return visibleRanges(this.strokeTiles, from, to, this.viewRect(), this.cullMargin())
  }

  private fillRanges(from: number, to: number): Range[] {
    if (this.fillTiles.length === 0) {
      const start = from === 0 ? 0 : this.opaqueFills
      const count = from === 0 ? this.opaqueFills : this.fillCount - this.opaqueFills
      return count > 0 ? [{ start, count }] : []
    }
    return visibleRanges(this.fillTiles, from, to, this.viewRect(), this.cullMargin())
  }

  /** The atlas em this view wants, quantised. */
  private targetEm(): number {
    if (!this.textRecords) return 0
    const cam = this.camera
    const [minX, minY] = cam.toLocal(0, 0)
    const [maxX, maxY] = cam.toLocal(cam.width, cam.height)
    return clampEm(
      targetEmFor(
        this.textRecords,
        { minX, minY, maxX, maxY, scale: cam.scale },
        this.glyphRequests.length,
      ),
    )
  }

  /**
   * Rasterise the atlas at `em` and lay the text out against it.
   *
   * Glyph *positions* do not depend on the em: the atlas reports its metrics in
   * em units, so a run occupies the same box whatever resolution it was
   * rasterised at. Only the texture and the UVs change, which is what makes
   * this safe to do mid-session.
   */
  private rebuildText(em: number) {
    const gl = this.gl
    this.releaseText()
    this.skippedTextRuns = 0
    if (!this.textRecords || !this.textStrings || this.glyphRequests.length === 0) return

    // The caller has already loaded and awaited the faces these runs name.
    // Rasterising before they are ready would silently fall back to a system
    // font, which is the machine-dependence the bundle exists to remove.
    const atlas = GlyphAtlas.build(
      this.glyphRequests,
      gl.getParameter(gl.MAX_TEXTURE_SIZE) as number,
      em,
    )
    this.atlasEm = atlas.em
    const laid = layoutText(this.textRecords, this.textStrings, atlas)
    this.skippedTextRuns = laid.skippedRuns
    if (laid.glyphCount === 0) return

    this.atlasTex = gl.createTexture()
    gl.bindTexture(gl.TEXTURE_2D, this.atlasTex)
    gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1)
    // White glyphs on opaque black (glyph-atlas.ts): the red channel is the coverage.
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8, gl.RED, gl.UNSIGNED_BYTE, atlas.canvas)
    gl.generateMipmap(gl.TEXTURE_2D)
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
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = Math.max(1, Math.round(this.canvas.clientWidth * dpr))
    const h = Math.max(1, Math.round(this.canvas.clientHeight * dpr))
    if (this.canvas.width === w && this.canvas.height === h) return false
    this.canvas.width = w
    this.canvas.height = h
    this.camera.width = w
    this.camera.height = h
    return true
  }

  requestDraw() {
    if (this.disposed) return
    this.scheduleTextResolutionCheck()
    if (this.frame) return
    this.frame = requestAnimationFrame(() => {
      this.frame = 0
      this.draw()
    })
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
    this.textResolutionTimer = setTimeout(() => {
      if (this.disposed || !this.textRecords) return
      const want = this.targetEm()
      // 0 means nothing is on screen to size against; leave the page alone
      // rather than rebuild it twice while panning across empty paper.
      if (want === 0 || want <= this.atlasEm) return
      this.rebuildText(want)
      if (!this.frame) {
        this.frame = requestAnimationFrame(() => {
          this.frame = 0
          this.draw()
        })
      }
    }, Renderer.TEXT_SETTLE_MS) as unknown as number
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
    gl.clearColor(this.background[0], this.background[1], this.background[2], 1)
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT)

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
    }

    // Fills first: hatches sit under the linework that bounds them. Each
    // buffer is opaque up front and translucent after; the tail draws with
    // depth writes off, so geometry behind it still blends through instead of
    // being rejected by depth it should never have written.
    if (this.fillCount > 0 && this.fillVao) {
      gl.useProgram(this.fillProg)
      setCommon(this.fillU)
      gl.uniform3f(this.fillU.uBackground, ...this.background)
      gl.bindVertexArray(this.fillVao)
      const opaque = this.fillRanges(0, this.opaqueFillTiles)
      for (const r of opaque) gl.drawArrays(gl.TRIANGLES, r.start, r.count)
      const rest = this.fillRanges(this.opaqueFillTiles, this.fillTiles.length)
      if (rest.length > 0) {
        gl.depthMask(false)
        for (const r of rest) gl.drawArrays(gl.TRIANGLES, r.start, r.count)
        gl.depthMask(true)
      }
      this.drawnFills = rangeTotal(opaque) + rangeTotal(rest)
      this.drawCalls += opaque.length + rest.length
    }

    if (this.strokeCount > 0 && this.strokeVao) {
      gl.useProgram(this.strokeProg)
      setCommon(this.strokeU)
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      gl.uniform1f(
        this.strokeU.uLineScale,
        this.lineweights ? PX_PER_HUNDREDTH_MM * this.lineweightScale * dpr : 0,
      )
      gl.uniform1f(this.strokeU.uMinWidth, dpr)
      // On a sheet a lineweight is a width on the page, so it grows with zoom.
      // A hundredth of a millimetre is a hundredth of a paper unit, since a
      // layout's units are millimetres.
      gl.uniform1f(
        this.strokeU.uLineWorld,
        this.lineweights && this.paperSpace ? 0.01 * this.lineweightScale : 0,
      )
      gl.bindVertexArray(this.strokeVao)
      // Instancing has no first-instance argument, so each range is reached by
      // re-pointing the per-instance attributes at its start.
      const opaque = this.strokeRanges(0, this.opaqueStrokeTiles)
      for (const r of opaque) {
        this.setStrokeInstanceOffset(r.start)
        gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, r.count)
      }
      const rest = this.strokeRanges(this.opaqueStrokeTiles, this.strokeTiles.length)
      if (rest.length > 0) {
        gl.depthMask(false)
        for (const r of rest) {
          this.setStrokeInstanceOffset(r.start)
          gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, r.count)
        }
        gl.depthMask(true)
      }
      this.setStrokeInstanceOffset(0)
      this.drawnStrokes = rangeTotal(opaque) + rangeTotal(rest)
      this.drawCalls += opaque.length + rest.length
    }

    // Text is submitted last, but depth still places each run where the
    // drawing puts it.
    if (this.glyphCount > 0 && this.textVao && this.atlasTex) {
      gl.useProgram(this.textProg)
      setCommon(this.textU)
      gl.activeTexture(gl.TEXTURE1)
      gl.bindTexture(gl.TEXTURE_2D, this.atlasTex)
      gl.uniform1i(this.textU.uAtlas, 1)
      gl.bindVertexArray(this.textVao)
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, 4, this.glyphCount)
      gl.activeTexture(gl.TEXTURE0)
    }

    gl.bindVertexArray(null)
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
  }
}
