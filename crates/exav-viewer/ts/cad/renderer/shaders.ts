// GLSL ES 3.00 sources. Kept in one place so the two pipelines share their
// coordinate and layer-visibility conventions verbatim.

/**
 * Shared prelude: local coordinates to framebuffer pixels, and the layer
 * visibility lookup.
 *
 * Framebuffer space is y-up with the origin at the bottom-left, which is what
 * `gl_FragCoord.xy` reports, so the fragment shader can measure distances in
 * the same space without a flip.
 */
const COMMON = /* glsl */ `
uniform vec2  uCenter;    // view centre, local coordinates
uniform float uScale;     // local units per device pixel
uniform vec2  uViewport;  // device pixels
uniform sampler2D uLayerVis;

vec2 toFb(vec2 local) {
  return (local - uCenter) / uScale + uViewport * 0.5;
}

uniform float uMaxOrder;

/// Depth from an entity's position in the drawing's draw order.
///
/// Later entities must cover earlier ones, so they map nearer. This is what
/// lets a small solid fill placed after a hatch mask the hatch, which is how a
/// roof vent blanks the tiles under it. Batching all fills before all strokes
/// otherwise paints the hatch straight back over the top.
float orderDepth(uint order) {
  return 1.0 - (float(order) + 1.0) / (uMaxOrder + 2.0);
}

vec4 toClip(vec2 fb, uint order) {
  return vec4(fb / uViewport * 2.0 - 1.0, orderDepth(order), 1.0);
}

bool layerVisible(uint layer) {
  return texelFetch(uLayerVis, ivec2(int(layer % 256u), int(layer / 256u)), 0).r > 0.5;
}

// Placing a vertex outside the clip volume drops the whole primitive.
const vec4 CULLED = vec4(2.0, 2.0, 2.0, 1.0);
`

/**
 * Keeps colour-7 geometry visible against the chosen background.
 *
 * AutoCAD's colour 7 is "white or black, whichever contrasts", and drawings
 * lean on that: the same file is authored against a dark model space and
 * plotted on white paper. Without this, half a drawing disappears when the
 * background is switched.
 *
 * Only colour 7 flips, which the tessellator flags. A true colour that happens
 * to be white is white on purpose, and flipping it turns a white masking hatch
 * into a black box over the sheet.
 */
const CONTRAST = /* glsl */ `
const uint FLAG_CONTRAST = 0x80u;

vec3 contrastFix(vec3 rgb, float bgLuma, uint flags) {
  if ((flags & FLAG_CONTRAST) == 0u) return rgb;
  float luma = dot(rgb, vec3(0.2126, 0.7152, 0.0722));
  if (bgLuma > 0.5 && luma > 0.93) return vec3(0.0);
  if (bgLuma <= 0.5 && luma < 0.07) return vec3(1.0);
  return rgb;
}
`

/**
 * Strokes are instanced quads, one per line segment.
 *
 * gl.lineWidth() is clamped to 1px on Apple and ANGLE drivers, so lineweight
 * has to be built out of geometry. The quad is the segment's bounding box
 * expanded by the half-width plus a pixel of room for the antialiasing ramp;
 * the fragment shader then does an exact distance test, which gives round caps
 * and joins for free and renders a zero-length segment (a POINT entity) as a
 * dot.
 */
export const STROKE_VERT = /* glsl */ `#version 300 es
precision highp float;

layout(location = 0) in vec2  aCorner;  // unit quad, components in {-1, +1}
layout(location = 1) in vec2  aP0;
layout(location = 2) in vec2  aP1;
layout(location = 3) in vec4  aColor;   // normalised UNSIGNED_BYTE
layout(location = 4) in uint  aAttr;    // layer | lineweight | flags
layout(location = 5) in uint  aOrder;
${COMMON}

uniform float uLineScale;  // device px per 1/100 mm
uniform float uMinWidth;   // device px
/**
 * Drawing units per 1/100 mm, or zero for the screen convention.
 *
 * In model space a lineweight is a pixel width that does not change with zoom.
 * On a paper-space sheet it is a real width on the page, so it has to grow as
 * the sheet is zoomed into, the way it would on paper.
 */
uniform float uLineWorld;

out vec2  vP0;
out vec2  vP1;
out vec4  vColor;
out float vHalf;
flat out uint vFlags;

/**
 * Hatch pattern lines carry their spacing in the flags byte.
 *
 * Every hairline is drawn at least one pixel wide. Once a pattern's lines sit
 * closer together than that, they overlap and the fill turns solid black,
 * while a plot of the same drawing shows light grey: on paper the line is far
 * thinner than the gap. Fading by the sub-pixel spacing recovers the tone the
 * lines should average out to.
 */
float spacingFade(uint attr, float unitsPerPixel) {
  uint code = (attr >> 24) & 0x7Fu;
  if (code == 0u) return 1.0;
  float spacingWorld = exp2(float(code) / 8.0);
  return clamp(spacingWorld / unitsPerPixel, 0.08, 1.0);
}

void main() {
  uint layer = aAttr & 0xFFFFu;
  if (!layerVisible(layer)) {
    gl_Position = CULLED;
    return;
  }

  vec2 s0 = toFb(aP0);
  vec2 s1 = toFb(aP1);

  float lw = float((aAttr >> 16) & 0xFFu);
  float widthPx = uLineWorld > 0.0 ? lw * uLineWorld / uScale : lw * uLineScale;
  float halfW = max(uMinWidth, widthPx) * 0.5;

  vec2 d = s1 - s0;
  float len = length(d);
  vec2 t = len > 1e-6 ? d / len : vec2(1.0, 0.0);
  vec2 n = vec2(-t.y, t.x);

  float pad = halfW + 1.0;
  vec2 mid = (s0 + s1) * 0.5;
  vec2 pos = mid + t * aCorner.x * (len * 0.5 + pad) + n * aCorner.y * pad;

  vP0 = s0;
  vP1 = s1;
  vColor = vec4(aColor.rgb, aColor.a * spacingFade(aAttr, uScale));
  vFlags = (aAttr >> 24) & 0xFFu;
  vHalf = halfW;
  gl_Position = toClip(pos, aOrder);
}
`

export const STROKE_FRAG = /* glsl */ `#version 300 es
precision highp float;

in vec2  vP0;
in vec2  vP1;
in vec4  vColor;
in float vHalf;
flat in uint vFlags;
${CONTRAST}

// AutoCAD colour 7 renders white on a dark background and black on a light
// one. Anything that would vanish into the background gets the same treatment,
// in whichever direction the background calls for.
uniform float uBgLuma;

out vec4 outColor;

float segDistance(vec2 p, vec2 a, vec2 b) {
  vec2 pa = p - a;
  vec2 ba = b - a;
  float h = clamp(dot(pa, ba) / max(dot(ba, ba), 1e-9), 0.0, 1.0);
  return length(pa - ba * h);
}

void main() {
  float d = segDistance(gl_FragCoord.xy, vP0, vP1);
  float cov = 1.0 - smoothstep(vHalf - 0.5, vHalf + 0.5, d);
  if (cov <= 0.0) discard;

  outColor = vec4(contrastFix(vColor.rgb, uBgLuma, vFlags), vColor.a * cov);
}
`

/** Fills are plain triangles: solid hatches and SOLID/TRACE entities. */
export const FILL_VERT = /* glsl */ `#version 300 es
precision highp float;

layout(location = 0) in vec2 aPos;
layout(location = 1) in vec4 aColor;
layout(location = 2) in uint aAttr;
layout(location = 3) in uint aOrder;
${COMMON}

out vec4 vColor;
flat out uint vFlags;

void main() {
  uint layer = aAttr & 0xFFFFu;
  if (!layerVisible(layer)) {
    gl_Position = CULLED;
    return;
  }
  vColor = aColor;
  vFlags = (aAttr >> 24) & 0xFFu;
  gl_Position = toClip(toFb(aPos), aOrder);
}
`

export const FILL_FRAG = /* glsl */ `#version 300 es
precision highp float;

in vec4 vColor;
flat in uint vFlags;

uniform float uBgLuma;
uniform vec3 uBackground;
${CONTRAST}
out vec4 outColor;

void main() {
  // A WIPEOUT paints the background, hiding what is beneath it. The
  // tessellator cannot know that colour, so it flags the fill instead.
  if ((vFlags & 1u) != 0u) {
    outColor = vec4(uBackground, 1.0);
    return;
  }
  outColor = vec4(contrastFix(vColor.rgb, uBgLuma, vFlags), vColor.a);
}
`

/**
 * Glyphs are instanced quads sampling a Canvas-built alpha atlas.
 *
 * Each instance carries an origin and two edge vectors, so text rotation, the
 * DWG width factor and oblique slant are all already baked into those vectors
 * and the vertex shader is one multiply-add.
 */
export const TEXT_VERT = /* glsl */ `#version 300 es
precision highp float;

layout(location = 0) in vec2 aCorner;  // unit quad, components in {0, 1}
layout(location = 1) in vec2 aOrigin;
layout(location = 2) in vec2 aEdgeX;
layout(location = 3) in vec2 aEdgeY;
layout(location = 4) in vec4 aUv;      // normalised UNSIGNED_SHORT u0,v0,u1,v1
layout(location = 5) in vec4 aColor;
layout(location = 6) in uint aAttr;
layout(location = 7) in uint aOrder;
${COMMON}

out vec2 vUv;
out vec4 vColor;
flat out uint vFlags;

void main() {
  uint layer = aAttr & 0xFFFFu;
  if (!layerVisible(layer)) {
    gl_Position = CULLED;
    return;
  }
  vFlags = (aAttr >> 24) & 0xFFu;

  vec2 local = aOrigin + aEdgeX * aCorner.x + aEdgeY * aCorner.y;
  // Atlas rows run top-down, so v flips against the quad's y-up corner.
  vUv = vec2(mix(aUv.x, aUv.z, aCorner.x), mix(aUv.w, aUv.y, aCorner.y));
  vColor = aColor;
  gl_Position = toClip(toFb(local), aOrder);
}
`

export const TEXT_FRAG = /* glsl */ `#version 300 es
precision highp float;

in vec2 vUv;
in vec4 vColor;
flat in uint vFlags;

uniform sampler2D uAtlas;
uniform float uBgLuma;
${CONTRAST}

out vec4 outColor;

void main() {
  float a = texture(uAtlas, vUv).r;
  if (a <= 0.004) discard;
  outColor = vec4(contrastFix(vColor.rgb, uBgLuma, vFlags), vColor.a * a);
}
`
