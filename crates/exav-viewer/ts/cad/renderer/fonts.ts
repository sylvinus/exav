/**
 * The bundled outline faces, and loading them before anything measures.
 *
 * A DWG names a font and does not carry it, so every run is drawn with a
 * substitute. The viewer substitutes only from faces it ships: a system font
 * makes the same drawing look and wrap differently on every machine, and the
 * browser cannot even be asked whether it has one. `document.fonts.check()`
 * answers whether a family *name resolves*, which it always does: measured in
 * this project's own headless Chrome it returns true for a font name invented
 * for the test.
 *
 * The bundle is generic rather than a list of names drawings happen to use,
 * because that tail is endless. Three families cover the shapes CAD text comes
 * in, and the width tables compiled into the wasm carry the specificity.
 *
 * Stroke fonts are not here. Those are drawn as geometry on the Rust side, so
 * that the drawing's lineweight decides how thick their letters are.
 */

/** Families, in the order the wasm's face byte encodes them. */
export const FAMILIES = ['sans', 'serif', 'mono'] as const
export type FamilyName = (typeof FAMILIES)[number]

/** CSS family names, prefixed so they cannot collide with a page's own. */
const CSS_FAMILY: Record<FamilyName, string> = {
  sans: '__exav_cad_sans',
  serif: '__exav_cad_serif',
  mono: '__exav_cad_mono',
}

/** One downloadable file, and the slice of a family it provides. */
interface FaceFile {
  family: FamilyName
  file: string
  /**
   * Where the package ships it. A literal `new URL(..., import.meta.url)` per
   * file, so a bundler emits each one as an asset of its own, fetched only
   * when a drawing needs its family.
   */
  url: string
  /** CSS weight descriptor. A range means a variable font covers it. */
  weight: string
  style: 'normal' | 'italic'
}

/**
 * The bundle. Arimo is metric-compatible with Arial and Helvetica, Tinos with
 * Times New Roman, Cousine with Courier New; all three are SIL OFL 1.1 and are
 * the Chrome OS metric-compatible set.
 *
 * Arimo ships as a variable font, so one file covers regular through bold.
 * Tinos and Cousine do not, so each weight is its own file.
 */
const FILES: readonly FaceFile[] = [
  { family: 'sans', file: 'Arimo-wght.woff2', url: new URL('../../../assets/fonts/Arimo-wght.woff2', import.meta.url).href, weight: '400 700', style: 'normal' },
  { family: 'sans', file: 'Arimo-Italic-wght.woff2', url: new URL('../../../assets/fonts/Arimo-Italic-wght.woff2', import.meta.url).href, weight: '400 700', style: 'italic' },
  { family: 'serif', file: 'Tinos-Regular.woff2', url: new URL('../../../assets/fonts/Tinos-Regular.woff2', import.meta.url).href, weight: '400', style: 'normal' },
  { family: 'serif', file: 'Tinos-Bold.woff2', url: new URL('../../../assets/fonts/Tinos-Bold.woff2', import.meta.url).href, weight: '700', style: 'normal' },
  { family: 'serif', file: 'Tinos-Italic.woff2', url: new URL('../../../assets/fonts/Tinos-Italic.woff2', import.meta.url).href, weight: '400', style: 'italic' },
  { family: 'serif', file: 'Tinos-BoldItalic.woff2', url: new URL('../../../assets/fonts/Tinos-BoldItalic.woff2', import.meta.url).href, weight: '700', style: 'italic' },
  { family: 'mono', file: 'Cousine-Regular.woff2', url: new URL('../../../assets/fonts/Cousine-Regular.woff2', import.meta.url).href, weight: '400', style: 'normal' },
  { family: 'mono', file: 'Cousine-Bold.woff2', url: new URL('../../../assets/fonts/Cousine-Bold.woff2', import.meta.url).href, weight: '700', style: 'normal' },
  { family: 'mono', file: 'Cousine-Italic.woff2', url: new URL('../../../assets/fonts/Cousine-Italic.woff2', import.meta.url).href, weight: '400', style: 'italic' },
  { family: 'mono', file: 'Cousine-BoldItalic.woff2', url: new URL('../../../assets/fonts/Cousine-BoldItalic.woff2', import.meta.url).href, weight: '700', style: 'italic' },
]

/** How many distinct faces the wasm's face byte can name. */
export const FACE_COUNT = FAMILIES.length * 4

/**
 * Cap height as a fraction of em, per family, from each font's OS/2 table.
 *
 * Constants rather than measurements, for two reasons. Canvas reports
 * `actualBoundingBoxAscent` quantised to whole pixels, so measuring the same
 * face at different sizes gives different answers: Arimo reads 0.750 at 16px,
 * 0.703 at 64px and 0.691 at 256px against a true 0.688. Since a run's em is
 * its DWG height divided by this, a measurement that moves would make text
 * change size whenever the atlas is rasterised again at a new zoom.
 *
 * And these are the same numbers `crates/exav-render/scripts/font-tables.py` compiles into
 * `crates/exav-render/src/formats/dwg/metrics.rs`, so the host places glyphs on exactly the
 * figures the tessellator wrapped them with.
 *
 * Bold and italic share a family's cap height; measured, they are identical.
 */
export const CAP_RATIO: Record<FamilyName, number> = {
  sans: 0.687988, // Arimo, sCapHeight 1409 / 2048
  serif: 0.654785, // Tinos, 1341 / 2048
  mono: 0.658691, // Cousine, 1349 / 2048
}

export interface Face {
  family: FamilyName
  bold: boolean
  italic: boolean
}

/**
 * Decode the face byte a text record carries.
 *
 * Must stay in step with `TrueTypeFace::to_byte` in `crates/exav-render/src/formats/dwg/font.rs`,
 * which packs `family * 4 + bold * 2 + italic`.
 */
export function decodeFace(byte: number): Face {
  const i = byte >= 0 && byte < FACE_COUNT ? byte : 0
  return {
    family: FAMILIES[(i / 4) | 0],
    bold: ((i >> 1) & 1) === 1,
    italic: (i & 1) === 1,
  }
}

/** The CSS `font` shorthand for a face at `px`, for a Canvas 2D context. */
export function cssFont(px: number, face: Face): string {
  const style = face.italic ? 'italic ' : ''
  const weight = face.bold ? '700 ' : '400 '
  return `${style}${weight}${px}px ${CSS_FAMILY[face.family]}`
}

/** A directory serving the bundle under its file names, or null for the package's own copy. */
let fontsUrl: string | null = null

/** Point the loader at another copy of the bundle; null for the package's own. */
export function setFontsUrl(url: string | null) {
  if (url !== fontsUrl) {
    fontsUrl = url
    loaded.clear()
  }
}

/** Files already loaded or in flight, by file name. */
const loaded = new Map<string, Promise<void>>()

/** Which families a set of face bytes needs. */
export function familiesFor(faceBytes: Iterable<number>): Set<FamilyName> {
  const out = new Set<FamilyName>()
  for (const b of faceBytes) out.add(decodeFace(b).family)
  return out
}

/**
 * Load every file the given families need, and wait for them.
 *
 * Waiting is not optional. Canvas silently falls back to a default face if
 * asked to measure or rasterise before the font is ready, and that fallback is
 * a system font, which would put back exactly the machine-dependence this
 * bundle exists to remove, without any sign that it had happened.
 *
 * A file that fails to load is reported and skipped rather than thrown: a
 * drawing rendered in the wrong face is worth more than no drawing, and the
 * caller has no better recovery available.
 */
export async function loadFamilies(
  families: Iterable<FamilyName>,
  onError?: (file: string, err: unknown) => void,
): Promise<void> {
  if (typeof FontFace === 'undefined' || !('fonts' in document)) return

  const wanted = new Set(families)
  const jobs: Promise<void>[] = []

  for (const spec of FILES) {
    if (!wanted.has(spec.family)) continue
    let job = loaded.get(spec.file)
    if (!job) {
      // Relative to the page, as a path in CSS would be ("/static/fonts").
      const url = fontsUrl ? new URL(spec.file, new URL(fontsUrl.endsWith('/') ? fontsUrl : `${fontsUrl}/`, location.href)).href : spec.url
      job = (async () => {
        const face = new FontFace(CSS_FAMILY[spec.family], `url(${JSON.stringify(url)})`, {
          weight: spec.weight,
          style: spec.style,
        })
        await face.load()
        document.fonts.add(face)
      })().catch((err) => {
        // Drop it from the cache so a later draw can try again.
        loaded.delete(spec.file)
        onError?.(spec.file, err)
      })
      loaded.set(spec.file, job)
    }
    jobs.push(job)
  }

  await Promise.all(jobs)
}
