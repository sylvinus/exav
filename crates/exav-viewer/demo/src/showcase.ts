/**
 * The files the demo lists: demo/public/showcase/, copied from
 * github.com/sylvinus/exav-samples by `npm run demo:showcase`, and described
 * by its samples.json. The browser tests use the generated files of
 * e2e/.out/samples/ instead (e2e/fixtures/make-samples.mjs).
 */

/** The sidebar's sections, in this order; a group not named here comes last, under its own name. */
export const GROUPS: Record<string, { en: string; fr: string }> = {
  documents: { en: "Documents", fr: "Documents" },
  images: { en: "Images", fr: "Images" },
  cad: { en: "CAD", fr: "CAO" },
  "3d": { en: "3D", fr: "3D" },
  media: { en: "Audio and video", fr: "Audio et vidéo" },
  archives: { en: "Archives", fr: "Archives" },
  // Files the viewer does not open, to show what it says about them.
  unsupported: { en: "Unsupported", fr: "Non pris en charge" },
};

/** One entry of samples.json. */
export interface Sample {
  file: string;
  group: string;
  /** What it is and who made it. */
  credit: string;
  /** Where it was taken from. */
  source: string;
  licence: string;
  bytes: number;
  sha256: string;
}
