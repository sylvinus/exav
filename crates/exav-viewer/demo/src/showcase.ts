/**
 * The files the demo lists: demo/public/showcase/, copied from
 * github.com/sylvinus/exav-samples by `npm run demo:showcase`, and described
 * by its samples.json; and demo/public/examples/, put there by `npm run
 * demo:examples` and described by examples.json (demo/examples/). When both
 * have a file of the same name, the example is listed and the sample is not.
 * The browser tests use the generated files of e2e/.out/samples/ instead
 * (e2e/fixtures/make-samples.mjs).
 */

/** The sidebar's sections, in this order; a group not named here comes last, under its own name. */
export const GROUPS: Record<string, { en: string; fr: string }> = {
  documents: { en: "Documents", fr: "Documents" },
  pdf: { en: "PDF", fr: "PDF" },
  office: { en: "Word, Excel, PowerPoint", fr: "Word, Excel, PowerPoint" },
  converted: { en: "Other office formats", fr: "Autres formats bureautiques" },
  text: { en: "Text and code", fr: "Texte et code" },
  images: { en: "Images", fr: "Images" },
  raw: { en: "Camera RAW", fr: "Photos RAW" },
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

/** One entry of examples.json (demo/examples/): the facts the demo shows, a few of those it keeps. */
export interface Example {
  file: string;
  group: string;
  family: string;
  title: string;
  author: string;
  source: string;
  /** The SPDX id, or "public-domain (reason)". */
  licence: string;
  /** The line CC-BY, MIT, BSD and Apache ask to keep; "" for the others. */
  attribution: string;
  bytes: number;
  sha256: string;
}

/** Who made a file and what it is, one line (the line the licence asks to keep is `attribution`). */
export function credit(e: Example): string {
  return `${e.author}: ${e.title}`;
}
