import type { Warning } from "../core/types.js";
import type { Warnings } from "./types.js";

/** What a drawing's tab tells the user it left out; `previewShown` when its thumbnail stands in for it. */
export function cadWarnings(w: Warnings, previewShown: boolean): Warning[] {
  const out: Warning[] = [];
  if (previewShown) out.push({ key: "preview_shown", count: 0 });
  if (w.unknownEntities > 0) {
    const names = Object.entries(w.notDrawn ?? {}).map(([type, n]) => (n > 1 ? `${type} (${n})` : type));
    out.push({ key: "unknown_entities", count: w.unknownEntities, ...(names.length > 0 ? { names } : {}) });
  }
  if (w.externalReferences > 0) {
    const names = w.externalFiles ?? [];
    out.push({ key: "external_references", count: w.externalReferences, ...(names.length > 0 ? { names } : {}) });
  }
  if (w.sceneTruncated > 0) out.push({ key: "scene_truncated", count: w.sceneTruncated });
  if (w.proxyWithoutGraphics > 0) out.push({ key: "proxy_without_graphics", count: w.proxyWithoutGraphics });
  return out;
}
