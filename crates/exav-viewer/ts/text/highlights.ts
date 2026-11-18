/**
 * Highlights in a text or Markdown document: each quote found in the text
 * drawn is wrapped in `<mark>` elements, which the layout moves with the
 * text when it wraps again. A text has no pages: boxes (`HighlightRects`)
 * are not drawn.
 */
import { findQuote, fold, type HighlightTarget } from "../core/highlights.js";
import type { PlacedHighlight } from "../core/types.js";

const MARK = "exav-viewer-highlight-text";

/** The text nodes under `root`, in order. */
function textNodes(root: HTMLElement): Text[] {
  const walker = root.ownerDocument.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const out: Text[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) out.push(n as Text);
  return out;
}

/** Wraps characters `[start, end)` of `root`'s text in marks made by `make`. */
function wrap(root: HTMLElement, start: number, end: number, make: () => HTMLElement) {
  let at = 0;
  for (const node of textNodes(root)) {
    const length = node.data.length;
    const from = Math.max(start, at) - at;
    const to = Math.min(end, at + length) - at;
    at += length;
    if (to <= from) {
      if (at >= end) break;
      continue;
    }
    let piece = node;
    if (from > 0) piece = piece.splitText(from);
    if (to - from < piece.data.length) piece.splitText(to - from);
    const mark = make();
    piece.replaceWith(mark);
    mark.append(piece);
  }
}

/**
 * The target for `createHighlights` over the text drawn in `root`. `drawn`
 * resolves once all of it is in the page (a long file is drawn a piece at a
 * time).
 */
export function textHighlights(root: HTMLElement, drawn: Promise<void>): HighlightTarget {
  let folded: { chars: string; from: number[] } | null = null;
  /** Where each quote is, in characters of the text. */
  const found = new Map<string, { start: number; end: number }[]>();

  return {
    pageCount: () => null,
    async locate(h) {
      await drawn;
      // Marks do not change the text: it is folded once.
      folded ??= fold(root.textContent ?? "");
      const parts = findQuote(folded.chars, h.text);
      if (!parts) return null;
      const f = folded;
      found.set(
        h.text,
        parts.map((p) => ({ start: f.from[p.start]!, end: f.from[p.end - 1]! + 1 })),
      );
      return { page: null, rects: [] };
    },
    draw(items: readonly PlacedHighlight[], current: string | null) {
      for (const mark of root.querySelectorAll(`mark.${MARK}`)) mark.replaceWith(...mark.childNodes);
      root.normalize();
      for (const item of items) {
        const ranges = item.state === "shown" && item.text !== undefined ? found.get(item.text) : undefined;
        if (!ranges) continue;
        const make = () => {
          const mark = root.ownerDocument.createElement("mark");
          mark.className = `${MARK}${item.id === current ? " exav-viewer-highlight-current" : ""}`;
          mark.dataset.highlight = item.id;
          if (item.label) mark.title = item.label;
          // A custom property takes any value; the mark's background takes only a colour from it.
          if (item.color) mark.style.setProperty("--exav-viewer-highlight", item.color);
          return mark;
        };
        for (const r of ranges) wrap(root, r.start, r.end, make);
      }
    },
    reveal(item, smooth) {
      const marks = [...root.querySelectorAll<HTMLElement>(`mark.${MARK}`)].filter((m) => m.dataset.highlight === item.id);
      if (marks.length === 0) return;
      const view = root.getBoundingClientRect();
      const rects = marks.map((m) => m.getBoundingClientRect());
      const top = Math.min(...rects.map((r) => r.top));
      const bottom = Math.max(...rects.map((r) => r.bottom));
      const into = top - view.top + root.scrollTop;
      // In the middle, or its start near the top when it is taller than the view.
      const y = bottom - top > root.clientHeight - 24 ? into - 12 : into + (bottom - top) / 2 - root.clientHeight / 2;
      root.scrollTo({ top: Math.max(0, y), behavior: smooth ? "smooth" : "auto" });
    },
  };
}
