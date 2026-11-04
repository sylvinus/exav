/**
 * Highlights: the controller the formats share, and the text matching they
 * find a quote with. Each format says where a highlight is (`locate`), draws
 * them (`draw`) and brings one into view (`reveal`).
 */
import { writable } from "./store.js";
import type { Highlight, HighlightsController, PlacedHighlight, Region } from "./types.js";

/** Most highlights taken from one list. */
export const MAX_HIGHLIGHTS = 1000;
/** Most boxes of one highlight. */
export const MAX_HIGHLIGHT_RECTS = 1000;
/** Longest quote looked for. */
export const MAX_HIGHLIGHT_TEXT = 16_384;

/** Time the search may take before the page gets a turn. */
const SLICE_MS = 12;

/** The id of `h`, the `index`th of its list. */
export const highlightId = (h: Highlight, index: number): string => h.id ?? String(index);

// ── Text matching ────────────────────────────────────────────────────────────

/** Letters Unicode does not decompose, written as they are spelled out. */
const SPELLED: Record<string, string> = { œ: "oe", æ: "ae", ß: "ss" };

/**
 * `text` with only its letters and digits, lower case and without accents
 * (ligatures split, "ﬁ" is "fi", "œ" is "oe"), and for each character kept the index in
 * `text` of the one it comes from.
 */
export function fold(text: string): { chars: string; from: number[] } {
  let chars = "";
  const from: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) {
      if ((code >= 0x30 && code <= 0x39) || (code >= 0x61 && code <= 0x7a)) {
        chars += text[i];
        from.push(i);
      } else if (code >= 0x41 && code <= 0x5a) {
        chars += String.fromCharCode(code + 0x20);
        from.push(i);
      }
      continue;
    }
    let c = text[i]!;
    // A surrogate pair is one character.
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) c += text[i + 1]!;
    for (const k of c
      .normalize("NFKD")
      .toLowerCase()
      .replace(/[œæß]/g, (l) => SPELLED[l]!)) {
      if (!/[\p{L}\p{N}]/u.test(k) || /\p{M}/u.test(k)) continue;
      chars += k;
      for (let n = 0; n < k.length; n++) from.push(i);
    }
    if (c.length === 2) i++;
  }
  return { chars, from };
}

/** The parts of a quote that "..." or "…" separate, folded; empty parts left out. */
export function quoteParts(quote: string): string[] {
  return quote
    .slice(0, MAX_HIGHLIGHT_TEXT)
    .split(/\.{3,}|…/)
    .map((p) => fold(p).chars)
    .filter((p) => p.length > 0);
}

/**
 * Where the parts of `quote` are in `haystack` (folded by `fold`), in order,
 * each after the one before: ranges of folded characters, end excluded.
 * Null when one is not found.
 */
export function findQuote(haystack: string, quote: string): { start: number; end: number }[] | null {
  const parts = quoteParts(quote);
  if (parts.length === 0) return null;
  const out: { start: number; end: number }[] = [];
  let at = 0;
  for (const part of parts) {
    const start = haystack.indexOf(part, at);
    if (start < 0) return null;
    out.push({ start, end: start + part.length });
    at = start + part.length;
  }
  return out;
}

/**
 * Boxes on one line that touch or nearly touch, as one: the words of a line
 * of evidence, or the runs of text a quote covers.
 */
export function mergeLines(rects: readonly Region[]): Region[] {
  const out: Region[] = [];
  for (const r of rects) {
    const last = out[out.length - 1];
    if (last) {
      const top = Math.max(last.y, r.y);
      const bottom = Math.min(last.y + last.height, r.y + r.height);
      const overlap = bottom - top;
      const gap = r.x - (last.x + last.width);
      const h = Math.min(last.height, r.height);
      if (overlap > 0.5 * h && gap < 0.6 * h && r.x + r.width > last.x) {
        const x = Math.min(last.x, r.x);
        const y = Math.min(last.y, r.y);
        out[out.length - 1] = {
          x,
          y,
          width: Math.max(last.x + last.width, r.x + r.width) - x,
          height: Math.max(last.y + last.height, r.y + r.height) - y,
        };
        continue;
      }
    }
    out.push({ ...r });
  }
  return out;
}

/** A box within the page, clipped to it; null when nothing is left or it is not a box. */
export function clipRect(r: unknown): Region | null {
  if (typeof r !== "object" || r === null) return null;
  const { x, y, width, height } = r as Record<string, unknown>;
  if (![x, y, width, height].every((v) => typeof v === "number" && Number.isFinite(v))) return null;
  const clip = (v: number) => Math.min(1, Math.max(0, v));
  const left = clip(x as number);
  const top = clip(y as number);
  const right = clip((x as number) + (width as number));
  const bottom = clip((y as number) + (height as number));
  if (right <= left || bottom <= top) return null;
  return { x: left, y: top, width: right - left, height: bottom - top };
}

// ── The controller ───────────────────────────────────────────────────────────

/** What a format does for its highlights. */
export interface HighlightTarget {
  /** Pages the document has; null for a format without pages. */
  pageCount(): number | null;
  /** Where the quote is: its page (null without pages) and boxes, or null when not found. */
  locate(h: Extract<Highlight, { text: string }>, signal: AbortSignal): Promise<{ page: number | null; rects: Region[] } | null>;
  /** Shows `items` in place of what was shown; `current` is outlined. */
  draw(items: readonly PlacedHighlight[], current: string | null): void;
  /** Brings `item` into view: its boxes, or its page when it has none. */
  reveal(item: PlacedHighlight, smooth: boolean): void;
}

export interface Highlights {
  controller: HighlightsController;
  /** Looks for the quotes again (the document was replaced), keeping the list. */
  relocate(): void;
  destroy(): void;
}

/**
 * The controller over `target`. `highlights` are shown at once and the view
 * goes to `focus`, or to the first of them, as soon as it is found.
 */
export function createHighlights(target: HighlightTarget, highlights: readonly Highlight[] = [], focus?: string): Highlights {
  const state = writable<{ items: readonly PlacedHighlight[]; current: string | null }>({ items: [], current: null });
  let given: readonly Highlight[] = [];
  let run = new AbortController();
  /** A highlight asked for while its text is looked for, and how. */
  let wanted: { id: string; smooth: boolean } | null = null;
  let ended = false;

  const publish = (items: readonly PlacedHighlight[], current = state.get().current) => {
    state.set({ items, current });
    target.draw(items, current);
  };

  const place = (h: Highlight, index: number): PlacedHighlight => {
    const common = {
      id: highlightId(h, index),
      ...(typeof h.color === "string" && { color: h.color }),
      ...(typeof h.label === "string" && { label: h.label }),
    };
    const pages = target.pageCount();
    const pageOk = (p: unknown): p is number => Number.isSafeInteger(p) && (p as number) >= 1 && (pages === null || (p as number) <= pages);
    if ("text" in h && typeof h.text === "string") {
      return { ...common, text: h.text.slice(0, MAX_HIGHLIGHT_TEXT), state: quoteParts(h.text).length ? "pending" : "missing", page: null, rects: [] };
    }
    // Checked as data: a host's list may come from JSON.
    const given = (h as { rects?: unknown }).rects;
    const rects: unknown[] = Array.isArray(given) ? given.slice(0, MAX_HIGHLIGHT_RECTS) : [];
    const clipped = mergeLines(rects.map(clipRect).filter((r): r is Region => r !== null));
    // Boxes need pages to be on.
    if (pages === null || !pageOk(h.page) || clipped.length === 0) return { ...common, state: "missing", page: pages !== null && pageOk(h.page) ? h.page : null, rects: [] };
    return { ...common, state: "shown", page: h.page, rects: clipped };
  };

  const reveal = (item: PlacedHighlight, smooth: boolean) => {
    publish(state.get().items, item.id);
    target.reveal(item, smooth);
  };

  const goTo = (id: string, smooth: boolean) => {
    if (ended) return;
    const item = state.get().items.find((i) => i.id === id);
    if (!item) return;
    wanted = null;
    if (item.state === "pending") {
      wanted = { id, smooth };
      return;
    }
    if (item.state === "shown") return reveal(item, smooth);
    // Not found: its page, if it named one.
    const h = given[state.get().items.indexOf(item)];
    const pages = target.pageCount();
    if (h && Number.isSafeInteger(h.page) && pages !== null && h.page! >= 1 && h.page! <= pages) reveal({ ...item, page: h.page! }, smooth);
  };

  const start = (list: readonly Highlight[]) => {
    run.abort();
    run = new AbortController();
    const signal = run.signal;
    given = list.slice(0, MAX_HIGHLIGHTS);
    const items = given.map(place);
    const current = state.get().current;
    publish(items, items.some((i) => i.id === current) ? current : null);
    const queue = items.map((_, i) => i).filter((i) => items[i]!.state === "pending");
    void (async () => {
      // After the caller's `goTo`, so that the one it wants is looked for first.
      await Promise.resolve();
      let slice = performance.now();
      while (queue.length > 0) {
        if (signal.aborted) return;
        // A quote on pages whose text is already read is found without
        // leaving the microtask queue: the page gets a turn between slices.
        if (performance.now() - slice > SLICE_MS) {
          await new Promise((resolve) => setTimeout(resolve, 0));
          if (signal.aborted) return;
          slice = performance.now();
        }
        const w = wanted ? queue.findIndex((k) => items[k]!.id === wanted!.id) : -1;
        const i = queue.splice(Math.max(0, w), 1)[0]!;
        const h = given[i] as Extract<Highlight, { text: string }>;
        let found: { page: number | null; rects: Region[] } | null = null;
        try {
          found = await target.locate(h, signal);
        } catch (error) {
          if (signal.aborted) return;
          console.warn("highlights: a text could not be looked for", error);
        }
        if (signal.aborted) return;
        const now = [...state.get().items];
        const placed: PlacedHighlight = found
          ? { ...now[i]!, state: "shown", page: found.page, rects: mergeLines(found.rects) }
          : { ...now[i]!, state: "missing" };
        now[i] = placed;
        publish(now);
        if (wanted?.id === placed.id) {
          const { smooth } = wanted;
          wanted = null;
          goTo(placed.id, smooth);
        }
      }
    })();
  };

  start(highlights);
  const first = state.get().items[0];
  const opening = focus ?? first?.id;
  if (opening !== undefined) goTo(opening, false);

  return {
    controller: {
      get: state.get,
      subscribe: state.subscribe,
      set: (list) => !ended && start(list),
      goTo: (id) => goTo(id, true),
    },
    relocate: () => !ended && start(given),
    destroy() {
      ended = true;
      run.abort();
    },
  };
}
