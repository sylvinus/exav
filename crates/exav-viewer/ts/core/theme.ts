/**
 * The CSS custom properties the stylesheet draws with, and the theme a host
 * hands the sandboxed frame: its document does not inherit the page's
 * styles, so the values are read from the page and sent as plain data.
 */

/** Each property, its default, and what a value of it may be. */
const TOKEN_DEFS = {
  "--exav-viewer-surface": ["#f1f5f9", "color"],
  "--exav-viewer-panel": ["#ffffff", "color"],
  "--exav-viewer-border": ["#e2e8f0", "color"],
  "--exav-viewer-text": ["#334155", "color"],
  "--exav-viewer-text-strong": ["#0f172a", "color"],
  "--exav-viewer-muted": ["#64748b", "color"],
  "--exav-viewer-faint": ["#94a3b8", "color"],
  "--exav-viewer-hover": ["#f8fafc", "color"],
  "--exav-viewer-active": ["#f1f5f9", "color"],
  "--exav-viewer-accent": ["#0f172a", "color"],
  "--exav-viewer-on-accent": ["#ffffff", "color"],
  "--exav-viewer-error": ["#b91c1c", "color"],
  "--exav-viewer-warning": ["#b45309", "color"],
  "--exav-viewer-media-bg": ["#0f172a", "color"],
  // A colour too, in a theme: a gradient is not sent to the frame.
  "--exav-viewer-model-bg": ["radial-gradient(circle at 50% 30%, #ffffff 0%, #e2e8f0 55%, #cbd5e1 100%)", "color"],
  "--exav-viewer-radius": ["0.375rem", "length"],
  "--exav-viewer-rail-width": ["15rem", "length"],
  "--exav-viewer-tap": ["2.75rem", "length"],
  /** Kept free below a slide, for a pager drawn over it. */
  "--exav-viewer-pager-room": ["4.5rem", "length"],
  "--exav-viewer-font": ["inherit", "font"],
} as const;

export type Token = keyof typeof TOKEN_DEFS;

/**
 * The CSS custom properties of the default UI and of the engines' surfaces,
 * with their default values. Set any of them on an ancestor (or `:root`) to
 * restyle.
 */
export const TOKENS = Object.fromEntries(Object.entries(TOKEN_DEFS).map(([k, [v]]) => [k, v])) as { readonly [K in Token]: (typeof TOKEN_DEFS)[K][0] };

/** What the frame is given: values it checks, and the color scheme for its controls and scrollbars. */
export interface FrameTheme {
  tokens: Partial<Record<Token, string>>;
  scheme: "light" | "dark" | null;
}

/**
 * A colour the frame and the host may put in a style: hex, or a colour
 * function of plain numbers (what `getComputedStyle` writes). Anything else
 * could be `url(...)`, a request.
 */
export function isColor(v: unknown): v is string {
  if (typeof v !== "string" || v.length > 96) return false;
  if (/^#[0-9a-f]{3,8}$/i.test(v) || v === "transparent") return true;
  const args = String.raw`\s*-?[\d.]+(e-?\d+)?(%|deg)?(\s*[\s,/]\s*-?[\d.]+(e-?\d+)?(%|deg)?){2,3}\s*`;
  if (new RegExp(`^(rgb|hsl|hwb|lab|lch|oklab|oklch)a?\\(${args}\\)$`, "i").test(v)) return true;
  return new RegExp(`^color\\(\\s*(srgb|srgb-linear|display-p3|a98-rgb|prophoto-rgb|rec2020|xyz|xyz-d50|xyz-d65)\\s${args}\\)$`, "i").test(v);
}

const isLength = (v: string) => /^\d{1,5}(\.\d{1,4})?(px|rem|em|%)$/.test(v) || v === "0";
/** Family names and generic families, nothing that loads. */
const isFont = (v: string) => v.length <= 256 && /^[\w\s,"'.-]+$/.test(v);

/** The theme as the frame takes it: known properties whose value is of their kind, the rest dropped. */
export function checkTheme(v: unknown): FrameTheme {
  const out: FrameTheme = { tokens: {}, scheme: null };
  if (typeof v !== "object" || v === null) return out;
  const { tokens, scheme } = v as { tokens?: unknown; scheme?: unknown };
  if (scheme === "light" || scheme === "dark") out.scheme = scheme;
  if (typeof tokens !== "object" || tokens === null) return out;
  for (const [name, [, kind]] of Object.entries(TOKEN_DEFS) as [Token, readonly [string, string]][]) {
    const value = (tokens as Record<string, unknown>)[name];
    if (typeof value !== "string") continue;
    if (kind === "color" ? isColor(value) : kind === "length" ? isLength(value) : isFont(value)) out.tokens[name] = value;
  }
  return out;
}

/**
 * The theme in force at `element`: each property set on it or an ancestor,
 * resolved to a plain value (a colour as `rgb()`), and its color scheme
 * when it is light or dark alone. Properties not set are left out, so that
 * the frame keeps its defaults.
 */
export function themeOf(element: Element): FrameTheme {
  const view = element.ownerDocument.defaultView;
  if (!view) return { tokens: {}, scheme: null };
  const style = view.getComputedStyle(element);
  const probe = element.ownerDocument.createElement("span");
  probe.setAttribute("aria-hidden", "true");
  Object.assign(probe.style, { position: "absolute", visibility: "hidden", pointerEvents: "none" });
  element.append(probe);
  const tokens: FrameTheme["tokens"] = {};
  try {
    for (const [name, [, kind]] of Object.entries(TOKEN_DEFS) as [Token, readonly [string, string]][]) {
      const raw = style.getPropertyValue(name).trim();
      if (!raw) continue;
      if (kind === "font") {
        if (isFont(raw)) tokens[name] = raw;
        continue;
      }
      if (typeof CSS !== "undefined" && !CSS.supports(kind === "color" ? "color" : "width", raw)) continue;
      const property = kind === "color" ? "color" : "width";
      probe.style.setProperty(property, raw);
      const value = view.getComputedStyle(probe).getPropertyValue(property).trim();
      probe.style.removeProperty(property);
      if (kind === "color" ? isColor(value) : isLength(value)) tokens[name] = value;
    }
  } finally {
    probe.remove();
  }
  const words = style.colorScheme?.split(/\s+/) ?? [];
  const scheme = words.includes("dark") && !words.includes("light") ? "dark" : words.includes("light") && !words.includes("dark") ? "light" : null;
  return { tokens, scheme };
}
