import { createContext, useContext, useMemo, useRef, type ReactNode } from "react";

import { createViewer } from "../core/viewer.js";
import type { FormatPlugin, Viewer } from "../core/types.js";
import { builtinTranslate, type Translate } from "./messages.js";
import type { ViewerComponents } from "./parts.js";

export interface ViewerContextValue {
  viewer: Viewer;
  t: Translate;
  components: Partial<ViewerComponents>;
}

const Context = createContext<ViewerContextValue | null>(null);

export interface ViewerProviderProps {
  /** The engines, run in this page. Ignored with `viewer`. */
  plugins?: readonly FormatPlugin<any>[];
  /**
   * A viewer built elsewhere, used as it is: `plugins` and `assetBase` are
   * then not used. For a host that makes its own, or whose files run in a
   * sandboxed frame (`SandboxedViewerProvider`, from `@exav/viewer/react/sandbox`,
   * makes that one).
   */
  viewer?: Viewer;
  /** Where `@exav/viewer/vite` publishes the copied assets. Default "/exav-viewer/". */
  assetBase?: string;
  /**
   * How many bytes from the start of a file are read to tell what it is
   * (`ViewerConfig.sniffBytes`; 0: none). Default 65,536. Not used with `viewer`.
   */
  sniffBytes?: number;
  /**
   * How long the detection of a file's first bytes may take, in milliseconds,
   * before it is stopped and the file's name and type decide
   * (`ViewerConfig.sniffTimeoutMs`; 0: no timeout). Default 30,000. Not used
   * with `viewer`.
   */
  sniffTimeoutMs?: number;
  /**
   * The most bytes all the members of a ZIP (an Office file, an archive) may
   * come to once inflated (`ViewerConfig.maxExtractedBytes`; 0: no limit).
   * Default 536,870,912. Not used with `viewer`.
   */
  maxExtractedBytes?: number;
  /**
   * The most members a ZIP may have (`ViewerConfig.maxMembers`; 0: no limit).
   * Default 20,000. Not used with `viewer`.
   */
  maxMembers?: number;
  /**
   * The most a member of a ZIP may inflate to, as a multiple of its compressed
   * size (`ViewerConfig.maxCompressionRatio`; 0: no limit). Default 1000. Not
   * used with `viewer`.
   */
  maxCompressionRatio?: number;
  /** Picks the built-in strings ("en", "fr"). Default "en". */
  locale?: string;
  /** Replaces the built-in strings, for a host with its own i18n. */
  translate?: Translate;
  /** Replaces default pieces of the UI; each override receives the default as `Default`. */
  components?: Partial<ViewerComponents>;
  children: ReactNode;
}

const NONE: readonly FormatPlugin<any>[] = [];

export function ViewerProvider({
  plugins = NONE,
  viewer: given,
  assetBase,
  sniffBytes,
  sniffTimeoutMs,
  maxExtractedBytes,
  maxMembers,
  maxCompressionRatio,
  locale,
  translate,
  components,
  children,
}: ViewerProviderProps) {
  // One viewer for the plugin list: a new list with the same plugins (an
  // inline array) keeps the viewer it had.
  const kept = useRef(plugins);
  if (kept.current.length !== plugins.length || kept.current.some((p, i) => p !== plugins[i])) kept.current = plugins;
  const list = kept.current;
  const t = useMemo(() => translate ?? builtinTranslate(locale), [translate, locale]);
  const own = useMemo(
    () =>
      given
        ? null
        : createViewer({
            plugins: list,
            ...(assetBase !== undefined && { assetBase }),
            ...(sniffBytes !== undefined && { sniffBytes }),
            ...(sniffTimeoutMs !== undefined && { sniffTimeoutMs }),
            ...(maxExtractedBytes !== undefined && { maxExtractedBytes }),
            ...(maxMembers !== undefined && { maxMembers }),
            ...(maxCompressionRatio !== undefined && { maxCompressionRatio }),
          }),
    [given, assetBase, sniffBytes, sniffTimeoutMs, maxExtractedBytes, maxMembers, maxCompressionRatio, list],
  );
  const viewer = given ?? own!;
  const value = useMemo(() => ({ viewer, t, components: components ?? {} }), [viewer, t, components]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useViewerContext(): ViewerContextValue {
  const v = useContext(Context);
  if (!v) throw new Error("@exav/viewer/react: wrap the viewer in a <ViewerProvider>");
  return v;
}

/** The viewer of the nearest `ViewerProvider`. */
export function useViewer(): Viewer {
  return useViewerContext().viewer;
}
