/**
 * The default pieces of the UI. Each one can be replaced through
 * `ViewerProvider`'s `components`; a replacement receives the default it
 * replaces as `Default`, to wrap it rather than rewrite it.
 */
import { useId, useState, type ComponentProps, type ComponentType, type ReactNode } from "react";

import type { Store } from "../core/store.js";
import type {
  ArchiveController,
  DragController,
  FormatId,
  GroundController,
  LayersController,
  LayoutsController,
  OutlineController,
  PagesController,
  Selection,
  Status,
  ZoomController,
} from "../core/types.js";
import { folderOf } from "../archive/names.js";
import { useViewerContext } from "./context.js";
import { useStore } from "./hooks.js";
import { ArrowLeft, ChevronLeft, ChevronRight, Close, FileIcon, FitIcon, FolderIcon, Hand, LayersIcon, ListIcon, Minus, PanelClose, Plus, Spinner, TextCursor } from "./icons.js";
import type { MessageKey } from "./messages.js";

type Overridable<P> = ComponentType<P & { Default: ComponentType<P> }>;

export interface ShellProps {
  open: boolean;
  onClose: () => void;
  /** The dialog's accessible name: the file's title. */
  title: ReactNode;
  width: "full" | "page";
  children: ReactNode;
}
export interface StatusOverlayProps {
  status: Status;
  format: FormatId | null;
}
export interface PlaceholderProps {
  state: "pending" | "unavailable";
  label?: string;
}
export interface OutlineRailProps {
  outline: OutlineController;
}
export interface DrawingRailProps {
  layers?: LayersController;
  layouts?: LayoutsController;
  ground?: GroundController;
  selection?: Store<Selection | null>;
}
export interface SlidePagerProps {
  pages: PagesController;
}
export interface ArchiveListProps {
  archive: ArchiveController;
}
export interface ArchiveBackProps {
  archive: ArchiveController;
  name: string;
}
export interface InfoBadgeProps {
  format: FormatId | null;
  info: Record<string, number>;
}
export interface WarningsProps {
  warnings: readonly { key: string; count: number }[];
}
export interface ZoomControlsProps {
  zoom: ZoomController;
}
export interface DragToggleProps {
  drag: DragController;
}

export interface ViewerComponents {
  /** The dialog itself: a native `<dialog>` by default. */
  Shell: Overridable<ShellProps>;
  /** Opaque cover over the surface while loading, converting, empty or failed. */
  StatusOverlay: Overridable<StatusOverlayProps>;
  Placeholder: Overridable<PlaceholderProps>;
  /** PDF sections. */
  OutlineRail: Overridable<OutlineRailProps>;
  /** CAD and IFC: layouts (when more than one), selection, ground, layers. */
  DrawingRail: Overridable<DrawingRailProps>;
  /** PPTX: "Slide 2 / 9" with prev and next. */
  SlidePager: Overridable<SlidePagerProps>;
  ArchiveList: Overridable<ArchiveListProps>;
  ArchiveBack: Overridable<ArchiveBackProps>;
  /** STL triangle count. */
  InfoBadge: Overridable<InfoBadgeProps>;
  /** What is missing from the picture (a drawing's external references). */
  Warnings: Overridable<WarningsProps>;
  /** Zoom out, zoom in and fit, for a mouse (shown for a fine pointer only: a touch screen pinches). */
  ZoomControls: Overridable<ZoomControlsProps>;
  /** A PDF zoomed past the viewer: drag to move the page, or to select text. */
  DragToggle: Overridable<DragToggleProps>;
}

/** Renders the host's override of `name` if there is one, the default otherwise. */
export function Piece<K extends keyof ViewerComponents>({ name, props }: { name: K; props: Omit<ComponentProps<ViewerComponents[K]>, "Default"> }) {
  const { components } = useViewerContext();
  const Default = DEFAULTS[name] as ComponentType<any>;
  const Override = components[name] as ComponentType<any> | undefined;
  return Override ? <Override {...props} Default={Default} /> : <Default {...props} />;
}

// ── Shell ────────────────────────────────────────────────────────────────────

function Shell({ open, onClose, title, width, children }: ShellProps) {
  const id = useId();
  const ref = (el: HTMLDialogElement | null) => {
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  };
  if (!open) return null;
  return (
    <dialog
      ref={ref}
      className={`exv-dialog exv-dialog-${width}`}
      aria-labelledby={id}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div id={id} hidden>
        {title}
      </div>
      {children}
    </dialog>
  );
}

// ── Status ───────────────────────────────────────────────────────────────────

function statusMessage(status: Status, format: FormatId | null, t: (k: MessageKey, v?: Record<string, string | number>) => string): { text: string; tone: "busy" | "error" | "plain" } | null {
  const model = format === "ifc" || format === "stl";
  switch (status.phase) {
    case "ready":
      return null;
    case "loading":
      // A player shows its own controls at once.
      if (format === "video" || format === "audio") return null;
      return { text: status.label ?? t(model ? "loading_model" : "loading"), tone: "busy" };
    case "converting":
      return { text: status.label ?? t("converting_model", { percent: Math.round((status.progress ?? 0) * 100) }), tone: "busy" };
    case "empty":
      return { text: t("empty_model"), tone: "plain" };
    case "error": {
      const code = status.error.code;
      const key = code === "pdf" ? "error" : (`error_${code}` as MessageKey);
      // A host's own code, which its table does not word: the generic message, not the key.
      const worded = t(key);
      return { text: status.error.message ?? (worded === key ? t("error_file") : worded), tone: "error" };
    }
  }
}

function StatusOverlay({ status, format }: StatusOverlayProps) {
  const { t } = useViewerContext();
  const m = statusMessage(status, format, t);
  if (!m) return null;
  return (
    <div className={`exv-status exv-status-${m.tone}`} aria-live="polite">
      {m.tone === "busy" && <Spinner />}
      <p>{m.text}</p>
    </div>
  );
}

function Placeholder({ state, label }: PlaceholderProps) {
  const { t } = useViewerContext();
  return (
    <div className="exv-status exv-status-plain" aria-live="polite">
      {state === "pending" && <Spinner />}
      <p>{state === "pending" ? (label ?? t("drawing")) : (label ?? t("unavailable_offline"))}</p>
    </div>
  );
}

// ── Rails ────────────────────────────────────────────────────────────────────

/** Below this width a rail starts folded. Decided once: turning a tablet must not close it. */
const RAIL_FITS = 1024;

function Rail({ title, hideLabel, icon, children }: { title: string; hideLabel: string; icon: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(() => typeof window === "undefined" || window.innerWidth >= RAIL_FITS);
  const id = useId();
  if (!open) {
    return (
      <button type="button" className="exv-rail-unfold" onClick={() => setOpen(true)} aria-expanded={false} aria-controls={id} aria-label={title} title={title}>
        {icon}
      </button>
    );
  }
  // Unmounted when folded, not hidden: a `display: flex` beats `[hidden]`.
  return (
    <nav id={id} className="exv-rail" aria-label={title}>
      <div className="exv-rail-head">
        <span className="exv-rail-title">{title}</span>
        <button type="button" className="exv-icon-button exv-icon-button-small" onClick={() => setOpen(false)} aria-label={hideLabel}>
          <PanelClose />
        </button>
      </div>
      {children}
    </nav>
  );
}

function OutlineRail({ outline }: OutlineRailProps) {
  const { t } = useViewerContext();
  const entries = useStore(outline) ?? [];
  // A rail of one entry only jumps to where the reader already is.
  if (entries.length < 2) return null;
  return (
    <Rail title={t("sections")} hideLabel={t("sections_hide")} icon={<ListIcon />}>
      <div className="exv-rail-scroll exv-outline">
        {entries.map((e, i) => (
          <button
            key={`${e.page}:${e.title}:${i}`}
            type="button"
            className={`exv-outline-entry${e.depth === 0 ? " exv-outline-top" : ""}`}
            style={{ paddingLeft: `${e.depth * 12 + 8}px` }}
            onClick={() => outline.goTo(e)}
          >
            {e.title}
          </button>
        ))}
      </div>
    </Rail>
  );
}

function DrawingRail({ layers, layouts, ground, selection }: DrawingRailProps) {
  const { t } = useViewerContext();
  const layerState = useStore(layers);
  const layoutState = useStore(layouts);
  const groundState = useStore(ground);
  const selected = useStore(selection);
  const categories = layerState?.kind === "categories";
  return (
    <Rail title={t(categories ? "model_panel" : "drawing_panel")} hideLabel={t("panel_hide")} icon={<LayersIcon />}>
      {layouts && layoutState && layoutState.items.length > 1 && (
        <div className="exv-rail-section">
          <p className="exv-rail-label">{t("layouts")}</p>
          <div className="exv-layouts">
            {layoutState.items.map((l) => (
              <button
                key={l.id}
                type="button"
                className={`exv-row${l.id === layoutState.current ? " exv-row-current" : ""}`}
                aria-current={l.id === layoutState.current}
                onClick={() => void layouts.select(l.id)}
              >
                <span className="exv-truncate" title={l.isModel ? t("model_space") : l.name}>
                  {l.isModel ? t("model_space") : l.name}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
      {selection && (
        <div className="exv-rail-section">
          <p className="exv-rail-label">{t("selection")}</p>
          {selected ? (
            <>
              <p className="exv-truncate exv-strong" title={selected.name}>
                {selected.name || t("selection_unnamed")}
              </p>
              <p className="exv-truncate exv-muted" title={selected.category}>
                {selected.category}
              </p>
              {selected.storey && (
                <p className="exv-truncate exv-muted" title={selected.storey}>
                  {selected.storey}
                </p>
              )}
            </>
          ) : (
            <p className="exv-faint">{t("selection_none")}</p>
          )}
        </div>
      )}
      {ground && groundState && (
        <div className="exv-rail-section exv-rail-inline">
          <p className="exv-rail-label">{t("background")}</p>
          <div className="exv-segmented">
            {(["light", "dark"] as const).map((g) => (
              <button key={g} type="button" aria-pressed={groundState === g} onClick={() => ground.set(g)}>
                {t(`background_${g}`)}
              </button>
            ))}
          </div>
        </div>
      )}
      {layers && layerState && (
        <>
          <div className="exv-rail-section exv-rail-inline">
            <p className="exv-rail-label">{t(categories ? "categories" : "layers")}</p>
            <span className="exv-layer-all">
              <button type="button" onClick={() => layers.setAll(true)}>
                {t("layers_all")}
              </button>
              <button type="button" onClick={() => layers.setAll(false)}>
                {t("layers_none")}
              </button>
            </span>
          </div>
          <div className="exv-rail-scroll">
            {layerState.items.map((l) => (
              <label key={l.id} className="exv-layer">
                <input type="checkbox" checked={l.visible} onChange={(e) => layers.setVisible(l.id, e.target.checked)} />
                <span className="exv-swatch" style={{ background: l.color }} aria-hidden="true" />
                <span className={`exv-truncate${l.visible ? "" : " exv-faint"}`} title={l.name}>
                  {l.name}
                </span>
              </label>
            ))}
          </div>
        </>
      )}
    </Rail>
  );
}

// ── Floating pieces ──────────────────────────────────────────────────────────

function SlidePager({ pages }: SlidePagerProps) {
  const { t } = useViewerContext();
  const p = useStore(pages);
  if (!p || p.unit !== "slide" || p.total < 2) return null;
  return (
    <div className="exv-pager">
      <button type="button" className="exv-icon-button exv-icon-button-round" onClick={() => void pages.prev?.()} aria-label={t("prev")}>
        <ChevronLeft />
      </button>
      <span aria-live="polite">{t("slide_of", { current: p.current, total: p.total })}</span>
      <button type="button" className="exv-icon-button exv-icon-button-round" onClick={() => void pages.next?.()} aria-label={t("next")}>
        <ChevronRight />
      </button>
    </div>
  );
}

function InfoBadge({ format, info }: InfoBadgeProps) {
  const { t } = useViewerContext();
  if (format !== "stl" || !info.triangles) return null;
  return <p className="exv-badge">{t("stl_triangles", { count: info.triangles })}</p>;
}

function Warnings({ warnings }: WarningsProps) {
  const { t } = useViewerContext();
  // Dismissed for these warnings: another file's, or a new reading of this
  // one's, are new values and show again.
  const [dismissed, setDismissed] = useState<WarningsProps["warnings"] | null>(null);
  if (warnings.length === 0 || warnings === dismissed) return null;
  return (
    <div className="exv-warnings" role="status">
      <div>
        {warnings.map((w) => (
          <p key={w.key}>{t(`warning_${w.key}` as MessageKey, { count: w.count })}</p>
        ))}
      </div>
      <button type="button" className="exv-icon-button exv-icon-button-small" onClick={() => setDismissed(warnings)} aria-label={t("close")} title={t("close")}>
        <Close />
      </button>
    </div>
  );
}

// ── Zoom and drag ────────────────────────────────────────────────────────────

/** One press of a zoom button multiplies the scale by this, or divides. */
const ZOOM_STEP = 1.25;

function ZoomControls({ zoom }: ZoomControlsProps) {
  const { t } = useViewerContext();
  const state = useStore(zoom);
  if (!state) return null;
  const { scale, min, max } = state;
  return (
    <div className="exv-tool-group" role="group">
      <button type="button" className="exv-icon-button exv-icon-button-small" onClick={() => zoom.setScale(scale / ZOOM_STEP)} disabled={scale <= min} aria-label={t("zoom_out")} title={t("zoom_out")}>
        <Minus />
      </button>
      <button type="button" className="exv-icon-button exv-icon-button-small" onClick={() => zoom.setScale(scale * ZOOM_STEP)} disabled={scale >= max} aria-label={t("zoom_in")} title={t("zoom_in")}>
        <Plus />
      </button>
      <button type="button" className="exv-icon-button exv-icon-button-small" onClick={() => zoom.fit()} aria-label={t("zoom_fit")} title={t("zoom_fit")}>
        <FitIcon />
      </button>
    </div>
  );
}

function DragToggle({ drag }: DragToggleProps) {
  const { t } = useViewerContext();
  const state = useStore(drag);
  // Nothing to choose while the page fits: a drag selects.
  if (!state?.available) return null;
  return (
    <div className="exv-tool-group" role="group">
      <button
        type="button"
        className="exv-icon-button exv-icon-button-small"
        onClick={() => drag.choose("pan")}
        aria-pressed={state.mode === "pan"}
        aria-label={t("drag_pan")}
        title={t("drag_pan")}
      >
        <Hand />
      </button>
      <button
        type="button"
        className="exv-icon-button exv-icon-button-small"
        onClick={() => drag.choose("select")}
        aria-pressed={state.mode === "select"}
        aria-label={t("drag_select")}
        title={t("drag_select")}
      >
        <TextCursor />
      </button>
    </div>
  );
}

// ── Archive ──────────────────────────────────────────────────────────────────

/** B, KB, MB, GB, TB, base 1024, one decimal below 10. */
export function formatBytes(n: number): string {
  if (n < 0) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 || v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function ArchiveList({ archive }: ArchiveListProps) {
  const { t } = useViewerContext();
  const s = useStore(archive);
  if (!s || s.opened) return null;
  return (
    <div className="exv-archive">
      <p className="exv-archive-head">{t("archive_members", { count: s.members.length })}</p>
      {s.refused && <p className="exv-archive-refused">{t(s.refused.key)}</p>}
      <ul className="exv-archive-list">
        {s.members.map((m) => {
          const folder = folderOf(m.name);
          return (
            <li key={m.index}>
              <button type="button" className={`exv-member${m.encrypted ? " exv-member-locked" : ""}`} disabled={s.opening !== null || m.encrypted} onClick={() => void archive.open(m.index)}>
                {s.opening === m.index ? <Spinner /> : <FileIcon />}
                <span className="exv-member-name">
                  <span className="exv-truncate">{m.name.split("/").pop()}</span>
                  {folder && (
                    <span className="exv-member-folder exv-truncate">
                      <FolderIcon />
                      {folder}
                    </span>
                  )}
                </span>
                <span className="exv-member-size">{formatBytes(m.uncompressedSize)}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function ArchiveBack({ archive, name }: ArchiveBackProps) {
  const { t } = useViewerContext();
  return (
    <div className="exv-archive-back">
      <button type="button" onClick={() => archive.back()}>
        <ArrowLeft />
        {t("archive_back")}
      </button>
      <span className="exv-truncate" title={name}>
        {name}
      </span>
    </div>
  );
}

const DEFAULTS: { [K in keyof ViewerComponents]: ComponentType<any> } = {
  Shell,
  StatusOverlay,
  Placeholder,
  OutlineRail,
  DrawingRail,
  SlidePager,
  ArchiveList,
  ArchiveBack,
  InfoBadge,
  Warnings,
  ZoomControls,
  DragToggle,
};
