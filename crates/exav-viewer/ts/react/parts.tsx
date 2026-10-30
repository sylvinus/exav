/**
 * The default pieces of the UI. Each one can be replaced through
 * `ViewerProvider`'s `components`; a replacement receives the default it
 * replaces as `Default`, to wrap it rather than rewrite it.
 */
import { useId, useRef, useState, type ComponentProps, type ComponentType, type ReactNode } from "react";

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
  SheetsController,
  Status,
  StoreysController,
  Warning,
  ZoomController,
} from "../core/types.js";
import { folderOf } from "../archive/names.js";
import { useViewerContext } from "./context.js";
import { useFullscreen, usePanel, useStore, type PanelInfo } from "./hooks.js";
import { ArrowLeft, ChevronLeft, ChevronRight, Close, FileIcon, FolderIcon, FullscreenExitIcon, FullscreenIcon, Hand, LayersIcon, ListIcon, Minus, PanelClose, Plus, ResetIcon, Spinner, TextCursor } from "./icons.js";
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
  storeys?: StoreysController;
  layouts?: LayoutsController;
  ground?: GroundController;
  selection?: Store<Selection | null>;
}
export interface SlidePagerProps {
  pages: PagesController;
}
export interface SheetTabsProps {
  sheets: SheetsController;
}
export interface ArchiveListProps {
  archive: ArchiveController;
}
export interface ArchiveBackProps {
  archive: ArchiveController;
  name: string;
}
export interface WarningsProps {
  warnings: readonly Warning[];
}
export interface ZoomControlsProps {
  zoom: ZoomController;
}
export interface DragToggleProps {
  drag: DragController;
}
export type FullscreenToggleProps = Record<string, never>;
export interface PanelToggleProps extends PanelInfo {
  open: boolean;
  toggle: () => void;
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
  /** XLSX: a tab per sheet, below it, when there are several. */
  SheetTabs: Overridable<SheetTabsProps>;
  ArchiveList: Overridable<ArchiveListProps>;
  ArchiveBack: Overridable<ArchiveBackProps>;
  /** What is missing from the picture (a drawing's external references). */
  Warnings: Overridable<WarningsProps>;
  /** Zoom out, zoom in, and back to the opening view once zoomed, for a mouse (shown for a fine pointer only: a touch screen pinches). */
  ZoomControls: Overridable<ZoomControlsProps>;
  /** The viewer's box, full screen and back. Not shown where the browser has no full screen. */
  FullscreenToggle: Overridable<FullscreenToggleProps>;
  /** Folds and unfolds the side panel (sections, layers), beside the zoom buttons. Shown on a touch screen too. */
  PanelToggle: Overridable<PanelToggleProps>;
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
      className={`exav-viewer-dialog exav-viewer-dialog-${width}`}
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
  const model = format === "ifc" || format === "stl" || format === "obj" || format === "ply" || format === "gltf";
  switch (status.phase) {
    case "ready":
      return null;
    case "loading":
      // A player shows its own controls at once.
      if (format === "video" || format === "audio") return null;
      // A model is read and drawn as "the model".
      if (model && (status.step === undefined || status.step === "read" || status.step === "render")) return { text: status.label ?? t("loading_model"), tone: "busy" };
      return { text: status.label ?? (status.step ? t(`step_${status.step}`) : t("loading")), tone: "busy" };
    case "converting":
      return {
        text: status.label ?? (status.step ? t(`step_${status.step}`) : t("converting_model", { percent: Math.round((status.progress ?? 0) * 100) })),
        tone: "busy",
      };
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
  // A step that counts shows a bar; the stock "preparing the model" says its percentage.
  const share = (status.phase === "loading" || status.phase === "converting") && status.step && status.progress !== undefined ? status.progress : null;
  return (
    <div className={`exav-viewer-status exav-viewer-status-${m.tone}`} aria-live="polite">
      {m.tone === "busy" && <Spinner />}
      <p>{m.text}</p>
      {share !== null && (
        <div className="exav-viewer-progress">
          <div role="progressbar" aria-label={m.text} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(share * 100)}>
            <div style={{ width: `${share * 100}%` }} />
          </div>
        </div>
      )}
    </div>
  );
}

function Placeholder({ state, label }: PlaceholderProps) {
  const { t } = useViewerContext();
  return (
    <div className="exav-viewer-status exav-viewer-status-plain" aria-live="polite">
      {state === "pending" && <Spinner />}
      <p>{state === "pending" ? (label ?? t("drawing")) : (label ?? t("unavailable_offline"))}</p>
    </div>
  );
}

// ── Rails ────────────────────────────────────────────────────────────────────

function Rail({ title, hideLabel, icon, children }: { title: string; hideLabel: string; icon: ReactNode; children: ReactNode }) {
  const id = useId();
  const { open } = usePanel({ title, hideLabel, icon, controls: id });
  // Unmounted when folded, not hidden: a `display: flex` beats `[hidden]`.
  if (!open) return null;
  return (
    <nav id={id} className="exav-viewer-rail" aria-label={title}>
      <div className="exav-viewer-rail-head">
        <span className="exav-viewer-rail-title">{title}</span>
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
      <div className="exav-viewer-rail-scroll exav-viewer-outline">
        {entries.map((e, i) => (
          <button
            key={`${e.page}:${e.title}:${i}`}
            type="button"
            className={`exav-viewer-outline-entry${e.depth === 0 ? " exav-viewer-outline-top" : ""}`}
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

/** A storey's elevation in metres: "+3.2 m", "0 m", "-1.5 m". */
function formatElevation(metres: number): string {
  const text = String(Math.round(metres * 100) / 100);
  return `${metres > 0 ? "+" : ""}${text} m`;
}

function DrawingRail({ layers, storeys, layouts, ground, selection }: DrawingRailProps) {
  const { t } = useViewerContext();
  const layerState = useStore(layers);
  const storeyState = useStore(storeys);
  const layoutState = useStore(layouts);
  const groundState = useStore(ground);
  const selected = useStore(selection);
  const categories = layerState?.kind === "categories";
  return (
    <Rail title={t(categories ? "model_panel" : "drawing_panel")} hideLabel={t("panel_hide")} icon={<LayersIcon />}>
      {layouts && layoutState && layoutState.items.length > 1 && (
        <div className="exav-viewer-rail-section">
          <p className="exav-viewer-rail-label">{t("layouts")}</p>
          <div className="exav-viewer-layouts">
            {layoutState.items.map((l) => (
              <button
                key={l.id}
                type="button"
                className={`exav-viewer-row${l.id === layoutState.current ? " exav-viewer-row-current" : ""}`}
                aria-current={l.id === layoutState.current}
                onClick={() => void layouts.select(l.id)}
              >
                <span className="exav-viewer-truncate" title={l.isModel ? t("model_space") : l.name}>
                  {l.isModel ? t("model_space") : l.name}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
      {selection && (
        <div className="exav-viewer-rail-section">
          <p className="exav-viewer-rail-label">{t("selection")}</p>
          {selected ? (
            <>
              <p className="exav-viewer-truncate exav-viewer-strong" title={selected.name}>
                {selected.name || t("selection_unnamed")}
              </p>
              <p className="exav-viewer-truncate exav-viewer-muted" title={selected.category}>
                {selected.category}
              </p>
              {selected.storey && (
                <p className="exav-viewer-truncate exav-viewer-muted" title={selected.storey}>
                  {selected.storey}
                </p>
              )}
            </>
          ) : (
            <p className="exav-viewer-faint">{t("selection_none")}</p>
          )}
        </div>
      )}
      {ground && groundState && (
        <div className="exav-viewer-rail-section exav-viewer-rail-inline">
          <p className="exav-viewer-rail-label">{t("background")}</p>
          <div className="exav-viewer-segmented">
            {(["light", "dark"] as const).map((g) => (
              <button key={g} type="button" aria-pressed={groundState === g} onClick={() => ground.set(g)}>
                {t(`background_${g}`)}
              </button>
            ))}
          </div>
        </div>
      )}
      {storeys && storeyState && storeyState.items.length > 0 && (
        <>
          <div className="exav-viewer-rail-section exav-viewer-rail-inline">
            <p className="exav-viewer-rail-label">{t("storeys")}</p>
            <span className="exav-viewer-layer-all">
              <button type="button" onClick={() => storeys.setAll(true)}>
                {t("layers_all")}
              </button>
              <button type="button" onClick={() => storeys.setAll(false)}>
                {t("layers_none")}
              </button>
            </span>
          </div>
          <div className="exav-viewer-rail-scroll exav-viewer-storeys">
            {storeyState.items.map((s) => (
              <label key={s.id} className="exav-viewer-layer">
                <input type="checkbox" checked={s.visible} onChange={(e) => storeys.setVisible(s.id, e.target.checked)} />
                <span className={`exav-viewer-truncate${s.visible ? "" : " exav-viewer-faint"}`} title={s.name}>
                  {s.name}
                </span>
                {s.elevation !== null && <span className="exav-viewer-muted">{formatElevation(s.elevation)}</span>}
              </label>
            ))}
          </div>
        </>
      )}
      {layers && layerState && (
        <>
          <div className="exav-viewer-rail-section exav-viewer-rail-inline">
            <p className="exav-viewer-rail-label">{t(categories ? "categories" : "layers")}</p>
            <span className="exav-viewer-layer-all">
              <button type="button" onClick={() => layers.setAll(true)}>
                {t("layers_all")}
              </button>
              <button type="button" onClick={() => layers.setAll(false)}>
                {t("layers_none")}
              </button>
            </span>
          </div>
          <div className="exav-viewer-rail-scroll">
            {layerState.items.map((l) => (
              <label key={l.id} className="exav-viewer-layer">
                <input type="checkbox" checked={l.visible} onChange={(e) => layers.setVisible(l.id, e.target.checked)} />
                <span className="exav-viewer-swatch" style={{ background: l.color }} aria-hidden="true" />
                <span className={`exav-viewer-truncate${l.visible ? "" : " exav-viewer-faint"}`} title={l.name}>
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
    <div className="exav-viewer-pager">
      <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-round" onClick={() => void pages.prev?.()} aria-label={t("prev")}>
        <ChevronLeft />
      </button>
      <span aria-live="polite">{t("slide_of", { current: p.current, total: p.total })}</span>
      <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-round" onClick={() => void pages.next?.()} aria-label={t("next")}>
        <ChevronRight />
      </button>
    </div>
  );
}

function SheetTabs({ sheets }: SheetTabsProps) {
  const { t } = useViewerContext();
  const s = useStore(sheets);
  if (!s || s.items.length < 2) return null;
  return (
    <div className="exav-viewer-sheet-tabs" role="tablist" aria-label={t("sheets")}>
      {s.items.map((sheet) => (
        <button
          key={sheet.index}
          type="button"
          role="tab"
          aria-selected={sheet.index === s.current}
          className="exav-viewer-sheet-tab"
          title={sheet.name}
          onClick={() => void sheets.select(sheet.index)}
        >
          {sheet.name}
        </button>
      ))}
    </div>
  );
}

function Warnings({ warnings }: WarningsProps) {
  const { t } = useViewerContext();
  // Dismissed for these warnings: another file's, or a new reading of this
  // one's, are new values and show again.
  const [dismissed, setDismissed] = useState<WarningsProps["warnings"] | null>(null);
  if (warnings.length === 0 || warnings === dismissed) return null;
  return (
    <div className="exav-viewer-warnings" role="status">
      <div>
        {warnings.map((w) => (
          <p key={w.key}>
            {t(`warning_${w.key}` as MessageKey, { count: w.count })}
            {w.names && w.names.length > 0 && <span className="exav-viewer-warning-names"> {w.names.join(", ")}</span>}
          </p>
        ))}
      </div>
      <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" onClick={() => setDismissed(warnings)} aria-label={t("close")} title={t("close")}>
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
    <div className="exav-viewer-tool-group" data-pointer-only role="group">
      {/* First, as the tools are anchored at the right: the other buttons stay where they are as this one comes and goes. Nothing to go back to while the view is the one the file opened in. */}
      {Math.abs(scale - 1) > FIT_TOLERANCE && (
        <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" onClick={() => zoom.fit()} aria-label={t("zoom_fit")} title={t("zoom_fit")}>
          <ResetIcon />
        </button>
      )}
      <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" onClick={() => zoom.setScale(scale / ZOOM_STEP)} disabled={scale <= min} aria-label={t("zoom_out")} title={t("zoom_out")}>
        <Minus />
      </button>
      <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" onClick={() => zoom.setScale(scale * ZOOM_STEP)} disabled={scale >= max} aria-label={t("zoom_in")} title={t("zoom_in")}>
        <Plus />
      </button>
    </div>
  );
}

/** A zoom within this of 1 is the fitted view (a drawing's scale is a ratio of floats). */
const FIT_TOLERANCE = 0.01;

function PanelToggle({ open, title, hideLabel, icon, controls, toggle }: PanelToggleProps) {
  const label = open ? hideLabel : title;
  return (
    <button type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" onClick={toggle} aria-expanded={open} aria-controls={controls} aria-label={label} title={label}>
      {open ? <PanelClose /> : icon}
    </button>
  );
}

function FullscreenToggle(_: FullscreenToggleProps) {
  const { t } = useViewerContext();
  const button = useRef<HTMLButtonElement>(null);
  const { supported, active, toggle } = useFullscreen(() => button.current?.closest<HTMLElement>(".exav-viewer-body") ?? null);
  if (!supported) return null;
  const label = t(active ? "fullscreen_exit" : "fullscreen");
  return (
    <button ref={button} type="button" className="exav-viewer-icon-button exav-viewer-icon-button-small" data-pointer-only onClick={toggle} aria-label={label} title={label}>
      {active ? <FullscreenExitIcon /> : <FullscreenIcon />}
    </button>
  );
}

function DragToggle({ drag }: DragToggleProps) {
  const { t } = useViewerContext();
  const state = useStore(drag);
  // Nothing to choose while the page fits: a drag selects.
  if (!state?.available) return null;
  return (
    <div className="exav-viewer-tool-group" data-pointer-only role="group">
      <button
        type="button"
        className="exav-viewer-icon-button exav-viewer-icon-button-small"
        onClick={() => drag.choose("pan")}
        aria-pressed={state.mode === "pan"}
        aria-label={t("drag_pan")}
        title={t("drag_pan")}
      >
        <Hand />
      </button>
      <button
        type="button"
        className="exav-viewer-icon-button exav-viewer-icon-button-small"
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
    <div className="exav-viewer-archive">
      <p className="exav-viewer-archive-head">{t("archive_members", { count: s.members.length })}</p>
      {s.refused && <p className="exav-viewer-archive-refused">{t(s.refused.key)}</p>}
      <ul className="exav-viewer-archive-list">
        {s.members.map((m) => {
          const folder = folderOf(m.name);
          return (
            <li key={m.index}>
              <button type="button" className={`exav-viewer-member${m.encrypted ? " exav-viewer-member-locked" : ""}`} disabled={s.opening !== null || m.encrypted} onClick={() => void archive.open(m.index)}>
                {s.opening === m.index ? <Spinner /> : <FileIcon />}
                <span className="exav-viewer-member-name">
                  <span className="exav-viewer-truncate">{m.name.split("/").pop()}</span>
                  {folder && (
                    <span className="exav-viewer-member-folder exav-viewer-truncate">
                      <FolderIcon />
                      {folder}
                    </span>
                  )}
                </span>
                <span className="exav-viewer-member-size">{formatBytes(m.uncompressedSize)}</span>
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
    <div className="exav-viewer-archive-back">
      <button type="button" onClick={() => archive.back()}>
        <ArrowLeft />
        {t("archive_back")}
      </button>
      <span className="exav-viewer-truncate" title={name}>
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
  SheetTabs,
  ArchiveList,
  ArchiveBack,
  Warnings,
  ZoomControls,
  DragToggle,
  FullscreenToggle,
  PanelToggle,
};
