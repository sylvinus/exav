/**
 * `@exav/viewer/react`: the default UI, on React 19.
 *
 * Three levels, each usable alone: the CSS custom properties (`TOKENS`, in
 * `@exav/viewer/styles.css`); the components, any of which can be replaced
 * through `ViewerProvider`'s `components`; and headless, `useSession` and the
 * controllers, for a host drawing every piece itself.
 */
export { ViewerProvider, useViewer, type ViewerProviderProps } from "./context.js";
export { ViewerBody, type ViewerBodyProps } from "./ViewerBody.js";
export { ViewerDialog, type ViewerDialogItem, type ViewerDialogProps } from "./ViewerDialog.js";
export { useSession, useStore } from "./hooks.js";
export { reactOverlay } from "./overlay.js";
export { builtinTranslate, MESSAGES, type MessageKey, type Translate } from "./messages.js";
export { formatBytes, type ViewerComponents, type ShellProps, type StatusOverlayProps, type PlaceholderProps, type OutlineRailProps, type DrawingRailProps, type SlidePagerProps, type ArchiveListProps, type ArchiveBackProps, type InfoBadgeProps, type WarningsProps, type ZoomControlsProps, type DragToggleProps } from "./parts.js";

/**
 * The CSS custom properties of the default UI, with their default values.
 * Set any of them on an ancestor (or `:root`) to restyle.
 */
export const TOKENS = {
  "--exv-surface": "#f1f5f9",
  "--exv-panel": "#ffffff",
  "--exv-border": "#e2e8f0",
  "--exv-text": "#334155",
  "--exv-text-strong": "#0f172a",
  "--exv-muted": "#64748b",
  "--exv-faint": "#94a3b8",
  "--exv-hover": "#f8fafc",
  "--exv-active": "#f1f5f9",
  "--exv-accent": "#0f172a",
  "--exv-on-accent": "#ffffff",
  "--exv-error": "#b91c1c",
  "--exv-warning": "#b45309",
  "--exv-media-bg": "#0f172a",
  "--exv-model-bg": "radial-gradient(circle at 50% 30%, #ffffff 0%, #e2e8f0 55%, #cbd5e1 100%)",
  "--exv-radius": "0.375rem",
  "--exv-rail-width": "15rem",
  "--exv-tap": "2.75rem",
  "--exv-font": "inherit",
} as const;
