import { useCallback, useEffect, useState, type ReactNode } from "react";

import { canOpenInTab } from "../core/source.js";
import type { ViewerFile } from "../core/types.js";
import { useViewerContext } from "./context.js";
import { ChevronLeft, ChevronRight, Close, Download, External, Spinner } from "./icons.js";
import { Piece } from "./parts.js";
import { ViewerBody } from "./ViewerBody.js";

export interface ViewerDialogItem<Meta = unknown> extends ViewerFile<Meta> {
  /** The heading. */
  title: string;
  /** After the title, quieter: "Page 3". */
  hint?: string;
  /**
   * Download. `resolveUrl` for a URL signed on demand (the server names the
   * file: `download=` is ignored cross-origin). Without it, an anchor with
   * `download` on the source URL. Neither and no URL: no button.
   */
  download?: { resolveUrl?: () => Promise<string>; fileName?: string };
}

export interface ViewerDialogProps<Meta = unknown> {
  items: readonly ViewerDialogItem<Meta>[];
  /** `null` is closed. */
  index: number | null;
  onIndexChange: (index: number | null) => void;
  /** "full": the window less 2rem all round. "page": the same height, at most 72rem wide. */
  width?: "full" | "page";
  /** A line between the header and the body. */
  notice?: ReactNode;
  onDownloadError?: (error: unknown, item: ViewerDialogItem<Meta>) => void;
  /** Extra footer actions, before "open in a new tab" and "download". */
  actions?: (item: ViewerDialogItem<Meta>) => ReactNode;
}

/** The URL a source has, when it is a plain one. */
function urlOf(item: ViewerFile): string | null {
  return item.source && "url" in item.source ? item.source.url : null;
}

/** Clicks a temporary anchor: added to the document first, for Firefox. */
async function download(resolve: () => Promise<string>, fileName?: string) {
  const url = await resolve();
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  if (fileName) a.download = fileName;
  document.body.append(a);
  a.click();
  a.remove();
}

/**
 * A stack of files in a dialog: prev and next (buttons, and ArrowLeft and
 * ArrowRight on the window, since a canvas takes focus when touched), the
 * "2 / 11" counter, "Page 4 / 9" beside it when the body reports pages,
 * "open in a new tab" for a URL that outlives the page, download, Escape to
 * close. Every control is at least 44px.
 */
export function ViewerDialog<Meta = unknown>({ items, index, onIndexChange, width = "full", notice, onDownloadError, actions }: ViewerDialogProps<Meta>) {
  const { t } = useViewerContext();
  const open = index !== null;
  const item = index === null ? null : (items[index] ?? null);
  const [saving, setSaving] = useState(false);
  const [pages, setPages] = useState<{ current: number; total: number } | null>(null);
  useEffect(() => setPages(null), [item?.id]);
  const onPages = useCallback((p: { unit: "page" | "slide"; current: number; total: number } | null) => setPages(p && p.unit === "page" ? p : null), []);

  const n = items.length;
  const go = useCallback(
    (delta: number) => {
      if (index === null || n < 2) return;
      onIndexChange((index + delta + n) % n);
    },
    [index, n, onIndexChange],
  );
  useEffect(() => {
    if (!open || n < 2) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") go(-1);
      else if (e.key === "ArrowRight") go(1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, n, go]);

  const url = item ? urlOf(item) : null;
  const save = () => {
    const resolve = item?.download?.resolveUrl;
    if (!item || !resolve) return;
    setSaving(true);
    download(resolve, item.download?.fileName)
      .catch((error) => onDownloadError?.(error, item))
      .finally(() => setSaving(false));
  };

  const title = item ? (
    <>
      {item.title}
      {item.hint && <span className="exv-hint">{item.hint}</span>}
    </>
  ) : null;

  return (
    <Piece
      name="Shell"
      props={{
        open,
        onClose: () => onIndexChange(null),
        title: item?.title ?? "",
        width,
        children: item && (
          <div className="exv-dialog-inner">
            <header className="exv-dialog-head">
              <h2 className="exv-dialog-title">{title}</h2>
              <button type="button" className="exv-icon-button" onClick={() => onIndexChange(null)} aria-label={t("close")}>
                <Close />
              </button>
            </header>
            {notice}
            <div className="exv-frame">
              <ViewerBody key={item.id} file={item} onPages={onPages} />
            </div>
            <footer className="exv-dialog-foot">
              <div className="exv-foot-left">
                {n > 1 && (
                  <>
                    <button type="button" className="exv-icon-button" onClick={() => go(-1)} aria-label={t("prev")}>
                      <ChevronLeft />
                    </button>
                    <button type="button" className="exv-icon-button" onClick={() => go(1)} aria-label={t("next")}>
                      <ChevronRight />
                    </button>
                    <span className="exv-counter" aria-live="polite">
                      {t("counter", { current: (index ?? 0) + 1, total: n })}
                    </span>
                  </>
                )}
                {pages && pages.total > 1 && (
                  <span className={`exv-counter exv-muted${n > 1 ? " exv-separated" : ""}`} aria-live="polite">
                    {t("page_of", pages)}
                  </span>
                )}
              </div>
              <div className="exv-foot-right">
                {actions?.(item)}
                {canOpenInTab(url) && (
                  <a className="exv-button exv-button-outline" href={url ?? ""} target="_blank" rel="noreferrer">
                    <External />
                    {t("open_in_tab")}
                  </a>
                )}
                {item.download?.resolveUrl ? (
                  <button type="button" className="exv-button" disabled={saving} onClick={save}>
                    {saving ? <Spinner /> : <Download />}
                    {t("download")}
                  </button>
                ) : url ? (
                  <a className="exv-button" href={url} download={item.download?.fileName ?? true}>
                    <Download />
                    {t("download")}
                  </a>
                ) : null}
              </div>
            </footer>
          </div>
        ),
      }}
    />
  );
}
