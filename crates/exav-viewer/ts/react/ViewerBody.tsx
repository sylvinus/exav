import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

import type { Controllers, Session, Status, ViewerFile } from "../core/types.js";
import { useSession, useStore } from "./hooks.js";
import { Piece } from "./parts.js";

export interface ViewerBodyProps {
  file: ViewerFile;
  /** "default": the rails, pager and overlays. "none": the surface alone. */
  chrome?: "default" | "none";
  onStatus?: (status: Status) => void;
  /** Pages of a PDF or a Word document, slides of a presentation. */
  onPages?: (pages: { unit: "page" | "slide"; current: number; total: number } | null) => void;
  className?: string;
  /**
   * Drawn in the stage, over the surface, after the default overlays: a
   * node, or a function of the session's state, for a host's own zoom
   * buttons say. With an archive member open, these are the archive's;
   * follow `controllers.archive.opened.session` to reach the member's.
   */
  children?: ReactNode | ((state: { session: Session | null; status: Status; controllers: Controllers }) => ReactNode);
}

/**
 * The chrome of one session: its overlays where it draws, its rails in
 * `rails`, and the bars that lead back out of an archive in `bars`, above
 * the overlays' reach. An archive with a member open hands all three to the
 * member's own session, one level down, so a PDF inside a zip has its
 * outline.
 */
function Layer({ session, depth, rails, bars }: { session: Session; depth: number; rails: HTMLElement | null; bars: HTMLElement | null }) {
  const status = useStore(session.status) ?? { phase: "loading" as const };
  const c = useStore(session.controllers) ?? {};
  const archive = useStore(c.archive);
  const info = useStore(c.info);
  const warnings = useStore(c.warnings);
  const opened = archive?.opened;
  if (opened && c.archive) {
    return (
      <>
        {bars &&
          createPortal(
            // Portals into one element do not keep their order: `order` does.
            <div className="exv-stack" style={{ order: depth }}>
              <Piece name="ArchiveBack" props={{ archive: c.archive, name: opened.member.name }} />
            </div>,
            bars,
          )}
        <Layer session={opened.session} depth={depth + 1} rails={rails} bars={bars} />
      </>
    );
  }
  const drawing = c.layers || c.layouts || c.ground || c.selection;
  return (
    <>
      {c.archive && <Piece name="ArchiveList" props={{ archive: c.archive }} />}
      {c.pages && <Piece name="SlidePager" props={{ pages: c.pages }} />}
      {info && <Piece name="InfoBadge" props={{ format: session.format, info }} />}
      {warnings && <Piece name="Warnings" props={{ warnings }} />}
      {(c.zoom || c.drag) && (
        <div className="exv-tools">
          {c.drag && <Piece name="DragToggle" props={{ drag: c.drag }} />}
          {c.zoom && <Piece name="ZoomControls" props={{ zoom: c.zoom }} />}
        </div>
      )}
      <Piece name="StatusOverlay" props={{ status, format: session.format }} />
      {rails &&
        createPortal(
          <>
            {c.outline && <Piece name="OutlineRail" props={{ outline: c.outline }} />}
            {drawing && <Piece name="DrawingRail" props={{ layers: c.layers, layouts: c.layouts, ground: c.ground, selection: c.selection }} />}
          </>,
          rails,
        )}
    </>
  );
}

/**
 * Reports the pages of the session on screen: with an archive member open,
 * the member's (a PDF inside a zip has its own page counter), the archive's
 * own otherwise (none).
 */
function PagesOf({ session, onPages }: { session: Session; onPages: NonNullable<ViewerBodyProps["onPages"]> }) {
  const c = useStore(session.controllers) ?? {};
  const opened = useStore(c.archive)?.opened;
  const pages = useStore(c.pages);
  // Block body: a host callback may return a value, which React would take for the cleanup.
  useEffect(() => {
    if (!opened) onPages(pages ?? null);
  }, [opened, pages, onPages]);
  return opened ? <PagesOf session={opened.session} onPages={onPages} /> : null;
}

/**
 * One file, without the dialog. Keyed on `file.id` inside: a new id ends the
 * previous session first, which is what frees its worker, WebGL context and
 * bitmaps.
 */
export function ViewerBody({ file, chrome = "default", onStatus, onPages, className, children }: ViewerBodyProps) {
  const { session, status, controllers, ref } = useSession(file.source ? file : null);
  const [rails, setRails] = useState<HTMLDivElement | null>(null);
  const [bars, setBars] = useState<HTMLDivElement | null>(null);

  // Block bodies: a host callback may return a value (`(s) => log.push(s)`),
  // which React would take for the effect's cleanup and call.
  useEffect(() => {
    onStatus?.(status);
  }, [status, onStatus]);
  // Nothing to count until a session is there; `PagesOf` reports from then on.
  useEffect(() => {
    if (!session) onPages?.(null);
  }, [session, onPages]);

  const pending = !file.source;
  return (
    // `data-phase`: the session's phase, for a host's styles and tests.
    <div className={`exv-body${className ? ` ${className}` : ""}`} data-phase={pending ? "pending" : status.phase}>
      <div className="exv-main">
        {chrome === "default" && <div ref={setBars} className="exv-bars" />}
        {/* The overlays cover the stage, never the bars above it. */}
        <div className="exv-stage">
          <div ref={ref} className="exv-surface" />
          {pending && file.placeholder && <Piece name="Placeholder" props={{ state: file.placeholder.state, label: file.placeholder.label }} />}
          {pending && !file.placeholder && <Piece name="Placeholder" props={{ state: "unavailable" }} />}
          {chrome === "default" && session && <Layer session={session} depth={0} rails={rails} bars={bars} />}
          {typeof children === "function" ? children({ session, status, controllers }) : children}
        </div>
      </div>
      {chrome === "default" && <div ref={setRails} className="exv-rails" />}
      {session && onPages && <PagesOf session={session} onPages={onPages} />}
    </div>
  );
}
