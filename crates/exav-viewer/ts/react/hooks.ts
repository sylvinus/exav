import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";

import { sameSource } from "../core/source.js";
import type { Store } from "../core/store.js";
import type { Controllers, FileSource, Session, Status, ViewerFile } from "../core/types.js";
import { useViewer } from "./context.js";

const NONE = (): undefined => undefined;
const NO_SUBSCRIBE = () => () => {};

/** A store's value, re-rendering on each change; undefined without a store. */
export function useStore<T>(store: Store<T> | undefined): T | undefined {
  return useSyncExternalStore(
    store ? store.subscribe : NO_SUBSCRIBE,
    store ? store.get : NONE,
    store ? store.get : NONE,
  );
}

const LOADING: Status = { phase: "loading" };

/**
 * A session for `file`, mounted into the returned `ref`'s element once it is
 * attached. A new file id ends the previous session first, which frees its
 * workers, GL contexts and bitmaps. The same id with another source is the
 * same document with other bytes: it replaces the document in place, keeping
 * the zoom and scroll position where the format can (`Session.replace`), and
 * starts the session over where it cannot.
 */
export function useSession(file: ViewerFile | null) {
  const viewer = useViewer();
  const [host, setHost] = useState<HTMLDivElement | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  // Bumped to start over when a document cannot be replaced in place.
  const [restarts, setRestarts] = useState(0);
  const shown = useRef<FileSource | null>(null);
  const key = file ? `${file.id}\u0000${file.source ? "s" : "n"}\u0000${restarts}` : "";
  useEffect(() => {
    if (!file || !host) {
      setSession(null);
      return;
    }
    const s = viewer.mount(host, file);
    shown.current = file.source;
    setSession(s);
    const ro = new ResizeObserver(() => s.resize());
    ro.observe(host);
    return () => {
      ro.disconnect();
      s.destroy();
      host.replaceChildren();
    };
    // The file may be a new literal on each render: its id says whether it
    // is another file, and its source (below) whether it has other bytes.
  }, [viewer, host, key]);
  const source = file?.source ?? null;
  useEffect(() => {
    if (!session || !file || !source || sameSource(shown.current, source)) return;
    shown.current = source;
    let current = true;
    void session.replace(file).then((done) => {
      if (!done && current) setRestarts((n) => n + 1);
    });
    return () => {
      current = false;
    };
    // Whatever else the file carries (its meta, say) is read when it is mounted or replaced.
  }, [session, source]);
  const status = useStore(session?.status) ?? LOADING;
  const controllers: Controllers = useStore(session?.controllers) ?? {};
  return { session, status, controllers, ref: setHost };
}

// ── The tools' state, for the default pieces and for a host's own ───────────

/** Below this width the side panel starts folded. Decided once: turning a tablet must not close it. */
export const RAIL_FITS = 1024;

/** What the panel's toggle says about the rail it folds. */
export interface PanelInfo {
  title: string;
  hideLabel: string;
  icon: ReactNode;
  /** The rail's id, for the toggle's `aria-controls`. */
  controls: string;
}

/** Shared by the rails and the toggle among the tools (`ViewerBody` provides it). */
export const PanelContext = createContext<{ open: boolean; setOpen: (open: boolean) => void; register: (info: PanelInfo | null) => void } | null>(null);

const NO_OP = () => {};

/**
 * The side panel's fold state, shared by the rails and the toggle among the
 * tools; outside a viewer, always open. A rail of a host's own gives its
 * `info` and shows the default toggle for as long as it is mounted; read
 * `open` to draw or not.
 */
export function usePanel(info?: PanelInfo): { open: boolean; setOpen: (open: boolean) => void } {
  const panel = useContext(PanelContext);
  const register = panel?.register;
  // The icon is the same for as long as the rail is: left out of the deps.
  useEffect(() => {
    if (!info) return undefined;
    register?.(info);
    return () => register?.(null);
  }, [register, info?.title, info?.hideLabel, info?.controls]);
  return { open: panel ? panel.open : true, setOpen: panel?.setOpen ?? NO_OP };
}

/**
 * Full screen for the element `target` returns (a host's own box, or the
 * viewer's `.exav-viewer-body`), asked for from the host page, so a sandboxed
 * frame needs no permission. `supported` is false where the browser has none.
 */
export function useFullscreen(target: () => HTMLElement | null): { supported: boolean; active: boolean; toggle: () => void } {
  const latest = useRef(target);
  latest.current = target;
  const [active, setActive] = useState(false);
  useEffect(() => {
    const sync = () => setActive(document.fullscreenElement !== null && document.fullscreenElement === latest.current());
    document.addEventListener("fullscreenchange", sync);
    sync();
    return () => document.removeEventListener("fullscreenchange", sync);
  }, []);
  const supported = typeof document !== "undefined" && document.fullscreenEnabled === true;
  const toggle = () => {
    const el = latest.current();
    if (!el) return;
    // A refusal (a host page in a frame without `allow="fullscreen"`) leaves the view as it was.
    void (active ? document.exitFullscreen() : el.requestFullscreen()).catch(() => {});
  };
  return { supported, active, toggle };
}
