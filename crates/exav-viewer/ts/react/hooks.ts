import { useEffect, useRef, useState, useSyncExternalStore } from "react";

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
