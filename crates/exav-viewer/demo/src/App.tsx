import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode } from "react";

import type { ViewerFile } from "@exav/viewer";
import { allPlugins } from "@exav/viewer/all";
import { ViewerBody, ViewerProvider } from "@exav/viewer/react";
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

import { GROUPS, type Sample } from "./showcase.js";

type Locale = "en" | "fr";

/** A file in the list, shown by its name. */
type Item = ViewerFile;

const TEXT = {
  en: {
    tagline: "Files viewed in the browser. Nothing you open here leaves your device.",
    yours: "Your files",
    open: "Open one of your files",
    drop: "Drop files to view them",
    docs: "Documentation",
    licences: "Licences",
    upload: "Drop files here, or click to choose",
    formats: "PDF, images, DWG and DXF drawings, Word, Excel, PowerPoint, CSV, IFC and STL models, video, audio and archives. Or pick a sample on the left.",
  },
  fr: {
    tagline: "Des fichiers affichés dans le navigateur. Rien de ce que vous ouvrez ici ne quitte votre appareil.",
    yours: "Vos fichiers",
    open: "Ouvrir un de vos fichiers",
    drop: "Déposez des fichiers pour les afficher",
    docs: "Documentation",
    licences: "Licences",
    upload: "Déposez des fichiers ici, ou cliquez pour les choisir",
    formats: "PDF, images, plans DWG et DXF, Word, Excel, PowerPoint, CSV, maquettes IFC et STL, vidéo, audio et archives. Ou choisissez un exemple à gauche.",
  },
} satisfies Record<Locale, Record<string, string>>;

const BASE = import.meta.env.BASE_URL;

/**
 * Each file in a sandboxed frame (`@exav/viewer/frame`), served beside the
 * demo by `@exav/viewer/vite`. `?mode=page` runs the engines in this page
 * instead, the mode for hosts that cannot serve the frame.
 */
const QUERY = new URLSearchParams(location.search);
const IN_PAGE = QUERY.get("mode") === "page";

/** Where the demo is deployed (vite.config.ts): the frame may show media and fetch from it. */
declare const __DEMO_ORIGIN__: string;

/**
 * The frame's delivery per kind of file, defaults unless `?delivery=pdf:url,media:blob`
 * says otherwise (the browser tests).
 */
const DELIVERY = Object.fromEntries((QUERY.get("delivery") ?? "").split(",").filter(Boolean).map((d) => d.split(":")));
const SANDBOX = {
  url: `${BASE}frame/index.html`,
  origins: { media: [__DEMO_ORIGIN__], connect: [__DEMO_ORIGIN__] },
  delivery: DELIVERY,
};

/** `?url=<address>`: a file by its address, opened first. */
const LINKED = QUERY.get("url");

/** The engines in the page (`?mode=page`), or each file in a sandboxed frame, the default. */
function Provider({ plugins, locale, children }: { plugins: ReturnType<typeof allPlugins>; locale: Locale; children: ReactNode }) {
  return IN_PAGE ? (
    <ViewerProvider plugins={plugins} assetBase={`${BASE}exav-viewer/`} locale={locale}>
      {children}
    </ViewerProvider>
  ) : (
    <SandboxedViewerProvider sandbox={SANDBOX} locale={locale}>
      {children}
    </SandboxedViewerProvider>
  );
}

function initialLocale(): Locale {
  const asked = new URLSearchParams(location.search).get("lang");
  if (asked === "en" || asked === "fr") return asked;
  return navigator.language.toLowerCase().startsWith("fr") ? "fr" : "en";
}

export function App() {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const [own, setOwn] = useState<Item[]>([]);
  // Nothing open until a file is chosen, unless the address names one.
  const [selected, setSelected] = useState<string | null>(() => (LINKED ? "linked" : QUERY.get("file")));
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const counter = useRef(0);
  const t = TEXT[locale];

  // One plugin list for the page: `ViewerProvider` starts a viewer per list.
  const plugins = useMemo(() => allPlugins(), []);
  // The sidebar's files, from showcase/samples.json (`npm run demo:showcase`);
  // none when it was not copied in.
  const [samples, setSamples] = useState<Sample[]>([]);
  useEffect(() => {
    fetch(`${BASE}showcase/samples.json`)
      .then((r) => (r.ok ? r.json() : { samples: [] }))
      .then((j: { samples: Sample[] }) => setSamples(j.samples))
      .catch(() => setSamples([]));
  }, []);
  const showcase = useMemo(
    () => samples.map((s): Item => ({ id: `showcase:${s.file}`, name: s.file, source: { url: `${BASE}showcase/${s.file}` } })),
    [samples],
  );
  // Known groups in their order, then any other, in the order they come.
  const groups = useMemo(() => [...new Set([...Object.keys(GROUPS), ...samples.map((s) => s.group)])], [samples]);
  const linked = useMemo((): Item[] => {
    if (!LINKED) return [];
    const name = decodeURIComponent(new URL(LINKED, location.href).pathname.split("/").pop() || "file");
    return [{ id: "linked", name, source: { url: LINKED } }];
  }, []);
  const items = useMemo(() => [...linked, ...own, ...showcase], [linked, own, showcase]);
  const current = items.find((i) => i.id === selected) ?? null;

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const add = useCallback(
    (files: FileList | File[]) => {
      const picked = Array.from(files);
      if (!picked.length) return;
      // A file given again under the name of one already listed is the same
      // document with other bytes: it replaces it in place, and the viewer
      // keeps the zoom and scroll position where it can.
      const next = [...own];
      const added: Item[] = [];
      const shown: string[] = [];
      for (const f of picked) {
        const fields = { name: f.name, type: f.type, size: f.size, source: { blob: f } };
        const same = next.findIndex((i) => i.name === f.name);
        if (same >= 0) {
          next[same] = { ...next[same]!, ...fields };
          shown.push(next[same]!.id);
        } else {
          const item: Item = { id: `own:${++counter.current}`, ...fields };
          added.push(item);
          shown.push(item.id);
        }
      }
      setOwn([...added, ...next]);
      setSelected(shown[0]!);
    },
    [own],
  );

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    add(e.dataTransfer.files);
  };

  const entry = (item: Item) => (
    <li key={item.id}>
      <button type="button" className={`demo-file${item.id === selected ? " is-selected" : ""}`} aria-current={item.id === selected} onClick={() => setSelected(item.id)}>
        {item.name}
      </button>
    </li>
  );

  return (
    <Provider plugins={plugins} locale={locale}>
      <div
        className="demo"
        onDragOver={(e) => {
          if (!e.dataTransfer.types.includes("Files")) return;
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={(e) => {
          if (e.currentTarget === e.target) setDragging(false);
        }}
        onDrop={onDrop}
      >
        <header className="demo-head">
          <div className="demo-brand">
            <strong>@exav/viewer</strong>
            <span className="demo-tagline">{t.tagline}</span>
          </div>
          <nav className="demo-nav">
            <a href="https://exav.org/viewer/">{t.docs}</a>
            <a href="https://github.com/sylvinus/exav/tree/main/crates/exav-viewer">GitHub</a>
            <a href={`${BASE}licenses/README.txt`}>{t.licences}</a>
            <select aria-label="Language" value={locale} onChange={(e) => setLocale(e.target.value as Locale)}>
              <option value="en">English</option>
              <option value="fr">Français</option>
            </select>
          </nav>
        </header>
        <aside className="demo-side">
          <button type="button" className="demo-open" onClick={() => input.current?.click()}>
            {t.open}
          </button>
          <input
            ref={input}
            type="file"
            multiple
            hidden
            data-testid="file-input"
            onChange={(e) => {
              if (e.target.files) add(e.target.files);
              e.target.value = "";
            }}
          />
          {own.length > 0 && (
            <>
              <h2>{t.yours}</h2>
              <ul>{own.map(entry)}</ul>
            </>
          )}
          {groups.map((group) => {
            // `showcase` follows `samples`' order.
            const list = showcase.filter((_, i) => samples[i]!.group === group);
            return (
              list.length > 0 && (
                <section key={group}>
                  <h2>{GROUPS[group]?.[locale] ?? group}</h2>
                  <ul>{list.map(entry)}</ul>
                </section>
              )
            );
          })}
        </aside>
        <main className="demo-main">
          {current ? (
            <>
              <div className="demo-bar">
                <h1>
                  {current.name}
                </h1>
              </div>
              <div className="demo-frame">
                <ViewerBody key={current.id} file={current} />
              </div>
            </>
          ) : (
            <button type="button" className="demo-upload" onClick={() => input.current?.click()}>
              <strong>{t.upload}</strong>
              <span>{t.formats}</span>
            </button>
          )}
        </main>
        {dragging && <div className="demo-drop">{t.drop}</div>}
      </div>
    </Provider>
  );
}
