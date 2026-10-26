import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode } from "react";

import { BUILTIN_ORDER, type FileTree, type Session, type ViewerFile } from "@exav/viewer";
import { allPlugins } from "@exav/viewer/all";
import {
  coreldraw,
  doc,
  freehand,
  keynote,
  numbers,
  odg,
  odp,
  ods,
  odt,
  pagemaker,
  ppt,
  publisher,
  quarkxpress,
  rtf,
  visio,
  wpg,
  xls,
  zonerdraw,
} from "@exav/viewer/office";
import { ViewerBody, ViewerProvider } from "@exav/viewer/react";
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

import { ExportImage } from "./ExportImage.js";
import { credit, GROUPS, type Example, type Sample } from "./showcase.js";

type Locale = "en" | "fr";

/** A file in the list, shown by its name. */
type Item = ViewerFile;

/** A file chosen or dropped, and where it is in the folder it came from. */
interface Picked {
  file: File;
  path: string;
}

const picked = (files: FileList | File[]): Picked[] => Array.from(files).map((file) => ({ file, path: file.webkitRelativePath || file.name }));

/**
 * What a drop holds, folders walked: the files by their path from the
 * dropped folder's parent. `entries` are read before the first await, which
 * is when the browser lets them be.
 */
async function dropped(data: DataTransfer): Promise<Picked[]> {
  const entries = Array.from(data.items ?? [])
    .map((i) => i.webkitGetAsEntry?.())
    .filter((e): e is FileSystemEntry => !!e);
  if (!entries.length) return picked(data.files);
  const out: Picked[] = [];
  const walk = async (entry: FileSystemEntry): Promise<void> => {
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
      out.push({ file, path: entry.fullPath.replace(/^\//, "") });
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader();
      // A directory is read in batches until one is empty.
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
        if (!batch.length) break;
        for (const e of batch) await walk(e);
      }
    }
  };
  for (const e of entries) await walk(e);
  return out;
}

/** The files of a batch, each seen as one of them: a drawing finds the files it refers to among the others. */
function around(batch: Picked[], at: Picked): FileTree | undefined {
  if (batch.length < 2) return undefined;
  return {
    path: at.path,
    paths: batch.map((b) => b.path),
    open: async (path) => {
      const hit = batch.find((b) => b.path === path);
      if (!hit) throw new Error(`no ${path} in the folder`);
      return { blob: hit.file };
    },
  };
}

/** A sample or an example in the sidebar: its section, and who made it, under what licence. */
interface Listed {
  group: string;
  note: string;
  item: Item;
}

const TEXT = {
  en: {
    tagline: "Files viewed in the browser. Nothing you open here leaves your device.",
    yours: "Your files",
    open: "Open one of your files",
    folder: "Open a folder",
    drop: "Drop files or a folder to view them",
    docs: "Documentation",
    licences: "Licences",
    upload: "Drop files here, or click to choose",
    formats: "PDF, images, DWG and DXF drawings, Word, Excel, PowerPoint, CSV, text, Markdown, JSON and XML, IFC, STL, OBJ, PLY and glTF models, video, audio and archives. Or pick a sample on the left.",
  },
  fr: {
    tagline: "Des fichiers affichés dans le navigateur. Rien de ce que vous ouvrez ici ne quitte votre appareil.",
    yours: "Vos fichiers",
    open: "Ouvrir un de vos fichiers",
    folder: "Ouvrir un dossier",
    drop: "Déposez des fichiers ou un dossier pour les afficher",
    docs: "Documentation",
    licences: "Licences",
    upload: "Déposez des fichiers ici, ou cliquez pour les choisir",
    formats: "PDF, images, plans DWG et DXF, Word, Excel, PowerPoint, CSV, texte, Markdown, JSON et XML, maquettes IFC, STL, OBJ, PLY et glTF, vidéo, audio et archives. Ou choisissez un exemple à gauche.",
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
/** The external converter the demo was built with (`EXAV_EXTERNAL_CONVERTER`), or null. */
declare const __EXTERNAL_CONVERTER__: string | null;

/**
 * The frame's delivery per kind of file, defaults unless `?delivery=pdf:url,media:blob`
 * says otherwise (the browser tests).
 */
const DELIVERY = Object.fromEntries((QUERY.get("delivery") ?? "").split(",").filter(Boolean).map((d) => d.split(":")));

// Every format, the converted Office ones included: where no external
// converter was copied in, a format only it reads ends in "needs_converter".
/**
 * `?converter=exav` or `?converter=external` (the browser tests): without
 * it, text documents (DOC, ODT, RTF) go to the external converter when the
 * demo has one, else to exav-render's `docs`.
 */
const CONVERTER = {
  ...(QUERY.get("converter") === "exav" || QUERY.get("converter") === "external" ? { converter: QUERY.get("converter") as "exav" | "external" } : {}),
  // `?timeoutMs=500&maxMemory=5000000` (the browser tests).
  ...(QUERY.get("timeoutMs") ? { timeoutMs: Number(QUERY.get("timeoutMs")) } : {}),
  ...(QUERY.get("maxMemory") ? { maxMemory: Number(QUERY.get("maxMemory")) } : {}),
  // `?externalConverter=/e2e/fake-converter.js`: a converter by its URL (the browser tests).
  ...(QUERY.get("externalConverter") || __EXTERNAL_CONVERTER__ ? { externalConverter: QUERY.get("externalConverter") ?? __EXTERNAL_CONVERTER__! } : {}),
};

const SANDBOX = {
  url: `${BASE}frame/index.html`,
  options: { conversion: CONVERTER },
  origins: { media: [__DEMO_ORIGIN__], connect: [__DEMO_ORIGIN__] },
  delivery: DELIVERY,
  formats: BUILTIN_ORDER,
};

/** `?url=<address>`: a file by its address, opened first. */
const LINKED = QUERY.get("url");

/** `?cad=monochrome`: drawings in ink, as plotted; `?rasterTile=64`: pictures drawn in small tiles (the browser tests). */
const CAD = {
  ...(QUERY.get("cad") === "monochrome" ? { monochrome: true } : {}),
  ...(QUERY.get("rasterTile") ? { rasterTile: Number(QUERY.get("rasterTile")) } : {}),
};

/** `?rasterTile=64` and `?rasterSupersample=2`: the models' pictures drawn in small tiles, or supersampled (the browser tests). */
const MODEL = {
  ...(QUERY.get("rasterTile") ? { rasterTile: Number(QUERY.get("rasterTile")) } : {}),
  ...(QUERY.get("rasterSupersample") ? { rasterSupersample: Number(QUERY.get("rasterSupersample")) } : {}),
};

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

/** Hands the viewer's session to the page around it, and takes it back when the file goes. */
function SessionOut({ session, onSession }: { session: Session | null; onSession: (s: Session | null) => void }) {
  useEffect(() => {
    onSession(session);
    return () => onSession(null);
  }, [session, onSession]);
  return null;
}

export function App() {
  const [locale, setLocale] = useState<Locale>(initialLocale);
  const [own, setOwn] = useState<Item[]>([]);
  // Nothing open until a file is chosen, unless the address names one.
  const [selected, setSelected] = useState<string | null>(() => (LINKED ? "linked" : QUERY.get("file")));
  const [dragging, setDragging] = useState(false);
  // The session of the file on screen, for the host's controls beside its name.
  const [session, setSession] = useState<Session | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const folder = useRef<HTMLInputElement>(null);
  const counter = useRef(0);
  const t = TEXT[locale];

  // One plugin list for the page: `ViewerProvider` starts a viewer per list.
  const plugins = useMemo(
    () => [
      ...allPlugins({ cad: CAD, ifc: MODEL, model: MODEL }),
      ...[rtf(CONVERTER), doc(CONVERTER), odt(CONVERTER), ppt(CONVERTER), odp(CONVERTER), keynote(CONVERTER), xls(CONVERTER), ods(CONVERTER), numbers(CONVERTER)],
      ...[odg(CONVERTER), visio(CONVERTER), coreldraw(CONVERTER), publisher(CONVERTER), pagemaker(CONVERTER), freehand(CONVERTER), quarkxpress(CONVERTER), zonerdraw(CONVERTER), wpg(CONVERTER)],
    ],
    [],
  );
  // The sidebar's files, from showcase/samples.json (`npm run demo:showcase`)
  // and examples/examples.json (`npm run demo:examples`); none when they were
  // not copied in. A file is fetched only when it is selected.
  const [samples, setSamples] = useState<Sample[]>([]);
  const [examples, setExamples] = useState<Example[]>([]);
  useEffect(() => {
    fetch(`${BASE}showcase/samples.json`)
      .then((r) => (r.ok ? r.json() : { samples: [] }))
      .then((j: { samples: Sample[] }) => setSamples(j.samples))
      .catch(() => setSamples([]));
    fetch(`${BASE}examples/examples.json`)
      .then((r) => (r.ok ? r.json() : { examples: [] }))
      .then((j: { examples: Example[] }) => setExamples(j.examples))
      .catch(() => setExamples([]));
  }, []);
  const showcase = useMemo((): Listed[] => {
    // An example wins over a sample of the same file name.
    const named = new Set(examples.map((e) => e.file));
    return [
      ...samples
        .filter((s) => !named.has(s.file))
        .map((s): Listed => ({ group: s.group, note: `${s.credit}. ${s.licence}`, item: { id: `showcase:${s.file}`, name: s.file, source: { url: `${BASE}showcase/${s.file}` } } })),
      ...examples.map((e): Listed => ({ group: e.group, note: e.attribution || `${credit(e)}. ${e.licence}`, item: { id: `example:${e.file}`, name: e.file, source: { url: `${BASE}examples/${e.file}` } } })),
    ];
  }, [samples, examples]);
  // Known groups in their order, then any other, in the order they come.
  const groups = useMemo(() => [...new Set([...Object.keys(GROUPS), ...showcase.map((l) => l.group)])], [showcase]);
  const linked = useMemo((): Item[] => {
    if (!LINKED) return [];
    const name = decodeURIComponent(new URL(LINKED, location.href).pathname.split("/").pop() || "file");
    return [{ id: "linked", name, source: { url: LINKED } }];
  }, []);
  const items = useMemo(() => [...linked, ...own, ...showcase.map((l) => l.item)], [linked, own, showcase]);
  const current = items.find((i) => i.id === selected) ?? null;
  const note = showcase.find((l) => l.item.id === selected)?.note;

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const add = useCallback(
    (batch: Picked[]) => {
      if (!batch.length) return;
      // A file given again under the name of one already listed is the same
      // document with other bytes: it replaces it in place, and the viewer
      // keeps the zoom and scroll position where it can.
      const next = [...own];
      const added: Item[] = [];
      const shown: string[] = [];
      for (const p of batch) {
        const f = p.file;
        const tree = around(batch, p);
        const fields = { name: f.name, type: f.type, size: f.size, source: { blob: f }, ...(tree && { tree }) };
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
    void dropped(e.dataTransfer).then(add);
  };

  const entry = (item: Item, note?: string) => (
    <li key={item.id}>
      <button type="button" className={`demo-file${item.id === selected ? " is-selected" : ""}`} aria-current={item.id === selected} title={note} onClick={() => setSelected(item.id)}>
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
              if (e.target.files) add(picked(e.target.files));
              e.target.value = "";
            }}
          />
          <button type="button" className="demo-open" onClick={() => folder.current?.click()}>
            {t.folder}
          </button>
          <input
            ref={folder}
            type="file"
            {...{ webkitdirectory: "" }}
            hidden
            data-testid="folder-input"
            onChange={(e) => {
              if (e.target.files) add(picked(e.target.files));
              e.target.value = "";
            }}
          />
          {own.length > 0 && (
            <>
              <h2>{t.yours}</h2>
              <ul>{own.map((item) => entry(item))}</ul>
            </>
          )}
          {groups.map((group) => {
            const list = showcase.filter((l) => l.group === group);
            return (
              list.length > 0 && (
                <section key={group}>
                  <h2>{GROUPS[group]?.[locale] ?? group}</h2>
                  <ul>{list.map((l) => entry(l.item, l.note))}</ul>
                </section>
              )
            );
          })}
        </aside>
        <main className="demo-main">
          {current ? (
            <>
              <div className="demo-bar">
                <div className="demo-title">
                  <h1>{current.name}</h1>
                  <ExportImage session={session} name={current.name} />
                </div>
                {note && (
                  <a className="demo-credit" href={`${BASE}licenses/README.txt`} title={note}>
                    {note}
                  </a>
                )}
              </div>
              <div className="demo-frame">
                <ViewerBody key={current.id} file={current}>
                  {({ session }) => <SessionOut session={session} onSession={setSession} />}
                </ViewerBody>
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
