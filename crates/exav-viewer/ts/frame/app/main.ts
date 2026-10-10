/**
 * The frame app: one file, in a sandboxed iframe, driven by the host page
 * over a MessagePort (`../protocol.ts`). Built into `dist/frame/app/` by
 * `scripts/build-frame.mjs`, with every worker as a classic script and every
 * engine's files beside it, so that nothing is fetched from another origin.
 */
import { archive } from "../../archive/index.js";
// The plugins alone: `cad/index.ts` also re-exports the engine.
import { dwg, dxf } from "../../cad/plugin.js";
import { BUILTIN_ORDER } from "../../core/formats.js";
import type { BuiltinFormat, Controllers, FormatPlugin, Session, Status } from "../../core/types.js";
import { createViewer } from "../../core/viewer.js";
import { ifc } from "../../ifc/index.js";
import { image } from "../../image/index.js";
import { audio, video } from "../../media/index.js";
import { stl } from "../../model/index.js";
import { csv, docx, pptx, xlsx } from "../../office/index.js";
import { pdf } from "../../pdf/index.js";
import type { FileSource } from "../../core/types.js";
import { readPolicy } from "../policy.js";
import {
  checkBytes,
  checkCommand,
  checkOpen,
  CONTROLLER_KEYS,
  HELLO,
  PROTOCOL,
  type ArchiveSnapshot,
  type CommandMessage,
  type ControllerKey,
  type ErrorCode,
  type FrameMessage,
  type FrameOptions,
  type OpenSource,
  type Snapshots,
  type Statics,
  type StatusSnapshot,
} from "../protocol.js";
import { portRanges, type PortRanges } from "./ranges.js";
import { installWorkers } from "./workers.js";

const base = new URL("./", import.meta.url);
installWorkers(base);

let port: MessagePort | null = null;
const post = (m: FrameMessage) => port?.postMessage(m);

// Engines open links with `window.open`, which the sandbox refuses: the host
// is asked instead, and decides.
window.open = (url?: string | URL) => {
  if (url !== undefined) post({ type: "link", url: String(url) });
  return null;
};

// Engines copy with `navigator.clipboard.writeText`, which Chromium refuses
// under the frame's policy (the spreadsheet's selected cells on Ctrl+C): the
// text goes through the copy the user's key press starts instead, as a
// selection's would.
if (navigator.clipboard) {
  Object.defineProperty(navigator.clipboard, "writeText", {
    value: (text: string) =>
      new Promise<void>((resolve, reject) => {
        const onCopy = (e: ClipboardEvent) => {
          e.clipboardData?.setData("text/plain", text);
          e.preventDefault();
        };
        document.addEventListener("copy", onCopy);
        let copied = false;
        try {
          copied = document.execCommand("copy");
        } finally {
          document.removeEventListener("copy", onCopy);
        }
        if (copied) resolve();
        else reject(new DOMException("the browser refused the copy", "NotAllowedError"));
      }),
  });
}

function plugins(formats: readonly BuiltinFormat[], o: FrameOptions, source: OpenSource): FormatPlugin<any>[] {
  // The Office engines paint in a worker: their inline module workers cannot start here.
  const office = { mode: "worker" as const };
  const make: Record<BuiltinFormat, () => FormatPlugin<any>> = {
    pdf: () => pdf(o.pdf),
    // An image given by URL is shown without CORS: its pixels stay unreadable here.
    image: () => image({ ...o.image, wasmDecoders: true, ...(source.kind === "url" && { crossOrigin: null }) }),
    dwg: () => dwg({ ...o.cad, fontsUrl: new URL("./fonts/", base).href }),
    dxf: () => dxf({ ...o.cad, fontsUrl: new URL("./fonts/", base).href }),
    video,
    audio,
    ifc: () => ifc(o.ifc),
    stl: () => stl(o.model),
    docx: () => docx(office),
    xlsx: () => xlsx(office),
    pptx: () => pptx(office),
    csv: () => csv(office),
    archive: () => archive(o.archive),
  };
  return formats.map((f) => make[f]());
}

function statusOf(s: Status): StatusSnapshot {
  // The frame's plugins are the package's own: their codes are the built-in ones.
  // A plugin's `label` and an error's `message` stay here, as text from the frame is not shown by the host.
  switch (s.phase) {
    case "error":
      return { phase: "error", code: s.error.code as ErrorCode };
    case "loading":
    case "converting":
      return { phase: s.phase, ...(s.progress !== undefined && { progress: s.progress }) };
    default:
      return s;
  }
}

// ── Sessions: the file's, and each archive member's ──────────────────────────

interface Relay {
  id: number;
  session: Session;
  stop: () => void;
}

const sessions = new Map<number, Session>();
/** The member each archive session shows, by the archive session's number. */
const members = new Map<number, Relay>();
let nextSession = 1;

/** Stops following a member, and the members it showed in turn. */
function drop(relay: Relay) {
  relay.stop();
  sessions.delete(relay.id);
  const inner = members.get(relay.id);
  members.delete(relay.id);
  if (inner) drop(inner);
}

/** Plain data only: whatever else a store holds stays here. */
function snapshot<K extends ControllerKey>(key: K, value: unknown, from: number): Snapshots[K] {
  if (key !== "archive") return value as Snapshots[K];
  const a = value as ReturnType<NonNullable<Controllers["archive"]>["get"]>;
  let relay = members.get(from);
  if (relay && relay.session !== a.opened?.session) {
    drop(relay);
    relay = undefined;
  }
  let opened: ArchiveSnapshot["opened"] = null;
  if (a.opened) {
    if (!relay) {
      const r: Relay = { id: nextSession++, session: a.opened.session, stop: () => {} };
      members.set(from, r);
      // Once this snapshot is posted: the host learns the number from it.
      queueMicrotask(() => members.get(from) === r && start(r));
      relay = r;
    }
    const m = a.opened.member;
    opened = {
      member: { index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted },
      name: a.opened.file.name,
      format: a.opened.session.format,
      session: relay.id,
    };
  }
  const out: ArchiveSnapshot = {
    members: a.members.map((m) => ({ index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted })),
    opening: a.opening,
    opened,
    refused: a.refused,
  };
  return out as Snapshots[K];
}

function start(relay: Relay) {
  const { id, session } = relay;
  sessions.set(id, session);
  let stores: (() => void)[] = [];
  const wire = (c: Controllers) => {
    for (const stop of stores) stop();
    stores = [];
    const values: Partial<Snapshots> = {};
    for (const key of CONTROLLER_KEYS) {
      const store = c[key];
      if (!store) continue;
      (values as Record<string, unknown>)[key] = snapshot(key, store.get(), id);
      stores.push(store.subscribe((v) => post({ type: "state", session: id, key, value: snapshot(key, v, id) })));
    }
    const statics: Statics = {
      ...(c.pages && { pages: { goTo: !!c.pages.goTo, step: !!c.pages.next && !!c.pages.prev } }),
      ...(c.ground && { ground: { ...c.ground.colors } }),
    };
    post({ type: "controllers", session: id, values, statics });
  };
  const stopStatus = session.status.subscribe((s) => post({ type: "status", session: id, status: statusOf(s) }));
  const stopControllers = session.controllers.subscribe(wire);
  post({ type: "status", session: id, status: statusOf(session.status.get()) });
  wire(session.controllers.get());
  relay.stop = () => {
    stopStatus();
    stopControllers();
    for (const stop of stores) stop();
  };
}

// ── Commands from the host ───────────────────────────────────────────────────

const isInt = (v: unknown): v is number => Number.isSafeInteger(v);
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

async function run(m: CommandMessage): Promise<void> {
  const c = sessions.get(m.session)?.controllers.get();
  if (!c) return;
  const [a, b] = m.args;
  switch (`${m.target}.${m.action}`) {
    case "pages.goTo":
      if (isInt(a)) c.pages?.goTo?.(a);
      return;
    case "pages.next":
      return c.pages?.next?.();
    case "pages.prev":
      return c.pages?.prev?.();
    case "zoom.setScale": {
      const anchor = b as { x?: unknown; y?: unknown } | undefined;
      if (!isNum(a) || a <= 0) return;
      if (anchor === undefined) c.zoom?.setScale(a);
      else if (isNum(anchor?.x) && isNum(anchor?.y)) c.zoom?.setScale(a, { x: anchor.x, y: anchor.y });
      return;
    }
    case "zoom.fit":
      return c.zoom?.fit();
    case "drag.choose":
      if (a === "pan" || a === "select") c.drag?.choose(a);
      return;
    case "outline.goTo": {
      const entry = isInt(a) ? c.outline?.get()[a] : undefined;
      if (entry) c.outline?.goTo(entry);
      return;
    }
    case "layers.setVisible":
      if (typeof a === "string" && typeof b === "boolean") c.layers?.setVisible(a, b);
      return;
    case "layers.setAll":
      if (typeof a === "boolean") c.layers?.setAll(a);
      return;
    case "layouts.select":
      if (typeof a === "string") await c.layouts?.select(a);
      return;
    case "ground.set":
      if (a === "light" || a === "dark") c.ground?.set(a);
      return;
    case "archive.open":
      if (isInt(a)) await c.archive?.open(a);
      return;
    case "archive.back":
      return c.archive?.back();
  }
}

// ── The host ─────────────────────────────────────────────────────────────────

let opened = false;
let ranges: PortRanges | null = null;

function receive(data: unknown) {
  if (!opened) {
    const open = checkOpen(data, BUILTIN_ORDER);
    if (!open) return;
    opened = true;
    const viewer = createViewer({ plugins: plugins(open.formats, open.options, open.source), assetBase: new URL("./exav-viewer/", base).href });
    const host = document.getElementById("root")!;
    const { name, type, path, format } = open.file;
    const s = open.source;
    let source: FileSource;
    if (s.kind === "ranges") {
      ranges = portRanges(post, s.size, new Uint8Array(s.head));
      source = { ranges };
    } else source = s.kind === "url" ? { url: s.url } : { blob: s.blob };
    const session = viewer.mount(host, { id: "file", name, type, path, ...(format && { format }), source });
    start({ id: 0, session, stop: () => {} });
    addEventListener("resize", () => session.resize());
    return;
  }
  const bytes = checkBytes(data);
  if (bytes) return ranges?.receive(bytes);
  const command = checkCommand(data);
  if (!command) return;
  void run(command)
    .then(
      () => true,
      (error) => (console.warn("frame: a command failed", error), false),
    )
    .then((ok) => post({ type: "done", call: command.call, ok }));
}

// The port arrives once, from the page that embeds this frame. Any later
// window message is ignored.
addEventListener("message", function hello(e: MessageEvent) {
  const p = e.ports[0];
  if (e.source !== parent || parent === window || (e.data as { type?: unknown } | null)?.type !== HELLO || !p) return;
  removeEventListener("message", hello);
  port = p;
  port.onmessage = (m) => receive(m.data);
  // The policy in this page, for the host to check against its own origins.
  // One served as a header alone is not readable here.
  const csp = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.getAttribute("content");
  post({ type: "ready", protocol: PROTOCOL, policy: csp ? readPolicy(csp) : null });
});
