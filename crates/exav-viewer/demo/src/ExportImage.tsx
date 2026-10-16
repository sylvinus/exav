/**
 * "Export image": the session's pictures (`controllers.pictures`) saved as a
 * file, for any format that draws something. A button beside the file's name,
 * as it belongs to the host and not to the viewer, opening a dialog of
 * options. The region is the whole page or what the viewer shows when the
 * dialog opens (`controllers.viewport`). `window.exavDemo` is for the
 * browser tests.
 */
import { useEffect, useId, useRef, useState } from "react";

import { RasterError, type Raster, type RasterOptions, type RasterType, type Session } from "@exav/viewer";
import { useStore } from "@exav/viewer/react";

type Result = { url: string; name: string; info: string } | { error: string };

/** The session of the file on screen, or of the member of an archive that is open in it. */
function Export({ session, base }: { session: Session; base: string }) {
  const controllers = useStore(session.controllers);
  const opened = useStore(controllers?.archive)?.opened;
  const pictures = controllers?.pictures;
  const count = useStore(pictures)?.count ?? 0;
  const space = useStore(pictures)?.space;
  const [page, setPage] = useState(1);
  const [longEdge, setLongEdge] = useState(1600);
  const [region, setRegion] = useState<"whole" | "current">("whole");
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [open, setOpen] = useState(false);
  // Working out the viewport costs: it is followed only while the dialog shows "What I see".
  const viewport = useStore(open && region === "current" ? controllers?.viewport : undefined);
  const [type, setType] = useState<RasterType>("png");
  const [background, setBackground] = useState<"default" | "transparent" | "white">("default");
  const [fit, setFit] = useState<"contain" | "cover">("contain");
  const [lineweight, setLineweight] = useState<"screen" | "scaled">("screen");
  const [busy, setBusy] = useState<AbortController | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  useEffect(() => () => void (result && "url" in result && URL.revokeObjectURL(result.url)), [result]);
  // The page in view follows the viewer when the region is what it shows.
  const shown = region === "current" && viewport ? viewport.page : page;

  if (opened) return <Export session={opened.session} base={base} />;
  if (!pictures || count < 1) return null;

  const run = async () => {
    const abort = new AbortController();
    setBusy(abort);
    setResult(null);
    const options: RasterOptions & { type: RasterType } = {
      longEdge,
      fit,
      type,
      signal: abort.signal,
      ...(region === "current" && { region: "current" as const }),
      ...(background !== "default" && { background: background === "white" ? "#ffffff" : "transparent" }),
      ...(space === "drawing" && { lineweight }),
      ...(region === "current" && viewport?.layout !== undefined && { layout: viewport.layout }),
    };
    try {
      const { blob, ...raster } = await pictures.toBlob(shown, options);
      const info = describe(raster);
      setResult({ url: URL.createObjectURL(blob), name: `${base}-${shown}.${type === "jpeg" ? "jpg" : type}`, info });
    } catch (error) {
      setResult({ error: error instanceof RasterError ? `${error.code}: ${error.message}` : String(error) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <button type="button" className="demo-export-open" data-testid="export-open" onClick={() => {
          setOpen(true);
          dialog.current?.showModal();
        }}>
        Export image
      </button>
      <dialog
        ref={dialog}
        className="demo-export"
        aria-labelledby={titleId}
        onClose={() => setOpen(false)}
        onClick={(e) => e.target === e.currentTarget && dialog.current?.close()}
      >
        <div className="demo-export-head">
          <h2 id={titleId}>Export image</h2>
          <button type="button" className="demo-export-close" aria-label="Close" onClick={() => dialog.current?.close()}>
            &times;
          </button>
        </div>
        <div className="demo-export-body">
        <label>
          Page
          <select data-testid="export-page" value={shown} disabled={region === "current"} onChange={(e) => setPage(Number(e.target.value))}>
            {Array.from({ length: Math.min(count, 200) }, (_, i) => (
              <option key={i} value={i + 1}>
                {i + 1}
              </option>
            ))}
          </select>
        </label>
        <label>
          Long edge (px)
          <input data-testid="export-long-edge" type="number" min={1} max={16384} value={longEdge} onChange={(e) => setLongEdge(Number(e.target.value))} />
        </label>
        <label>
          Region
          <select data-testid="export-region" value={region} onChange={(e) => setRegion(e.target.value as "whole" | "current")}>
            <option value="whole">Whole page</option>
            <option value="current" disabled={!controllers?.viewport}>
              What I see
            </option>
          </select>
        </label>
        <label>
          Type
          <select data-testid="export-type" value={type} onChange={(e) => setType(e.target.value as RasterType)}>
            <option value="png">PNG</option>
            <option value="jpeg">JPEG</option>
            <option value="webp">WebP</option>
          </select>
        </label>
        <label>
          Background
          <select data-testid="export-background" value={background} onChange={(e) => setBackground(e.target.value as typeof background)}>
            <option value="default">Default</option>
            <option value="white">White</option>
            <option value="transparent">Transparent</option>
          </select>
        </label>
        <label>
          Fit
          <select data-testid="export-fit" value={fit} onChange={(e) => setFit(e.target.value as "contain" | "cover")}>
            <option value="contain">Contain</option>
            <option value="cover">Cover</option>
          </select>
        </label>
        {space === "drawing" && (
          <label>
            Line weights
            <select data-testid="export-lineweight" value={lineweight} onChange={(e) => setLineweight(e.target.value as "screen" | "scaled")}>
              <option value="screen">As on screen</option>
              <option value="scaled">Scaled to the picture</option>
            </select>
          </label>
        )}
        {busy ? (
          <button type="button" data-testid="export-cancel" onClick={() => busy.abort()}>
            Cancel
          </button>
        ) : (
          <button type="button" data-testid="export-run" onClick={() => void run()}>
            Export
          </button>
        )}
        {result &&
          ("error" in result ? (
            <p role="alert" data-testid="export-error">
              {result.error}
            </p>
          ) : (
            <p>
              <a data-testid="export-result" href={result.url} download={result.name}>
                {result.name}
              </a>{" "}
              <span data-testid="export-info">{result.info}</span>
            </p>
          ))}
        </div>
      </dialog>
    </>
  );
}

function describe(r: Omit<Raster, "bitmap">): string {
  const region = r.region ? ` of ${JSON.stringify(r.region, (_, v) => (typeof v === "number" ? Math.round(v * 1000) / 1000 : v))}` : "";
  return `${r.width} x ${r.height} px, page ${r.page}${r.layout !== undefined ? ` (${r.layout})` : ""}${region}`;
}

export function ExportImage({ session, name }: { session: Session | null; name: string }) {
  useEffect(() => {
    Object.assign(window, { exavDemo: { session: () => session } });
  }, [session]);
  return session ? <Export session={session} base={name.replace(/\.[^.]*$/, "") || "export"} /> : null;
}
