/**
 * The manifest `@exav/viewer/vite` (or the `exav-viewer-assets` command)
 * writes at `<assetBase>manifest.json`: where each copied asset lives, under
 * a directory named after the version it came from, so a host can serve the
 * whole of `assetBase` as immutable.
 */
export interface AssetManifest {
  /** Directories, relative to `assetBase`, ending in "/". */
  dirs: {
    pdfjs?: string;
  };
  /** Single files, relative to `assetBase`, by name. */
  files: Record<string, string>;
  /** Every file copied, relative to `assetBase`, for prefetching. */
  all: readonly string[];
}

const manifests = new Map<string, Promise<AssetManifest>>();

export function baseUrl(assetBase: string): string {
  return assetBase.endsWith("/") ? assetBase : `${assetBase}/`;
}

/** The manifest, fetched once per `assetBase`; a failed fetch is tried again next time. */
export function loadManifest(assetBase: string): Promise<AssetManifest> {
  const base = baseUrl(assetBase);
  let m = manifests.get(base);
  if (!m) {
    m = fetch(`${base}manifest.json`).then((r) => {
      if (!r.ok) throw new Error(`no asset manifest at ${base}manifest.json (HTTP ${r.status}): copy the assets with @exav/viewer/vite`);
      return r.json() as Promise<AssetManifest>;
    });
    manifests.set(base, m);
    m.catch(() => manifests.delete(base));
  }
  return m;
}
