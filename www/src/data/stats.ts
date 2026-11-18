// The figures of the Stats page: one <version>.json per release and
// bench.json, all written by scripts/stats.py. A file without the fields
// below fails the build.

export const GROUPS = ['code', 'tests', 'tools', 'vendored', 'dependencies'] as const;
type Group = (typeof GROUPS)[number];

export interface Release {
  version: string;
  date: string;
  rust_lines: Record<Group, number>;
  unsafe: Record<Exclude<Group, 'dependencies'>, number>;
  /** The third-party crates each binary is built from; null when the
   * release has no such binary. */
  built_from: Record<string, { crates: number; direct: number; lines: number; unsafe: number; unsafe_crates: number } | null>;
  dependencies: {
    all: number;
    lockfile: number;
    viewer_npm: { required: number; optional: number } | null;
  };
  /** `from`: a release older than the registry, counted against the
   * registry of that release. */
  formats: { registry: number; extractor: number; viewer: number; from?: string } | null;
  tests: { rust: number; js: number; e2e: number; fuzz_targets: number };
  sizes: {
    binaries: Record<string, Record<string, number>>;
    wasi: number | null;
    npm: Record<string, { tarball: number; unpacked: number | null; wasm: Record<string, number> }>;
  };
}

/** A run that did not get to the end of the files has no figures: `failed`
 * says how far it went, and `estimate` scales its time to all the bytes. */
export type Engine = {
  name: 'clamscan' | 'exav';
  version: string;
  start: number;
  build_exavdb?: number;
  start_exavdb?: number;
  /** Peak resident bytes with the signatures loaded and one small file
   * scanned, from the raw signatures and from the .exavdb. */
  memory_loaded?: number;
  memory_exavdb?: number;
} & (
  | { scan: number; cpu: number; memory_scan: number; found: number; failed?: undefined; estimate?: undefined }
  | {
      failed: { signal: string; files: number; bytes?: number };
      estimate?: { scan: number; cpu?: number };
      scan?: undefined;
      cpu?: undefined;
      memory_scan?: undefined;
      found?: undefined;
    }
);

export interface Bench {
  date: string;
  machine: { cpu: string; arch: string; cores: number; memory: number; kernel: string };
  signatures: Record<string, { version: number; signatures: number }>;
  dataset: { files: number; bytes: number; malware: number };
  runs: number;
  engines: Engine[];
}

const files = import.meta.glob<{ default: unknown }>('./stats/*.json', { eager: true });

function need(value: unknown, keys: string[], file: string): void {
  for (const key of keys) {
    let v: unknown = value;
    for (const part of key.split('.')) v = (v as Record<string, unknown> | null)?.[part];
    if (v === undefined) throw new Error(`${file}: no ${key}`);
  }
}

const byVersion = (a: string, b: string) => {
  const [x, y] = [a, b].map((v) => v.split('.').map(Number));
  return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
};

export const releases: Release[] = Object.entries(files)
  .filter(([path]) => /\/\d+\.\d+\.\d+\.json$/.test(path))
  .map(([path, mod]) => {
    need(mod.default, ['version', 'date', 'rust_lines', 'unsafe', 'built_from.exav', 'dependencies', 'formats', 'tests', 'sizes.binaries', 'sizes.npm'], path);
    return mod.default as Release;
  })
  .sort((a, b) => byVersion(a.version, b.version));

const benchFile = Object.entries(files).find(([path]) => path.endsWith('/bench.json'));
if (!benchFile) throw new Error('stats: no bench.json');
need(benchFile[1].default, ['date', 'machine', 'signatures', 'dataset', 'runs', 'engines'], benchFile[0]);
export const bench = benchFile[1].default as Bench;

const clam = bench.engines.find((e) => e.name === 'clamscan');
if (!clam || clam.failed) throw new Error('bench.json: no clamscan figures to compare with');
export const clamscan = clam;
export const exav = bench.engines.filter((e) => e.name === 'exav').sort((a, b) => byVersion(a.version, b.version));
export const latest = releases[releases.length - 1];

const en = new Intl.NumberFormat('en-US');
export const count = (n: number) => en.format(n);

/** 236188 as 236k, 1234567 as 1.2M: a chart's labels. */
export function compact(n: number): string {
  if (n >= 1e6) return `${+(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M`;
  if (n >= 1e4) return `${Math.round(n / 1e3)}k`;
  if (n >= 1e3) return `${+(n / 1e3).toFixed(1)}k`;
  return `${+n.toFixed(n < 10 ? 1 : 0)}`;
}

export const size = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB` : `${(n / 1e6).toFixed(1)} MB`);
export const seconds = (s: number) => `${s.toFixed(s < 100 ? 1 : 0)} s`;
export const times = (x: number) => `${x.toFixed(1)}×`;
