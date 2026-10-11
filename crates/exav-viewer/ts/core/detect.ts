import { SIGNATURES, UNKNOWN_TYPES } from "./formats.js";
import type { DetectionTable, Detector, FileInfo, FormatId, FormatMatcher, Signature } from "./types.js";

/** Bytes read from the head of a file to sniff it. */
export const HEAD_BYTES = 512;

function matches(head: Uint8Array, at: number, run: readonly number[]): boolean {
  if (at + run.length > head.length) return false;
  return run.every((byte, i) => head[at + i] === byte);
}

/** The content type the first bytes prove, or "" when they prove nothing. */
export function sniff(head: Uint8Array, signatures: readonly Signature[] = SIGNATURES): string {
  for (const s of signatures) {
    if (!matches(head, s.offset ?? 0, s.prefix)) continue;
    if (s.also && !matches(head, s.alsoOffset ?? 0, s.also)) continue;
    return s.type;
  }
  return "";
}

interface Entry {
  id: FormatId;
  match: FormatMatcher;
}

/**
 * Detection over these plugins' matchers, in their order. The steps are on
 * `FormatMatcher`.
 */
export function createDetector(entries: readonly Entry[]): Detector {
  const unknown = new Set(UNKNOWN_TYPES);
  const containers = new Set(entries.flatMap((e) => e.match.containerTypes ?? []));
  const signatures = [...SIGNATURES, ...entries.flatMap((e) => e.match.signatures ?? [])];

  const detect = (info: Pick<FileInfo, "type" | "path" | "name" | "kind">): FormatId | null => {
    if (info.kind === "link") return null;
    const type = (info.type ?? "").toLowerCase().split(";")[0]!.trim();
    const path = (info.path ?? info.name ?? "").toLowerCase();

    for (const e of entries) if (e.match.types?.includes(type)) return e.id;

    for (const e of entries) {
      const overrides = e.match.extensionOverrides ?? [];
      const allowed =
        unknown.has(type) ||
        (containers.has(type) && overrides.includes("container")) ||
        overrides.includes(type);
      if (allowed && e.match.extensions?.some((ext) => path.endsWith(ext))) return e.id;
    }

    for (const e of entries) if (e.match.containerTypes?.includes(type)) return e.id;
    return null;
  };

  return {
    detect,
    sniff: (head) => sniff(head, signatures),
    detectBytes(name, bytes) {
      const head = bytes.subarray(0, HEAD_BYTES);
      let type = sniff(head, signatures);
      // A sniffed type the bytes do not back, as its own plugin judges it.
      const claimant = entries.find((e) => e.match.types?.includes(type));
      if (claimant?.match.confirmSniff && !claimant.match.confirmSniff(head, name)) type = "";
      return detect({ type, path: name, name });
    },
    table(): DetectionTable {
      return {
        formats: entries.map((e) => {
          const { confirmSniff: _, ...matcher } = e.match;
          return { id: e.id, matcher };
        }),
        signatures,
        unknownTypes: UNKNOWN_TYPES,
      };
    },
  };
}
