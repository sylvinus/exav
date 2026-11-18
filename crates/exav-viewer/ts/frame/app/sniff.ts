/**
 * The frame's answer to a `sniff`: what a file is, by the rule of
 * `detectFile`, exav's detection of its first bytes against its name and
 * type. The bytes are the host's, or read here from the address the frame is
 * given the file at.
 */
import { checkSniffBytes, createDetector, type Officer, type Sniffer } from "../../core/detect.js";
import { createSourceReader } from "../../core/source.js";
import type { BuiltinFormat } from "../../core/types.js";
import { frameMatcher, type SniffMessage } from "../protocol.js";

/**
 * Among the formats the host opens and, with `shipped`, those this frame was
 * published for. A ZIP is told by its members with `officer`; a file given by
 * its first bytes has its end only if they are all of it.
 */
export async function sniffed(m: SniffMessage, sniffer: Sniffer, shipped: ReadonlySet<string> | null, officer?: Officer): Promise<BuiltinFormat | null> {
  const formats = shipped ? m.formats.filter((f) => shipped.has(f)) : m.formats;
  const detector = createDetector(
    formats.map((id) => ({ id, match: frameMatcher(id) })),
    sniffer,
    undefined,
    checkSniffBytes(m.sniff.bytes),
    undefined,
    officer,
  );
  const said = (id: string | null) => formats.find((f) => f === id) ?? null;
  try {
    if (m.source.kind === "head") return said(await detector.detectFile(m.file, new Uint8Array(m.source.head), m.source.size, undefined, async () => null));
    const reader = createSourceReader({ url: m.source.url }, new AbortController().signal);
    try {
      const head = await reader.head(detector.headBytes);
      return said(head ? await detector.detectFile(m.file, head.bytes, head.size, undefined, (n) => reader.tail(n)) : detector.detect(m.file));
    } finally {
      reader.dispose();
    }
  } catch (error) {
    console.warn("frame: the first bytes could not be read, the name and the type decide", error);
    return said(detector.detect(m.file));
  }
}
