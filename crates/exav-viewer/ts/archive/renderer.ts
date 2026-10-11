import { writable } from "../core/store.js";
import type { ArchiveController, ArchiveMember, Renderer, Session, ViewerFile } from "../core/types.js";
import type { ArchiveOptions } from "./index.js";
import { decompressedName, STREAM_MEMBER } from "./names.js";
import { isZip, openRanged, type RangedArchive } from "./ranged.js";

/**
 * What one archive may cost. The library enforces them: an archive is
 * untrusted, and a few kilobytes can decompress to a terabyte. These are far
 * above any real delivery and far below a bomb.
 */
const DEFAULTS = { maxExtractedBytes: 512 * 1024 * 1024, maxMembers: 5_000, maxCompressionRatio: 200 };

type State = ArchiveController extends { get(): infer S } ? S : never;

export const renderer: Renderer<ArchiveOptions> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    // An option given as undefined keeps its default: no limit is lifted by
    // accident.
    const o = ctx.options;
    const limits = {
      maxExtractedBytes: o.maxExtractedBytes ?? DEFAULTS.maxExtractedBytes,
      maxMembers: o.maxMembers ?? DEFAULTS.maxMembers,
      maxCompressionRatio: o.maxCompressionRatio ?? DEFAULTS.maxCompressionRatio,
    };
    const list = async (archive: RangedArchive): Promise<ArchiveMember[]> => {
      try {
        if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
        // Directories are left out: the tree is in the names.
        return (await archive.list())
          .filter((m) => !m.name.endsWith("/"))
          .map((m) => ({ index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted }));
      } catch (error) {
        // The archive and its worker are closed whatever went wrong.
        void archive.close();
        throw error;
      }
    };
    // A ZIP read by ranges is read where its central directory and the
    // members opened are. Other formats are walked from their start, and so
    // is a ZIP that could not be read by ranges: read whole, as a Blob, which
    // is read a piece at a time in a worker.
    const given = ctx.file.source;
    const ranges = given && "ranges" in given ? given.ranges : null;
    let chosen: RangedArchive | null = null;
    let members: ArchiveMember[] = [];
    if (ranges && isZip(await ranges.read(0, Math.min(4, ranges.size), ctx.signal))) {
      try {
        chosen = await openRanged(ranges, limits, ctx.signal);
        members = await list(chosen);
      } catch (error) {
        if (ctx.signal.aborted) throw error;
        console.warn("archive: could not be read by ranges, read whole instead", error);
        chosen = null;
      }
    }
    if (!chosen) {
      const { Archive } = await import("@exav/unpack-wasm");
      chosen = await Archive.open(await ctx.source.blob(), limits);
      members = await list(chosen);
      // A compressed stream holds one file, which the library names after the
      // compression ("gzip-content"): it takes its own name back from the
      // stream's. A tarball (.tar.gz, .tgz...) is shown as the tar inside,
      // as an archive tool shows it, rather than as a list of one; any other
      // stream is decompressed only when its file is opened.
      const only = members.length === 1 ? members[0]! : null;
      if (only && STREAM_MEMBER.test(only.name)) {
        const name = decompressedName(ctx.file.name, only.name);
        members = [{ ...only, name }];
        if (/\.tar$/i.test(name)) {
          try {
            const entry = await chosen.extract(only.index);
            if (!entry.unsupported && ctx.detector.detectBytes(name, entry.bytes) === "archive") {
              const inner = await Archive.open(entry.bytes, limits);
              const innerMembers = await list(inner);
              void chosen.close();
              chosen = inner;
              members = innerMembers;
            }
          } catch (error) {
            if (ctx.signal.aborted) {
              void chosen.close();
              throw error;
            }
            // The stream's own list stands: its one file, opened on its own.
            console.warn("archive: the tar inside could not be read", error);
          }
        }
      }
    }
    const archive = chosen;

    const surface = document.createElement("div");
    surface.className = "exv-archive-member";
    host.append(surface);

    const state = writable<State>({ members, opening: null, opened: null, refused: null });
    let nested: Session | null = null;
    let destroyed = false;

    const back = () => {
      nested?.destroy();
      nested = null;
      state.update((s) => ({ ...s, opened: null }));
    };

    const controller: ArchiveController = {
      ...state,
      async open(index) {
        const member = members.find((m) => m.index === index);
        if (!member || state.get().opening !== null) return;
        back();
        state.update((s) => ({ ...s, opening: index, refused: null }));
        try {
          const entry = await archive.extract(index);
          if (destroyed) return;
          if (entry.unsupported) {
            console.warn(`archive: ${member.name}: ${entry.unsupported}`);
            state.update((s) => ({ ...s, refused: { key: entry.encrypted ? "archive_member_encrypted" : "archive_member_unsupported" } }));
            return;
          }
          // The member's listed name: the library's, or the one a compressed
          // stream's member took back from the stream above.
          const format = ctx.detector.detectBytes(member.name, entry.bytes);
          if (!format) {
            state.update((s) => ({ ...s, refused: { key: "archive_no_reader" } }));
            return;
          }
          const file: ViewerFile = {
            id: `${ctx.file.id}:${index}`,
            name: member.name,
            path: member.name,
            format,
            source: { bytes: entry.bytes },
          };
          const session = ctx.mountNested(surface, file);
          nested = session;
          state.update((s) => ({ ...s, opened: { member, file, session } }));
        } catch (error) {
          console.warn("archive: could not extract", error);
          if (!destroyed) state.update((s) => ({ ...s, refused: { key: "archive_failed_member" } }));
        } finally {
          if (!destroyed) state.update((s) => ({ ...s, opening: null }));
        }
      },
      back,
    };

    ctx.status({ phase: "ready" });
    return {
      controllers: { archive: controller },
      resize: () => nested?.resize(),
      destroy() {
        destroyed = true;
        nested?.destroy();
        nested = null;
        void archive.close();
        surface.remove();
      },
    };
  },
};
