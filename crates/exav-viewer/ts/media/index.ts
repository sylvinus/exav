/**
 * `@exav/viewer/media`: video and audio, on the browser's own elements. Only
 * the formats browsers play are claimed: a format the platform cannot decode
 * would be a black rectangle where a download used to be. A file the device
 * still cannot play (HEVC outside Safari, say) is reported as such.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin, Renderer } from "../core/types.js";

const player = (kind: "video" | "audio"): Renderer<Record<string, never>> => ({
  async mount(host, ctx) {
    const url = await ctx.source.url();
    const root = document.createElement("div");
    root.className = `exv-media exv-media-${kind}`;
    const el = document.createElement(kind);
    el.controls = true;
    el.preload = "metadata";
    if (el instanceof HTMLVideoElement) el.playsInline = true;
    el.onerror = () => ctx.status({ phase: "error", error: { code: "media", cause: el.error } });
    el.src = url;
    root.append(el);
    host.append(root);
    ctx.status({ phase: "ready" });
    return {
      controllers: {},
      destroy() {
        el.pause();
        el.removeAttribute("src");
        el.load();
        root.remove();
      },
    };
  },
});

export function video(): FormatPlugin<Record<string, never>> {
  return { id: "video", match: MATCHERS.video, capabilities: [], options: {}, load: async () => player("video") };
}

export function audio(): FormatPlugin<Record<string, never>> {
  return { id: "audio", match: MATCHERS.audio, capabilities: [], options: {}, load: async () => player("audio") };
}
