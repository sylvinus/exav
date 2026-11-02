/**
 * `@exav/viewer/media`: video and audio, on the browser's own elements. Only
 * the formats browsers play are claimed: a format the platform cannot decode
 * would be a black rectangle where a download used to be. A file the device
 * still cannot play (HEVC outside Safari, say) is reported as such.
 */
import { MATCHERS } from "../core/formats.js";
import { planRect, RasterError, throwIfAborted } from "../core/pictures.js";
import { bitmapOf, createCanvas, createPictures, release } from "../core/raster.js";
import { writable } from "../core/store.js";
import type { FormatPlugin, MediaController, MediaState, Raster, RasterOptions, Renderer } from "../core/types.js";

export interface MediaOptions {
  /**
   * "native" (default): the browser's player controls. "none": none, for a
   * host that draws its own from the `media` controller; a click on a video
   * plays or pauses it.
   */
  controls?: "native" | "none";
}

/** The end of the buffered range that holds `t`, or `t` when none does. */
function bufferedAt(el: HTMLMediaElement, t: number): number {
  const b = el.buffered;
  for (let i = 0; i < b.length; i++) if (b.start(i) <= t && t <= b.end(i)) return b.end(i);
  return t;
}

/** The element's state, every number a number the protocol takes. */
export function stateOf(el: HTMLMediaElement, kind: "video" | "audio", blocked: boolean, waiting: boolean): MediaState {
  const time = Number.isFinite(el.currentTime) && el.currentTime > 0 ? el.currentTime : 0;
  const duration = el.duration === Infinity ? Infinity : Number.isFinite(el.duration) && el.duration > 0 ? el.duration : 0;
  return {
    kind,
    paused: el.paused,
    ended: el.ended,
    currentTime: time,
    duration,
    buffered: bufferedAt(el, time),
    volume: Math.min(1, Math.max(0, el.volume)),
    muted: el.muted,
    rate: el.playbackRate > 0 && el.playbackRate <= 16 ? el.playbackRate : 1,
    waiting,
    blocked,
  };
}

/** How long a frame decoded but not yet presented is waited for. */
const PRESENT_TRIES = 20;
const PRESENT_WAIT_MS = 50;

/**
 * The frame `el` shows now, as a picture. The size is the frame's own unless
 * one is asked for; a width and a height of another shape draw it whole
 * (`fit` "contain", default) or filled ("cover"), never stretched, on
 * `background` (transparent by default). A frame has no region. A video the
 * page may not read (another origin that sends no CORS headers, which taints
 * the canvas, or a URL given to the sandboxed frame, whose origin is opaque)
 * is "unsupported", not a blank picture.
 */
export async function frameOf(el: Pick<HTMLVideoElement, "videoWidth" | "videoHeight" | "readyState"> & CanvasImageSource, page: number, options: RasterOptions): Promise<Raster> {
  if (options.region !== undefined) throw new RasterError("invalid", "a video frame has no region");
  const { videoWidth: width, videoHeight: height } = el;
  if (el.readyState < 2 || !(width > 0 && height > 0)) throw new RasterError("failed", "the video has no frame to draw yet");
  const plan = planRect(options, { x: 0, y: 0, width, height }, { x: 1, y: 1 }, null, "transparent");
  const { canvas, ctx } = createCanvas(plan.width, plan.height);
  try {
    ctx.imageSmoothingQuality = "high";
    const r = plan.region;
    const sx = Math.max(0, r.x);
    const sy = Math.max(0, r.y);
    const sw = Math.min(width, r.x + r.width) - sx;
    const sh = Math.min(height, r.y + r.height) - sy;
    const kx = plan.width / r.width;
    const ky = plan.height / r.height;
    const [dx, dy, dw, dh] = [(sx - r.x) * kx, (sy - r.y) * ky, sw * kx, sh * ky];
    for (let attempt = 0; ; attempt++) {
      ctx.clearRect(0, 0, plan.width, plan.height);
      ctx.drawImage(el, sx, sy, sw, sh, dx, dy, dw, dh);
      let alpha: number;
      try {
        // A tainted canvas draws, and refuses to be read: ask for one pixel.
        alpha = ctx.getImageData(Math.min(plan.width - 1, Math.floor(dx + dw / 2)), Math.min(plan.height - 1, Math.floor(dy + dh / 2)), 1, 1).data[3]!;
      } catch {
        throw new RasterError("unsupported", "this video cannot be read as a picture: it comes from another origin without CORS headers (or by URL to a sandboxed frame)");
      }
      if (alpha > 0) break;
      // A frame decoded but not yet presented draws nothing, for a moment.
      if (attempt >= PRESENT_TRIES) throw new RasterError("failed", "the video has not presented a frame to draw");
      await new Promise((resolve) => setTimeout(resolve, PRESENT_WAIT_MS));
      throwIfAborted(options.signal);
    }
    if (plan.background !== "transparent") {
      ctx.globalCompositeOperation = "destination-over";
      ctx.fillStyle = plan.background;
      ctx.fillRect(0, 0, plan.width, plan.height);
    }
    return { bitmap: await bitmapOf(canvas), width: plan.width, height: plan.height, page, space: "frame" };
  } catch (error) {
    release(canvas);
    throw error;
  }
}

const EVENTS = ["play", "pause", "playing", "ended", "timeupdate", "durationchange", "loadedmetadata", "volumechange", "ratechange", "progress", "seeked", "emptied"];

const player = (kind: "video" | "audio"): Renderer<MediaOptions> => ({
  async mount(host, ctx) {
    const url = await ctx.source.url();
    const native = ctx.options.controls !== "none";
    const root = document.createElement("div");
    root.className = `exav-viewer-media exav-viewer-media-${kind}`;
    const el = document.createElement(kind);
    el.controls = native;
    el.preload = "metadata";
    if (el instanceof HTMLVideoElement) el.playsInline = true;
    let blocked = false;
    let waiting = false;
    const state = writable<MediaState>(stateOf(el, kind, blocked, waiting));
    const sync = () => state.set(stateOf(el, kind, blocked, waiting));
    const onWaiting = () => {
      waiting = true;
      sync();
    };
    const onFlowing = () => {
      waiting = false;
      sync();
    };
    for (const e of EVENTS) el.addEventListener(e, sync);
    el.addEventListener("waiting", onWaiting);
    el.addEventListener("playing", onFlowing);
    el.addEventListener("canplay", onFlowing);
    el.onerror = () => ctx.status({ phase: "error", error: { code: "media", cause: el.error } });

    const play = async () => {
      try {
        await el.play();
        blocked = false;
      } catch (error) {
        // Refused for want of a click on the page, or the file cannot play
        // (reported by `onerror`).
        if (error instanceof DOMException && error.name === "NotAllowedError") blocked = true;
      }
      sync();
    };
    // Without the browser's controls, a click on the picture is the player's.
    const toggle = () => void (el.paused || el.ended ? play() : el.pause());
    if (!native) root.addEventListener("click", toggle);

    el.src = url;
    root.append(el);
    host.append(root);
    ctx.status({ phase: "ready" });
    const media: MediaController = {
      ...state,
      play,
      pause: () => el.pause(),
      seek: (seconds) => {
        if (!Number.isFinite(seconds)) return;
        const end = Number.isFinite(el.duration) ? el.duration : Infinity;
        el.currentTime = Math.min(Math.max(0, seconds), end);
      },
      setVolume: (volume) => {
        if (Number.isFinite(volume)) el.volume = Math.min(1, Math.max(0, volume));
      },
      setMuted: (muted) => {
        el.muted = muted;
      },
      setRate: (rate) => {
        if (Number.isFinite(rate) && rate > 0) el.playbackRate = Math.min(16, Math.max(0.0625, rate));
      },
    };
    // The picture is the frame on show; audio has none.
    const pictures =
      el instanceof HTMLVideoElement
        ? createPictures({
            count: 1,
            space: "frame",
            async raster(page, options) {
              throwIfAborted(options.signal);
              return frameOf(el, page, options);
            },
          }).controller
        : undefined;
    return {
      controllers: { media, ...(pictures && { pictures }) },
      destroy() {
        root.removeEventListener("click", toggle);
        for (const e of EVENTS) el.removeEventListener(e, sync);
        el.removeEventListener("waiting", onWaiting);
        el.removeEventListener("playing", onFlowing);
        el.removeEventListener("canplay", onFlowing);
        el.pause();
        el.removeAttribute("src");
        el.load();
        root.remove();
      },
    };
  },
});

export function video(options: MediaOptions = {}): FormatPlugin<MediaOptions> {
  return { id: "video", match: MATCHERS.video, capabilities: ["media", "pictures"], options, load: async () => player("video") };
}

export function audio(options: MediaOptions = {}): FormatPlugin<MediaOptions> {
  return { id: "audio", match: MATCHERS.audio, capabilities: ["media"], options, load: async () => player("audio") };
}
