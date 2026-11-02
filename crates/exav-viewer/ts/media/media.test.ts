import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RasterError } from "../core/pictures.js";
import { FakeCanvas, stubCanvas } from "../test/fake-canvas.js";
import { frameOf, stateOf } from "./index.js";

const ranges = (...r: [number, number][]) => ({ length: r.length, start: (i: number) => r[i]![0], end: (i: number) => r[i]![1] });
const element = (over: Record<string, unknown>) =>
  ({ paused: true, ended: false, currentTime: 0, duration: NaN, volume: 1, muted: false, playbackRate: 1, buffered: ranges(), ...over }) as unknown as HTMLMediaElement;

it("reports a player's state in numbers the protocol takes", () => {
  // Before its metadata, a player has no duration: 0.
  expect(stateOf(element({}), "video", false, false)).toEqual({
    kind: "video",
    paused: true,
    ended: false,
    currentTime: 0,
    duration: 0,
    buffered: 0,
    volume: 1,
    muted: false,
    rate: 1,
    waiting: false,
    blocked: false,
  });
  expect(stateOf(element({ duration: Infinity }), "audio", false, false).duration).toBe(Infinity);
  expect(stateOf(element({ playbackRate: 0 }), "audio", false, false).rate).toBe(1);
  expect(stateOf(element({ currentTime: NaN }), "audio", true, true)).toMatchObject({ currentTime: 0, blocked: true, waiting: true });
});

it("reports what is buffered from where it plays", () => {
  const el = element({ currentTime: 12, duration: 60, buffered: ranges([0, 5], [10, 20], [30, 40]) });
  expect(stateOf(el, "video", false, false).buffered).toBe(20);
  expect(stateOf(element({ currentTime: 25, buffered: ranges([0, 5]) }), "video", false, false).buffered).toBe(25);
});

describe("the frame of a video as a picture", () => {
  beforeEach(stubCanvas);
  afterEach(() => vi.unstubAllGlobals());

  const video = (over: Record<string, unknown> = {}) => ({ videoWidth: 640, videoHeight: 360, readyState: 4, ...over }) as unknown as HTMLVideoElement;
  const code = (p: Promise<unknown>) => p.then(() => "none", (e) => (e instanceof RasterError ? e.code : `other: ${String(e)}`));

  it("is the frame at its own size, or at the size asked with the shape kept", async () => {
    const el = video();
    const own = await frameOf(el, 1, { width: 640 });
    expect([own.width, own.height, own.space, own.page, own.region]).toEqual([640, 360, "frame", 1, undefined]);
    const canvas = FakeCanvas.made[0]!;
    // Transparent unless a background is asked for.
    expect(canvas.fills).toEqual([]);
    expect(canvas.draws[0]).toEqual([el, 0, 0, 640, 360, 0, 0, 640, 360]);
    const small = await frameOf(el, 1, { longEdge: 320 });
    expect([small.width, small.height]).toEqual([320, 180]);
  });

  it("never stretches: contain draws it whole on the background, cover fills the picture", async () => {
    const el = video();
    await frameOf(el, 1, { width: 100, height: 100, background: "#000000" });
    const contain = FakeCanvas.made[0]!;
    expect(contain.fills[0]).toEqual(["#000000", 0, 0, 100, 100]);
    const [, sx, sy, sw, sh, dx, dy, dw, dh] = contain.draws[0]!;
    expect([sx, sy, sw, sh, dx, dw]).toEqual([0, 0, 640, 360, 0, 100]);
    expect(dy).toBeCloseTo(21.875);
    expect(dh).toBeCloseTo(56.25);
    await frameOf(el, 1, { width: 100, height: 100, fit: "cover" });
    const [, cx, cy, cw, ch, ...dest] = FakeCanvas.made[1]!.draws[0]!;
    expect(cx).toBeCloseTo(140);
    expect([cy, cw, ch]).toEqual([0, 360, 360]);
    expect(dest).toEqual([0, 0, 100, 100]);
  });

  it("has no region", async () => {
    expect(await code(frameOf(video(), 1, { width: 10, region: { x: 0, y: 0, width: 1, height: 1 } }))).toBe("invalid");
    expect(await code(frameOf(video(), 1, { width: 10, region: "current" }))).toBe("invalid");
    expect(FakeCanvas.made).toHaveLength(0);
  });

  it("is not drawn before there is a frame", async () => {
    expect(await code(frameOf(video({ readyState: 1 }), 1, { width: 10 }))).toBe("failed");
    expect(await code(frameOf(video({ videoWidth: 0 }), 1, { width: 10 }))).toBe("failed");
  });

  it("waits for a frame decoded but not yet presented, which draws nothing, and draws it again", async () => {
    // Two reads of a transparent pixel, then the frame.
    FakeCanvas.reads = [[0, 0, 0, 0], [0, 0, 0, 0]];
    const r = await frameOf(video(), 1, { width: 64 });
    const canvas = FakeCanvas.made[0]!;
    expect(canvas.draws).toHaveLength(3);
    expect(canvas.clears).toBe(3);
    expect(r.width).toBe(64);
  });

  it("gives up on a frame that never comes, and stops waiting when aborted", async () => {
    vi.useFakeTimers();
    try {
      FakeCanvas.reads = Array.from({ length: 100 }, () => [0, 0, 0, 0]);
      const never = code(frameOf(video(), 1, { width: 64 }));
      await vi.advanceTimersByTimeAsync(5000);
      expect(await never).toBe("failed");
      FakeCanvas.reads = Array.from({ length: 100 }, () => [0, 0, 0, 0]);
      const abort = new AbortController();
      const waiting = code(frameOf(video(), 1, { width: 64, signal: abort.signal }));
      abort.abort();
      await vi.advanceTimersByTimeAsync(100);
      expect(await waiting).toBe("aborted");
    } finally {
      vi.useRealTimers();
    }
  });

  it("puts the background behind the frame, so that it does not hide a frame not yet presented", async () => {
    await frameOf(video(), 1, { width: 64, background: "#102030" });
    const canvas = FakeCanvas.made[0]!;
    expect(canvas.fills).toEqual([["#102030", 0, 0, 64, 36]]);
    // Filled after the frame was drawn and read.
    expect(canvas.draws).toHaveLength(1);
  });

  it("says unsupported for a video the page cannot read, and frees the canvas", async () => {
    vi.spyOn(FakeCanvas.prototype, "getContext").mockReturnValue({
      drawImage() {},
      clearRect() {},
      fillRect() {},
      getImageData() {
        throw new DOMException("tainted", "SecurityError");
      },
    } as never);
    expect(await code(frameOf(video(), 1, { width: 64 }))).toBe("unsupported");
    expect([FakeCanvas.made[0]!.width, FakeCanvas.made[0]!.height]).toEqual([0, 0]);
    vi.restoreAllMocks();
  });
});
