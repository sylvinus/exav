import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Camera } from "./renderer/camera.js";
import { createZoomGesture, viewTransform } from "./zoom-gesture.js";

function camera(init: Partial<Camera>) {
  return Object.assign(new Camera(), { width: 800, height: 600 }, init);
}

describe("viewTransform", () => {
  it("is the identity for the camera that drew", () => {
    const c = camera({ cx: 12, cy: -3, scale: 0.5 });
    const t = viewTransform(c, c, 2);
    expect(t.k).toBe(1);
    expect(Math.abs(t.x)).toBe(0);
    expect(Math.abs(t.y)).toBe(0);
  });

  it("puts every point where the new camera would draw it, in CSS pixels", () => {
    const dpr = 2;
    const drawn = camera({ cx: 100, cy: 50, scale: 0.25 });
    const now = camera({ cx: 130, cy: 20, scale: 0.1 });
    const t = viewTransform(drawn, now, dpr);
    for (const [lx, ly] of [
      [100, 50],
      [90, 60],
      [150, -10],
    ] as const) {
      // Device pixels, y up, to CSS pixels, y down.
      const css = (c: Camera) => {
        const [sx, sy] = c.toScreen(lx, ly);
        return [sx / dpr, (c.height - sy) / dpr] as const;
      };
      const [x0, y0] = css(drawn);
      const [x1, y1] = css(now);
      expect(t.k * x0 + t.x).toBeCloseTo(x1, 6);
      expect(t.k * y0 + t.y).toBeCloseTo(y1, 6);
    }
  });

  it("scales about the point a zoom held fixed", () => {
    const drawn = camera({ cx: 0, cy: 0, scale: 1 });
    const now = camera({ cx: 0, cy: 0, scale: 1 });
    // A 2x zoom about device pixel (600, 200), y up.
    now.zoomAt(600, 200, 2);
    const t = viewTransform(drawn, now, 1);
    expect(t.k).toBe(2);
    // The same point in CSS pixels, y down: (600, 400).
    expect(t.k * 600 + t.x).toBeCloseTo(600, 6);
    expect(t.k * 400 + t.y).toBeCloseTo(400, 6);
  });
});

describe("a zoom gesture", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "requestAnimationFrame", "cancelAnimationFrame", "performance"] });
  });
  afterEach(() => vi.useRealTimers());

  function make() {
    const frame = vi.fn();
    const draw = vi.fn();
    return { frame, draw, gesture: createZoomGesture({ settleMs: 100, staleMs: 500, frame, draw }) };
  }

  it("shows the canvas moved once per animation frame, however many events there are", () => {
    const { gesture, frame, draw } = make();
    for (let i = 0; i < 10; i++) gesture.touch();
    expect(frame).not.toHaveBeenCalled();
    vi.advanceTimersByTime(16);
    expect(frame).toHaveBeenCalledTimes(1);
    for (let i = 0; i < 10; i++) gesture.touch();
    vi.advanceTimersByTime(16);
    expect(frame).toHaveBeenCalledTimes(2);
    expect(draw).not.toHaveBeenCalled();
  });

  it("draws sharp once, when the events stop", () => {
    const { gesture, draw } = make();
    for (let t = 0; t < 300; t += 16) {
      gesture.touch();
      vi.advanceTimersByTime(16);
    }
    expect(draw).not.toHaveBeenCalled();
    // The last event was 16 ms ago.
    vi.advanceTimersByTime(83);
    expect(draw).not.toHaveBeenCalled();
    vi.advanceTimersByTime(2);
    expect(draw).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1000);
    expect(draw).toHaveBeenCalledTimes(1);
  });

  it("draws sharp now and then while it goes on", () => {
    const { gesture, draw } = make();
    for (let t = 0; t < 1200; t += 16) {
      gesture.touch();
      vi.advanceTimersByTime(16);
    }
    // At 500 and 1000 ms, not at every event.
    expect(draw.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(draw.mock.calls.length).toBeLessThanOrEqual(3);
  });

  it("publishes what is pending when asked to, and not again", () => {
    const { gesture, frame } = make();
    gesture.touch();
    gesture.flush();
    expect(frame).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(16);
    expect(frame).toHaveBeenCalledTimes(1);
    gesture.flush();
    expect(frame).toHaveBeenCalledTimes(1);
  });

  it("does nothing more once cancelled", () => {
    const { gesture, frame, draw } = make();
    gesture.touch();
    gesture.cancel();
    vi.advanceTimersByTime(1000);
    expect(frame).not.toHaveBeenCalled();
    expect(draw).not.toHaveBeenCalled();
    // And a later gesture starts afresh.
    gesture.touch();
    vi.advanceTimersByTime(16);
    expect(frame).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(200);
    expect(draw).toHaveBeenCalledTimes(1);
  });
});
