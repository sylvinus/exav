import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { createSurface, SURFACE_DEFAULTS, wheelAction, type SurfaceOptions } from "./surface.js";

const wheel = (init: Partial<WheelEventInit>) => ({ deltaX: 0, deltaY: 0, deltaMode: 0, ctrlKey: false, metaKey: false, ...init });

describe("wheelAction", () => {
  it("zooms by a step on a plain wheel, in the direction of the scroll", () => {
    expect(wheelAction(wheel({ deltaY: 100 }), "zoom", 0.08, 500)).toEqual({ zoom: 0.92 });
    expect(wheelAction(wheel({ deltaY: -100 }), "zoom", 0.08, 500)).toEqual({ zoom: 1.08 });
  });

  it("pans on a plain wheel when asked to, lines and pages brought to pixels", () => {
    expect(wheelAction(wheel({ deltaX: 3, deltaY: 40 }), "pan", 0.08, 500)).toEqual({ pan: { dx: 3, dy: 40 } });
    expect(wheelAction(wheel({ deltaY: 2, deltaMode: 1 }), "pan", 0.08, 500)).toEqual({ pan: { dx: 0, dy: 32 } });
    expect(wheelAction(wheel({ deltaY: 1, deltaMode: 2 }), "pan", 0.08, 500)).toEqual({ pan: { dx: 0, dy: 500 } });
  });

  it("zooms on Ctrl or ⌘ with the wheel, in either mode", () => {
    for (const mode of ["zoom", "pan"] as const) {
      for (const key of ["ctrlKey", "metaKey"] as const) {
        const a = wheelAction(wheel({ deltaY: -10, [key]: true }), mode, 0.08, 500);
        expect(a).toEqual({ zoom: Math.exp(0.1) });
      }
    }
  });

  it("clamps a mouse notch, so that one click is not a zoom by 2.7", () => {
    expect(wheelAction(wheel({ deltaY: -100, ctrlKey: true }), "zoom", 0.08, 500)).toEqual({ zoom: Math.exp(0.3) });
    expect(wheelAction(wheel({ deltaY: 100, ctrlKey: true }), "zoom", 0.08, 500)).toEqual({ zoom: Math.exp(-0.3) });
    // A line of a Firefox notch is clamped too.
    expect(wheelAction(wheel({ deltaY: -3, deltaMode: 1, ctrlKey: true }), "zoom", 0.08, 500)).toEqual({ zoom: Math.exp(0.3) });
  });
});

describe("a surface's wheel", () => {
  beforeAll(() => {
    globalThis.ResizeObserver ??= class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });
  const open: { destroy(): void }[] = [];
  afterEach(() => open.splice(0).forEach((s) => s.destroy()));

  function make(options: Partial<SurfaceOptions>) {
    const host = document.createElement("div");
    document.body.append(host);
    const picture = document.createElement("canvas");
    const surface = createSurface(host, picture, { width: 100, height: 100 }, { ...SURFACE_DEFAULTS, ...options });
    open.push(surface);
    const root = host.querySelector<HTMLElement>(".exv-image")!;
    const send = (init: WheelEventInit) => root.dispatchEvent(new WheelEvent("wheel", { bubbles: true, cancelable: true, ...init }));
    return { surface, send, root };
  }

  it("reports a tap in fractions of the page and in container pixels", () => {
    const taps: unknown[] = [];
    const { surface, root } = make({ onTap: (point, _event, screen) => taps.push({ point, screen }) });
    // jsdom lays nothing out: the container is 200 by 200, the picture fitted to it.
    Object.defineProperty(root, "clientWidth", { value: 200 });
    Object.defineProperty(root, "clientHeight", { value: 200 });
    surface.resize();
    const pointer = (type: string, x: number, y: number) =>
      root.dispatchEvent(Object.assign(new MouseEvent(type, { clientX: x, clientY: y, bubbles: true }), { pointerId: 1, isPrimary: true, pointerType: "touch" }));
    pointer("pointerdown", 50, 150);
    pointer("pointerup", 50, 150);
    expect(taps).toEqual([{ point: { x: 0.25, y: 0.75 }, screen: { x: 50, y: 150 } }]);
  });

  it("picks the marker nearest a container point, within a radius", () => {
    const { surface, root } = make({});
    Object.defineProperty(root, "clientWidth", { value: 200 });
    Object.defineProperty(root, "clientHeight", { value: 200 });
    surface.resize();
    const pins = [
      { id: "a", x: 0.25, y: 0.25 },
      { id: "b", x: 0.5, y: 0.5 },
      { id: "c", x: 0.52, y: 0.5 },
    ];
    // The page is 200 by 200 pixels: "b" is at (100, 100), "c" at (104, 100).
    expect(surface.pick(pins, { x: 101, y: 100 })?.id).toBe("b");
    expect(surface.pick(pins, { x: 103, y: 100 })?.id).toBe("c");
    expect(surface.pick(pins, { x: 52, y: 52 })?.id).toBe("a");
    expect(surface.pick(pins, { x: 160, y: 160 })).toBeNull();
    // A radius of its own, and after zooming the pins are further apart on screen.
    expect(surface.pick(pins, { x: 80, y: 100 }, 10)).toBeNull();
    expect(surface.pick(pins, { x: 80, y: 100 }, 25)?.id).toBe("b");
    surface.zoom.setScale(2, { x: 0, y: 0 });
    expect(surface.pick(pins, { x: 101, y: 100 })?.id).toBe("a");
    expect(surface.pick(pins, { x: 200, y: 200 })?.id).toBe("b");
  });

  it("shows another picture in place of this one, keeping the view when the shape is the same", () => {
    const { surface, root } = make({});
    Object.defineProperty(root, "clientWidth", { value: 200 });
    Object.defineProperty(root, "clientHeight", { value: 200 });
    surface.resize();
    surface.zoom.setScale(3, { x: 50, y: 50 });
    const before = surface.get();
    const next = document.createElement("canvas");
    surface.replacePicture(next, { width: 200, height: 200 });
    expect(root.querySelector(".exv-image-picture")).toBe(next);
    expect(root.querySelectorAll(".exv-image-picture")).toHaveLength(1);
    expect(surface.get()).toMatchObject({ scale: before.scale, x: before.x, y: before.y });
    // Another shape is fitted again.
    surface.replacePicture(document.createElement("canvas"), { width: 100, height: 200 });
    expect(surface.get().scale).toBe(1);
  });

  it("zooms on a plain wheel by default", () => {
    const { surface, send } = make({});
    send({ deltaY: -100 });
    expect(surface.get().scale).toBeCloseTo(1.08);
  });

  it("moves the sheet instead with wheel: pan, and still zooms with Ctrl", () => {
    const { surface, send } = make({ wheel: "pan" });
    send({ deltaX: 5, deltaY: 40 });
    expect(surface.get()).toMatchObject({ scale: 1, x: -5, y: -40 });
    send({ deltaY: -100, ctrlKey: true });
    expect(surface.get().scale).toBeCloseTo(Math.exp(0.3));
  });
});
