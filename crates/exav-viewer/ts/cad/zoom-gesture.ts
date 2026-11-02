/**
 * A zoom gesture (a pinch, ctrl and the wheel) on the drawing's canvas.
 *
 * Drawing a frame costs the GPU time in proportion to what is in view, which
 * on a large drawing is more than a frame of the display. A frame drawn per
 * event queues behind the last one and the zoom lags seconds behind the
 * fingers. So while the gesture goes on, the canvas already drawn is moved and
 * scaled by the compositor (`viewTransform`) to where the camera now is, at
 * most once per animation frame, and the drawing is drawn sharp once the
 * gesture pauses (and now and then if it does not).
 */

/** What `Camera` holds: where it looks, and the framebuffer it looks through. */
export interface View {
  cx: number;
  cy: number;
  /** Local units per device pixel. */
  scale: number;
  width: number;
  height: number;
}

/**
 * The CSS transform, with its origin at the canvas's top left, that shows a
 * canvas drawn from `drawn` as it would look drawn from `now`. `dpr` is the
 * device pixels per CSS pixel the framebuffer was made for.
 */
export function viewTransform(drawn: View, now: View, dpr: number): { k: number; x: number; y: number } {
  const k = drawn.scale / now.scale;
  const width = drawn.width / dpr;
  const height = drawn.height / dpr;
  return {
    k,
    x: (width * (1 - k)) / 2 + (drawn.cx - now.cx) / (now.scale * dpr),
    // The camera's y is up, a CSS y is down.
    y: (height * (1 - k)) / 2 - (drawn.cy - now.cy) / (now.scale * dpr),
  };
}

export interface ZoomGesture {
  /** The camera moved by a zoom event. */
  touch(): void;
  /** Runs the pending `frame` now, so that what it publishes is up to date. */
  flush(): void;
  /** The view is drawn sharp by someone else: nothing is pending. */
  cancel(): void;
}

export interface ZoomGestureOptions {
  /** Time without a zoom event after which the gesture is over, in ms. */
  settleMs: number;
  /** The longest a gesture goes on showing the same frame scaled, in ms. */
  staleMs: number;
  /** Once per animation frame while the camera moves: shows the frame already drawn where the camera is. */
  frame(): void;
  /** Asks for a sharp frame at the camera. */
  draw(): void;
}

export function createZoomGesture(o: ZoomGestureOptions): ZoomGesture {
  let raf = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let moving = false;
  // When a sharp frame was last asked for.
  let sharpAt = 0;

  const run = () => {
    raf = 0;
    o.frame();
    if (moving && performance.now() - sharpAt >= o.staleMs) {
      sharpAt = performance.now();
      o.draw();
    }
  };
  const stop = () => {
    clearTimeout(timer);
    timer = undefined;
    moving = false;
  };
  return {
    touch() {
      if (!moving) {
        moving = true;
        sharpAt = performance.now();
      }
      if (!raf) raf = requestAnimationFrame(run);
      clearTimeout(timer);
      timer = setTimeout(() => {
        stop();
        o.draw();
      }, o.settleMs);
    },
    flush() {
      if (!raf) return;
      cancelAnimationFrame(raf);
      run();
    },
    cancel() {
      stop();
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
    },
  };
}
