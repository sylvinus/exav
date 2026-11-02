import { vi } from "vitest";

/** A canvas that records what is drawn on it (no drawing happens). */
export class FakeCanvas {
  static made: FakeCanvas[] = [];
  /** Pixels the next reads give, before the canvas's own. */
  static reads: number[][] = [];
  draws: unknown[][] = [];
  fills: unknown[][] = [];
  fillStyle = "";
  imageSmoothingQuality = "low";
  constructor(
    public width: number,
    public height: number,
  ) {
    FakeCanvas.made.push(this);
  }
  /** What a read of one pixel gives (alpha last); opaque white. */
  pixel = [255, 255, 255, 255];
  clears = 0;
  getContext() {
    const canvas = this;
    return {
      drawImage: (...a: unknown[]) => this.draws.push(a),
      fillRect: (...a: unknown[]) => this.fills.push([this.fillStyle, ...a]),
      clearRect: () => this.clears++,
      getImageData: () => ({ data: Uint8ClampedArray.from(FakeCanvas.reads.shift() ?? canvas.pixel) }),
      globalCompositeOperation: "source-over",
      set fillStyle(v: string) {
        canvas.fillStyle = v;
      },
      set imageSmoothingQuality(v: string) {
        canvas.imageSmoothingQuality = v;
      },
    };
  }
  /** The bitmaps handed out of it. */
  bitmaps: FakeBitmap[] = [];
  transferToImageBitmap() {
    const b = new FakeBitmap(this.width, this.height);
    this.bitmaps.push(b);
    return b;
  }
}

export class FakeBitmap {
  closed = false;
  constructor(
    public width: number,
    public height: number,
  ) {}
  close() {
    this.closed = true;
  }
}

/** Makes `OffscreenCanvas` and `ImageBitmap` the fakes; undo with `vi.unstubAllGlobals()`. */
export function stubCanvas(): void {
  FakeCanvas.made = [];
  FakeCanvas.reads = [];
  vi.stubGlobal("OffscreenCanvas", FakeCanvas);
  vi.stubGlobal("ImageBitmap", FakeBitmap);
}
