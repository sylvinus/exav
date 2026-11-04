import { act } from "react";
import { createRoot } from "react-dom/client";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_PACKAGE_LIMITS } from "../core/detect.js";
import { createInspector, createSniffer } from "../core/sniff-engine.js";
import type { Viewer } from "../core/types.js";
import { ViewerProvider, useViewer, type ViewerProviderProps } from "./context.js";

// What the viewer a provider makes asks of the detection engine.
vi.mock("../core/sniff-engine.js", () => ({
  createSniffer: vi.fn(() => async () => ""),
  createInspector: vi.fn(() => async () => ({ verdict: "not-inspected", needs: -1, reason: "" })),
  createOfficer: vi.fn(() => async () => ({ needs: -1, kinds: [] })),
}));

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

/** The viewer a `ViewerProvider` with `props` makes. */
async function viewerOf(props: Omit<ViewerProviderProps, "children">): Promise<Viewer> {
  const host = document.createElement("div");
  document.body.append(host);
  let seen: Viewer | null = null;
  const Probe = () => {
    seen = useViewer();
    return null;
  };
  await act(async () =>
    createRoot(host).render(
      <ViewerProvider plugins={[]} {...props}>
        <Probe />
      </ViewerProvider>,
    ),
  );
  return seen!;
}

/** The `headBytes` of the viewer a `ViewerProvider` with `props` makes. */
async function headBytes(props: Omit<ViewerProviderProps, "children">): Promise<number> {
  return (await viewerOf(props)).headBytes;
}

beforeEach(() => {
  vi.mocked(createSniffer).mockClear();
  vi.mocked(createInspector).mockClear();
});

describe("ViewerProvider", () => {
  it("passes sniffBytes to the viewer it makes", async () => {
    expect(await headBytes({ sniffBytes: 8 })).toBe(8);
    expect(await headBytes({ sniffBytes: 0 })).toBe(0);
    expect(await headBytes({})).toBe(65_536);
  });

  it("passes sniffTimeoutMs to the detection of the viewer it makes", async () => {
    await headBytes({ sniffTimeoutMs: 1234 });
    expect(vi.mocked(createSniffer).mock.calls.at(-1)).toEqual([1234]);
    expect(vi.mocked(createInspector).mock.calls.at(-1)).toEqual([1234]);
    await headBytes({ sniffTimeoutMs: 0 });
    expect(vi.mocked(createSniffer).mock.calls.at(-1)).toEqual([0]);
    await headBytes({});
    expect(vi.mocked(createSniffer).mock.calls.at(-1)).toEqual([undefined]);
  });

  it("passes the three limits on a ZIP's directory to the viewer it makes", async () => {
    expect((await viewerOf({ plugins: [], maxExtractedBytes: 1000, maxMembers: 7, maxCompressionRatio: 3 })).limits).toEqual({
      maxExtractedBytes: 1000,
      maxMembers: 7,
      maxCompressionRatio: 3,
    });
    expect((await viewerOf({ plugins: [], maxMembers: 0 })).limits).toEqual({ ...DEFAULT_PACKAGE_LIMITS, maxMembers: 0 });
    expect((await viewerOf({ plugins: [] })).limits).toEqual(DEFAULT_PACKAGE_LIMITS);
  });
});
