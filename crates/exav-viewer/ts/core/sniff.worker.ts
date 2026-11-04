// exav's detection (exav_viewer_sniff.wasm): the content type the start of a file gives, what is wrong with a file that failed to open, and which Office formats a ZIP's members say it is.
import init, { contentType, inspect, zipOfficeKinds } from "../../wasm/exav_viewer_sniff.js";

import type { Finding, OfficeFinding } from "./detect.js";
import type { InspectRequest, OfficeRequest, SniffRequest } from "./sniff-engine.js";
import { serve } from "./worker-host.js";

let ready: Promise<unknown> | null = null;

serve<SniffRequest | InspectRequest | OfficeRequest, string | Finding | OfficeFinding>(async (request) => {
  ready ??= init();
  await ready;
  const head = new Uint8Array(request.head);
  if ("office" in request) {
    const found = zipOfficeKinds(head, new Uint8Array(request.tail), request.size);
    try {
      return { value: { needs: found.needs, kinds: found.kinds } };
    } finally {
      found.free();
    }
  }
  if ("kind" in request) {
    const { limits } = request;
    const found = inspect(request.kind, head, new Uint8Array(request.tail), request.size, limits.maxExtractedBytes, limits.maxMembers, limits.maxCompressionRatio);
    try {
      return { value: { verdict: found.verdict as Finding["verdict"], needs: found.needs, reason: found.reason } };
    } finally {
      found.free();
    }
  }
  return { value: contentType(head, request.size) };
});
