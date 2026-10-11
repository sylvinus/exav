import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { FRAME_CSP, frameCsp, frameHeaders, OFFICE_STYLE_HASH, policyMismatch, readPolicy } from "./policy.js";

/** The policy's directives, by name. */
const directives = (csp: string) => new Map(csp.split(";").map((d) => d.trim().split(/\s+/)).map(([name, ...values]) => [name!, values]));

describe("the frame's policy", () => {
  it("starts from nothing and allows only its own origin, wasm and blob: workers", () => {
    const d = directives(FRAME_CSP);
    expect(d.get("default-src")).toEqual(["'none'"]);
    expect(d.get("script-src")).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(d.get("connect-src")).toEqual(["'self'"]);
    expect(d.get("worker-src")).toEqual(["blob:"]);
    expect(d.get("require-trusted-types-for")).toEqual(["'script'"]);
    expect(d.get("trusted-types")).toEqual(["exav-worker", "default"]);
    for (const name of ["base-uri", "form-action", "object-src", "frame-src"]) expect(d.get(name), name).toEqual(["'none'"]);
    // Nothing that would let a string become code, or a style be anything.
    expect(FRAME_CSP).not.toMatch(/'unsafe-eval'|'unsafe-inline'|\*|https?:/);
  });

  it("names the frame's origin beside 'self' for WebKit, and refuses anything but an origin", () => {
    const d = directives(frameCsp("https://viewer.example.com"));
    expect(d.get("connect-src")).toEqual(["'self'", "https://viewer.example.com"]);
    expect(d.get("script-src")).toEqual(["'self'", "https://viewer.example.com", "'wasm-unsafe-eval'"]);
    for (const bad of ["https://x.test; script-src *", "https://x.test/path", "*", "https:", "'unsafe-inline'", "https://x.test 'unsafe-eval'"]) {
      expect(() => frameCsp(bad), bad).toThrow();
    }
  });

  it("allows media and image origins to be shown, connect origins to be fetched, and nothing more", () => {
    const d = directives(frameCsp("https://viewer.example.com", { media: ["https://media.test", "https://viewer.example.com"], connect: ["https://files.test"] }));
    expect(d.get("media-src")).toEqual(["blob:", "https://media.test", "https://viewer.example.com"]);
    expect(d.get("img-src")).toEqual(["'self'", "https://viewer.example.com", "blob:", "data:", "https://media.test"]);
    expect(d.get("connect-src")).toEqual(["'self'", "https://viewer.example.com", "https://files.test"]);
    expect(d.get("script-src")).toEqual(["'self'", "https://viewer.example.com", "'wasm-unsafe-eval'"]);
    expect(d.get("font-src")).toEqual(["'self'", "https://viewer.example.com", "blob:", "data:"]);
    expect(frameHeaders("'self'", undefined, { media: ["https://media.test"] })["Content-Security-Policy"]).toContain("media-src blob: https://media.test;");
    for (const bad of ["https://x.test; script-src *", "https://x.test/", "*", "https://*.x.test", "HTTPS://X.TEST", "blob:"]) {
      expect(() => frameCsp(undefined, { media: [bad] }), bad).toThrow();
      expect(() => frameCsp(undefined, { connect: [bad] }), bad).toThrow();
    }
  });

  it("is reported by the frame and checked by the host: the configured origins, exactly", () => {
    const origins = { media: ["https://media.test"], connect: ["https://files.test"] };
    expect(policyMismatch(readPolicy(frameCsp(undefined, origins)), origins)).toBeNull();
    expect(policyMismatch(readPolicy(frameCsp("https://viewer.example.com", origins)), origins)).toBeNull();
    expect(policyMismatch(readPolicy(FRAME_CSP), {})).toBeNull();
    expect(policyMismatch(null, {})).toBeNull();
    expect(policyMismatch(null, origins)).toMatch(/no Content-Security-Policy/);
    expect(policyMismatch(readPolicy(FRAME_CSP), origins)).toMatch(/media-src lacks https:\/\/media\.test.*connect-src lacks https:\/\/files\.test/);
    expect(policyMismatch(readPolicy(frameCsp(undefined, origins)), { media: origins.media })).toMatch(/connect-src also allows https:\/\/files\.test/);
    expect(policyMismatch(readPolicy(FRAME_CSP.replace("connect-src 'self'", "connect-src *")), {})).toMatch(/also allows \*/);
    // The first directive of a name is the one that counts.
    expect(readPolicy("media-src blob:; media-src *").media).toEqual(["blob:"]);
  });

  it("is served with the directives a meta tag cannot carry, and with CORS for the opaque origin", () => {
    const h = frameHeaders("https://host.example.com");
    const d = directives(h["Content-Security-Policy"]!);
    expect(d.get("frame-ancestors")).toEqual(["https://host.example.com"]);
    expect(d.get("sandbox")).toEqual(["allow-scripts"]);
    expect(h["Access-Control-Allow-Origin"]).toBe("*");
    expect(h["Referrer-Policy"]).toBe("no-referrer");
    expect(h["X-Content-Type-Options"]).toBe("nosniff");
    for (const f of ["camera", "microphone", "geolocation", "payment", "usb", "clipboard-read"]) expect(h["Permissions-Policy"]).toContain(`${f}=()`);
  });

  it("allows the spreadsheet engine's stylesheet by the hash of the installed engine's", () => {
    const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "node_modules", "@silurus", "ooxml", "dist");
    const hashes = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith(".js"))
      .flatMap((f) => {
        const m = /"data-xlsx-viewer-styles",\s*\w+\s*=\s*("(?:[^"\\]|\\.)*")/.exec(fs.readFileSync(path.join(dir, f), "utf8"));
        return m ? [`sha256-${createHash("sha256").update(JSON.parse(m[1]!)).digest("base64")}`] : [];
      });
    expect(hashes).toEqual([OFFICE_STYLE_HASH]);
    expect(directives(FRAME_CSP).get("style-src")).toEqual(["'self'", `'${OFFICE_STYLE_HASH}'`]);
  });
});
