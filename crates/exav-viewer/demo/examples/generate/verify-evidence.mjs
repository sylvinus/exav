#!/usr/bin/env node
// Fetches the page that states each third-party example's licence and checks
// that the words recorded in examples.json (`evidence_quote`) are on it.
//
//     node generate/verify-evidence.mjs [name-fragment ...]
//
// A name fragment also matches the evidence address (`commons.wikimedia.org`).
// It needs the network and is slow on purpose (one request at a time, with a
// pause), so it is not part of the demo build. A page that is a PDF is read with
// pdftotext, and a web page is read without its tags. An entry with `evidence_row` names a field (the file's SHA-256) that
// must sit in the same row of a JSON table as the quote. Exit 1 when a quote is
// missing or a page cannot be read.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const { examples } = JSON.parse(fs.readFileSync(path.join(here, "..", "examples.json"), "utf8"));
const only = process.argv.slice(2);
const USER_AGENT = "exav-examples/1.0 (https://github.com/sylvinus/exav)";

const norm = (s) =>
  s
    .replace(/\\\//g, "/")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\\"/g, '"')
    .replace(/\s+/g, " ")
    .replace(/ ([.,;:!?)])/g, "$1");

const cache = new Map();
async function page(url) {
  if (cache.has(url)) return cache.get(url);
  let last;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(url, { headers: { "User-Agent": USER_AGENT, Accept: "*/*" }, redirect: "follow" });
      if (res.ok) {
        const buf = Buffer.from(await res.arrayBuffer());
        let raw;
        const texts = [];
        if (buf.subarray(0, 5).toString() === "%PDF-") {
          const tmp = path.join(os.tmpdir(), `exav-evidence-${process.pid}.pdf`);
          fs.writeFileSync(tmp, buf);
          raw = execFileSync("pdftotext", [tmp, "-"], { maxBuffer: 1 << 28 }).toString();
          fs.rmSync(tmp);
        } else {
          raw = buf.toString("utf8");
          // A web page is also read as a person sees it, tags apart.
          if (/<html[\s>]/i.test(raw.slice(0, 2000)) || /^\s*<!doctype html/i.test(raw)) {
            texts.push(raw.replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]*>/g, " "));
          }
        }
        texts.push(raw);
        cache.set(url, texts);
        return texts;
      }
      last = new Error(`HTTP ${res.status}`);
      if (res.status !== 429 && res.status < 500) break;
    } catch (e) {
      last = e;
    }
    await new Promise((r) => setTimeout(r, 2000 * attempt));
  }
  throw new Error(`${url}: ${last?.message ?? last}`);
}

let failed = 0;
let checked = 0;
for (const e of examples) {
  if (e.generated || (only.length && !only.some((o) => e.file.includes(o) || e.evidence.includes(o)))) continue;
  checked++;
  try {
    const texts = await page(e.evidence);
    const quote = norm(e.evidence_quote);
    let ok;
    if (e.evidence_row) {
      const row = norm(texts.at(-1)).split(/\],\s?\[/).find((r) => r.includes(e[e.evidence_row]));
      ok = Boolean(row) && row.includes(quote);
    } else {
      ok = texts.some((t) => norm(t).includes(quote));
    }
    console.log(`${ok ? "ok  " : "FAIL"} ${e.file}: ${e.evidence}`);
    if (!ok) failed++;
  } catch (err) {
    console.log(`FAIL ${e.file}: ${err.message}`);
    failed++;
  }
  await new Promise((r) => setTimeout(r, 400));
}
console.log(`${checked} pages checked, ${failed} failed`);
process.exit(failed ? 1 : 0);
