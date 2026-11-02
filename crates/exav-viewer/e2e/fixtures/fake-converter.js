// A minimal external converter, for the tests of the contract (see
// `ExternalConverter` in ts/office/external.ts). It reads the file's first
// word to know what to do, and answers with a one-page PDF that says what it
// was given, so that a test can see the hint, the size and the memory option
// arrive.
//
//   FAIL...   rejects with an error
//   HANG...   waits for the signal, and rejects with its reason
//   DEAF...   never answers and never looks at the signal
//   SHEET...  answers an XLSX (empty bytes: for tests that do not draw it)
//   BAD...    answers what the contract does not allow
//   anything else: a PDF.
//
// A call is counted in `globalThis.fakeConverterCalled` and a signal that
// aborts in `globalThis.fakeConverterAborted`, for a test that reads them in
// the page.

/** A PDF of one page holding `text`, its cross-reference table written out. */
function pdf(text) {
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
    undefined,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
  ];
  const content = `BT /F1 14 Tf 20 100 Td (${text.replace(/[()\\]/g, "")}) Tj ET`;
  objects[3] = `<< /Length ${content.length} >>\nstream\n${content}\nendstream`;
  let out = "%PDF-1.4\n";
  const offsets = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) out += `${String(o).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new TextEncoder().encode(out);
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 80));

export async function convert(bytes, { hint, maxMemory, signal, onProgress } = {}) {
  globalThis.fakeConverterCalled = (globalThis.fakeConverterCalled ?? 0) + 1;
  signal?.addEventListener("abort", () => (globalThis.fakeConverterAborted = (globalThis.fakeConverterAborted ?? 0) + 1), { once: true });
  const word = new TextDecoder().decode(bytes.subarray(0, 8));
  onProgress?.({ stage: "download", loaded: 1, total: 2 });
  await tick();
  onProgress?.({ stage: "download", loaded: 2, total: 2 });
  onProgress?.({ stage: "start" });
  await tick();
  onProgress?.({ stage: "load", done: 1, total: 2 });
  await tick();
  if (word.startsWith("FAIL")) throw new Error("the fake converter was asked to fail");
  if (word.startsWith("HANG")) {
    await new Promise((_, reject) => {
      if (signal?.aborted) reject(signal.reason);
      signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  }
  if (word.startsWith("DEAF")) await new Promise(() => {});
  if (word.startsWith("BAD")) return { format: "docx", bytes: new Uint8Array(1) };
  onProgress?.({ stage: "export", done: 1, total: 1 });
  if (word.startsWith("SHEET")) return { format: "xlsx", bytes: new Uint8Array(0) };
  return { format: "pdf", bytes: pdf(`fake converter: ${hint}, ${bytes.length} bytes, memory ${maxMemory ?? "unset"}`) };
}

export function prefetch(hint) {
  return [`fake-data-${hint}.bin`];
}
