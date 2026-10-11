// Fails when the package's own code (ts/, demo/src/; not the tests, which
// hold hostile strings on purpose) reaches for an API that turns data into
// code, markup or a navigation, unless the occurrence is on the list below
// with the reason it is safe. Read from the syntax tree, so comments that
// mention a sink do not count, and an entry that no longer matches anything
// fails too: the list stays exact.
//
// Usage: node scripts/check-sinks.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

/**
 * Known, reviewed occurrences: the file (relative to the package), the rule,
 * the code (whitespace collapsed), and why it is safe.
 */
export const ALLOWED = [
  {
    file: "ts/frame/index.ts",
    rule: "window.open",
    code: 'window.open(url, "_blank", "noopener,noreferrer")',
    why: "the host opens a link the frame asked for: absolute http(s) only (linkTarget), after the host's confirmation",
  },
  {
    file: "ts/frame/index.ts",
    rule: "postMessage to *",
    code: 'frame.contentWindow?.postMessage({ type: HELLO, protocol: PROTOCOL }, "*", [channel.port2])',
    why: "an opaque origin cannot be named: this message carries the port and nothing else",
  },
  {
    file: "ts/frame/index.ts",
    rule: "src from a variable",
    code: "frame.src = config.url",
    why: "the frame app's URL, from the host's own configuration",
  },
  {
    file: "ts/frame/app/main.ts",
    rule: "window.open",
    code: 'window.open = (url?: string | URL) => { if (url !== undefined) post({ type: "link", url: String(url) }); return null; }',
    why: "replaces window.open in the frame: a link becomes a request to the host",
  },
  {
    file: "ts/pdf/reader.ts",
    rule: "window.open",
    code: 'window.open(link.url, "_blank", "noopener,noreferrer")',
    why: "a PDF link the user clicked: absolute http(s) only (readLinks, through linkTarget); in the frame, a request to the host, which asks first",
  },
  {
    file: "ts/pdf/reader.ts",
    rule: "href from a variable",
    code: 'a.href = "url" in link ? link.url : "#"',
    why: "the same absolute http(s) address, shown on hover; a click is handled by the line above",
  },
  {
    file: "ts/react/ViewerDialog.tsx",
    rule: "href from a variable",
    code: "a.href = url",
    why: "the download URL the host's own resolveUrl returned",
  },
  {
    file: "ts/image/renderer.ts",
    rule: "src from a variable",
    code: "img.src = url",
    why: "the file's own URL or an object URL of its bytes, shown as an image",
  },
  {
    file: "ts/cad/view.ts",
    rule: "src from a variable",
    code: "img.src = URL.createObjectURL(new Blob([p.data], { type: p.mime }))",
    why: "an object URL of the drawing's thumbnail bytes (PNG or BMP, typed by exav-render), shown as an image",
  },
  {
    file: "ts/media/index.ts",
    rule: "src from a variable",
    code: "el.src = url",
    why: "the file's own URL or an object URL of its bytes, played as media",
  },
];

/** The rule an expression breaks, or null. */
function ruleOf(node, sf) {
  const text = (n) => n.getText(sf);
  const isWindowish = (n) => ts.isIdentifier(n) && ["window", "self", "globalThis", "top", "parent"].includes(n.text);
  const literal = (n) => ts.isStringLiteralLike(n);

  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    const callee = node.expression;
    const args = node.arguments ?? [];
    if (ts.isIdentifier(callee)) {
      if (callee.text === "eval") return "eval";
      if (callee.text === "Function") return "Function constructor";
      if (callee.text === "open" && ts.isCallExpression(node)) return "window.open";
      if ((callee.text === "setTimeout" || callee.text === "setInterval") && args[0] && isStringy(args[0])) return "string timer";
      if (callee.text === "importScripts") return "importScripts";
      if (callee.text === "Worker" && ts.isNewExpression(node) && !isOwnUrl(args[0])) return "worker from a variable";
    }
    if (ts.isPropertyAccessExpression(callee)) {
      const name = callee.name.text;
      if (["insertAdjacentHTML", "createContextualFragment", "parseFromString", "setHTMLUnsafe"].includes(name)) return name;
      if ((name === "write" || name === "writeln") && text(callee.expression) === "document") return "document.write";
      if (name === "open" && isWindowish(callee.expression)) return "window.open";
      if ((name === "setTimeout" || name === "setInterval") && isWindowish(callee.expression) && args[0] && isStringy(args[0])) return "string timer";
      if (name === "eval" && isWindowish(callee.expression)) return "eval";
      if (name === "postMessage" && args.length >= 2 && literal(args[1]) && args[1].text === "*") return "postMessage to *";
      if (name === "setAttribute" && args[0] && literal(args[0])) {
        const attr = args[0].text.toLowerCase();
        if (attr.startsWith("on")) return "event handler attribute";
        if (["href", "src", "srcdoc", "action", "formaction", "xlink:href", "data"].includes(attr) && args[1] && !literal(args[1])) return `${attr} from a variable`;
      }
    }
    if (node.expression.kind === ts.SyntaxKind.ImportKeyword && args[0] && !literal(args[0])) return "import() of a variable";
  }
  if (ts.isBinaryExpression(node) && isAssignment(node.operatorToken.kind) && ts.isPropertyAccessExpression(node.left)) {
    const name = node.left.name.text;
    if (["innerHTML", "outerHTML", "srcdoc"].includes(name)) return name;
    if (name === "open" && isWindowish(node.left.expression)) return "window.open";
    if (/^on[a-z]+$/.test(name) && isStringy(node.right)) return "event handler from a string";
    if (["href", "src", "action", "formAction"].includes(name) && !literal(node.right) && !isOwnUrl(node.right)) return `${name.toLowerCase()} from a variable`;
  }
  if (ts.isJsxAttribute(node) && node.name.getText(sf) === "dangerouslySetInnerHTML") return "dangerouslySetInnerHTML";
  if ((ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) && /javascript\s*:/i.test(node.text)) return "javascript: URL";
  return null;
}

const isAssignment = (k) => k === ts.SyntaxKind.EqualsToken || k === ts.SyntaxKind.PlusEqualsToken;
const isStringy = (n) => ts.isStringLiteralLike(n) || ts.isTemplateExpression(n) || (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken);
/** `new URL("literal", import.meta.url)`: a file of the package, which the bundler resolves. */
function isOwnUrl(n) {
  if (!n || !ts.isNewExpression(n) || !ts.isIdentifier(n.expression) || n.expression.text !== "URL") return false;
  const [what, base] = n.arguments ?? [];
  return !!what && ts.isStringLiteralLike(what) && !!base && base.getText().replace(/\s/g, "") === "import.meta.url";
}

const collapse = (s) => s.replace(/\s+/g, " ").trim();

/** Every finding in `files` ({ path, text } with paths relative to the package), allowed or not. */
export function findSinks(files) {
  const found = [];
  for (const f of files) {
    const kind = f.path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
    const sf = ts.createSourceFile(f.path, f.text, ts.ScriptTarget.Latest, true, kind);
    const visit = (node) => {
      const rule = ruleOf(node, sf);
      if (rule) {
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        found.push({ file: f.path, line: line + 1, rule, code: collapse(node.getText(sf)) });
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return found;
}

/** What fails: findings not on `allowed`, and entries of `allowed` that match nothing. */
export function checkSinks(files, allowed = ALLOWED) {
  const found = findSinks(files);
  const used = new Set();
  const refused = found.filter((s) => {
    const i = allowed.findIndex((a) => a.file === s.file && a.rule === s.rule && a.code === s.code);
    if (i < 0) return true;
    used.add(i);
    return false;
  });
  const stale = allowed.filter((_, i) => !used.has(i));
  return { refused, stale };
}

/** The package's own sources: ts/ and demo/src/, tests left out. */
export function sources(root) {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|tsx|mts)$/.test(e.name) && !/\.d\.ts$|\.test\.tsx?$/.test(e.name)) out.push({ path: path.relative(root, p).split(path.sep).join("/"), text: fs.readFileSync(p, "utf8") });
    }
  };
  walk(path.join(root, "ts"));
  walk(path.join(root, "demo", "src"));
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const files = sources(root);
  const { refused, stale } = checkSinks(files);
  for (const s of refused) console.error(`${s.file}:${s.line}: ${s.rule}: ${s.code}`);
  for (const a of stale) console.error(`allowed but not found (remove it from ALLOWED): ${a.file}: ${a.rule}: ${a.code}`);
  if (refused.length || stale.length) {
    console.error("check-sinks: failed");
    process.exit(1);
  }
  console.log(`check-sinks: ${files.length} files, ${ALLOWED.length} reviewed occurrences, nothing else`);
}
