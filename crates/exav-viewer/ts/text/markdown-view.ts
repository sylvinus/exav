/**
 * Draws a parsed Markdown tree. Elements are made with `createElement` and
 * given text with `textContent`: no markup string is ever parsed, and no
 * attribute carries data from the file except a list's start number, which
 * is a digit string made here. A link is its label with the address it goes
 * to written out beside it. An http or https link is followed on a click or
 * Enter by `window.open`, as a PDF's links are: in the frame a request the
 * host confirms, in the page a new tab with no opener. It is not an anchor,
 * so the document itself never navigates; a `mailto:` link is text, and so
 * is a link whose address `safeTarget` refuses. The reader bounds how deep
 * the tree goes.
 */
import { plain, safeTarget, type Block, type Inline } from "./markdown.js";

function el(tag: string, cls?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function span(cls: string, text: string): HTMLElement {
  const e = el("span", cls);
  e.textContent = text;
  return e;
}

export function drawInline(parent: Node, nodes: Inline[]): void {
  for (const n of nodes) {
    switch (n.t) {
      case "text":
        parent.appendChild(document.createTextNode(n.s));
        break;
      case "br":
        parent.appendChild(el("br"));
        break;
      case "code": {
        const e = el("code");
        e.textContent = n.s;
        parent.appendChild(e);
        break;
      }
      case "image":
        parent.appendChild(span("exav-viewer-md-image", n.alt ? `[${n.alt}]` : "[image]"));
        break;
      case "link": {
        const url = safeTarget(n.url);
        if (!url) {
          drawInline(parent, n.c);
          break;
        }
        const label = plain(n.c);
        const a = el("span", "exav-viewer-text-link");
        drawInline(a, n.c);
        if (/^https?:/i.test(url)) {
          const follow = () => window.open(url, "_blank", "noopener,noreferrer");
          a.tabIndex = 0;
          a.setAttribute("role", "link");
          a.addEventListener("click", follow);
          a.addEventListener("keydown", (e) => {
            if (e.key === "Enter") follow();
          });
        }
        parent.appendChild(a);
        const bare = url.replace(/^mailto:/, "");
        if (label !== url && label !== bare) parent.appendChild(span("exav-viewer-text-url", ` (${url})`));
        break;
      }
      default: {
        const e = el(n.t === "em" ? "em" : n.t === "strong" ? "strong" : "del");
        drawInline(e, n.c);
        parent.appendChild(e);
      }
    }
  }
}

export function drawBlocks(parent: Node, blocks: Block[], tight = false): void {
  for (const b of blocks) {
    switch (b.t) {
      case "p": {
        if (tight) {
          drawInline(parent, b.c);
          break;
        }
        const e = el("p");
        drawInline(e, b.c);
        parent.appendChild(e);
        break;
      }
      case "h": {
        const e = el(`h${b.level}`);
        drawInline(e, b.c);
        parent.appendChild(e);
        break;
      }
      case "code": {
        const pre = el("pre");
        const code = el("code");
        code.textContent = b.s;
        pre.appendChild(code);
        parent.appendChild(pre);
        break;
      }
      case "hr":
        parent.appendChild(el("hr"));
        break;
      case "raw": {
        const e = el("p", "exav-viewer-md-raw");
        e.textContent = b.s;
        parent.appendChild(e);
        break;
      }
      case "quote": {
        const e = el("blockquote");
        drawBlocks(e, b.c);
        parent.appendChild(e);
        break;
      }
      case "list": {
        const e = el(b.ordered ? "ol" : "ul", b.tight ? "exav-viewer-md-tight" : undefined);
        if (b.ordered && b.start !== 1) e.setAttribute("start", String(Math.trunc(b.start)));
        for (const item of b.items) {
          const li = el("li");
          drawBlocks(li, item, b.tight);
          e.appendChild(li);
        }
        parent.appendChild(e);
        break;
      }
      case "table": {
        const table = el("table");
        const row = (cells: Inline[][], tag: string) => {
          const tr = el("tr");
          cells.forEach((c, k) => {
            const cell = el(tag, b.align[k] ? `exav-viewer-md-${b.align[k]}` : undefined);
            drawInline(cell, c);
            tr.appendChild(cell);
          });
          return tr;
        };
        const thead = el("thead");
        thead.appendChild(row(b.head, "th"));
        const tbody = el("tbody");
        for (const r of b.rows) tbody.appendChild(row(r, "td"));
        table.append(thead, tbody);
        parent.appendChild(table);
        break;
      }
    }
  }
}
