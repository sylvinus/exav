/**
 * Selecting a Word or PowerPoint document's text. The engines
 * (`enableTextSelection`) lay each page's or slide's text over its canvas as
 * transparent runs, `[data-ooxml-selection-run]`, in a
 * `[data-ooxml-selection-surface]` that lets the pointer through between
 * them. Two things are added here:
 *
 * - While a selection is dragged, a cover under the runs of each surface and
 *   of each slide shape, so that the pointer off the text leaves the
 *   selection where it was: on the canvas, or on a shape's blank area,
 *   every browser moves it back to the top.
 * - A copy with line breaks, which the runs do not have.
 *
 * Returns what removes both.
 */
export function textSelection(root: HTMLElement): () => void {
  const doc = root.ownerDocument;
  const covers: HTMLElement[] = [];
  const onDown = (e: MouseEvent) => {
    if (!(e.target as Element | null)?.closest?.("[data-ooxml-selection-run]")) return;
    // Each surface, and each box the runs are in within it (a slide's
    // shapes, which take the pointer over their whole area).
    const holders = new Set<Element>(root.querySelectorAll("[data-ooxml-selection-surface]"));
    for (const run of root.querySelectorAll("[data-ooxml-selection-run]")) if (run.parentElement) holders.add(run.parentElement);
    for (const holder of holders) {
      const cover = doc.createElement("div");
      cover.className = "exv-office-text-end";
      // First: the runs after it are drawn, and hit, above it.
      holder.prepend(cover);
      covers.push(cover);
    }
  };
  const onUp = () => {
    for (const cover of covers.splice(0)) cover.remove();
  };
  // On the document: a copy is fired at what has focus, not at the selection.
  const onCopy = (e: ClipboardEvent) => {
    const text = selectedText(root, doc.getSelection());
    if (text === null || !e.clipboardData) return;
    e.clipboardData.setData("text/plain", text);
    e.preventDefault();
  };
  root.addEventListener("mousedown", onDown);
  doc.addEventListener("pointerup", onUp);
  doc.defaultView?.addEventListener("blur", onUp);
  doc.addEventListener("copy", onCopy);
  return () => {
    root.removeEventListener("mousedown", onDown);
    doc.removeEventListener("pointerup", onUp);
    doc.defaultView?.removeEventListener("blur", onUp);
    doc.removeEventListener("copy", onCopy);
    onUp();
  };
}

/**
 * The selected part of each run in `root`, in document order, with a line
 * break between paragraphs; null when the selection is not there. A Word
 * run names its paragraph; a PowerPoint run only its shape, so a run that
 * starts below the last one starts a line too.
 */
export function selectedText(root: HTMLElement, selection: Selection | null): string | null {
  if (!selection || selection.isCollapsed || selection.rangeCount === 0) return null;
  const ranges = Array.from({ length: selection.rangeCount }, (_, i) => selection.getRangeAt(i));
  if (!ranges.every((r) => root.contains(r.commonAncestorContainer))) return null;
  let text = "";
  let last: { key: string; surface: Element | null; bottom: number } | null = null;
  for (const run of root.querySelectorAll<HTMLElement>("[data-ooxml-selection-run]")) {
    const range = ranges.find((r) => r.intersectsNode(run));
    if (!range) continue;
    // The run, cut down to the selection where it begins or ends inside it.
    const part = run.ownerDocument.createRange();
    part.selectNodeContents(run);
    if (range.compareBoundaryPoints(Range.START_TO_START, part) > 0) part.setStart(range.startContainer, range.startOffset);
    if (range.compareBoundaryPoints(Range.END_TO_END, part) < 0) part.setEnd(range.endContainer, range.endOffset);
    const d = run.dataset;
    const surface = run.closest("[data-ooxml-selection-surface]");
    const paragraph = d.paragraphId ?? (d.sourcePath !== undefined ? `${d.sourceStory}|${d.sourceStoryInstance}|${d.sourcePath}` : null);
    const key = paragraph ?? `shape|${d.shapeId}`;
    const box = run.getBoundingClientRect();
    if (last) {
      // A Word paragraph may go on to the next page; a shape is on one slide.
      const apart = paragraph === null && (surface !== last.surface || box.top >= last.bottom - box.height / 2);
      if (key !== last.key || apart) text += "\n";
    }
    last = { key, surface, bottom: box.bottom };
    text += part.toString();
  }
  return text === "" ? null : text;
}
