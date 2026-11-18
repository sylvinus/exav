// What the charts of the Stats page share.

export const W = 640;
export const [LEFT, TOP] = [52, 20];

/** A value axis from 0: a round step for about four lines, and room above
 * the highest value for its label. */
export function axis(max: number) {
  const top = max || 1;
  const raw = top / 4;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * pow).find((s) => s >= raw)!;
  const ceiling = Math.ceil((top * 1.08) / step) * step;
  return { ceiling, ticks: Array.from({ length: Math.round(ceiling / step) + 1 }, (_, i) => i * step) };
}

/** Labels under the plot, tilted once they no longer fit side by side
 * (about 7 units a letter), and the room they take. */
export function categoryAxis(categories: string[], group: number) {
  const tilt = categories.some((c) => c.length * 7 > group - 6);
  return { tilt, bottom: tilt ? 16 + 5 * Math.max(...categories.map((c) => c.length)) : 28 };
}
