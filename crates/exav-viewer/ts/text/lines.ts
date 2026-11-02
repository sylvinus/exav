/** A piece of a line, with the class that colours it. */
export type Seg = readonly [text: string, cls?: string];

/** A line: plain text, or pieces. */
export type Line = string | readonly Seg[];

export const lineLength = (line: Line): number => (typeof line === "string" ? line.length : line.reduce((n, s) => n + s[0].length, 0));

export const lineText = (line: Line): string => (typeof line === "string" ? line : line.map((s) => s[0]).join(""));

/**
 * Collects lines up to a cap. Past it, `full` is true and nothing more is
 * kept, so that a producer can stop early.
 */
export class LineBuilder {
  readonly lines: Line[] = [];
  private current: Seg[] = [];
  full = false;

  constructor(private readonly max: number) {}

  add(text: string, cls?: string): void {
    if (text) this.current.push(cls ? [text, cls] : [text]);
  }

  /** Ends the line. */
  end(): void {
    if (this.lines.length >= this.max) {
      this.full = true;
      this.current = [];
      return;
    }
    this.lines.push(this.current);
    this.current = [];
  }

  /** Ends the line being written if it has anything. */
  finish(): void {
    if (this.current.length) this.end();
  }
}
