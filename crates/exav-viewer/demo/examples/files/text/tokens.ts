// An arithmetic tokenizer and evaluator. CC0-1.0, exav project.
type Token = { kind: "num"; value: number } | { kind: "op"; value: "+" | "-" | "*" | "/" | "^" } | { kind: "paren"; value: "(" | ")" };

export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const re = /\s*(?:(\d+(?:\.\d+)?)|([-+*/^])|([()]))/y;
  let match: RegExpExecArray | null;
  while (re.lastIndex < source.length && (match = re.exec(source))) {
    if (match[1] !== undefined) tokens.push({ kind: "num", value: Number(match[1]) });
    else if (match[2]) tokens.push({ kind: "op", value: match[2] as "+" });
    else tokens.push({ kind: "paren", value: match[3] as "(" });
  }
  if (re.lastIndex < source.trimEnd().length) throw new SyntaxError(`unexpected character at ${re.lastIndex}`);
  return tokens;
}

const PRECEDENCE: Record<string, [number, "left" | "right"]> = { "+": [1, "left"], "-": [1, "left"], "*": [2, "left"], "/": [2, "left"], "^": [3, "right"] };

/** Evaluates with the shunting-yard algorithm. */
export function evaluate(source: string): number {
  const out: number[] = [];
  const ops: string[] = [];
  const apply = (op: string) => {
    const b = out.pop();
    const a = out.pop();
    if (a === undefined || b === undefined) throw new SyntaxError("missing operand");
    out.push(op === "+" ? a + b : op === "-" ? a - b : op === "*" ? a * b : op === "/" ? a / b : a ** b);
  };
  for (const t of tokenize(source)) {
    if (t.kind === "num") out.push(t.value);
    else if (t.kind === "op") {
      const [p, assoc] = PRECEDENCE[t.value]!;
      while (ops.length) {
        const top = ops[ops.length - 1]!;
        const [tp] = PRECEDENCE[top] ?? [-1];
        if (top !== "(" && (tp > p || (tp === p && assoc === "left"))) apply(ops.pop()!);
        else break;
      }
      ops.push(t.value);
    } else if (t.value === "(") ops.push("(");
    else {
      while (ops.length && ops[ops.length - 1] !== "(") apply(ops.pop()!);
      if (ops.pop() !== "(") throw new SyntaxError("unbalanced parenthesis");
    }
  }
  while (ops.length) {
    const op = ops.pop()!;
    if (op === "(") throw new SyntaxError("unbalanced parenthesis");
    apply(op);
  }
  return out[0] ?? NaN;
}

console.log(evaluate("2 + 3 * (4 - 1) ^ 2"));
