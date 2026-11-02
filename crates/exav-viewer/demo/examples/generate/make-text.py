#!/usr/bin/env python3
"""Writes the demo's text examples into ../files/text/.

    python3 -I make-text.py [OUT_DIR]

Output: CC0-1.0, a public domain dedication by the exav project. Everything
here is written for the demo: the prose, the data (made up, from a seeded
random generator) and the programs.

Needs: Python 3.
"""
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "files", "text")
os.makedirs(OUT, exist_ok=True)


def write(name, text):
    with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


FILES = {}

FILES["field-guide.md"] = r"""# Field guide to Markdown

A short document that uses most of what Markdown can say. It is written for the
exav demo and is in the public domain (CC0-1.0).

## Emphasis and spans

Text can be **bold**, *italic*, ***both***, ~~struck through~~ or `code`. A line
that ends with two spaces
breaks without starting a paragraph. A [link with a title](https://exav.org/ "exav.org"),
an autolink <https://exav.org/viewer/>, and a reference link: [the demo][demo].

[demo]: https://exav.org/viewer/demo/

Escapes: \*not italic\*, 2 \< 3, a literal backtick \`, and entities: &copy; &amp; &eacute;.
Unicode goes through unchanged: café, naïve, Ωmega, Жук, 日本語, مرحبا, ☃.

## Headings

### Third level
#### Fourth level
##### Fifth level
###### Sixth level

Setext heading
==============

Another one
-----------

## Lists

- A bullet
- Another, with a nested list:
  - second level
    - third level
  - back to the second
- And a last one

1. Numbered
2. Items
   1. Nested numbers
   2. Continue
3. Done

7. A list that starts at seven
8. and goes on

- [x] A finished task
- [ ] An open task
- [ ] Another open task, with `code` in it

Loose list:

- First paragraph.

  A second paragraph inside the same item.

- Next item.

## Quotes

> A quotation, which can wrap over several lines and holds
> *other* **formatting**.
>
> > A quotation inside it.
>
> - and a list

## Tables

| Left | Centre | Right |
| :--- | :----: | ----: |
| a | b | c |
| `code` | **bold** | 1,234.50 |
| A longer cell that holds more words | x | 7 |

## Code

Inline `let x = 1;` and a fenced block with a language:

```rust
fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a + b);
    }
    a
}
```

```python
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
```

```diff
- old line
+ new line
```

An indented block:

    four spaces make this code
    and it keeps   its spacing

## Rules, HTML and footnotes

---

Inline HTML such as <kbd>Ctrl</kbd> + <kbd>C</kbd> and <sub>sub</sub> and <sup>sup</sup> is
shown as text or ignored, never run: <script>alert(1)</script> does nothing.

A sentence with a footnote.[^1] And another one.[^note]

[^1]: The first footnote.
[^note]: A second, with *formatting*.

![An image reference](https://example.invalid/not-fetched.png)

The end.
"""

FILES["field-notes.txt"] = """Field notes
===========

Plain text is shown as it is written: line breaks, indentation, tabs and
long lines are kept.

	A line that starts with a tab.
        A line that starts with eight spaces.

A very long line, to see how the viewer wraps or scrolls it: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.

Pangrams, one for each script:

  English   The quick brown fox jumps over the lazy dog.
  Français Portez ce vieux whisky au juge blond qui fume.
  Deutsch   Zwölf Boxkämpfer jagen Viktor quer über den großen Sylter Deich.
  Español  El pingüino Wenceslao hizo kilómetros bajo exhaustiva lluvia y frío.
  Ελληνικά   Ξεσκεπάζω την ψυχοφθόρα βδελυγμία.
  Русский   Съешь же ещё этих мягких французских булок да выпей чаю.
  日本語    いろはにほへと ちりぬるを わかよたれそ つねならむ
  العربية   نص حكيم له سر قاطع وذو شأن عظيم مكتوب على ثوب أخضر ومزخرف
  עברית    דג סקרן שט בים מאוכזב ולפתע מצא לו חברה איך הקליטה

Symbols and box drawing:

  ┌──────┬──────┐   ← ↑ → ↓   ✓ ✗   ½ ⅓ ¾   ± × ÷ ≠ ≤ ≥ ∞
  │ a    │ b    │   € £ ¥ ₿   © ® ™   ☀ ☁ ☂ ☃
  └──────┴──────┘

The last line has no newline at the end."""

FILES["recipes.json"] = json.dumps(
    {
        "title": "A small recipe book",
        "version": 3,
        "published": True,
        "updated": None,
        "tags": ["cooking", "demo", "café", "日本語"],
        "numbers": {"integer": 42, "negative": -7, "float": 3.14159, "exponent": 6.02e23, "tiny": 1e-9, "zero": 0},
        "recipes": [
            {
                "name": "Crepes",
                "serves": 4,
                "time": {"prep_min": 10, "rest_min": 30, "cook_min": 20},
                "ingredients": [{"item": "flour", "amount": 250, "unit": "g"}, {"item": "milk", "amount": 0.5, "unit": "l"}, {"item": "eggs", "amount": 3, "unit": None}, {"item": "salt", "amount": "a pinch"}],
                "steps": ["Whisk the flour and eggs.", "Add the milk slowly.", "Rest for 30 minutes.", "Cook in a hot pan, a minute a side."],
                "nutrition": {"kcal": 210, "protein_g": 8.5, "vegetarian": True},
            },
            {
                "name": "Ratatouille",
                "serves": 6,
                "time": {"prep_min": 25, "cook_min": 60},
                "ingredients": [{"item": "aubergine", "amount": 2}, {"item": "courgette", "amount": 3}, {"item": "tomatoes", "amount": 500, "unit": "g"}, {"item": "olive oil", "amount": 4, "unit": "tbsp"}],
                "steps": ["Dice the vegetables.", "Fry each in turn.", "Stew together for an hour."],
                "nutrition": {"kcal": 160, "protein_g": 3.1, "vegetarian": True, "vegan": True},
            },
        ],
        "nested": {"a": {"b": {"c": {"d": {"e": [1, [2, [3, [4, [5]]]]]}}}}},
        "escapes": "quote \" backslash \\ slash / newline \n tab \t unicode é 中 😀",
        "empty": {"object": {}, "array": [], "string": ""},
    },
    indent=2,
    ensure_ascii=False,
) + "\n"

FILES["config.yaml"] = """# A configuration file, to show YAML as text.
service:
  name: harbour-register
  port: 8080
  debug: false
  tags: [boats, berths, "quay east"]
  limits:
    requests_per_minute: 600
    body_bytes: 1048576
database:
  url: postgres://register@localhost:5432/harbour
  pool: {min: 2, max: 10}
berths:
  - number: 1
    length_m: 6.5
    vessel: Aurora
  - number: 2
    length_m: 8.2
    vessel: Brise
notes: |
  A block of text that keeps
  its line breaks.
folded: >
  A block of text that is
  folded into one line.
anchors:
  base: &base {retries: 3, timeout_s: 30}
  copy: *base
"""

FILES["pyproject.toml"] = """# A project file, to show TOML as text.
[project]
name = "harbour-register"
version = "1.4.0"
description = "The mooring register of the east quay"
requires-python = ">=3.11"
dependencies = ["httpx>=0.27", "pydantic>=2"]

[project.optional-dependencies]
test = ["pytest", "pytest-cov"]

[tool.ruff]
line-length = 100
select = ["E", "F", "I"]

[[tool.harbour.berths]]
number = 1
length = 6.5

[[tool.harbour.berths]]
number = 2
length = 8.2
"""

FILES["feed.xml"] = """<?xml version="1.0" encoding="UTF-8"?>
<!-- An Atom feed, to show XML as text. -->
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <title>Notes from the east quay</title>
  <subtitle type="html">Moorings, tides &amp; weather</subtitle>
  <link href="https://example.invalid/feed.xml" rel="self"/>
  <link href="https://example.invalid/"/>
  <id>urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6</id>
  <updated>2000-01-03T12:00:00Z</updated>
  <author><name>The harbour office</name><email>office@example.invalid</email></author>
  <entry>
    <title>New berths on the east quay</title>
    <link href="https://example.invalid/2000/01/berths"/>
    <id>urn:uuid:1225c695-cfb8-4ebb-aaaa-80da344efa6a</id>
    <updated>2000-01-03T12:00:00Z</updated>
    <summary>Twelve berths for visiting boats open on 1 March.</summary>
    <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>The <b>east quay</b> is longer by 40&#160;metres.</p></div></content>
    <category term="moorings"/>
  </entry>
  <entry>
    <title>Tide tables for the year</title>
    <link href="https://example.invalid/2000/01/tides"/>
    <id>urn:uuid:1225c695-cfb8-4ebb-aaaa-80da344efa6b</id>
    <updated>2000-01-01T08:00:00Z</updated>
    <summary><![CDATA[High water at 06:12 & 18:34; low water at <12:00.]]></summary>
  </entry>
</feed>
"""


def gpx():
    pts = []
    for i in range(60):
        t = i / 59
        lat = 48.3794 + 0.03 * math.sin(t * 5) + 0.01 * t
        lon = -4.4900 + 0.06 * t + 0.01 * math.cos(t * 7)
        ele = 20 + 15 * math.sin(t * 9) + 10 * t
        pts.append(f'      <trkpt lat="{lat:.5f}" lon="{lon:.5f}"><ele>{ele:.1f}</ele><time>2000-01-01T{8 + i // 60:02d}:{i % 60:02d}:00Z</time></trkpt>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<gpx version="1.1" creator="exav make-text.py" xmlns="http://www.topografix.com/GPX/1/1">\n'
        "  <metadata><name>Coastal walk (made up)</name><desc>A made-up track, 60 points.</desc></metadata>\n"
        '  <wpt lat="48.3794" lon="-4.4900"><name>Start</name><sym>Flag</sym></wpt>\n'
        '  <wpt lat="48.4100" lon="-4.4300"><name>Viewpoint</name><desc>Seals on the rocks, in winter.</desc></wpt>\n'
        "  <trk>\n    <name>Morning walk</name>\n    <trkseg>\n" + "\n".join(pts) + "\n    </trkseg>\n  </trk>\n</gpx>\n"
    )


FILES["route.gpx"] = gpx()

FILES["places.kml"] = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Places (made up)</name>
    <Style id="harbour"><IconStyle><color>ff0000ff</color><scale>1.2</scale></IconStyle><PolyStyle><color>7f00ff00</color></PolyStyle></Style>
    <Placemark>
      <name>East quay</name>
      <description><![CDATA[<b>Moorings</b> for 60 boats.]]></description>
      <styleUrl>#harbour</styleUrl>
      <Point><coordinates>-4.4860,48.3830,0</coordinates></Point>
    </Placemark>
    <Placemark>
      <name>Breakwater</name>
      <LineString><tessellate>1</tessellate><coordinates>-4.4900,48.3790,0 -4.4850,48.3820,0 -4.4800,48.3835,0</coordinates></LineString>
    </Placemark>
    <Placemark>
      <name>Anchorage</name>
      <styleUrl>#harbour</styleUrl>
      <Polygon><outerBoundaryIs><LinearRing><coordinates>-4.4950,48.3850,0 -4.4900,48.3850,0 -4.4900,48.3900,0 -4.4950,48.3900,0 -4.4950,48.3850,0</coordinates></LinearRing></outerBoundaryIs></Polygon>
    </Placemark>
  </Document>
</kml>
"""


def harbour_csv():
    rng = random.Random(11)
    boats = ["Aurora", "Brise", "Calypso", "Dorade", "Etoile", "Fauvette", "Goeland", "Hirondelle", "Iroise", "Jolie Brise", "Kerguelen", "La Mouette"]
    kinds = ["sloop", "ketch", "trawler", "motor yacht", "catamaran", "dinghy"]
    notes = ["", "", "", "Arrived late, \"quiet\" night", "Bill sent; paid by cheque", "Owner: M. Le Gall, tel. 02 98 00 00 00", "Two nights,\nleft at dawn", "Café voucher given", ""]
    rows = ["date,vessel,type,length_m,beam_m,berth,nights,fee_eur,notes"]

    def q(s):
        s = str(s)
        return '"' + s.replace('"', '""') + '"' if any(c in s for c in ',"\n') else s

    for i in range(300):
        d = 1 + i // 10
        month = 1 + (d - 1) // 28
        day = 1 + (d - 1) % 28
        length = round(rng.uniform(4.5, 16.0), 1)
        nights = rng.randint(1, 5)
        rows.append(",".join(q(v) for v in [f"2000-{month:02d}-{day:02d}", rng.choice(boats) + (f" {i // 40 + 2}" if i > 40 else ""), rng.choice(kinds), length, round(length * 0.33, 2), rng.randint(1, 60), nights, f"{nights * (8 + length * 1.6):.2f}", rng.choice(notes)]))
    return "\n".join(rows) + "\n"


FILES["harbour-log.csv"] = harbour_csv()

FILES["tides.tsv"] = "day\thigh_1\theight_1_m\tlow_1\theight_2_m\tcoefficient\n" + "\n".join(
    f"{d}\t{(5 + d * 0.8) % 24:05.2f}\t{4.5 + 2.4 * math.sin(d / 4.7):.2f}\t{(11 + d * 0.8) % 24:05.2f}\t{1.2 + 0.8 * math.cos(d / 4.7):.2f}\t{int(70 + 40 * math.sin(d / 4.7))}" for d in range(1, 29)
) + "\n"

FILES["prix.csv"] = "Région;Produit;Quantité;Prix unitaire (€);Total (€)\n" + "\n".join(
    f"{r};{p};{q};{u:.2f}".replace(".", ",") + ";" + f"{q * u:.2f}".replace(".", ",")
    for r, p, q, u in [("Bretagne", "Cidre", 120, 3.5), ("Bretagne", "Galettes", 300, 1.2), ("Normandie", "Cidre", 90, 3.8), ("Normandie", "Camembert", 200, 4.1), ("Alsace", "Riesling", 150, 7.9), ("Alsace", "Bretzels", 500, 0.6)]
) + "\n"

FILES["life.py"] = '''"""Conway's Game of Life on a torus, printed as text. CC0-1.0, exav project."""
import random
import sys

WIDTH, HEIGHT = 40, 16


def step(cells):
    """The next generation of a set of (x, y) cells on a WIDTH by HEIGHT torus."""
    counts = {}
    for (x, y) in cells:
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if dx or dy:
                    key = ((x + dx) % WIDTH, (y + dy) % HEIGHT)
                    counts[key] = counts.get(key, 0) + 1
    return {cell for cell, n in counts.items() if n == 3 or (n == 2 and cell in cells)}


def show(cells):
    return "\\n".join("".join("#" if (x, y) in cells else "." for x in range(WIDTH)) for y in range(HEIGHT))


def main(generations=20, seed=7):
    rng = random.Random(seed)
    cells = {(x, y) for x in range(WIDTH) for y in range(HEIGHT) if rng.random() < 0.25}
    for g in range(generations):
        print(f"generation {g}: {len(cells)} cells")
        print(show(cells))
        cells = step(cells)


if __name__ == "__main__":
    main(*(int(a) for a in sys.argv[1:3]))
'''

FILES["lru.rs"] = '''//! A small least-recently-used cache. CC0-1.0, exav project.
use std::collections::HashMap;
use std::hash::Hash;

/// A cache that keeps at most `capacity` entries and drops the one used longest ago.
pub struct Lru<K, V> {
    capacity: usize,
    tick: u64,
    entries: HashMap<K, (V, u64)>,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "a cache holds at least one entry");
        Lru { capacity, tick: 0, entries: HashMap::with_capacity(capacity) }
    }

    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.tick += 1;
        let tick = self.tick;
        self.entries.get_mut(key).map(|(v, used)| {
            *used = tick;
            &*v
        })
    }

    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        self.tick += 1;
        if !self.entries.contains_key(&key) && self.entries.len() == self.capacity {
            let oldest = self.entries.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(key, (value, self.tick)).map(|(v, _)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_the_least_recently_used() {
        let mut c = Lru::new(2);
        c.put("a", 1);
        c.put("b", 2);
        assert_eq!(c.get(&"a"), Some(&1));
        c.put("c", 3);
        assert_eq!(c.get(&"b"), None);
        assert_eq!(c.len(), 2);
    }
}
'''

FILES["tokens.ts"] = '''// An arithmetic tokenizer and evaluator. CC0-1.0, exav project.
type Token = { kind: "num"; value: number } | { kind: "op"; value: "+" | "-" | "*" | "/" | "^" } | { kind: "paren"; value: "(" | ")" };

export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  const re = /\\s*(?:(\\d+(?:\\.\\d+)?)|([-+*/^])|([()]))/y;
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
'''

FILES["bits.c"] = '''/* Bit tricks on 32-bit words. CC0-1.0, exav project. */
#include <stdint.h>
#include <stdio.h>

/* The number of set bits, by the parallel sum. */
static unsigned popcount32(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0f0f0f0fu;
    return (x * 0x01010101u) >> 24;
}

/* The index of the highest set bit, or -1 for zero. */
static int high_bit(uint32_t x) {
    int n = -1;
    while (x) {
        n++;
        x >>= 1;
    }
    return n;
}

/* The next power of two that is not below x. */
static uint32_t next_pow2(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

/* The bits of x in reverse order. */
static uint32_t reverse32(uint32_t x) {
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    return (x >> 16) | (x << 16);
}

int main(void) {
    const uint32_t samples[] = {0u, 1u, 255u, 1000u, 0xdeadbeefu};
    for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
        uint32_t v = samples[i];
        printf("%10u: bits %2u, high %2d, pow2 %10u, reversed %08x\\n", v, popcount32(v), high_bit(v), next_pow2(v), reverse32(v));
    }
    return 0;
}
'''

FILES["report.sql"] = """-- Moorings by month, with window functions. CC0-1.0, exav project.
CREATE TABLE vessel (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    length_m  REAL NOT NULL CHECK (length_m > 0),
    kind      TEXT NOT NULL DEFAULT 'sloop'
);

CREATE TABLE stay (
    id        INTEGER PRIMARY KEY,
    vessel_id INTEGER NOT NULL REFERENCES vessel (id),
    berth     INTEGER NOT NULL,
    arrived   DATE NOT NULL,
    nights    INTEGER NOT NULL,
    fee_eur   NUMERIC(8, 2)
);

CREATE INDEX stay_by_arrival ON stay (arrived);

WITH monthly AS (
    SELECT strftime('%Y-%m', arrived) AS month,
           count(*)                    AS stays,
           sum(nights)                 AS nights,
           sum(fee_eur)                AS income
    FROM stay
    GROUP BY 1
)
SELECT month,
       stays,
       income,
       income - lag(income) OVER (ORDER BY month) AS change,
       round(100.0 * income / sum(income) OVER (), 1) AS share_pct,
       rank() OVER (ORDER BY income DESC) AS income_rank
FROM monthly
ORDER BY month;

-- The ten longest boats that stayed more than three nights.
SELECT v.name, v.length_m, s.nights
FROM vessel AS v
JOIN stay AS s ON s.vessel_id = v.id
WHERE s.nights > 3 AND v.kind IN ('ketch', 'trawler')
ORDER BY v.length_m DESC
LIMIT 10;
"""

FILES["deploy.sh"] = """#!/usr/bin/env bash
# Build, check and copy a static site. CC0-1.0, exav project.
set -euo pipefail

SITE_DIR="${SITE_DIR:-./public}"
REMOTE="${REMOTE:-deploy@example.invalid:/var/www/site}"
LOG="$(mktemp)"

cleanup() {
  local status=$?
  rm -f "$LOG"
  if [ "$status" -ne 0 ]; then
    echo "deploy failed with status $status" >&2
  fi
}
trap cleanup EXIT

log() { printf '[%s] %s\\n' "$(date +%H:%M:%S)" "$*"; }

build() {
  log "building"
  npm ci --silent >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
  npm run build --silent
}

check() {
  local broken=0
  while IFS= read -r -d '' file; do
    if ! grep -q '</html>' "$file"; then
      log "incomplete page: $file"
      broken=$((broken + 1))
    fi
  done < <(find "$SITE_DIR" -name '*.html' -print0)
  return "$broken"
}

case "${1:-all}" in
  build) build ;;
  check) check ;;
  all)   build && check && rsync -az --delete "$SITE_DIR/" "$REMOTE" && log "done" ;;
  *)     echo "usage: $0 [build|check|all]" >&2; exit 2 ;;
esac
"""

FILES["style.css"] = """/* A small stylesheet with custom properties, grid and a media query. CC0-1.0, exav project. */
:root {
  --ink: #1b2430;
  --paper: #fbfaf7;
  --accent: #0b7285;
  --radius: 0.5rem;
  --gap: clamp(0.75rem, 2vw, 1.5rem);
  color-scheme: light dark;
}

@media (prefers-color-scheme: dark) {
  :root { --ink: #e7edf3; --paper: #12171d; --accent: #66d9e8; }
}

*, *::before, *::after { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 1rem/1.55 system-ui, sans-serif;
}

.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
  gap: var(--gap);
  padding: var(--gap);
}

.card {
  padding: 1rem;
  border: 1px solid color-mix(in srgb, var(--ink) 20%, transparent);
  border-radius: var(--radius);
  transition: transform 120ms ease, box-shadow 120ms ease;
}

.card:hover,
.card:focus-within {
  transform: translateY(-2px);
  box-shadow: 0 6px 18px rgb(0 0 0 / 0.12);
}

.card > h2::after { content: " \\2192"; color: var(--accent); }

a:not([class]) { color: var(--accent); text-underline-offset: 0.2em; }

@media (max-width: 40rem) {
  .cards { grid-template-columns: 1fr; }
}
"""

FILES["page.html"] = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>A page, shown as its source</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="style.css">
  <style>.note { font-style: italic; }</style>
</head>
<body>
  <!-- HTML is shown as text: nothing in this file runs. CC0-1.0, exav project. -->
  <header><h1>Harbour office</h1><nav><a href="#berths">Berths</a> <a href="#tides">Tides</a></nav></header>
  <main>
    <section id="berths">
      <h2>Berths</h2>
      <table>
        <thead><tr><th scope="col">Berth</th><th scope="col">Length</th></tr></thead>
        <tbody><tr><td>1</td><td>6.5&nbsp;m</td></tr><tr><td>2</td><td>8.2&nbsp;m</td></tr></tbody>
      </table>
      <p class="note">Lengths are over all, in metres.</p>
    </section>
    <form action="/search" method="get"><label>Boat <input name="q" type="search" required></label> <button>Search</button></form>
  </main>
  <script>
    document.querySelectorAll("nav a").forEach((a) => a.addEventListener("click", () => console.log(a.hash)));
  </script>
</body>
</html>
"""

FILES["changes.diff"] = """diff --git a/src/berths.py b/src/berths.py
index 3f2a1c4..9b7d0e8 100644
--- a/src/berths.py
+++ b/src/berths.py
@@ -10,12 +10,16 @@ class Berth:
     number: int
     length_m: float
+    max_draught_m: float = 1.5

     def fits(self, boat):
-        return boat.length_m <= self.length_m
+        return boat.length_m <= self.length_m and boat.draught_m <= self.max_draught_m

     def label(self):
-        return "Berth %d" % self.number
+        return f"Berth {self.number} ({self.length_m:.1f} m)"
@@ -40,7 +44,7 @@ def free_berths(register, boat):
     for berth in register:
         if berth.fits(boat):
             yield berth
-    return
+    return None
diff --git a/README.md b/README.md
index 1e2d3f4..5a6b7c8 100644
--- a/README.md
+++ b/README.md
@@ -1,4 +1,5 @@
 # Harbour register

 The mooring register of the east quay.
+Berths now have a maximum draught.
"""

FILES["subtitles.srt"] = "\n".join(
    f"{i}\n00:00:{2 * i:02d},000 --> 00:00:{2 * i + 1:02d},800\n{line}\n"
    for i, line in enumerate(["The tide is coming in.", "Berth fourteen is free.", "<i>A gull laughs.</i>", "Take the line, please.", "Engine off, thank you.", "Welcome to the east quay."], 1)
)

FILES["server.log"] = "".join(
    f'2000-01-01T{8 + i // 60:02d}:{i % 60:02d}:{(i * 7) % 60:02d}Z {["INFO", "INFO", "INFO", "WARN", "ERROR"][i % 5]} request id={1000 + i} path=/berths/{i % 60 + 1} status={[200, 200, 304, 404, 500][i % 5]} ms={12 + (i * 37) % 250}\n' for i in range(120)
)

for name, text in FILES.items():
    write(name, text)
