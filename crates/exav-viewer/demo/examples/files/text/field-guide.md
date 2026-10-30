# Field guide to Markdown

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
