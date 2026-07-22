# exav-grep

**`grep`, but it can see inside archives.**

Ordinary `grep -r` stops at the container: a ZIP, ISO, 7z or Word document is one
opaque binary blob to it. `exav-grep` walks *into* containers, recursively, and
searches every member as if it were a file on disk — reporting matches with a
path that shows the nesting.

```sh
exav-grep 'BEGIN RSA PRIVATE KEY' backups/
backups/2024.zip!home/dev/keys.tar!id_rsa:1:-----BEGIN RSA PRIVATE KEY-----
```

```rust
use exav_grep::{Matcher, Options, Searcher};

let matcher = Matcher::fixed("password", false)?;
let mut searcher = Searcher::new(matcher, Options::default());
// The sink returns `true` to keep going, `false` to stop the search.
searcher.search_path(std::path::Path::new("backup.zip"), &mut |ev| {
    println!("{ev}");
    true
})?;
```

## Everything happens in memory

No member is ever written to disk, so the zip-slip / path-traversal / symlink
class of bug does not arise — there is no path to traverse to. Extraction runs
under the same decompression-bomb budgets the exav scanner uses, so a malicious
archive cannot turn a search into an unbounded allocation.

`#![forbid(unsafe_code)]`, in this crate and in the extractor beneath it.

## Members that cannot be read are reported

A member that cannot be decoded — an unsupported codec, encryption without a
working password, a budget stop — is **not silently omitted from the results**.
It is surfaced as its own event, because "no matches" and "I could not look" are
different answers, and quietly conflating them is how a search tool lies to you.

The CLI prints those to stderr and sets a distinct exit code:

| code | meaning |
|---|---|
| 0 | matches found |
| 1 | no matches |
| 2 | a usage or I/O error |
| 3 | **no matches, but some members could not be read** — the search was incomplete |

Exit code 3 is the one that matters. Anything that scripts a search for secrets
or indicators across an archive tree needs to know the difference between a
clean result and an incomplete one.

## Formats

Whatever [`exav-unpack`](https://crates.io/crates/exav-unpack) opens: ZIP, RAR,
7z, tar and every common compressor, ISO and disk images, OLE/CFB and OOXML
documents, PDF, email (MIME/TNEF), CAB, ARJ, LHA, ZOO, EGG, ALZ and more —
nested arbitrarily deep, each format behind its own Cargo feature.

## License

MIT.
