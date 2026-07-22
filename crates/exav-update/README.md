# exav-update

**A standalone signature-database fetcher for exav.**

It fetches ClamAV-format CVD/CLD containers, plain signature files, and exav's
own prebuilt `.exavdb`, over plain conditional HTTPS.

## exav bundles no URLs

The caller supplies them — `--sig-sources` and `--db-url`.
Nothing here points at any vendor by default: exav treats Cisco's "official"
CVDs as three more URLs, no different from any other feed. Which mirrors you
trust is your decision, not a default compiled into a binary.

## Why it is a separate crate

This is the single place a TLS stack (`ureq → rustls → ring`) enters the tree,
kept out of `exav-core` so the scanning engine stays pure Rust and links no
C or assembly at all. A deployment that updates its database out-of-band — from
a config-management system, a container image, or a shared volume — never builds
this crate and never links that stack.

It contains no `unsafe` of its own (`#![forbid(unsafe_code)]`); the only native
code anywhere beneath it is the transitive `ring`.

## What a fetch is

A conditional HTTPS `GET`. An `ETag`/`Last-Modified` validator — or, failing
that, a byte-comparison against the on-disk copy — decides whether anything
changed. The body is validated before it can overwrite a good file, and the
install is atomic (write to a temporary file, then rename), so an interrupted
update leaves the previous database intact rather than a truncated one.

A downloaded `.exavdb` carries an embedded SHA-256 which is verified before
installation, for the same reason.

## What it does not do

There is **no digital-signature verification** and **no rsync**. For GPG-signed
or rsync-only feeds (Sanesecurity, for example), run `clamav-unofficial-sigs`
into the signature directory and let exav read what it leaves there. Claiming to
verify a signature without doing so would be worse than not offering it.

## License

MIT.
