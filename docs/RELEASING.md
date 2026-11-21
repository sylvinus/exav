# Releasing

Everything to do between "the fixes are in" and a published version, in order.
`scripts/release.sh` checks the artifact and publishes it; this page is the
rest. Do not start a step before the one above it is green: a version number
published to crates.io is gone for good.

## 1. Freeze

- The tree builds from a clean checkout and `git status` is clean apart from the
  release edits below. No work in progress is left behind a feature flag that
  the release would ship half done.
- Open items worth settling first are in [BACKLOG.md](BACKLOG.md); anything the
  release changes the meaning of is written in the changelog (step 6), not
  deferred.

## 2. Dependencies

This is the late pass of [DEPENDENCIES.md](DEPENDENCIES.md) ("Lifecycle"). The
early pass, where replacements, vendoring and major upgrades are decided, is
done right after the previous release, not here: nothing in this step may
need a design decision. `make deps-review` prints what to compare with the last
`[[review]]` entry of [dependencies.toml](dependencies.toml); the entry is
rewritten at the end of this step.

- `cargo update` (workspace), then in each excluded workspace too:
  `fuzz`, `crates/exav-unpack-wasm`, `crates/exav-viewer`. Read what moved
  (`git diff Cargo.lock`), not just that the build passes.
- The pins stay on purpose, each with its reason and what lets it go in
  [dependencies.toml](dependencies.toml) (the image decoders at the versions
  libclamav links, `hayro-*`, `html5gum`, `wasm-bindgen` equal to the CLI's).
  A pin the script reports without an entry is a finding.
- The report's findings table lists what has a newer release; the policy of what
  may be added is [DEPENDENCIES.md](DEPENDENCIES.md).
- npm: `npm outdated` and `npm audit` in `crates/exav-viewer`,
  `crates/exav-unpack-wasm` and `www`.
- Audit: `cargo deny --all-features check advisories bans sources licenses`
  and `cargo audit` for the workspace, and `cargo deny` for the viewer and the
  unpack-wasm manifests as CI does (`.github/workflows/ci.yml`, job `audit`).
  An ignore in `deny.toml` whose crate has a fixed release is dropped, not
  kept.
- The MSRV: `rust-version` in `Cargo.toml` is raised only for a reason, and
  `make msrv` builds with it. Check the toolchain pinned in the workflows.

## 3. Code and format checks

- `make lint` (rustfmt and every clippy pass with `-D warnings`).
- `make test`: the native matrix, wasm32, the JS suites, the viewer (vitest,
  package, gates, playwright) and the site. `make test-native` alone is the
  Rust half. Read the output for skipped suites: a test that needs a tool that
  is missing reports green having checked nothing. `make test-yara-diff` fails
  instead, so run it with yara-x's `yr` and the rule corpus
  (`EXAV_DEBUG_YARA_CORPUS`).
- The viewer on every file of its demo: `make test-viewer` runs
  `e2e/examples.spec.ts`, which opens each example and each sidebar sample in
  headless Chromium, in the sandboxed frame and in the page, and fails on a
  file that is not shown (an "unsupported" one that is), on an error in the
  console and on a policy violation. CI runs the frame's half only
  (`EXAV_EXAMPLES_MODES=sandbox`), so the page's half is run here. Its list is the demo's
  (`demo/examples/examples.json`, exav-samples' `viewer/samples.json`): a
  file added there is tested with the next run.
- `scripts/check-features.sh`: each format feature of `exav-unpack` builds
  alone.
- `make av-audit` when fixtures changed (no EICAR literal committed unmasked).
- The release build over the whole tracked tree, with the full database:
  `git ls-files -z | xargs -0 target/release/exav -d <database>`. Nothing may
  be `FOUND`: a fixture that holds EICAR or a signature's match, whole or inside
  an archive, is committed masked (`.xor`). `PASSWORD-PROTECTED`,
  `UNSCANNABLE` and `LIMITS-EXCEEDED` lines are the fixtures made for them.
- The differential harnesses are research signals, not gates, and are run when
  the area changed: `scripts/difftest.sh` (against ClamAV), `make test-yara-diff`.

## 4. Fuzzing

- CI's `fuzz-smoke` (60 seconds a target) and the nightly campaign
  (`fuzz-nightly`, three hours) must be green on the commit to release.
- A longer round before a release that touched a reader:
  `TOTAL=14400 scripts/fuzz-campaign.sh`, or `TARGETS="..."` for the targets of
  the readers that changed. It builds every target first and stops if one does
  not build. Triage every artifact it reports ([FUZZING.md](FUZZING.md),
  "Triage & fix workflow"): each defect found gets a test that fails without the
  fix, and a line in the findings log.
- Seeds for a new reader or format are added to the seed scripts before the
  round, or it fuzzes nothing new.

## 5. Formats and documentation

- `formats/registry.json` is the one list of formats. After any change to it:
  `make formats` (rewrites the format matrix of the site and the READMEs, and
  the viewer summary sentence), then `make test-formats`.
- The format count in the READMEs and the site, the support matrix, and the
  pages that say what is read (`www/src/content/docs`) match the registry;
  `make test-www` builds the site and finds broken links and bad frontmatter.
- [GAPS.md](GAPS.md) lists what is reported and not opened; a format that
  became readable leaves it, one that was dropped joins it.
- Crate READMEs (`crates/*/README.md`) and the docs under `docs/` that quote a
  version, a flag or a limit: grep for the old version number (step 7) and for
  each option the release adds, renames or removes.

## 6. Changelog

- Move `[Unreleased]` to `[x.y.z] - date`, keep an empty `[Unreleased]` above
  it.
- Trim it to what a user of the release sees: one bullet per change in the
  user's terms (what was wrong or missing, what it does now), the numbers that
  show it, and the API that moved. Internal steps of a change that went in
  and out inside the release are not told. A change that breaks an API or a
  default is said as such.
- Every claim in it is checked against the code (limits, defaults, option
  names), and nothing in it names a private path or a corpus.

## 7. Versions

One edit of each, all to the same number:

- `Cargo.toml` (`[workspace.package]` version), and the `version = "..."` of
  every path dependency in `crates/*/Cargo.toml` (they are checked by
  `cargo publish`, not by the build).
- `crates/exav-unpack-wasm/Cargo.toml` and `package.json` (the release
  workflow fails if `package.json` differs from the tag), `crates/exav-viewer/Cargo.toml`
  and `package.json`.
- The lockfiles of the excluded workspaces, rewritten by building each.
- The snippets in the docs that show a version:
  `grep -rn "<old version>" --exclude-dir=target --exclude-dir=node_modules .`
  (`crates/exav/src/main.rs`, `docs/DATABASE.md`, `www/src/content/docs`...).
- The Helm chart (`deploy/helm`, version 0.0.0 in the repository) takes the
  tag's version when it is packaged; the `helm` workflow fails if the tag and
  the workspace version differ.

## 8. The new version against the earlier ones

With the versions bumped and committed, on the machine of the Stats page,
plugged in (a laptop on battery runs slower) and doing nothing else:

- `python3 -I scripts/stats.py candidate` builds what the release workflow
  builds (each binary for this machine's musl target, the WASI module, both
  npm packages), counts HEAD as `release` counts a tag, measures its `exav`
  in the same run as every release's against clamscan, and prints every
  figure of each release and of the new version side by side, with the change
  from the last release (`scripts/stats.py compare` prints it again). It needs
  `rustup target add <arch>-unknown-linux-musl`, what the npm builds need
  (wasm-pack, wasm-bindgen-cli, wasm-opt, and `npm ci` run on this machine in
  both package directories) and what `bench` needs, and takes about three
  hours. Its sizes are those of this machine's toolchain, not the workflow's.
- Each figure that got worse (slower, more memory, larger, more crates or
  `unsafe`, fewer tests or formats) is fixed or understood before the gate.

## 9. Gate and publish

- `scripts/release.sh --gate-only`, then `make publish-check` (the gate and
  `cargo publish --dry-run` of every crate), then `make publish`.
  The gate checks the tree is clean, the version is free on crates.io, fmt and
  clippy, the tests, the MSRV, the package contents, that the manifests of the
  packages with a binary carry the workspace's `[profile.release]` and
  `[profile.fast-build]` (the script copies them in, as `cargo install` reads
  only a package's own), that the published tarballs build on their own, that
  no crate tarball or the binary built from them holds a path of the machine
  (see below), and that no EICAR literal is in a tarball or in the tracked
  tree. It stops for a human before the first upload.
- Tag `vX.Y.Z` and push the tag: `.github/workflows/release.yml` builds the
  binaries, the WASI module and the two npm tarballs (`@exav/unpack-wasm`,
  `@exav/viewer`), `docker.yml` the image. The npm packages are published from
  those tarballs, downloaded from the release page, and never built or packed
  on another machine, so that npm and the release carry the same bytes:
  `npm publish exav-unpack-wasm-X.Y.Z.tgz`, then `npm publish
  exav-viewer-X.Y.Z.tgz` (the workflow ran the `prepublishOnly` checks of both
  before packing; publishing a tarball does not run them).
- After: install from the registry in a clean directory (`cargo install exav`,
  `npm install @exav/viewer`), run `exav --version` and scan the EICAR test
  file; check the release page's assets and the image. Each npm package is the
  release's tarball: `npm pack @exav/viewer@X.Y.Z` in a clean directory gives a
  file `cmp` finds identical to the asset.

No build path in a released file: every build of one maps the checkout, the
cargo home and the rustup home to `/exav`, `/cargo` and `/rustup`
(`scripts/build-flags.sh` prints the `RUSTFLAGS`; `release.sh`, the workflows,
`npm run build` in `crates/exav-unpack-wasm`, `crates/exav-viewer/scripts/build-wasm.sh`
and `stats.py candidate` use it). Cargo's `trim-paths` is not stable in any
Cargo up to 1.99, the MSRV is 1.95. `scripts/check-build-paths.py` refuses a
file that holds `/Users/`, `/home/`, `C:\Users\` or this machine's checkout,
cargo home, rustup home or home directory, looking inside archives (tarballs,
zips, a saved image); `--source` is for crate tarballs, whose tests name
`/home/x` as an example. It runs in `release.sh` (the crates and the binary built
from them), in the release workflow (the archives of the binaries before the first
upload, the npm tarballs and the WASI module), in `docker.yml` (the binaries the
image is made of, in the job that builds them and in the one that pushes) and in
`helm.yml` (the chart). A build made by hand without the flags fails it. The
viewer ships three wasm parsers of `@silurus/ooxml` and pdf.js's worker as they
were published, and the gate lists them by name (`--except`); a new version of
either that holds a path of its own is a decision, not a gate to loosen.
`scripts/test-build-paths.sh` tests the script (it is in `make test-native`).
- Once the site is deployed, the viewer again on every file of the demo, as
  the deployed server sends them (its headers and compression are not the
  preview server's): from `crates/exav-viewer`, with the demo's files copied
  in (`npm run demo:showcase`, `npm run demo:examples`),
  `E2E_BASE_URL=https://exav.org/viewer/demo/ npx playwright test e2e/examples.spec.ts --project=chromium`.

## 10. Stats

Once the release workflow has attached every binary and both npm packages are
out, on the machine that measured the earlier releases, plugged in and doing
nothing else:

- `python3 -I scripts/stats.py release X.Y.Z` writes
  `www/src/data/stats/X.Y.Z.json` (lines, crates, `unsafe`, tests, formats,
  sizes), from the tag and what was published.
- `python3 -I scripts/stats.py bench` measures every release again against
  clamscan and rewrites `bench.json` (about two hours; the corpus and the
  signatures of `freshclam` are needed, and `--work` has to be on a local
  disk).
- Commit both: the site's Stats page reads them when it is built.
