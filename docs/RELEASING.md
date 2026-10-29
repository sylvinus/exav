# Releasing

Everything to do between "the fixes are in" and a published version, in order.
`scripts/release.sh` is the last step and checks the artifact; this page is the
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
- Audit: `cargo deny check advisories bans sources licenses` and `cargo audit`
  for the workspace, and `cargo deny` for the viewer and the unpack-wasm
  manifests as CI does (`.github/workflows/ci.yml`, job `audit`). An ignore in
  `deny.toml` whose crate has a fixed release is dropped, not kept.
- The MSRV: `rust-version` in `Cargo.toml` is raised only for a reason, and
  `make msrv` builds with it. Check the toolchain pinned in the workflows.

## 3. Code and format checks

- `make lint` (rustfmt and every clippy pass with `-D warnings`).
- `make test`: the native matrix, wasm32, the JS suites, the viewer (vitest,
  package, gates, playwright) and the site. `make test-native` alone is the
  Rust half. Read the output for skipped suites: a test that needs a tool that
  is missing reports green having checked nothing (`make test-yara-diff` is the
  one to name).
- `scripts/check-features.sh`: each format feature of `exav-unpack` builds
  alone.
- `make av-audit` when fixtures changed (no EICAR literal committed unmasked).
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

## 8. Gate and publish

- `scripts/release.sh --gate-only`, then `make publish-check` (the gate and
  `cargo publish --dry-run` of every crate), then `make publish`.
  The gate checks the tree is clean, the version is free on crates.io, fmt and
  clippy, the tests, the MSRV, the package contents, that the published
  tarballs build on their own, and that no EICAR literal is in a tarball or in
  the tracked tree. It stops for a human before the first upload.
- Tag `vX.Y.Z` and push the tag: `.github/workflows/release.yml` builds the
  binaries and the npm tarball, `docker.yml` the image. The npm packages are
  published from their crate directories, not from `pkg/`.
- After: install from the registry in a clean directory (`cargo install exav`,
  `npm install @exav/viewer`), run `exav --version` and scan the EICAR test
  file; check the release page's assets and the image.
