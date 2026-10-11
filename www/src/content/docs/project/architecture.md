---
title: Technical architecture
description: How exav's crates and WebAssembly packages depend on each other, and why the extractor, the emulator and the decoders are crates of their own.
---

exav is a Cargo workspace of focused crates rather than one binary, plus two
WebAssembly packages built outside the workspace with their own profile. How
the scanner works inside is in
[How scanning works](/scanner/concepts/how-it-works/), and how the extractor
does in [How extraction works](/unpack/how-it-works/).

## How the crates compose

The CLI (which is also the daemon) drives the scanning engine, `exav-core`,
which also builds its own WASI binary, `exav-wasm` (feature `wasi-bin`). Two
front ends use only the extractor, `exav-unpack`: the archive grep and
`@exav/unpack-wasm`. `@exav/viewer`'s wasm modules use only `exav-render`.

`exav-core` hashes images through `exav-imagehash` (the `image-hash`
feature), which decodes them with `exav-render`. exav-render reads DWG and DXF
with exav-unpack's drawing parsers (its `dwg` feature); the scanner draws
nothing. `exav-update`, behind the `http-update` feature (part of `http`),
sits to the side, feeding fresh signatures out of band.

Every arrow points down: nothing calls anything above it, which is what lets
the extraction, decoding and hashing crates be taken on their own. Dashed
arrows are optional dependencies, each behind the Cargo feature it is
labelled with.

<div class="diagram">
<svg viewBox="0 0 790 820" role="img" aria-labelledby="craten crated" style="width:100%;height:auto;max-width:790px">
  <title id="craten">exav crate dependency graph</title>
  <desc id="crated">Four front ends sit on top: exav, exav-viewer (the wasm
  half of @exav/viewer), exav-grep and exav-unpack-wasm. exav depends on
  exav-core, and on exav-update behind the http-update feature. exav-core also
  builds exav-wasm, its wasm32-wasip1 binary. exav-core depends on
  exav-imagehash behind the image-hash feature, on exav-unpack, and on exav-x86
  for the bytecode disassembly API. exav-imagehash and exav-viewer depend on
  exav-render, which depends on exav-unpack behind its dwg feature. exav-grep
  and exav-unpack-wasm depend on exav-unpack, which depends on exav-pe-emu
  behind its pe-emu feature, which depends on exav-x86.</desc>
  <defs>
    <marker id="crate-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <text x="4" y="14" fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">FRONT ENDS</text>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="4" y="24" width="308" height="70" rx="6"/>
    <rect x="320" y="24" width="150" height="70" rx="6"/>
    <rect x="478" y="24" width="150" height="70" rx="6"/>
    <rect x="636" y="24" width="150" height="70" rx="6"/>
    <rect x="4" y="150" width="146" height="62" rx="6"/>
    <rect x="160" y="150" width="180" height="96" rx="6"/>
    <rect x="290" y="270" width="150" height="62" rx="6"/>
    <rect x="300" y="380" width="220" height="74" rx="6"/>
    <rect x="190" y="510" width="596" height="78" rx="6"/>
    <rect x="300" y="640" width="190" height="62" rx="6"/>
    <rect x="300" y="750" width="190" height="62" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14" font-weight="600" text-anchor="middle">
    <text x="158" y="48">exav</text>
    <text x="395" y="48">exav-viewer</text>
    <text x="553" y="48">exav-grep</text>
    <text x="711" y="48">exav-unpack-wasm</text>
    <text x="77" y="174">exav-update</text>
    <text x="250" y="174">exav-core</text>
    <text x="365" y="294">exav-imagehash</text>
    <text x="410" y="404">exav-render</text>
    <text x="488" y="538">exav-unpack</text>
    <text x="395" y="664">exav-pe-emu</text>
    <text x="395" y="774">exav-x86</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="158" y="66">malware scanner</text>
    <text x="158" y="82">CLI · daemon · ICAP server</text>
    <text x="395" y="66">file viewer, wasm</text>
    <text x="395" y="82">@exav/viewer</text>
    <text x="553" y="66">grep inside</text>
    <text x="553" y="82">archives</text>
    <text x="711" y="66">extractor, wasm</text>
    <text x="711" y="82">@exav/unpack-wasm</text>
    <text x="77" y="196">signature download</text>
    <text x="250" y="196">typing · patterns · hashes</text>
    <text x="250" y="214">YARA · .cbc VM</text>
    <text x="250" y="236">+ exav-wasm (WASI binary)</text>
    <text x="365" y="316">image hashes</text>
    <text x="410" y="426">image decoders</text>
    <text x="410" y="444">DWG · DXF · IFC · STL</text>
    <text x="488" y="560">archives · disk images · documents</text>
    <text x="488" y="578">packed executables</text>
    <text x="395" y="684">packer stub emulator</text>
    <text x="395" y="794">x86 instruction decoder</text>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="11" opacity="0.72" text-anchor="start">
    <text x="46" y="134">http-update</text>
    <text x="328" y="261">image-hash</text>
    <text x="418" y="486">dwg</text>
    <text x="403" y="618">pe-emu</text>
    <text x="183" y="730">bytecode disasm</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#crate-arrow)">
    <path d="M237 94 V146"/>
    <path d="M462 94 V376"/>
    <path d="M553 94 V506"/>
    <path d="M711 94 V506"/>
    <path d="M200 246 V506"/>
    <path d="M175 246 V781 H296"/>
    <path d="M365 332 V376"/>
    <path d="M395 702 V746"/>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 4" marker-end="url(#crate-arrow)">
    <path d="M40 94 V146"/>
    <path d="M320 246 V266"/>
    <path d="M410 454 V506"/>
    <path d="M395 588 V636"/>
  </g>
</svg>
</div>

Every crate in the graph is `#![forbid(unsafe_code)]` except `exav`, whose
daemon calls libc to fork its workers, set their limits, handle signals and
pass file descriptors between processes.
The `unsafe` that remains is in dependencies (see
[Dependencies](/project/dependencies/)).

Extraction touches hostile bytes first and hardest, so it lives in its own
crate with its own budget and panic containment. It also means one piece can be
used alone: a build system that needs to look inside archives does not need a
virus scanner, and a reverse engineer who wants to unpack a packed executable
needs neither.

`exav-pe-emu` sits below the extractor for the same reason. Running a packer's stub
is the one place where the scanner executes attacker-authored *control flow*
rather than parsing attacker-authored data, so it is its own crate with its own
budgets and no way to reach a syscall.

Each crate has its own page, with install instructions, API, and examples:
[exav-unpack](/unpack/rust/) and [`@exav/unpack-wasm`](/unpack/wasm/)
under Archive extraction, `@exav/viewer` under [File viewer](/viewer/), and the rest
under [Subprojects](/subprojects/).
