// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightSidebarTopics from 'starlight-sidebar-topics';

const GITHUB_REPO = 'https://github.com/sylvinus/exav';

export default defineConfig({
  site: 'https://exav.org',
  redirects: {
    // Folded into Design principles; keep old links working.
    '/concepts/never-silent/': '/scanner/concepts/design-principles/#never-a-silent-clean',
    // Superseded by the per-crate pages; the one part that was not duplicated
    // there (how the crates compose) moved into Architecture.
    '/concepts/packages/': '/subprojects/',
    // The site was organised by doc type (getting started, guides, reference,
    // concepts) around the scanner, with every other product under
    // "Subprojects". It is now one topic per product; these keep the old URLs.
    '/getting-started/introduction/': '/scanner/getting-started/introduction/',
    '/getting-started/installation/': '/scanner/getting-started/installation/',
    '/getting-started/quick-start/': '/scanner/getting-started/quick-start/',
    '/guides/migrating-from-clamav/': '/scanner/guides/migrating-from-clamav/',
    '/guides/signatures/': '/scanner/guides/signatures/',
    '/guides/scanning/': '/scanner/guides/scanning/',
    '/guides/prebuilt-database/': '/scanner/guides/prebuilt-database/',
    '/guides/daemon/': '/scanner/guides/daemon/',
    '/guides/icap/': '/scanner/guides/icap/',
    '/guides/docker/': '/scanner/guides/docker/',
    '/guides/sizing/': '/scanner/guides/sizing/',
    '/guides/yara/': '/scanner/guides/yara/',
    '/guides/wasm-sandbox/': '/scanner/guides/wasm-sandbox/',
    '/guides/library-usage/': '/subprojects/exav-core/',
    '/guides/troubleshooting/': '/scanner/guides/troubleshooting/',
    '/reference/cli/': '/scanner/reference/cli/',
    '/reference/clamav-flag-matrix/': '/scanner/reference/clamav-flag-matrix/',
    '/reference/verdicts/': '/scanner/reference/verdicts/',
    '/reference/limits/': '/scanner/reference/limits/',
    '/reference/configuration/': '/scanner/reference/configuration/',
    '/reference/feature-flags/': '/scanner/reference/feature-flags/',
    '/reference/formats/': '/scanner/reference/formats/',
    '/reference/dependencies/': '/project/dependencies/',
    '/concepts/design-principles/': '/scanner/concepts/design-principles/',
    '/concepts/architecture/': '/scanner/concepts/how-it-works/',
    '/concepts/archive-extraction/': '/unpack/how-it-works/',
    '/concepts/streaming-memory/': '/scanner/concepts/streaming-memory/',
    '/concepts/bytecode-sandbox/': '/scanner/concepts/bytecode-sandbox/',
    '/concepts/pe-emulation/': '/scanner/concepts/pe-emulation/',
    '/concepts/differential-testing/': '/scanner/concepts/differential-testing/',
    '/concepts/quirks/': '/scanner/concepts/quirks/',
    '/subprojects/exav-unpack/': '/unpack/rust/',
    '/subprojects/exav-viewer/': '/viewer/',
    '/subprojects/exav-viewer/integration/': '/viewer/integration/',
    '/subprojects/exav-viewer/api/': '/viewer/api/',
    '/subprojects/exav-viewer/react/': '/viewer/react/',
    '/subprojects/exav-viewer/security/': '/viewer/security/',
    // Subprojects were briefly under /libraries/.
    '/libraries/': '/subprojects/',
    '/libraries/exav-imagehash/': '/subprojects/exav-imagehash/',
    '/libraries/exav-grep/': '/subprojects/exav-grep/',
    '/libraries/exav-pe-emu/': '/subprojects/exav-pe-emu/',
    '/libraries/exav-x86/': '/subprojects/exav-x86/',
    '/libraries/exav-update/': '/subprojects/exav-update/',
    '/libraries/exav-core/': '/subprojects/exav-core/',
    // Moved after the split into topics.
    '/file-viewer/exav-render/': '/subprojects/exav-render/',
    '/project/comparison-with-clamav/': '/scanner/reference/comparison-with-clamav/',
    // Each page under the product it is about: the library guide merged into
    // exav-core, the scanner's architecture renamed beside the extractor's,
    // the quirks (mostly the scanner's) under its concepts.
    '/scanner/guides/library-usage/': '/subprojects/exav-core/',
    '/scanner/concepts/architecture/': '/scanner/concepts/how-it-works/',
    '/extraction/quirks/': '/scanner/concepts/quirks/',
    // Each product's section is named after its crate. The viewer demo, which
    // had /viewer/, is now /viewer/demo/.
    '/extraction/': '/unpack/',
    '/extraction/cli/': '/unpack/cli/',
    '/extraction/rust/': '/unpack/rust/',
    '/extraction/wasm/': '/unpack/wasm/',
    '/extraction/formats/': '/unpack/formats/',
    '/extraction/how-it-works/': '/unpack/how-it-works/',
    '/file-viewer/': '/viewer/',
    '/file-viewer/integration/': '/viewer/integration/',
    '/file-viewer/react/': '/viewer/react/',
    '/file-viewer/api/': '/viewer/api/',
    '/file-viewer/security/': '/viewer/security/',
    '/project/design-principles/': '/scanner/concepts/design-principles/',
  },
  integrations: [
    starlight({
      title: 'exav',
      tagline: 'Memory-safe tools for untrusted files.',
      // Mark only: the "exav" wordmark next to it is rendered as real text by
      // Starlight, so it uses the site font rather than whatever the viewer's
      // OS happens to substitute inside an <img>-loaded SVG.
      logo: {
        src: './src/assets/logo.svg',
        alt: '',
      },
      favicon: '/favicon.svg',
      social: [
        { icon: 'github', label: 'GitHub', href: GITHUB_REPO },
      ],
      editLink: {
        baseUrl: `${GITHUB_REPO}/edit/main/www/`,
      },
      customCss: ['./src/styles/custom.css'],
      // Dark only: no light code theme to ship.
      expressiveCode: { themes: ['starlight-dark'] },
      components: {
        // Topics are listed in the header; the sidebar lists them only where
        // the header has no room (in place of the plugin's Sidebar).
        Header: './src/components/Header.astro',
        Sidebar: './src/components/Sidebar.astro',
        // Dark only.
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      // One topic per product, each with its own sidebar. A page belongs to the
      // first topic whose sidebar marks it current.
      plugins: [
        starlightSidebarTopics([
          {
            label: 'Malware scanning',
            link: '/scanner/getting-started/introduction/',
            icon: 'magnifier',
            items: [
              {
                label: 'Getting started',
                items: [
                  { label: 'Introduction', slug: 'scanner/getting-started/introduction' },
                  { label: 'Installation', slug: 'scanner/getting-started/installation' },
                  { label: 'Quick start', slug: 'scanner/getting-started/quick-start' },
                ],
              },
              {
                label: 'Guides',
                items: [
                  { label: 'Scanning', slug: 'scanner/guides/scanning' },
                  { label: 'Signatures', slug: 'scanner/guides/signatures' },
                  { label: 'YARA rules', slug: 'scanner/guides/yara' },
                  { label: 'Prebuilt database', slug: 'scanner/guides/prebuilt-database' },
                  { label: 'Daemon mode', slug: 'scanner/guides/daemon' },
                  { label: 'ICAP server', slug: 'scanner/guides/icap' },
                  { label: 'Docker', slug: 'scanner/guides/docker' },
                  { label: 'Sizing a server', slug: 'scanner/guides/sizing' },
                  { label: 'WASM sandbox', slug: 'scanner/guides/wasm-sandbox' },
                  { label: 'Migrating from ClamAV', slug: 'scanner/guides/migrating-from-clamav' },
                  { label: 'Troubleshooting & FAQ', slug: 'scanner/guides/troubleshooting' },
                ],
              },
              {
                label: 'Reference',
                items: [
                  { label: 'CLI', slug: 'scanner/reference/cli' },
                  { label: 'Configuration', slug: 'scanner/reference/configuration' },
                  { label: 'Verdicts & exit codes', slug: 'scanner/reference/verdicts' },
                  { label: 'Limits and tuning', slug: 'scanner/reference/limits' },
                  { label: 'Feature flags', slug: 'scanner/reference/feature-flags' },
                  { label: 'Supported formats', slug: 'scanner/reference/formats' },
                  { label: 'ClamAV flag matrix', slug: 'scanner/reference/clamav-flag-matrix' },
                  { label: 'Comparison with ClamAV', slug: 'scanner/reference/comparison-with-clamav' },
                ],
              },
              {
                label: 'Concepts',
                items: [
                  { label: 'Design principles', slug: 'scanner/concepts/design-principles' },
                  { label: 'How scanning works', slug: 'scanner/concepts/how-it-works' },
                  { label: 'Streaming & memory', slug: 'scanner/concepts/streaming-memory' },
                  { label: 'Bytecode sandbox', slug: 'scanner/concepts/bytecode-sandbox' },
                  { label: 'PE stub emulation', slug: 'scanner/concepts/pe-emulation' },
                  { label: 'Interesting quirks', slug: 'scanner/concepts/quirks' },
                  { label: 'Differential testing', slug: 'scanner/concepts/differential-testing' },
                ],
              },
            ],
          },
          {
            label: 'Archive extraction',
            link: '/unpack/',
            icon: 'download',
            items: [
              { label: 'Overview', slug: 'unpack' },
              { label: 'Command line', slug: 'unpack/cli' },
              { label: 'Rust crate', slug: 'unpack/rust' },
              { label: 'Browser and Node', slug: 'unpack/wasm' },
              { label: 'Supported formats', slug: 'unpack/formats' },
              { label: 'How it works', slug: 'unpack/how-it-works' },
            ],
          },
          {
            label: 'File viewer',
            link: '/viewer/',
            icon: 'document',
            items: [
              { label: 'Overview', slug: 'viewer' },
              { label: 'Integration', slug: 'viewer/integration' },
              { label: 'React UI', slug: 'viewer/react' },
              { label: 'Core API', slug: 'viewer/api' },
              { label: 'Security', slug: 'viewer/security' },
              { label: 'Live demo', link: '/viewer/demo/', attrs: { target: '_blank' } },
            ],
          },
          {
            label: 'Subprojects',
            link: '/subprojects/',
            icon: 'puzzle',
            items: [
              { label: 'Overview', slug: 'subprojects' },
              {
                label: 'Tools',
                items: [
                  { label: 'exav-grep', slug: 'subprojects/exav-grep' },
                  { label: 'exav-imagehash', slug: 'subprojects/exav-imagehash' },
                  { label: 'exav-pe-emu', slug: 'subprojects/exav-pe-emu' },
                ],
              },
              {
                label: 'Libraries',
                items: [
                  { label: 'exav-core', slug: 'subprojects/exav-core' },
                  { label: 'exav-render', slug: 'subprojects/exav-render' },
                  { label: 'exav-x86', slug: 'subprojects/exav-x86' },
                  { label: 'exav-update', slug: 'subprojects/exav-update' },
                ],
              },
            ],
          },
          {
            label: 'About',
            link: '/project/architecture/',
            icon: 'open-book',
            items: [
              { label: 'Technical architecture', slug: 'project/architecture' },
              { label: 'Roadmap', slug: 'project/roadmap' },
              { label: 'Contributing', slug: 'project/contributing' },
              { label: 'Security', slug: 'project/security' },
              { label: 'License', slug: 'project/license' },
              { label: 'Dependencies', slug: 'project/dependencies' },
            ],
          },
        ]),
      ],
    }),
  ],
});
