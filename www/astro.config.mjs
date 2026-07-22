// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const GITHUB_REPO = 'https://github.com/sylvinus/exav';

export default defineConfig({
  site: 'https://exav.org',
  redirects: {
    // Folded into Design principles; keep old links working.
    '/concepts/never-silent/': '/concepts/design-principles/#never-a-silent-clean',
    // Superseded by the per-crate Subprojects pages; the one part that was not
    // duplicated there (how the crates compose) moved into Architecture.
    '/concepts/packages/': '/subprojects/',
  },
  integrations: [
    starlight({
      title: 'exav',
      tagline: 'A fast, memory-safe malware scanner written in Rust.',
      // Mark only — the "exav" wordmark next to it is rendered as real text by
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
      sidebar: [
        { label: 'Overview', link: '/' },
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction', slug: 'getting-started/introduction' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quick start', slug: 'getting-started/quick-start' },
          ],
        },
        {
          label: 'Usage guides',
          items: [
            { label: 'Scanning', slug: 'guides/scanning' },
            { label: 'Daemon mode', slug: 'guides/daemon' },
            { label: 'ICAP server', slug: 'guides/icap' },
            { label: 'Docker', slug: 'guides/docker' },
            { label: 'Signatures', slug: 'guides/signatures' },
            { label: 'Prebuilt database', slug: 'guides/prebuilt-database' },
            { label: 'YARA rules', slug: 'guides/yara' },
            { label: 'Migrating from ClamAV', slug: 'guides/migrating-from-clamav' },
            { label: 'WASM sandbox', slug: 'guides/wasm-sandbox' },
            { label: 'Rust library usage', slug: 'guides/library-usage' },
            { label: 'Troubleshooting & FAQ', slug: 'guides/troubleshooting' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI', slug: 'reference/cli' },
            { label: 'ClamAV flag matrix', slug: 'reference/clamav-flag-matrix' },
            { label: 'Verdicts & exit codes', slug: 'reference/verdicts' },
            { label: 'Limits and tuning', slug: 'reference/limits' },
            { label: 'Configuration', slug: 'reference/configuration' },
            { label: 'Feature flags', slug: 'reference/feature-flags' },
            { label: 'Supported formats', slug: 'reference/formats' },
            { label: 'Dependencies', slug: 'reference/dependencies' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Design principles', slug: 'concepts/design-principles' },
            { label: 'Architecture', slug: 'concepts/architecture' },
            { label: 'Archive extraction', slug: 'concepts/archive-extraction' },
            { label: 'Streaming & memory', slug: 'concepts/streaming-memory' },
            { label: 'Bytecode sandbox', slug: 'concepts/bytecode-sandbox' },
            { label: 'PE stub emulation', slug: 'concepts/pe-emulation' },
            { label: 'Differential testing', slug: 'concepts/differential-testing' },
            { label: 'Interesting quirks', slug: 'concepts/quirks' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Comparison with ClamAV', slug: 'project/comparison-with-clamav' },
            { label: 'Roadmap', slug: 'project/roadmap' },
            { label: 'Contributing', slug: 'project/contributing' },
            { label: 'Security', slug: 'project/security' },
            { label: 'License', slug: 'project/license' },
          ],
        },
        {
          label: 'Subprojects',
          items: [
            { label: 'Overview', slug: 'subprojects' },
            { label: 'exav-unpack', slug: 'subprojects/exav-unpack' },
            { label: 'exav-grep', slug: 'subprojects/exav-grep' },
            { label: 'exav-core', slug: 'subprojects/exav-core' },
            { label: 'exav-pe-emu', slug: 'subprojects/exav-pe-emu' },
            { label: 'exav-x86', slug: 'subprojects/exav-x86' },
            { label: 'exav-update', slug: 'subprojects/exav-update' },
          ],
        },
      ],
    }),
  ],
});
