// pdf.js's worker, started as a module worker beside the module that needs
// it, so the host's bundler emits it from the host's own pdfjs-dist (the
// worker must be the library's version) and serves it from the same origin.
import "pdfjs-dist/build/pdf.worker.min.mjs";
