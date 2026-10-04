// Inline icons, so the UI needs no icon library. 24-unit strokes, currentColor.
import type { ReactNode } from "react";

const Svg = ({ children, size = 16 }: { children: ReactNode; size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
    {children}
  </svg>
);

export const ChevronLeft = () => (
  <Svg size={20}>
    <path d="m15 18-6-6 6-6" />
  </Svg>
);
export const ChevronRight = () => (
  <Svg size={20}>
    <path d="m9 18 6-6-6-6" />
  </Svg>
);
export const Close = () => (
  <Svg size={20}>
    <path d="M18 6 6 18M6 6l12 12" />
  </Svg>
);
export const Download = () => (
  <Svg>
    <path d="M12 15V3M7 10l5 5 5-5M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
  </Svg>
);
export const External = () => (
  <Svg>
    <path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
  </Svg>
);
export const Spinner = () => (
  <span className="exv-spinner" aria-hidden="true">
    <Svg>
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </Svg>
  </span>
);
export const LayersIcon = () => (
  <Svg>
    <path d="m12 2 10 5-10 5L2 7l10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
  </Svg>
);
export const ListIcon = () => (
  <Svg>
    <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
  </Svg>
);
export const PanelClose = () => (
  <Svg>
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <path d="M15 3v18M8 9l3 3-3 3" />
  </Svg>
);
export const Plus = () => (
  <Svg size={18}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);
export const Minus = () => (
  <Svg size={18}>
    <path d="M5 12h14" />
  </Svg>
);
export const FitIcon = () => (
  <Svg size={18}>
    <path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3" />
  </Svg>
);
export const Hand = () => (
  <Svg size={18}>
    <path d="M18 11V6a2 2 0 0 0-4 0M14 10V4a2 2 0 0 0-4 0v2M10 10.5V6a2 2 0 0 0-4 0v8M18 8a2 2 0 1 1 4 0v6a8 8 0 0 1-8 8h-2c-2.8 0-4.5-.9-5.9-2.4L3.4 16a2 2 0 0 1 3.2-2.4L8 15" />
  </Svg>
);
export const TextCursor = () => (
  <Svg size={18}>
    <path d="M17 22h-1a4 4 0 0 1-4-4V6a4 4 0 0 1 4-4h1M7 22h1a4 4 0 0 0 4-4v-1M7 2h1a4 4 0 0 1 4 4v1" />
  </Svg>
);
export const ArrowLeft = () => (
  <Svg>
    <path d="M19 12H5M12 19l-7-7 7-7" />
  </Svg>
);
export const FileIcon = () => (
  <Svg>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
  </Svg>
);
export const FolderIcon = () => (
  <Svg size={12}>
    <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.7-.9l-.8-1.2A2 2 0 0 0 7.9 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z" />
  </Svg>
);
