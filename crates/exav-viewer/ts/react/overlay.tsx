import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";

import type { ImageSurface, OverlayHost, ViewState } from "../core/types.js";

/**
 * An overlay written in React, rendered into the image surface's page layer
 * (page pixels, transformed with the image) or, with `layer: "screen"`, its
 * untransformed screen layer. Rendered again on every change of the view.
 *
 *     image({ overlay: (file) => reactOverlay((surface) => <Marks file={file} surface={surface} />) })
 */
export function reactOverlay(render: (surface: ImageSurface, view: ViewState) => ReactNode, options: { layer?: "page" | "screen" } = {}): OverlayHost {
  return {
    mount(surface) {
      const host = document.createElement("div");
      host.className = "exv-overlay";
      (options.layer === "screen" ? surface.screenLayer : surface.pageLayer).append(host);
      const root = createRoot(host);
      const draw = (view: ViewState) => root.render(render(surface, view));
      draw(surface.get());
      const unsubscribe = surface.subscribe(draw);
      return {
        destroy() {
          unsubscribe();
          // After the current render: unmounting inside one throws.
          queueMicrotask(() => root.unmount());
          host.remove();
        },
      };
    },
  };
}
