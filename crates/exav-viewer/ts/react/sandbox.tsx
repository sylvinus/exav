/**
 * `@exav/viewer/react/sandbox`: the React side of the sandboxed frame, kept
 * out of `@exav/viewer/react` so that a host that runs its engines in the
 * page does not carry the frame's host code.
 */
import { useMemo, useRef, type ReactNode } from "react";

import { createSandboxedViewer, type SandboxConfig } from "../frame/index.js";
import { ViewerProvider, type ViewerProviderProps } from "./context.js";
import { builtinTranslate } from "./messages.js";
import { ViewerBody, type ViewerBodyProps } from "./ViewerBody.js";

export interface SandboxedViewerProviderProps extends Pick<ViewerProviderProps, "locale" | "translate" | "components"> {
  /** The frame to run every file in (`@exav/viewer/frame`); read once: a new object does not start a new viewer. */
  sandbox: SandboxConfig;
  children: ReactNode;
}

/**
 * A `ViewerProvider` whose files run in a sandboxed frame: the engines are the
 * frame's, and a question about following a link is asked in the current
 * language.
 */
export function SandboxedViewerProvider({ sandbox, locale, translate, components, children }: SandboxedViewerProviderProps) {
  const t = useMemo(() => translate ?? builtinTranslate(locale), [translate, locale]);
  // The link question in the current language, without a new viewer when it changes.
  const tRef = useRef(t);
  tRef.current = t;
  const frame = useRef(sandbox).current;
  const viewer = useMemo(() => createSandboxedViewer({ confirmLink: (url) => window.confirm(tRef.current("link_confirm", { url })), ...frame }), [frame]);
  return (
    <ViewerProvider viewer={viewer} locale={locale} translate={translate} components={components}>
      {children}
    </ViewerProvider>
  );
}

export interface SandboxedViewerProps extends ViewerBodyProps, Pick<ViewerProviderProps, "locale" | "translate" | "components"> {
  /** The frame to run the file in; read once. */
  sandbox: SandboxConfig;
}

/**
 * One file in a sandboxed frame, with the default UI: a `ViewerBody` under
 * its own `SandboxedViewerProvider`. For a dialog or several bodies, use the
 * provider.
 */
export function SandboxedViewer({ sandbox, locale, translate, components, ...body }: SandboxedViewerProps) {
  return (
    <SandboxedViewerProvider sandbox={sandbox} locale={locale} translate={translate} components={components}>
      <ViewerBody {...body} />
    </SandboxedViewerProvider>
  );
}
