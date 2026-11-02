---
title: React UI
description: "@exav/viewer/react: ViewerProvider, ViewerBody and ViewerDialog, replacing any piece of the UI, the CSS custom properties, and the built-in strings in five languages."
---

`@exav/viewer/react` is the default UI, on React 19. It can be taken at
three depths: restyled with CSS custom properties, with some of its pieces
replaced, or not at all, a host drawing everything from `useSession` and the
[controllers](/viewer/api/#controllers).

```tsx
import "@exav/viewer/styles.css";
import { ViewerBody, ViewerDialog, ViewerProvider } from "@exav/viewer/react";
```

## ViewerProvider

One viewer for the components inside it.

| Prop | |
|---|---|
| `plugins` | The plugins, run in the page. Keep the list stable (a module constant, or `useMemo`): a new list starts a new viewer. |
| `viewer` | Instead of `plugins`: a viewer built elsewhere, used as it is (`createViewer`, or `createSandboxedViewer` from `@exav/viewer/frame`). |
| `assetBase` | Where the [runtime files](/viewer/integration/) are served. Default `"/exav-viewer/"`. Not used with `viewer`. |
| `locale` | Picks the built-in strings by language (`"fr"`, `"de-AT"`...): English, French, German, Spanish or Dutch; English otherwise. |
| `translate` | Replaces the built-in strings: `(key, vars) => string`, for a host with its own i18n. |
| `components` | Replaces pieces of the UI (below). |

## ViewerBody

One file, filling its parent (give the parent a height). Its rails (a PDF's
sections; a drawing's layouts, ground and layers) sit on its right, folded
under 1024 px. A button among the zoom buttons folds and unfolds them.

| Prop | |
|---|---|
| `file` | A [`ViewerFile`](/viewer/api/#files). A new `id` ends the previous session first. |
| `chrome` | `"default"`, or `"none"` for the surface alone. |
| `onStatus(status)` | Each status change. |
| `onPages(pages)` | The page or slide counter, for a host showing it elsewhere. With an archive member open, the member's. |
| `className` | |
| `children` | Drawn in the stage, over the surface: a node, or `({ session, status, controllers }) => node` for a host's own controls, such as zoom buttons that call `controllers.zoom.setScale(...)`. With an archive member open these are the archive's: follow `controllers.archive.opened.session` to reach the member's. |

A PDF's section rail shows from two entries: an outline of one only jumps to
where the reader already is.

The element carries `data-phase` (`loading`, `ready`, `error`...), for a
host's styles and tests.

The same `file.id` with another `source` is the same document with other
bytes: it is replaced in place, and a PDF or an image keeps its zoom and
position ([Replacing the document](/viewer/api/#replacing-the-document)).

## In a sandboxed frame

The sandboxed frame's React side is in its own entry, `@exav/viewer/react/sandbox`,
so that a host that runs its engines in the page does not carry it:

```tsx
import { SandboxedViewer, SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

// A provider for several bodies or a dialog:
<SandboxedViewerProvider sandbox={{ url: "https://viewer-frame.example-files.com/exav-frame/index.html" }} locale="fr">
  <ViewerBody file={file} />
</SandboxedViewerProvider>

// Or one file, a `ViewerBody` in a provider of its own:
<SandboxedViewer sandbox={{ url: "https://viewer-frame.example-files.com/exav-frame/index.html" }} file={file} locale="fr" />
```

`sandbox` is `{ url, formats?, options?, confirmLink?, startTimeoutMs?, delivery?, origins?, keys?, theme? }`
([Core API](/viewer/api/#the-viewer-in-a-sandboxed-frame), [Security](/viewer/security/)),
read once. The question before a document's link opens is the `link_confirm`
string; `confirmLink` replaces it. `SandboxedViewerProvider` takes the
provider's `locale`, `translate` and `components`.

In the sandboxed mode the rails, pager, archive list and dialog are the
host page's, as in the page; what the engine draws is in the frame, whose
inside the host's styles do not reach: the custom properties below are read
where the file is mounted and sent to it (`theme`). The arrow keys and
Escape pressed while the focus is in the document reach the dialog and the
page, unless the document scrolls with them. A frame holds one file: a
replaced source gets a new frame, and the zoom and position start over.

## ViewerDialog

A list of files in a modal `<dialog>`: previous and next (buttons, and the
arrow keys), "2 / 11", the page counter of a PDF, open in a new tab for a
URL that outlives the page, download, Escape to close. Every control is at
least 44 px.

```tsx
const [index, setIndex] = useState<number | null>(null);

<ViewerDialog
  items={items}               // ViewerFile & { title, hint?, download? }
  index={index}               // null: closed
  onIndexChange={setIndex}
  width="full"                // or "page": at most 72rem wide
  actions={(item) => <ShareButton item={item} />}
/>;
```

`download.resolveUrl` signs a URL when the button is pressed (the server
names the file: `download=` is ignored across origins). Without it the
button is an anchor on the source URL; with neither, there is no button.

## Replacing a piece

Each piece is a component a host can replace through `components`. The
replacement receives the default as `Default`, to wrap it rather than
rewrite it:

```tsx
const components = {
  StatusOverlay: ({ Default, ...props }) =>
    props.status.phase === "error" ? <MyErrorCard format={props.format} /> : <Default {...props} />,
};

<ViewerProvider plugins={plugins} components={components}>
```

| Piece | Props | Shown |
|---|---|---|
| `Shell` | `open`, `onClose`, `title`, `width`, `children` | the dialog itself |
| `StatusOverlay` | `status`, `format` | over the surface while loading, converting, empty or failed |
| `Placeholder` | `state`, `label` | instead of the surface when `source` is null |
| `OutlineRail` | `outline` | a PDF's sections |
| `DrawingRail` | `layers`, `layouts`, `ground`, `selection` | drawings and models |
| `SlidePager` | `pages` | a presentation's "Slide 2 / 9" |
| `SheetTabs` | `sheets` | a workbook's sheets, as tabs below it, when there are several |
| `ArchiveList` | `archive` | an archive's members |
| `ArchiveBack` | `archive`, `name` | the bar back out of a member |
| `Warnings` | `warnings` | what a drawing or model lacks, or that the file was downloaded whole (with a button to dismiss it) |
| `ZoomControls` | `zoom` | zoom out, zoom in (a quarter each), and back to the fitted view once the zoom is not it, over the surface; shown for a mouse (`any-pointer: fine`) or when the browser reports no pointer (`none`), not on a touch screen, which pinches |
| `DragToggle` | `drag` | a PDF zoomed past the viewer: a hand to move the page by dragging (the default), a text cursor to select text |
| `FullscreenToggle` | none | the viewer's box in full screen and back, where the browser has full screen; it is the host page that asks for it, so the frame needs no permission |
| `PanelToggle` | `open`, `title`, `hideLabel`, `icon`, `controls`, `toggle` | folds and unfolds the side panel; there when a rail is, on a touch screen too |

The four last ones sit together at the bottom right of the surface. The two
toggles are buttons in one group, full screen then the panel's. Replace one
with `() => null` to drop it, or with your own, which receives the controller.

On a touch screen, which pinches and has no use for buttons for a mouse, the
element that has the attribute `data-pointer-only` is hidden, and a group left
with nothing else with it. The default zoom and drag groups and the full screen
button have it; so does a replacement of yours that should go as they do. One
without it is shown everywhere, which is what the panel toggle does.

### Hooks for your own controls

- `useFullscreen(() => element)` returns `{ supported, active, toggle }` for
  the element you give (your own box, or a viewer's `.exav-viewer-body`). The
  host page asks for full screen, so a sandboxed frame needs no permission. It
  is what `FullscreenToggle` is made of.
- `usePanel(info?)` returns `{ open, setOpen }`, the fold state of the side
  panel, shared by the rails and the toggle (outside a viewer, always open). A
  rail of your own gives `info` (`title`, `hideLabel`, `icon`, `controls`: its
  id) and the default toggle shows for as long as it is mounted; draw nothing
  when `open` is false. Without `info` it only reads and sets the state, as a
  `PanelToggle` of your own may.
- The zoom controller's `scale` is 1 at the fitted view: show your button back
  to it when `Math.abs(scale - 1)` is more than a hundredth, as `ZoomControls`
  does.

## Without the components

```tsx
import { useSession, useStore } from "@exav/viewer/react";

function Bare({ file }: { file: ViewerFile }) {
  const { status, controllers, ref } = useSession(file);
  const pages = useStore(controllers.pages);
  return (
    <div>
      <div ref={ref} style={{ height: 600 }} />
      {status.phase === "ready" && pages && <p>{pages.current} / {pages.total}</p>}
    </div>
  );
}
```

`useSession(file)` mounts the file into the element given to `ref` once it
is attached, follows its size, and ends the session when the file's id
changes or the component unmounts. Another `source` under the same id replaces
the document in place, or starts the session over where the format cannot. `useStore(store)` re-renders on each
change of a store.

## Styles

Every colour, radius and size is a custom property, set on an ancestor or
`:root`. `TOKENS` exports them with their defaults:

| Property | Default |
|---|---|
| `--exav-viewer-surface` | `#f1f5f9`, behind the file |
| `--exav-viewer-panel` | `#ffffff`, rails and bars |
| `--exav-viewer-border` | `#e2e8f0` |
| `--exav-viewer-text`, `--exav-viewer-text-strong`, `--exav-viewer-muted`, `--exav-viewer-faint` | `#334155`, `#0f172a`, `#64748b`, `#94a3b8` |
| `--exav-viewer-hover`, `--exav-viewer-active` | `#f8fafc`, `#f1f5f9` |
| `--exav-viewer-accent`, `--exav-viewer-on-accent` | `#0f172a`, `#ffffff` |
| `--exav-viewer-error`, `--exav-viewer-warning` | `#b91c1c`, `#b45309` |
| `--exav-viewer-media-bg` | `#0f172a`, behind video |
| `--exav-viewer-model-bg` | a light radial gradient, behind models |
| `--exav-viewer-radius` | `0.375rem` |
| `--exav-viewer-rail-width` | `15rem` |
| `--exav-viewer-tap` | `2.75rem`, the smallest control |
| `--exav-viewer-pager-room` | `4.5rem`, kept free below a slide for the pager over it |
| `--exav-viewer-font` | `inherit` |

The demo sets them for a dark theme under `prefers-color-scheme: dark`.

## Strings

`MESSAGES` holds the built-in English, French, German, Spanish and Dutch
strings, by key; `locale` picks one by its language, English otherwise
(also exported from `@exav/viewer`, for a host without React). Plural
keys end in `_one` and `_other`; a `translate` function receives the key
without the suffix and a `count`. Variables are written `{{name}}`:

```ts
const translate: Translate = (key, vars) => i18n.t(`viewer.${key}`, vars);
```

`MessageKey` is the union of the keys, so a host's table can be checked
against it.
