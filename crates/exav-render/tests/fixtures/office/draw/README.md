# Fixtures

- `sample.fodg`, `sample.odg`: OpenDocument drawings (two pages, a hidden
  layer, a master page with a frame).
- `sample.vsdx`, `themed.vsdx`: Visio drawings, written by `make_vsdx.py`
  (`python3 make_vsdx.py <output directory>`) for these tests, from the Visio
  file format reference and [MS-VSDX]; no Visio file is in them. CC0-1.0.
  - `sample.vsdx`: three pages. "Plan" (11 by 8.5 inches) has two instances
    of a master (one wider than it, with text, bold at 18 points and a link;
    one turned 30 degrees, mirrored, with its own fill), a dashed connector
    with an arrow, a shape on a layer that does not show, a group of a
    square and an ellipse, text in a text block off to one side, and the
    background page "Back". "Detail" (5.8 by 8.2) has a 4 by 3 pixel PNG
    and a shape linking to "Plan". The style sheets give the first master
    its fill and line through the colour table.
  - `themed.vsdx`: one page of five boxes with the theme's `Themed` values:
    the root style sheet's colours, accent 1 and 2 of the colour scheme,
    a variation colour, a variation that does not exist (65534), and the
    background colour.

Other Visio files were used as inputs, and another application's renderings
of them as a black box, while writing the reader (see the crate's NOTICE).
