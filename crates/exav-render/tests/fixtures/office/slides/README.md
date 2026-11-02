# Fixtures

- `sample.fodp`: written by hand for these tests (two slides: a title, a
  bulleted list, a filled rectangle with text and an ellipse; a title and a
  text box).
- `sample.odp` and `sample.ppt`: `sample.fodp` saved as ODP and as
  PowerPoint 97 by an office application.
- `sample.key`: keynote-parser's `tests/data/simple-oneslide.key`
  (https://github.com/psobot/keynote-parser, MIT, Copyright 2019-2025 Peter
  Sobot): one slide with a title and a subtitle, saved by Keynote.
- `chart.odp`, `chart.fodp`, `chart.ppt`: written by hand for these tests
  (one slide holding a bar chart of three quarters' sales, as an ODF chart
  object in a package, inline in a flat file); `chart.ppt` is `chart.odp`
  saved as PowerPoint 97 by an office application, which stores the chart as
  an OLE object holding its ODF package. CC0-1.0.
- `pictures.odp`, `pictures.ppt`: written by hand for these tests (two
  slides, each with one picture: a 64 by 48 pixel red PNG, then 250 by 250
  pixels of noise that does not compress); `pictures.ppt` is `pictures.odp`
  saved as PowerPoint 97 by an office application. CC0-1.0.
- `table.key`: keynote-parser's `tests/data/table.key` (MIT, as `sample.key`):
  one slide with a table of four columns and five rows, without text.

`chart.ppt` and `pictures.ppt` are those files without their
`SummaryInformation` stream, which holds a 440 KB thumbnail (the other
streams are as the application wrote them, in a compound file rewritten by
`exav_render::formats::office::test_util::build_cfb`).

The tests of PowerPoint 95 (tests/office_slides_old_ppt.rs) and of Keynote 1 to 5
(tests/office_slides_keynote_xml.rs) build their documents themselves: no permissively
licensed samples of those formats were found.
