# Test fixtures

- `sample.fods`: written by hand for these tests (a small budget table and a
  second sheet). Public domain (CC0-1.0).
- `sample.ods`, `sample.xls`: `sample.fods` saved by an office application as
  ODS and as Excel 97. CC0-1.0, as their source.
- `sample.numbers`: `tests/data/issue-18.numbers` from numbers-parser
  (https://github.com/masaccio/numbers-parser), MIT, Copyright 2021 Jon
  Connell. A Numbers document written by SheetJS: one table with a merged
  range, in the layout without formula owner records.
- `sample-2003.xml`, `sample.html`, `sample.slk`: the budget table of
  `sample.fods` written by hand for these tests as Excel writes an XML
  Spreadsheet, a worksheet saved as a web page and a SYLK file. CC0-1.0.
- `numbers09.numbers`: `testNumbers.numbers` from Apache Tika's test
  documents
  (https://github.com/apache/tika, `tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-apple-module/src/test/resources/test-documents/`),
  Apache License 2.0, unmodified. A Numbers '09 document (`index.xml` in a
  ZIP): two sheets, three tables, formulas across tables, a chart.

Files the tests need in other versions (BIFF2 to BIFF5 workbooks, encrypted
workbooks, damaged compound files, Numbers documents with formulas across
tables) are built by the tests themselves: no current application writes
BIFF5, and no permissively licensed samples of them were found.
