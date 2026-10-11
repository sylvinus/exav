//! exav-render's reading of DWG files against its reading of the DXF the
//! ODA File Converter writes from each, by handle.
//!
//! `EXAV_DEBUG_CAD_CORPUS=<dir>` names a directory whose subdirectories hold
//! DWG files, each with the DXF of the same version the converter made of it
//! in a sibling directory named after it with `-dxf` (`ACAD2000/x.dwg` and
//! `ACAD2000-dxf/x.dxf`); the converter keeps handles when it does not
//! change the version. A subdirectory named `orig` holds files the converter
//! did not write; one named `source` the drawings the others were converted
//! from, by the same file names. Without the variable the test only says it
//! skipped.
//!
//! The corpus is local and its files are not named here: a file is the
//! first 8 hexadecimal digits of the SHA-256 of the drawing it comes from
//! (`source/x.dwg` when there is one, else itself), after its set
//! (`ACAD2000/1a2b3c4d`).
//!
//! What the DWG reader reads is compared: the header, the LAYER, LTYPE,
//! STYLE, DIMSTYLE and VPORT tables entry by entry, the blocks by record
//! handle, and each block's entities in order, by handle, every field the
//! model has (an INSERT's attributes and a POLYLINE's vertices included),
//! and the objects (layouts, dictionaries, draw order, image and underlay
//! definitions, multiline and multileader styles) by handle, with those
//! the converter makes again under new handles matched by what names them
//! (`cad_common/compare.rs`). Floats compare within a relative 1e-9.
//!
//! Differences whose cause is known and lies outside the DWG reader are
//! listed in [`EXPLAINED`] with the evidence; they are counted but do not
//! fail the test. Any other difference fails it.

#[path = "cad_common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::compare::{compare, entity_diffs, object_differences, repair_name};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Differences explained: the sets they occur in (`*` any; a set is the
/// subdirectory, `orig-R14`/`orig-R2000` for the originals), a pattern that
/// starts and ends so, and why.
const EXPLAINED: &[(&[&str], &str, &str, &str)] = &[
    (&["*"], "header.handle_seed", "", HANDSEED),
    (&["ACAD13"], "header.code_page (case)", "", R13_CODE_PAGE),
    (&["ACAD13"], "header.measurement", "", R13_MEASUREMENT),
    (&["*"], "linetypes.elements[].scale", "", DASH_SCALE),
    (&["*"], "text_styles.name ($TEMP_REC)", "", TEMP_REC),
    (&["*"], "entity:", " (case)", CASE),
    (&["*"], "entity:", " (fit points)", FIT_SPLINE),
    (&["*"], "entity:", ".flags (computed bits)", SPLINE_BITS),
    (&["*"], "entity:", " (closed)", CLIP_CLOSED),
    (
        &["*"],
        "entity:LEADER.",
        " (no annotation)",
        LEADER_NO_ANNOTATION,
    ),
    (&["*"], "entity:LEADER.", " (hookline)", LEADER_HOOKLINE),
    (
        &[
            "ACAD2010",
            "ACAD2013",
            "ACAD2018",
            "orig-R2010",
            "orig-R2013",
            "orig-R2018",
        ],
        "entity:LEADER.",
        " (no box)",
        LEADER_NO_BOX,
    ),
    (
        &["orig-R14", "orig-R2000", "orig-R2004", "orig-R2007"],
        "entity:LEADER.text_width",
        "",
        LEADER_BOX,
    ),
    (&["*"], "entity:VIEWPORT.frozen_layers", " (repair)", REPAIR),
    (&["*"], "entity:HATCH.pattern_name (,_O)", "", HATCH_O),
    (
        &["*"],
        "entity:POLYLINE.vertices[].",
        " (default width)",
        DEFAULT_WIDTH,
    ),
    (
        &["ACAD13"],
        "entity:POLYLINE.vertices[].location[] (elevation)",
        "",
        R13_ELEVATION,
    ),
    (
        &["ACAD13"],
        "entity:POLYLINE.vertices[].handle",
        "",
        R13_VERTEX_HANDLES,
    ),
    (
        &["ACAD2004", "ACAD2007"],
        "entity:MTEXT.background_",
        "",
        BACKGROUND_2004,
    ),
    (&["ACAD13"], "entity:ATTDEF.text.v_align", "", R13_ATTDEF),
    (
        &["ACAD13"],
        "entity:",
        ".block_name (renumbered)",
        R13_RENUMBERED,
    ),
    (
        &["orig-R2013"],
        "entity:",
        ".block_name (renumbered)",
        RENUMBERED,
    ),
    (&["orig-R2013"], "entity:MTEXT.text", "", MTEXT_2013),
    (&["orig-R2007"], "entity:MTEXT.text", "", MTEXT_INDENT),
    (
        &["orig-R2013"],
        "entity:MTEXT.columns.heights[]",
        "",
        MTEXT_2013,
    ),
    (
        &[
            "ACAD13",
            "ACAD14",
            "ACAD2000",
            "ACAD2004",
            "orig-R2000",
            "orig-R2004",
        ],
        "entity:MTEXT.columns (not in the DXF)",
        "",
        COLUMNS_XDATA,
    ),
    (
        &[
            "orig-R2000",
            "orig-R2004",
            "orig-R2007",
            "orig-R2010",
            "orig-R2013",
            "orig-R2018",
        ],
        "entity:HELIX.spline.",
        "",
        HELIX_REBUILT,
    ),
    (
        &[
            "ACAD2010",
            "ACAD2013",
            "ACAD2018",
            "orig-R2010",
            "orig-R2013",
            "orig-R2018",
        ],
        "entity:ACAD_TABLE.",
        "",
        TABLE_CONTENT,
    ),
    (
        &["orig-R2004"],
        "entity:PDFUNDERLAY.clip_vertices (length)",
        "",
        UNDERLAY_CLIP,
    ),
    (&["*"], "layers (only DWG) (repair)", "", REPAIR),
    (&["*"], "layers (only DXF) (repair)", "", REPAIR),
    (&["*"], "entity:", ".layer (repair)", REPAIR),
    (&["*"], "blocks.entities (handles) SHAPE", "", SHAPE),
    (&["*"], "blocks (only DWG) unreferenced", "", UNREFERENCED),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "blocks (only DWG) *Paper_Space",
        "",
        R14_PAPER,
    ),
    (
        &["ACAD13"],
        "blocks (only DXF) anonymous",
        "",
        R13_ANONYMOUS,
    ),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "blocks.layout",
        "",
        LAYOUTS,
    ),
    (
        &["ACAD13", "ACAD14"],
        "entity:ACAD_TABLE.type",
        "",
        R14_TYPES,
    ),
    (&["ACAD13", "ACAD14"], "entity:HELIX.type", "", R14_TYPES),
    (
        &["ACAD14", "orig-R14"],
        "entity:MULTILEADER.type",
        "",
        R14_TYPES,
    ),
    (&["ACAD14"], "entity:POLYLINE.type", "", R14_POLYLINE),
    (
        &["ACAD2004", "ACAD2007", "ACAD2010", "ACAD2013", "ACAD2018"],
        "header.textsize",
        "",
        TEXTSIZE,
    ),
    (&["*"], "entity:", ".type (proxy)", PROXY),
    (
        &["orig-R2004", "orig-R2018"],
        "entity:",
        ".graphics (length)",
        SURFACE_GRAPHICS,
    ),
    (&["orig-R2013"], "blocks.name (renumbered)", "", RENUMBERED),
    (&["orig-R2018"], "blocks.flags", "", HAS_ATTRIBUTES),
    (&["*"], "dictionaries", " (remade)", REMADE),
    (&["*"], "layouts (remade)", "", REMADE),
    (&["*"], "", " (added)", ADDED),
    (
        &["orig-R2013"],
        "sort_tables.entries (null entity)",
        "",
        NULL_SORT,
    ),
    (&["*"], "dictionaries.entries (order)", "", ORDER),
    (&["*"], "sort_tables.entries (order)", "", ORDER),
    (
        &["orig-R2013"],
        "dictionaries.entries (renumbered)",
        "",
        GROUPS_RENUMBERED,
    ),
    (&["*"], "dictionaries", " (empty)", EMPTY),
    (&["*"], "dictionaries", " (roundtrip)", ROUNDTRIP),
    (&["*"], "dictionaries", " (data storage)", DATA_STORAGE),
    (&["*"], "dictionaries", " (material map)", MATERIAL_MAP),
    (
        &["ACAD13", "ACAD14", "ACAD2000"],
        "dictionaries",
        " (polysolid)",
        POLYSOLID,
    ),
    (&["*"], "layouts.last_viewport (model)", "", MODEL_VIEWPORT),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "layouts",
        "",
        R14_OBJECTS,
    ),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "mleader_styles (only DWG)",
        "",
        R14_OBJECTS,
    ),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "dictionaries",
        " (R2000 dictionary)",
        R14_OBJECTS,
    ),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "dictionaries",
        " (layout)",
        R14_OBJECTS,
    ),
    (
        &["ACAD13", "ACAD14"],
        "dictionaries.entries (only DWG)",
        "",
        R14_OBJECTS,
    ),
    (
        &["ACAD13", "ACAD14", "orig-R14"],
        "dictionaries.entries[] (case)",
        "",
        R14_OBJECTS,
    ),
    // Real-world drawings (C7: AutoCAD, its verticals, LT, BricsCAD,
    // nanoCAD and others, R13 to 2018, in `orig`).
    (&["orig-R13"], "header.code_page (case)", "", R13_CODE_PAGE),
    (
        &["orig-R13"],
        "entity:POLYLINE.vertices[].handle",
        "",
        R13_VERTEX_HANDLES,
    ),
    (
        &["orig-R13"],
        "blocks (only DXF) anonymous",
        "",
        R13_ANONYMOUS,
    ),
    (&["orig-R13"], "blocks.layout", "", LAYOUTS),
    (&["orig-R13"], "entity:POLYLINE.", "", R13_POLYLINE),
    (&["orig-R14"], "entity:POLYLINE.type", "", R14_POLYLINE),
    (
        &["*"],
        "entity:POLYLINE.vertices[].location[] (elevation)",
        "",
        R13_ELEVATION,
    ),
    (&["*"], "", " (audit)", AUDIT),
    (&["*"], "entity:", ".type (R13 hatch)", R13_HATCH),
    (&["*"], "entity:", ".style (first style)", FIRST_STYLE),
    (
        &["*"],
        "entity:MTEXT.text (formatting)",
        "",
        MTEXT_FORMATTING,
    ),
    (&["*"], "entity:MTEXT.x_direction (default)", "", X_DEFAULT),
    (
        &["*"],
        "entity:",
        ".field_length (field length)",
        FIELD_LENGTH,
    ),
    (
        &["*"],
        "entity:DIMENSION.",
        " (regenerated)",
        DIM_REGENERATED,
    ),
    (&["*"], "entity:VIEWPORT.", " (stacking)", STACKING),
    (&ORIG, "layouts.last_viewport", "", STACKING),
    (
        &["*"],
        "entity:VIEWPORT.layer (overall)",
        "",
        OVERALL_VIEWPORT,
    ),
    (
        &["*"],
        "entity:SPLINE.extrusion[] (plane normal)",
        "",
        SPLINE_NORMAL,
    ),
    (&["*"], "entity:", ".extrusion[] (zero normal)", ZERO_NORMAL),
    (
        &["*"],
        "entity:LWPOLYLINE.",
        " (constant width)",
        CONSTANT_WIDTH,
    ),
    (
        &["*"],
        "entity:HATCH.paths",
        " (same boundary)",
        SAME_BOUNDARY,
    ),
    (
        &["*"],
        "entity:HATCH.associative (no sources)",
        "",
        NO_SOURCES,
    ),
    (&["*"], "linetypes.elements[].flags (bit 8)", "", LTYPE_BIT8),
    (&["*"], "entity:", ".block_name (renumbered)", RENUMBERED),
    (&["*"], "blocks.name (renumbered)", "", RENUMBERED),
    (
        &["*"],
        "dictionaries.entries (renumbered)",
        "",
        GROUPS_RENUMBERED,
    ),
    (&["*"], "blocks.flags", "", HAS_ATTRIBUTES),
    (&ORIG, "entity:MTEXT.background_", "", BACKGROUND_2004),
    (&ORIG, "header.textsize", "", TEXTSIZE),
    (&ORIG, "text_styles.last_height", "", LAST_HEIGHT),
    (&ORIG, "entity:LEADER.text_", "", LEADER_BOX),
    (
        &ORIG,
        "entity:LEADER.hookline_direction",
        "",
        LEADER_HOOK_DIRECTION,
    ),
    (
        &["orig-R13", "orig-R14"],
        "entity:LEADER.leader_color",
        "",
        LEADER_COLOR,
    ),
    (&ORIG, "entity:LEADER.block_offset[]", "", LEADER_OFFSET),
    (&ORIG, "entity:VIEWPORT.snap_spacing[]", "", ZERO_SNAP),
    (&ORIG, "layouts.plot.plot_view", "", PLOT_VIEW),
    (&ORIG, "layouts.tab_order", "", TAB_ORDER),
    (&ORIG, "linetypes.", "", ONE_DASH),
    (&ORIG, "layers.material", "", NULL_MATERIAL),
    (&ORIG, "layers.plot_style", "", PLOT_STYLE),
    (&ORIG, "layers.name", "", LAYER_NAMES),
    (&ORIG, "entity:DIMENSION.layer", "", LAYER_NAMES),
    (&ORIG, "text_styles.flags", "", SHAPE_REF),
    (&ORIG, "text_styles.oblique", "", OBLIQUE),
    (&ORIG, "dim_styles.dimclr", "", DIM_TRUE_COLOR),
    (&ORIG, "entity:DIMENSION.insertion_point[]", "", DIM_POINT_Z),
    (&ORIG, "entity:DIMENSION.text", "", DIM_TEXT_CODE_PAGE),
    (&ORIG, "entity:POLYLINE.vertices[].location[]", "", VERTEX_Z),
    (&ORIG, "entity:LINE.start[]", "", DYNAMIC_BLOCK),
    (&ORIG, "entity:SPLINE.", "", SPLINE_REBUILT),
    (&ORIG, "entity:LWPOLYLINE.vertices (length)", "", ONE_VERTEX),
    (&ORIG, "entity:HATCH.", "", HATCH_REPAIRED),
    (&ORIG, "blocks (only D", " anonymous", DIM_BLOCKS),
    (&ORIG, "blocks.entities (handles)", "", DROPPED_ENTITIES),
    (&ORIG, "sort_tables", "", SORT_TABLES),
    (
        &ORIG,
        "dictionaries",
        " (application data)",
        APPLICATION_DATA,
    ),
    (
        &ORIG,
        "dictionaries",
        " (draw order)",
        DRAW_ORDER_DICTIONARY,
    ),
    (&ORIG, "dictionaries.", "", DICTIONARY_REPAIRS),
    (&ORIG, "mleader_styles (only DXF)", "", ADDED),
    (&ORIG, "warning", "", MISSING_RECORDS),
];

/// The sets of real-world drawings.
const ORIG: [&str; 8] = [
    "orig-R13",
    "orig-R14",
    "orig-R2000",
    "orig-R2004",
    "orig-R2007",
    "orig-R2010",
    "orig-R2013",
    "orig-R2018",
];

const R13_POLYLINE: &str = "AutoCAD R13 2D POLYLINEs the converter's R13 DXF writes otherwise: \
    without their default widths (a101ca49's 12AA6: 40 and 0 in the DWG, every vertex 0 and 0), \
    with the curve-fit flag (2) of one without fit vertices cleared (cbac1764's 50B), without \
    the tangents and tangent flags (2) of vertices of polylines not curve-fit (0aefc8e0's 841), \
    and with a polyline of one vertex given a second (1f6e3ee2's 7E2F); vertex handles are new";
const AUDIT: &str = "the converter's audit renames an entry whose name it rejects \
    ($TD_AUDIT_GENERATED_(<handle>)) and repairs it: names in the drawing's code page (1d989593's \
    layers 67 to 6F, GBK in an ANSI_936 R2000 file; 14d12839 and 1f65c773 (R2004), 0c86acbe's \
    style 1E (R14)), an empty layer name (1b8bdf08's 99D9, whose ByBlock colour it makes 7); \
    what names them follows (entities' layers, $CLAYER); the DWG reader keeps the file's names";
const R13_HATCH: &str = "an INSERT with R14_HATCH_DATA extended data, a hatch as R13 keeps it, \
    in AutoCAD 2007 files (2948f53e's 61D4, 258c843b, 330bfec2, 511ba870): the converter's DXF \
    has a HATCH rebuilt from that data under the INSERT's handle; the DWG reader reads the INSERT";
const FIRST_STYLE: &str =
    "the converter leaves out group 7 of a text on the drawing's first STYLE \
    entry whatever its name, which DXF then reads as STANDARD: 69c08825's SIMPLEX (C, the drawing \
    has no STANDARD, the converter adds one), 7802a3cc's ROMANS (154, beside a STANDARD 161), \
    5aba4fe9's ROMANS (R13)";
const MTEXT_FORMATTING: &str =
    "the converter writes an MTEXT's spacing and paragraph codes again: \
    the same text once spaces, braces and \\p codes are left out (d744670f's 1101A: 'Notes:      \
    Component' as 'Notes: Component'; 8c78010e's 7B800 indents)";
const X_DEFAULT: &str = "an MTEXT direction within 1e-12 of (1, 0, 0) (79428019's 1C3: (1, \
    9.4e-17, 0)), for which the converter writes no 11";
const FIELD_LENGTH: &str = "the converter writes 73 = 0 for an attribute field length the DWG has \
    as 2 (1bb1ef38's ATTDEF 5017 and ATTRIB 501A)";
const DIM_REGENERATED: &str = "a DIMENSION with a null style handle (1efd993f's 13C to 13F, \
    691b762b's 9BB): the converter's audit gives it the Standard style and makes it again: a new \
    *D block (flag 32, the DWG's *D left unused), its measurement, text and definition points";
const STACKING: &str = "the converter stacks a layout's viewports from the last active one, which \
    it sets itself for the current layout of a drawing in paper space (db41a481's LAYOUT 177: \
    viewport ABB in the DWG, the overall 181 in the DXF) and for a layout whose DWG has none \
    (0c4abe5a's 6F)";
const OVERALL_VIEWPORT: &str = "the converter puts a layout's overall viewport (id 1) on layer 0 \
    (0f702fdf's 9A is on VIEWPORTS in the DWG, 26c068d2's 4C on 002_THIN)";
const SPLINE_NORMAL: &str = "a DWG's SPLINE has no normal (spec 20.4.40): the model's is the \
    default (0, 0, 1); the converter's DXF gives a planar spline its plane's (88d811b4's 7C: \
    (0.866, -0.5, 0))";
const ZERO_NORMAL: &str = "a normal stored as (0, 0, 0) (a4c8933f's LINE 11B7 and ATTRIB 18CB, \
    three BD 0 that end the object's data), which the converter writes as (0, 0, -1)";
const CONSTANT_WIDTH: &str = "an LWPOLYLINE whose vertices all have the same start and end width \
    and no constant width (578964ea's 12A: 200): the converter's DXF gives it that constant width \
    (43) and no vertex widths";
const SAME_BOUNDARY: &str = "HATCH boundaries that are the same curves: arcs and ellipses whose \
    angles differ by whole turns (0a02dc34's 3D7: 9.42 and 11.0 in the DWG, 3.14 and 4.71 in the \
    DXF; a full turn 0 to 2 pi as -pi to pi, f24866f0's F802), an ellipse's major axis reversed \
    with its angles turned by pi (e8bea4a6's 15C6), a spline edge's knots scaled (f24866f0's \
    F767: x 23.96), the undocumented path flag 32 the DXF leaves out (ba25a0df's FC76), and the \
    paths around texts (flag 8), which the converter computes again from the text \
    (0909d1cd's 1214: two lines in the DWG, the text's box in the DXF)";
const NO_SOURCES: &str = "an associative HATCH with no source object (7447f770's 27388E): the \
    converter's audit makes it not associative";
const LTYPE_BIT8: &str = "a linetype text element's undocumented 8 bit (08fe5efe's A4: 10), which \
    the converter's DXF leaves out (2)";
const LAST_HEIGHT: &str =
    "the converter writes a STYLE's last height 0 as the drawing's text size \
    (26c068d2: every style 0 in the DWG, 2.5 = $TEXTSIZE in the DXF)";
const LEADER_HOOK_DIRECTION: &str = "the converter writes the hookline direction (74) of a LEADER \
    from where its annotation lies, not the DWG's bit (499033fa's F2FF: 1 in the DWG, no 74 with \
    its MTEXT F2FE to the left)";
const LEADER_COLOR: &str = "an R13 or R14 LEADER's colour (spec 20.4.47, R13-R14 only), which the \
    converter does not write as 77 (1fab104d's 7B75: 2)";
const LEADER_OFFSET: &str = "71fa8576's LEADER 2324 stores 3.7e193 as its block offset's Y; the \
    converter leaves 212 out";
const ZERO_SNAP: &str = "a viewport snap spacing of 0 in the DWG, which the converter writes as \
    the drawing's (42ee4fa4's B2D1: 0.5; 9834a019's 99: 10)";
const PLOT_VIEW: &str = "AutoCAD 2000 files of the corpus name a plot view 'A' that no VIEW \
    entry has (1efd993f's LAYOUT 21, and 20 others); the converter writes 6 empty";
const TAB_ORDER: &str = "the converter numbers a drawing's layout tabs without gaps (637735ae's \
    2BC: 3 in the DWG, 2 in the DXF)";
const ONE_DASH: &str = "a linetype of one dash (8ed179f8's 20E39: pattern length 10, one element \
    10), which the converter writes as continuous (no element, length 0)";
const NULL_MATERIAL: &str = "a layer with no material (57823859's 4BA), which the converter gives \
    the Global material (3C)";
const PLOT_STYLE: &str = "a layer whose plot style handle names no plot style name object \
    (a5f62813's 358C: 75), which the converter sets to the Normal one (F)";
const LAYER_NAMES: &str = "names the converter changes: an R14 layer name past 31 characters \
    cut (add377fe's 58), AutoCAD's constraint layer *LayerNameForDynamicConstraint named \
    *ADSK_CONSTRAINTS (52d14a7b's 1B81, and the dimensions on it)";
const SHAPE_REF: &str = "a shape file style of an external reference (0c9f5884's 29C7 \
    SHAPE|REF, flags 17): the converter's DXF writes 1, and no name";
const OBLIQUE: &str = "an oblique angle past 85 degrees (4ceb1d91's style 2D6: 2.43, 139 \
    degrees), which the converter writes as 0";
const DIM_TRUE_COLOR: &str = "a dimension style's line colours as true colours (77b96672's \
    4156: #00bf30), which R2018 DXF (176, 177) can only give as an index (102)";
const DIM_POINT_Z: &str = "the Z of a dimension's insertion point (12), which the converter \
    writes as 0 (10356729's F71A: -4.55)";
const DIM_TEXT_CODE_PAGE: &str = "0a02dc34 (R2004, ANSI_1251) has a DIMENSION text M65x2-6g, \
    its M Cyrillic (0xCC); the converter's DXF writes \\U+00CC (Latin I with grave), as Windows-1252 \
    would read it";
const VERTEX_Z: &str = "a 2D POLYLINE vertex whose Z the file stores as 7.95e26 (afb6e375's \
    3B892, R2004): the converter writes 0";
const DYNAMIC_BLOCK: &str = "the converter evaluates dynamic blocks again: 7213afc9's LINE 401 in \
    a dynamic block starts at Y 0.85 in the DWG, 1.7 in the DXF";
const SPLINE_REBUILT: &str = "splines the converter writes again: closed and periodic (11) set \
    for a spline whose ends meet (71fa8576's 2251: 0 in the DWG), the fit data of a spline with \
    control points left out (1082e083's 434), tangents recomputed";
const ONE_VERTEX: &str = "an LWPOLYLINE of one vertex (af358f44's 263B47), to which the \
    converter's audit adds a second";
const HATCH_REPAIRED: &str = "HATCHes the converter repairs: a seed point added or dropped \
    (8c78010e's 6E605), source handles of objects that are gone dropped, a solid fill named \
    _SOLID written SOLID (b9a5cce9's 6FC8)";
const DIM_BLOCKS: &str = "anonymous dimension blocks the converter makes again (*D4.. in \
    1efd993f's DXF, the DWG's *D0..*D3 then unused, see DIM_REGENERATED) or leaves out \
    (1082e083's *D13, used by no DIMENSION)";
const DROPPED_ENTITIES: &str = "entities the converter leaves out of a block: two DIMENSIONs on \
    *ADSK_CONSTRAINTS of d69212c0's block A$C31A0201F (5EB6, 5EB7), a polyface mesh POLYLINE \
    of acc69644's EABC (32 entities in the DWG, 31 in the DXF)";
const SORT_TABLES: &str = "the converter writes draw order tables again: one of no block (\
    1082e083's 700) left out, entries that change nothing (an entity sorted at its own handle, \
    or no entity: 0a02dc34's 29A) left out, its own sort keys (8d599508's 2CE2: entity 2E26 \
    at 2E26 in the DWG, 2E27 in the DXF)";
const APPLICATION_DATA: &str = "dictionaries of associative networks, dimension associations, \
    dynamic block data, annotation scale contexts and render materials (ACAD_ASSOCNETWORK, \
    ACAD_DIMASSOC, ACAD_ENHANCEDBLOCK*, AcDbContextDataManager, ADVMATERIAL...: 0435f25a's \
    1272, fb58c917's 426), which the converter leaves out of DXF or makes again";
const DRAW_ORDER_DICTIONARY: &str = "extension dictionaries holding a block's draw order table \
    that the converter leaves out with the table: an empty one (e9dd55a8's 11F5, of the dynamic \
    block reference *U50 10E0, its table 11F6 with no entry), one of a block record the file \
    lacks (93b65dc0's 274DAF, of 274DAE)";
const DICTIONARY_REPAIRS: &str = "dictionaries the converter changes: anonymous groups (*A) \
    dropped and renumbered (3fc2b503's group dictionary D: 31 entries in the DWG, 27 in the \
    DXF), an owner repaired (bd302ccc's 2DC911BAC), an entry Normal written NORMAL (8128d8d3)";
const MISSING_RECORDS: &str = "BLOCK_RECORD and LAYER handles a control object or an entity \
    names that the file's object map does not have (85cd9742's BLOCK_CONTROL lists 50 such \
    records; 85431781, d459d256, fb58c917, 93b65dc0, b235e4fd; a4c8933f's LAYER 1FFA): the \
    converter's DXF has none of them either; the reader warns and goes on";

const REMADE: &str = "the converter makes some objects again when it reads a DWG, under new \
    handles past the DWG's seed: ACAD2000/02f62c86's extension dictionary 26D of object 8 \
    (ACAD_XREC_ROUNDTRIP) is 2B3 in its DXF, the DWG's seed being 2AF; dictionary entries naming \
    such objects differ so (the DXF handle past the seed is the check)";
const ADDED: &str = "objects the converter adds when it reads a DWG, under handles past the \
    DWG's seed: round-trip data for the version it writes (ACAD2010/02f62c86's dictionary 29E, \
    ACAD_ROUNDTRIP_2008_TABLESTYLE_CELLSTYLEMAP of the table style 87), the objects of later \
    releases it gives an AutoCAD 2000 drawing (orig-R2000/20db22c3's MLEADERSTYLE 85, scale \
    list and visual style dictionaries), and in R13/R14 DXF LAYOUT objects of its own";
const NULL_SORT: &str = "AutoCAD's 97156d13 has four draw order entries for entity 0 (an erased \
    entity: sort handles 397, 4C3, 3A0 and 403 in its SORTENTSTABLE 415); the converter's DXF \
    keeps one (397); the other 35 entries are the DWG's";
const ORDER: &str = "the same entries in another order: the converter writes a dictionary's \
    sorted by name, ignoring case (ACAD2000/205fdde7's 34E has MCS_DOCUMENT_ID, MCS_PARAMS_DATA, \
    MC_VERSION_DATA in its DWG, MC_VERSION_DATA first in its DXF), and a SORTENTSTABLE's by \
    entity handle (orig/22852ead's 22C starts with entity 250 in the DWG, 14B in the DXF); the \
    DWG reader keeps the stored order (the note is given only when the DXF's is so sorted)";
const GROUPS_RENUMBERED: &str = "the converter renumbers anonymous groups in handle order: \
    AutoCAD's 55017b3e names its group BB4A *A10 in ACAD_GROUP (10C), the DXF *A2; both have \
    the same 38 groups";
const EMPTY: &str = "the converter leaves out of DXF the empty dictionaries of AutoCAD's files \
    (orig-R2004/56165720's E6, the extension dictionary of object 10, has no entry)";
const ROUNDTRIP: &str = "data the converter keeps for a round trip through an older version, \
    which it consumes when it reads a DWG and writes again when it needs it: \
    ACAD_XREC_ROUNDTRIP extension dictionaries (ACAD2000/02f62c86's 26B of object 10), \
    ACDB_RECOMPOSE_DATA, ACAD_LAYOUTSELFREF, ADSK_XREC_LAYOUTTHUMBNAIL, ASDK_XREC_ANNO_SCALE_INFO, \
    the header variables of later releases (the dictionary holding CEPSNTYPE, FINGERPRINTGUID...), \
    AutoCAD's ACAD_MTEXT_2008_RT (orig-R2013/55017b3e), and what these dictionaries own";
const DATA_STORAGE: &str = "the index of R2013's data storage section (AcDsRecords, AcDsSchemas, \
    AcDsDecomposeData, and dictionaries below them whose names are numbers: orig-R2000/\
    02f62c86's 229 and 22A), which AutoCAD writes and the converter leaves out of DXF";
const MATERIAL_MAP: &str =
    "the map entries (BUMPTILE, DIFFUSETILE, OPACITYTILE, REFLECTIONTILE...) \
    of the materials' extension dictionaries of AutoCAD's files (orig-R2000/22852ead's 110), \
    which the converter leaves out of DXF";
const POLYSOLID: &str = "the polysolid variables PSOLWIDTH and PSOLHEIGHT (DICTIONARYVAR 566 and \
    567 of ACAD2000/7ba7ea2e's variables dictionary 5E) are in the converter's R13 to 2000 DWGs \
    and not in its DXF of them; its 2004 and later DXF has them";
const MODEL_VIEWPORT: &str = "a model layout's last active viewport is null in every DWG, \
    AutoCAD's included; the converter's DXF names the *Active VPORT entry there \
    (ACAD2000/02f62c86's model layout 22: 0 in the DWG, VPORT 94 in the DXF; the note checks the \
    DXF handle is the *Active entry's)";
const R14_OBJECTS: &str = "R13/R14 DXF: the converter writes LAYOUT objects of its own, under \
    handles past the DWG's seed, with a default page setup and one paper space (ACAD14/02f62c86: \
    the DWG's LAYOUTs 22, 59, 5E, named MODEL, LAYOUT1, LAYOUT2 in ACAD_LAYOUT 1A, plotter \
    none_device, margins 6.35 and 19.05; the DXF's 2F8 and 2F9, past the seed 2CD, in no \
    dictionary, no plotter, margins 0), and leaves out objects of classes R13/R14 DXF has no form \
    of, which the DWG keeps: MLEADERSTYLE (D8 STANDARD, E5 ANNOTATIVE), the ACAD_TABLESTYLE and \
    ACAD_PLOTSTYLENAME dictionaries, a DATATABLE (4d3d81a0's 91, MAP_DISPLAY_CUSTOMOBJ_REG_TABLE), \
    a VISUALSTYLE a group names (915f6069's *A1, 2E8); its entry names are in capitals \
    (55017b3e's ACDBBLOCKTABLERECORDDATA, AcDbBlockTableRecordData in the DWG)";

const HANDSEED: &str = "the converter's DXF has objects the DWG does not (XRECORD, DICTIONARY, \
    DICTIONARYVAR: 66 of them, 267 to 2A9, in orig/02f62c86's) and a $HANDSEED past them; the \
    DWG's seed is one past its own highest handle in the converter's DWGs (2AB after 2AA in \
    ACAD2004/02f62c86, 26C after 26B in ACAD2013's), and further in AutoCAD's (21F after 20A in \
    orig/22f3275c)";
const TEXTSIZE: &str = "e296ca50: the converter writes the current text style's last height \
    (0.2) as $TEXTSIZE when it reads an R2004 to R2018 DWG of it; the DWG's header holds 0.1875 \
    (0.2 is nowhere in its AcDb:Header section) as do the R13 to R2000 conversions and their \
    DXF, and its ACAD2004 DWG converted to R2000 DXF gives 0.2 (experiments/textsize)";
const PROXY: &str = "entities of classes the converter has no application for (97156d13's \
    TCH_WALL... of TArch) are ACAD_PROXY_ENTITY in its DXF, and in its DWGs of another version \
    than the original's (those agree); a DWG of the original's version keeps them as objects of \
    their class, whose DXF name the DWG reader gives";
const SURFACE_GRAPHICS: &str = "AutoCAD saves proxy graphics with its own surfaces and section \
    objects, which the model does not read: a wireframe of polylines and elliptical arcs (7ba7ea2e's \
    PLANESURFACE 50A: 13 polylines, 1 elliptical arc, traits); the converter's DXF has one shell it \
    makes for each instead";
const RENUMBERED: &str = "the converter renumbers anonymous blocks when it writes a file: \
    AutoCAD's 97156d13 names *D20 what the converter's DXF and DWG (ACAD2013, which agrees) name \
    *D12, and so on";
const HAS_ATTRIBUTES: &str = "AutoCAD set the has-attributes flag (2) of two blocks of \
    95cc558d that have no ATTDEF; the converter clears it in the DXF and in its DWG (ACAD2018, \
    which agrees)";
const R13_CODE_PAGE: &str = "the converter writes R13 DXF's $DWGCODEPAGE in lower case";
const R13_MEASUREMENT: &str = "R13 DXF has no $MEASUREMENT: the DXF reader gives 0, the DWG's \
    own section (spec 22) says";
const DASH_SCALE: &str = "the converter writes group 46 only for a dash with a shape or text (74 \
    not 0): the DXF reader gives 1 for the others, the DWG holds the stored scale (0.1, 0)";
const TEMP_REC: &str = "a shape file's STYLE entry of an R11 drawing: the converter names it \
    $TEMP_REC1 in DWG and writes no name in DXF";
const CASE: &str = "symbol names are case-insensitive: the converter writes linetype flag 2 \
    (CONTINUOUS) as `Continuous` whatever the entry's spelling (`CONTINUOUS` in an R11 drawing), \
    and no text style (7) for an entity on the drawing's `Standard` style, which the DXF reader \
    takes as the reference's default STANDARD";
const FIT_SPLINE: &str = "a DWG keeps a spline drawn through fit points as the fit points and \
    tangents (spec 20.4.40, scenario 2: no knots, control points or their tolerances, in \
    AutoCAD's files too); the converter's DXF adds the knots and control points it computes and \
    tolerances of 1e-10 (05761169's 1BE: 9 knots, 5 control points, 3 fit points)";
const SPLINE_BITS: &str = "a DWG's SPLINE has closed, periodic and rational only (spec \
    20.4.40); the closed and rational bits agree (the note is given only then); the converter's \
    DXF sets periodic (2) for every closed spline whatever the DWG's bit (experiments/\
    spline-flags), 8 (planar) and 16 (linear) from the geometry, and 32 and 1024 for fit-point \
    splines (70 = 1064 for every one of them, 8 or 24 for the others)";
const CLIP_CLOSED: &str = "a polygonal IMAGE or WIPEOUT clip boundary is stored open, in \
    AutoCAD's files too (orig 947e28fb's 81B: 5 vertices); the converter's DXF repeats the first \
    vertex at the end";
const LEADER_NO_ANNOTATION: &str = "the converter writes no hookline direction (74) for a LEADER \
    without annotation (73 = 3: 22852ead's 22E, 55017b3e's 875B...), so DXF reads 0; the DWG \
    has the bit set";
const LEADER_HOOKLINE: &str = "for a LEADER whose annotation is off to the side of its last \
    segment the converter computes a hookline: 75 = 1, a vertex where it starts, and the \
    annotation's box (37361cb2's 9DD, a TOLERANCE leader: 4 vertices and box height 0.669 in \
    every DWG, 5 vertices and 0.446 in DXF); the DWG keeps neither the flag nor the vertex \
    (spec 20.4.47)";
const LEADER_NO_BOX: &str = "R2010 and later LEADERs have no text box height and width (their \
    data ends 132 bits before an R2004 LEADER's, the bits after the end point projection being \
    those after the box there); the converter writes its annotation's height and width (0.18 and \
    0.771 for 947e28fb's 72E)";
const LEADER_BOX: &str = "the converter recomputes the box width of the LEADER 72E of AutoCAD's \
    947e28fb, 3a65cf07 and 8e9750fd when reading them: 0.825 in AutoCAD's DWG, 0.771 in the DXF \
    and in the converter's own DWGs of them";
const HATCH_O: &str = "the solid fill of 9d03bcf4's two HATCHes is named `SOLID,_O` in its R14 to \
    2018 DWGs and in AutoCAD's own; the converter's DXF says `SOLID`";
const DEFAULT_WIDTH: &str = "the converter leaves out a VERTEX's widths (40, 41) that equal its \
    POLYLINE's default widths, which the DXF reader takes as the reference's default 0; the DWG \
    stores them with every vertex (205fdde7's 1EF: 0.15)";
const R13_ELEVATION: &str = "R13 DXF puts a 2D POLYLINE's elevation in the Z of each vertex \
    (20db22c3 and 7b06770e's 44: 2); the DWG's vertices have 0 (spec 20.4.11: the Z is the \
    polyline's elevation), as the converter's R14 and later DXF";
const R13_VERTEX_HANDLES: &str = "R13 DXF gives VERTEX entities new handles (c73b1d1f's 1C2: \
    292 in the DWG, 2D6 in the DXF); later versions keep them";
const BACKGROUND_2004: &str = "the converter writes no MTEXT background (90, 63, 421, 45) in 2004 \
    and 2007 DXF; its 2010 and later DXF of the same drawing has the DWG's (55017b3e's C577: 90 = \
    3, colour 200,200,200, scale 1.1), as has its 2010 DXF of the ACAD2007 DWG \
    (experiments/r2007/background)";
const MTEXT_INDENT: &str = "the converter rewrites the paragraph code `\\pi102.25;` that starts \
    the MTEXT 522 of AutoCAD's 0e3eccc7 as `\\pxqc;` when it reads it, in its 2007 and 2018 DXF \
    and in its own DWGs (the ACAD2007 set agrees with its DXF)";
const R13_ATTDEF: &str = "R13 DXF has no ATTDEF vertical alignment (74): the converter leaves it \
    out (4d3d81a0's 78: 74 = 2 in its 2000 DXF)";
const R13_RENUMBERED: &str = "the anonymous blocks the converter makes for R13 DXF (HATCH, \
    ACAD_TABLE) take numbers the drawing's own then lose: 22852ead's *X9 is *X11 there";
const MTEXT_2013: &str = "AutoCAD's 55017b3e holds annotative MTEXT whose text is `-\\P`, \
    `2\\P`... and whose column data (ACAD_MTEXT_COLUMN_INFO) has a height of 0; the converter \
    rewrites them `\\pxr0.75;-` and -2, -2.049... in its DXF and in its own DWGs (the ACAD2013 \
    set agrees)";
const COLUMNS_XDATA: &str = "the converter's R13 to 2004 DXF leaves out an MTEXT's \
    ACAD_MTEXT_COLUMN_INFO extended data, which its DWGs of the same versions and AutoCAD's keep \
    and its 2010 and later DXF has (7c63119c's 1C0: dynamic, one column, gutter 1)";
const HELIX_REBUILT: &str = "the converter rebuilds a HELIX's spline from its axis, radius, \
    turns and turn height when it reads AutoCAD's file (74da1ac1: 56 knots in AutoCAD's DWG, 31 \
    in the DXF and in the converter's own DWGs, which agree)";
const TABLE_CONTENT: &str = "from R2010 a table's rows, columns and style are in its table \
    content (spec 20.4.97), which the reader does not read: its block and insertion point, \
    which draw it, are read";
const UNDERLAY_CLIP: &str = "AutoCAD's 0f061fe4 keeps a 6-vertex clip boundary on an underlay \
    whose clipping is off (280 = 30); the converter drops it";
const REPAIR: &str = "the converter's audit moves some entities to layers it makes, named \
    `<name> @ <n>` (`_@_` in R13/R14, whose names have no spaces): in orig/947e28fb the LEADER \
    72E is on layer 0 (handle 10) in the DWG and on a new `0 @ 1` (AC5) in its DXF. Its \
    conversions of 947e28fb (all versions) and 55017b3e carry such layers, which get new \
    handles each time it reads the file and which it leaves out of R13/R14 DXF, putting the \
    entities back on the original layer; the DWG reader reads what each DWG has";
const SHAPE: &str = "the converter leaves out of DXF a SHAPE whose shape file it cannot load: \
    DXF names the shape (group 2), which only the .shx file knows (f9b37257, 54eb4d0c, \
    20db22c3, 7b06770e)";
const UNREFERENCED: &str = "the converter leaves out of DXF an anonymous block nothing uses \
    (f9b37257 and 54eb4d0c's *D2; their DIMENSION names *D3)";
const R14_PAPER: &str = "R13/R14 DXF has one paper space: the converter leaves the other \
    layouts' blocks out of DXF; the DWG has them (8ac3451b and 3a65cf07, R14 files with two \
    layouts, and every conversion of a drawing with more than one)";
const R13_ANONYMOUS: &str = "the converter writes entities R13 DXF has no form of (ACAD_TABLE, \
    HATCH, gradients) as INSERTs of anonymous blocks it makes for the DXF";
const LAYOUTS: &str = "R13/R14 block records have no layout handle; both readers link each \
    block to the LAYOUT object naming it: the DWG's own, in the DXF the converter's (see the \
    layouts' note, R13/R14 DXF)";
const R14_TYPES: &str = "types R13/R14 DXF has no form of: the converter writes ACAD_TABLE as an \
    INSERT, HELIX as a SPLINE, MULTILEADER (R14) as ACAD_PROXY_ENTITY";
const R14_POLYLINE: &str = "the converter writes R14 DXF's 2D POLYLINEs as LWPOLYLINEs, the form \
    R14 introduced (205fdde7)";

#[derive(Default)]
struct Tally {
    compared: usize,
    equal: usize,
    agree: usize,
}

#[derive(Default)]
struct Report {
    /// Per set and kind ("layers", "entity LINE"...).
    tallies: BTreeMap<(String, String), Tally>,
    /// Per pattern: count and a few examples.
    diffs: BTreeMap<String, (usize, Vec<String>)>,
}

impl Report {
    fn diff(&mut self, pattern: String, example: String) {
        // EXAV_DEBUG_CAD_EXAMPLES: how many examples a pattern shows.
        let max = std::env::var("EXAV_DEBUG_CAD_EXAMPLES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let e = self.diffs.entry(pattern).or_default();
        e.0 += 1;
        if e.1.len() < max {
            e.1.push(example);
        }
    }

    /// One item compared: its differences reported, its tally counted.
    fn item(&mut self, set: &str, kind: &str, found: Vec<(String, String)>, what: &str) {
        let t = self
            .tallies
            .entry((set.to_string(), kind.to_string()))
            .or_default();
        t.compared += 1;
        if found.is_empty() {
            t.equal += 1;
        }
        if found
            .iter()
            .all(|(p, _)| explained(&format!("{set} {p}")).is_some())
        {
            t.agree += 1;
        }
        for (p, e) in found {
            self.diff(format!("{set} {p}"), format!("{what} {e}"));
        }
    }
}

fn keyed<'a>(v: &'a Value, key: &str) -> BTreeMap<String, &'a Value> {
    v.as_array()
        .map(|l| {
            l.iter()
                .map(|e| (e[key].as_str().unwrap_or("").to_string(), e))
                .collect()
        })
        .unwrap_or_default()
}

/// What kind of block a name is, for the patterns of blocks one side lacks:
/// a paper space, an anonymous block (`unreferenced` when no DIMENSION or
/// INSERT of the DXF names it), or a named one.
fn block_kind(b: &Value, used: &[String]) -> &'static str {
    let upper = b["name"].as_str().unwrap_or("").to_ascii_uppercase();
    if upper.starts_with("*PAPER_SPACE") {
        "*Paper_Space"
    } else if upper.starts_with('*') && used.contains(&upper) {
        "anonymous"
    } else if upper.starts_with('*') {
        "unreferenced"
    } else {
        "named"
    }
}

/// Block names the DIMENSIONs and INSERTs of a DXF reading use.
fn used_blocks(d: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for b in d["blocks"].as_array().into_iter().flatten() {
        for e in b["entities"].as_array().into_iter().flatten() {
            if let Some(n) = e["block_name"].as_str() {
                out.push(n.to_ascii_uppercase());
            }
        }
    }
    out
}

fn compare_files(dwg: &Value, dxf: &Value, file: &str, set: &str, r: &mut Report) {
    let mut found = Vec::new();
    compare(&dwg["header"], &dxf["header"], "header", &mut found);
    for k in dwg["header"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k)
    {
        let mine: Vec<_> = found
            .iter()
            .filter(|(p, _)| p == &format!("header.{k}") || p.starts_with(&format!("header.{k} ")))
            .cloned()
            .collect();
        r.item(set, "header variables", mine, file);
    }

    let seed = u64::from_str_radix(dwg["header"]["handle_seed"].as_str().unwrap_or(""), 16)
        .unwrap_or(u64::MAX);
    for table in ["layers", "linetypes", "text_styles", "dim_styles", "vports"] {
        let ours = keyed(&dwg[table], "handle");
        let theirs = keyed(&dxf[table], "handle");
        for (h, a) in &ours {
            let found = match theirs.get(h) {
                Some(b) => {
                    let mut found = Vec::new();
                    compare(a, b, table, &mut found);
                    // An entry the converter's audit renamed: its other
                    // fields may be repaired too (an empty-named layer's
                    // ByBlock colour is 7).
                    if b["name"]
                        .as_str()
                        .is_some_and(|n| n.starts_with("$TD_AUDIT_GENERATED"))
                    {
                        for f in &mut found {
                            if !f.0.ends_with(" (audit)") {
                                f.0.push_str(" (audit)");
                            }
                        }
                    }
                    found
                }
                None => {
                    let note = if repair_name(a["name"].as_str().unwrap_or("")) {
                        " (repair)"
                    } else {
                        ""
                    };
                    vec![(format!("{table} (only DWG){note}"), String::new())]
                }
            };
            r.item(set, table, found, &format!("{file}: {h}"));
        }
        for (h, b) in theirs.iter().filter(|(h, _)| !ours.contains_key(*h)) {
            let note = if repair_name(b["name"].as_str().unwrap_or("")) {
                " (repair)"
            } else if u64::from_str_radix(h, 16).is_ok_and(|v| v >= seed) {
                " (added)"
            } else {
                ""
            };
            r.item(
                set,
                table,
                vec![(format!("{table} (only DXF){note}"), String::new())],
                &format!("{file}: {h} {}", b["name"]),
            );
        }
    }

    compare_objects(dwg, dxf, file, set, r);

    let used = used_blocks(dxf);
    // The handles of the repair layers either side has.
    let repair: Vec<String> = [dwg, dxf]
        .iter()
        .flat_map(|d| d["layers"].as_array().into_iter().flatten())
        .filter(|l| repair_name(l["name"].as_str().unwrap_or("")))
        .map(|l| l["handle"].as_str().unwrap_or("").to_string())
        .collect();
    let first_style = dwg["text_styles"][0]["name"].as_str().unwrap_or("");
    let ours = keyed(&dwg["blocks"], "record");
    let theirs = keyed(&dxf["blocks"], "record");
    for (h, a) in &ours {
        let Some(b) = theirs.get(h) else {
            let kind = block_kind(a, &used);
            r.item(
                set,
                "blocks",
                vec![(format!("blocks (only DWG) {kind}"), String::new())],
                &format!("{file}: {h} {}", a["name"]),
            );
            continue;
        };
        let mut found = Vec::new();
        for (k, v) in a.as_object().into_iter().flatten() {
            if k != "entities" {
                compare(v, &b[k], &format!("blocks.{k}"), &mut found);
            }
        }
        let empty = Vec::new();
        let es = a["entities"].as_array().unwrap_or(&empty);
        let ts = b["entities"].as_array().unwrap_or(&empty);
        let handles = |l: &[Value]| -> Vec<String> {
            l.iter()
                .map(|e| e["handle"].as_str().unwrap_or("").to_string())
                .collect()
        };
        let (ours_h, theirs_h) = (handles(es), handles(ts));
        if ours_h != theirs_h {
            // Which types one side has that the other lacks.
            let mut extra: Vec<String> = es
                .iter()
                .filter(|e| !theirs_h.contains(&e["handle"].as_str().unwrap_or("").to_string()))
                .map(|e| e["type"].as_str().unwrap_or("?").to_string())
                .collect();
            extra.sort();
            extra.dedup();
            let rest: Vec<&String> = ours_h.iter().filter(|x| theirs_h.contains(x)).collect();
            let same_order =
                rest.len() == theirs_h.len() && rest.iter().zip(&theirs_h).all(|(a, b)| *a == b);
            let note = if same_order && !extra.is_empty() {
                format!(" {}", extra.join(","))
            } else {
                String::new()
            };
            found.push((
                format!("blocks.entities (handles){note}"),
                format!("{} vs {} entities", ours_h.len(), theirs_h.len()),
            ));
        }
        r.item(set, "blocks", found, &format!("{file}: {h} {}", a["name"]));

        let theirs_by: BTreeMap<&str, &Value> = ts
            .iter()
            .map(|e| (e["handle"].as_str().unwrap_or(""), e))
            .collect();
        for e in es {
            let eh = e["handle"].as_str().unwrap_or("");
            let Some(t) = theirs_by.get(eh) else {
                continue;
            };
            let ty = e["type"].as_str().unwrap_or("?").to_string();
            let mut found = entity_diffs(e, t, &format!("entity:{ty}"), &repair);
            // The converter leaves out the style (7) of the entities on the
            // drawing's first STYLE entry whatever its name, which DXF then
            // reads as STANDARD.
            for f in &mut found {
                if f.0.ends_with(".style")
                    && f.1.ends_with(&format!("\"{first_style}\" vs \"STANDARD\""))
                {
                    f.0.push_str(" (first style)");
                }
            }
            r.item(
                set,
                &format!("entity {ty}"),
                found,
                &format!("{file}: {eh}"),
            );
        }
    }
    for (h, b) in theirs.iter().filter(|(h, _)| !ours.contains_key(*h)) {
        let kind = block_kind(b, &used);
        r.item(
            set,
            "blocks",
            vec![(format!("blocks (only DXF) {kind}"), String::new())],
            &format!("{file}: {h} {}", b["name"]),
        );
    }
}

/// The objects of the two readings (`object_differences`), one item each.
fn compare_objects(dwg: &Value, dxf: &Value, file: &str, set: &str, r: &mut Report) {
    let seed = u64::from_str_radix(dwg["header"]["handle_seed"].as_str().unwrap_or(""), 16)
        .unwrap_or(u64::MAX);
    for (kind, h, found) in object_differences(dwg, dxf, seed) {
        r.item(set, kind, found, &format!("{file}: {h}"));
    }
}

/// Every `.dwg` one level below `dir`, with its DXF.
fn pairs(dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for sub in rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        let Some(name) = sub.file_name().map(|n| n.to_string_lossy().to_string()) else {
            continue;
        };
        if name == "source" {
            continue;
        }
        let dxf_dir = sub.with_file_name(format!("{name}-dxf"));
        let Ok(files) = std::fs::read_dir(&sub) else {
            continue;
        };
        for f in files.flatten().map(|e| e.path()) {
            if f.extension().is_some_and(|e| e.eq_ignore_ascii_case("dwg")) {
                let stem = f
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                out.push((f, dxf_dir.join(format!("{stem}.dxf"))));
            }
        }
    }
    out.sort();
    out
}

/// The first 8 hexadecimal digits of a file's SHA-256.
fn sha8(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What a file is called in the report: its set and the hash of the
/// drawing it comes from.
fn label(root: &Path, dwg: &Path, set: &str) -> String {
    let source = dwg
        .file_name()
        .map(|n| root.join("source").join(n))
        .filter(|p| p.exists())
        .unwrap_or_else(|| dwg.to_path_buf());
    format!("{set}/{}", sha8(&source))
}

fn explained(pattern: &str) -> Option<&'static str> {
    let (set, rest) = pattern.split_once(' ').unwrap_or((pattern, ""));
    EXPLAINED
        .iter()
        .find(|(sets, start, end, _)| {
            (sets.contains(&"*") || sets.contains(&set))
                && rest.starts_with(start)
                && rest.ends_with(end)
        })
        .map(|(_, _, _, why)| *why)
}

#[test]
fn dwg_reads_as_its_dxf_conversion() {
    let Some(dir) = std::env::var_os("EXAV_DEBUG_CAD_CORPUS") else {
        eprintln!("EXAV_DEBUG_CAD_CORPUS not set; skipping the DWG/DXF differential test");
        return;
    };
    let root = Path::new(&dir);
    let all = pairs(root);
    assert!(!all.is_empty(), "no .dwg under {}", root.display());

    let mut r = Report::default();
    let (mut read, mut no_dxf) = (0, 0);
    let mut failed = Vec::new();
    for (dwg_path, dxf_path) in &all {
        let dir = dwg_path
            .parent()
            .and_then(|p| p.file_name())
            .map_or(String::new(), |n| n.to_string_lossy().to_string());
        let mut name = label(root, dwg_path, &dir);
        let Ok(dxf_bytes) = std::fs::read(dxf_path) else {
            no_dxf += 1;
            continue;
        };
        let dwg_bytes = std::fs::read(dwg_path).expect("read");
        let dwg = match exav_render::cad::read_dwg(&dwg_bytes) {
            Ok(d) => d,
            Err(e) => {
                failed.push(format!("{name}: {e}"));
                continue;
            }
        };
        let dxf = exav_render::cad::read_dxf(&dxf_bytes).expect("the DXF reads");
        read += 1;
        let set = if dir == "orig" {
            let set = format!("orig-{:?}", dwg.header.version);
            name = label(root, dwg_path, &set);
            set
        } else {
            dir
        };
        for w in &dwg.warnings {
            let note = if w.message.contains("referenced but not in the file") {
                " referenced but not in the file"
            } else {
                ""
            };
            r.diff(
                format!("{set} warning{note}"),
                format!("{name}: {:?} {}", w.kind, w.message),
            );
        }
        let a: Value = serde_json::from_str(&exav_render::cad::to_json(&dwg)).expect("JSON");
        let b: Value = serde_json::from_str(&exav_render::cad::to_json(&dxf)).expect("JSON");
        compare_files(&a, &b, &name, &set, &mut r);
    }

    eprintln!(
        "\n{} DWG files, {read} read and compared, {} failed, {no_dxf} without a DXF",
        all.len(),
        failed.len()
    );
    for f in &failed {
        eprintln!("  {f}");
    }
    eprintln!("\nagreement: identical, identical or explained, compared");
    for ((set, kind), t) in &r.tallies {
        let pct = |n: usize| 100.0 * n as f64 / t.compared.max(1) as f64;
        eprintln!(
            "  {set:11} {kind:28} {:>7} {:>7.2}%  {:>7} {:>7.2}%  {:>7}",
            t.equal,
            pct(t.equal),
            t.agree,
            pct(t.agree),
            t.compared
        );
    }
    let mut unexplained = 0;
    for (pattern, (count, examples)) in &r.diffs {
        match explained(pattern) {
            Some(why) => eprintln!("\n[explained] {pattern}: {count} ({why})"),
            None => {
                unexplained += count;
                eprintln!("\n{pattern}: {count}");
            }
        }
        for e in examples {
            eprintln!("    {e}");
        }
    }
    assert!(failed.is_empty(), "DWG files that did not read");
    assert_eq!(unexplained, 0, "unexplained differences");
}
