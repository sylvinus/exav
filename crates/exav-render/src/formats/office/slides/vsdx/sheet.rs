//! Sheets, sections, rows and cells ([MS-VSDX] 2.2.5), read from the XML
//! parts of a drawing: a shape, a style sheet or a page sheet is a `Sheet`.

use crate::formats::office::common::xml::{Child, Node};
use std::collections::HashMap;

/// The name of an element or attribute without its namespace prefix.
pub fn local(name: &str) -> &str {
    name.rsplit([':', '}']).next().unwrap_or(name)
}

/// A cell: its value as the V attribute holds it, and its formula.
#[derive(Debug, Clone, Default)]
pub struct Cell {
    pub v: Option<String>,
    pub f: Option<String>,
}

impl Cell {
    /// The formula to evaluate: not "Inh" (inherited) nor "No Formula".
    pub fn formula(&self) -> Option<&str> {
        self.f
            .as_deref()
            .filter(|f| !f.is_empty() && *f != "Inh" && *f != "No Formula")
    }
}

pub type Cells = HashMap<String, Cell>;

#[derive(Debug, Default)]
pub struct Row {
    /// The row type of a geometry row (MoveTo, LineTo...).
    pub t: Option<String>,
    pub ix: Option<u32>,
    pub n: Option<String>,
    pub del: bool,
    pub cells: Cells,
}

/// A row of a section, by its index or its name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RowKey {
    Ix(u32),
    Name(String),
}

#[derive(Debug, Default)]
pub struct Section {
    pub name: String,
    pub ix: Option<u32>,
    pub del: bool,
    /// The cells of the section itself (NoFill, NoLine, NoShow of a path).
    pub cells: Cells,
    pub rows: Vec<Row>,
    /// Where each row is, by key; the first of rows with the same key.
    index: HashMap<RowKey, usize>,
}

impl Section {
    /// The row `k` names.
    pub fn find_row(&self, k: &RowKey) -> Option<&Row> {
        self.index.get(k).and_then(|i| self.rows.get(*i))
    }

    fn add_row(&mut self, row: Row) {
        let key = match (row.ix, &row.n) {
            (Some(i), _) => Some(RowKey::Ix(i)),
            (None, Some(n)) => Some(RowKey::Name(n.clone())),
            _ => None,
        };
        if let Some(k) = key {
            self.index.entry(k).or_insert(self.rows.len());
        }
        self.rows.push(row);
    }
}

/// What a Text element holds, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Piece {
    Text(String),
    /// The start of a run with the properties of a Character row.
    Cp(u32),
    Pp(u32),
    Tp(u32),
    /// A field of the Field section, with the text it was saved with.
    Fld(u32, String),
}

#[derive(Debug, Default)]
pub struct Foreign {
    /// The part the image is in, as a path of the package.
    pub target: Option<String>,
}

#[derive(Debug, Default)]
pub struct Sheet {
    pub id: u32,
    pub name: String,
    /// Shape, Group, Foreign or Guide.
    pub kind: String,
    pub del: bool,
    pub master: Option<u32>,
    pub master_shape: Option<u32>,
    pub line_style: Option<u32>,
    pub fill_style: Option<u32>,
    pub text_style: Option<u32>,
    pub cells: Cells,
    pub sections: Vec<Section>,
    pub text: Option<Vec<Piece>>,
    pub foreign: Option<Foreign>,
    pub shapes: Vec<Sheet>,
}

fn flag(n: &Node, k: &str) -> bool {
    matches!(n.attr(k), Some("1" | "true"))
}

fn uint(n: &Node, k: &str) -> Option<u32> {
    n.attr(k).and_then(|v| v.trim().parse().ok())
}

fn cell(n: &Node) -> Cell {
    Cell {
        v: n.attr("V").map(str::to_string),
        f: n.attr("F").map(str::to_string),
    }
}

fn cells_of(n: &Node, into: &mut Cells) {
    for c in n.nodes().filter(|c| local(&c.name) == "Cell") {
        if let Some(name) = c.attr("N") {
            into.insert(name.to_string(), cell(c));
        }
    }
}

/// Shapes nested deeper than this are left out.
const MAX_NESTING: u32 = 64;

/// Sections of one sheet past this are left out: a sheet is searched
/// section by section.
const MAX_SECTIONS: usize = 1024;

/// What `parse` needs of the part: where its relationships lead, by id.
pub struct Rels<'a>(pub &'a HashMap<String, String>);

/// The sheet of a Shape, StyleSheet or PageSheet element, and the shapes in
/// it. `count` is incremented for each sheet read.
pub fn parse(n: &Node, rels: &Rels, count: &mut usize, depth: u32) -> Sheet {
    *count += 1;
    let mut s = Sheet {
        id: uint(n, "ID").unwrap_or(0),
        name: n.attr("NameU").or(n.attr("Name")).unwrap_or("").to_string(),
        kind: n.attr("Type").unwrap_or("Shape").to_string(),
        del: flag(n, "Del"),
        master: uint(n, "Master"),
        master_shape: uint(n, "MasterShape"),
        line_style: uint(n, "LineStyle"),
        fill_style: uint(n, "FillStyle"),
        text_style: uint(n, "TextStyle"),
        ..Sheet::default()
    };
    cells_of(n, &mut s.cells);
    for c in n.nodes() {
        match local(&c.name) {
            "Section" => {
                let mut sec = Section {
                    name: c.attr("N").unwrap_or("").to_string(),
                    ix: uint(c, "IX"),
                    del: flag(c, "Del"),
                    ..Section::default()
                };
                cells_of(c, &mut sec.cells);
                for r in c.nodes().filter(|r| local(&r.name) == "Row") {
                    let mut row = Row {
                        t: r.attr("T").map(str::to_string),
                        ix: uint(r, "IX"),
                        n: r.attr("N").map(str::to_string),
                        del: flag(r, "Del"),
                        ..Row::default()
                    };
                    cells_of(r, &mut row.cells);
                    sec.add_row(row);
                }
                if s.sections.len() < MAX_SECTIONS {
                    s.sections.push(sec);
                }
            }
            "Text" => s.text = Some(pieces(c)),
            "ForeignData" => {
                let rel = c
                    .nodes()
                    .find(|r| local(&r.name) == "Rel")
                    .and_then(|r| r.attr("r:id").or(r.attr("id")));
                s.foreign = Some(Foreign {
                    target: rel.and_then(|id| rels.0.get(id).cloned()),
                });
            }
            "Shapes" if depth < MAX_NESTING => {
                for k in c.nodes().filter(|k| local(&k.name) == "Shape") {
                    s.shapes.push(parse(k, rels, count, depth + 1));
                }
            }
            _ => {}
        }
    }
    s
}

fn pieces(n: &Node) -> Vec<Piece> {
    let mut out: Vec<Piece> = vec![];
    for c in &n.children {
        match c {
            Child::Text(t) => match out.last_mut() {
                Some(Piece::Text(p)) => p.push_str(t),
                _ => out.push(Piece::Text(t.clone())),
            },
            Child::Node(e) => {
                let ix = uint(e, "IX").unwrap_or(0);
                match local(&e.name) {
                    "cp" => out.push(Piece::Cp(ix)),
                    "pp" => out.push(Piece::Pp(ix)),
                    "tp" => out.push(Piece::Tp(ix)),
                    "fld" => out.push(Piece::Fld(ix, e.own_text())),
                    _ => {}
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::common::xml;

    fn sheet(x: &str) -> Sheet {
        let n = xml::parse(x.as_bytes(), &mut xml::within(1 << 24)).unwrap();
        let rels: HashMap<String, String> =
            [("rId1".to_string(), "visio/media/image1.png".to_string())].into();
        parse(&n, &Rels(&rels), &mut 0, 0)
    }

    #[test]
    fn cells_sections_rows_text_and_children() {
        let s = sheet(
            r#"<Shape xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ID="3" NameU="Box" Type="Group" Master="4" MasterShape="9" LineStyle="1" FillStyle="2" TextStyle="3">
              <Cell N="Width" V="2.5" F="Inh"/>
              <Section N="Geometry" IX="0"><Cell N="NoFill" V="1"/>
                <Row T="MoveTo" IX="1"><Cell N="X" V="0" F="Width*0"/></Row></Section>
              <Text>a<cp IX="1"/>b<fld IX="0">p1</fld>c<pp IX="2"/><tp IX="1"/></Text>
              <ForeignData ForeignType="Bitmap"><Rel r:id="rId1"/></ForeignData>
              <Shapes><Shape ID="4"/></Shapes></Shape>"#,
        );
        assert_eq!(
            (s.id, s.name.as_str(), s.kind.as_str()),
            (3, "Box", "Group")
        );
        assert_eq!((s.master, s.master_shape), (Some(4), Some(9)));
        assert_eq!(
            (s.line_style, s.fill_style, s.text_style),
            (Some(1), Some(2), Some(3))
        );
        assert_eq!(s.cells["Width"].v.as_deref(), Some("2.5"));
        assert_eq!(s.cells["Width"].formula(), None);
        let g = &s.sections[0];
        assert_eq!((g.name.as_str(), g.ix), ("Geometry", Some(0)));
        assert_eq!(g.cells["NoFill"].v.as_deref(), Some("1"));
        assert_eq!(g.rows[0].t.as_deref(), Some("MoveTo"));
        assert_eq!(g.rows[0].cells["X"].formula(), Some("Width*0"));
        assert_eq!(
            s.text.unwrap(),
            vec![
                Piece::Text("a".into()),
                Piece::Cp(1),
                Piece::Text("b".into()),
                Piece::Fld(0, "p1".into()),
                Piece::Text("c".into()),
                Piece::Pp(2),
                Piece::Tp(1)
            ]
        );
        let f = s.foreign.unwrap();
        assert_eq!(f.target.as_deref(), Some("visio/media/image1.png"));
        assert_eq!(s.shapes[0].id, 4);
    }

    #[test]
    fn a_shape_without_attributes_is_a_plain_shape_and_unprefixed_names_read() {
        let s = sheet("<Shape/>");
        assert_eq!((s.id, s.kind.as_str(), s.del), (0, "Shape", false));
        assert!(s.text.is_none() && s.foreign.is_none() && s.shapes.is_empty());
    }

    #[test]
    fn rows_are_found_by_index_or_name_the_first_of_a_key_winning() {
        let s = sheet(
            "<Shape><Section N='Geometry' IX='0'><Row IX='1' T='MoveTo'/><Row IX='2' T='LineTo'/><Row IX='2' T='ArcTo'/>\
             <Row N='a' T='Named'/><Row/></Section></Shape>",
        );
        let g = &s.sections[0];
        assert_eq!(g.rows.len(), 5);
        let t = |k: RowKey| g.find_row(&k).and_then(|r| r.t.clone());
        assert_eq!(t(RowKey::Ix(2)).as_deref(), Some("LineTo"));
        assert_eq!(t(RowKey::Name("a".into())).as_deref(), Some("Named"));
        assert_eq!(t(RowKey::Ix(9)), None);
    }

    #[test]
    fn sections_past_the_bound_are_left_out() {
        let x = format!(
            "<Shape>{}</Shape>",
            "<Section N='User'/>".repeat(MAX_SECTIONS + 10)
        );
        assert_eq!(sheet(&x).sections.len(), MAX_SECTIONS);
    }

    #[test]
    fn shapes_nested_past_the_bound_are_left_out() {
        let mut x = String::from("<Shape ID='1'>");
        for _ in 0..100 {
            x.push_str("<Shapes><Shape ID='2'>");
        }
        for _ in 0..100 {
            x.push_str("</Shape></Shapes>");
        }
        x.push_str("</Shape>");
        let s = sheet(&x);
        let mut depth = 0;
        let mut cur = &s;
        while let Some(c) = cur.shapes.first() {
            depth += 1;
            cur = c;
        }
        assert_eq!(depth, MAX_NESTING);
    }
}
