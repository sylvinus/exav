//! Records written by hand, for the cases where a group code means one thing
//! in one subclass or position and another elsewhere.

use super::super::{read_dxf, EntityKind, HAlign, VAlign};

fn drawing(sections: &str) -> super::super::Drawing {
    let text = format!("{sections}0\nEOF\n");
    read_dxf(text.as_bytes()).expect("reads")
}

fn first_entity(entities: &str) -> EntityKind {
    let d = drawing(&format!("0\nSECTION\n2\nENTITIES\n{entities}0\nENDSEC\n"));
    d.blocks
        .iter()
        .find_map(|b| b.entities.first())
        .map(|e| e.kind.clone())
        .expect("an entity")
}

/// From 2018 AcDbAttribute carries 71 (attribute type), 72 and 11, which
/// are not the text's generation flags, alignment and alignment point.
#[test]
fn attribute_groups_are_read_from_their_own_subclass() {
    let kind = first_entity(
        "0\nATTDEF\n5\n85\n100\nAcDbEntity\n8\n0\n100\nAcDbText\n10\n1\n20\n2\n30\n0\n\
         40\n0.5\n1\ndefault\n72\n1\n11\n3\n21\n4\n31\n0\n\
         100\nAcDbAttributeDefinition\n3\nprompt\n2\nTAG\n70\n0\n74\n2\n280\n1\n\
         71\n1\n72\n0\n11\n0\n21\n0\n31\n0\n",
    );
    let EntityKind::AttributeDefinition(a) = kind else {
        panic!("not an ATTDEF: {kind:?}");
    };
    assert_eq!(a.tag, "TAG");
    assert_eq!(a.prompt, "prompt");
    assert_eq!(a.text.generation, 0);
    assert_eq!(a.text.h_align, HAlign::Center);
    assert_eq!(a.text.v_align, VAlign::Middle);
    let p = a.text.alignment_point.expect("alignment point");
    assert_eq!((p.x, p.y), (3.0, 4.0));
}

/// AutoCAD writes a control character in a DXF string as a caret and a
/// letter (`^J`, `^I`) and a caret as caret, space; reading undoes it (DXF
/// reference, "ASCII Control Characters in DXF Files"). The ODA File
/// Converter does so too: `A^JB^ C^IT` in a DXF is `A\nB^C\tT` in the DWG
/// it writes (experiments/caret). An MTEXT's chunks are joined first.
#[test]
fn carets_in_strings_are_control_characters() {
    let d = drawing(
        "0\nSECTION\n2\nTABLES\n0\nTABLE\n2\nLAYER\n0\nLAYER\n5\n10\n100\nAcDbSymbolTableRecord\n\
         100\nAcDbLayerTableRecord\n2\nL^ 1\n70\n0\n62\n7\n6\nCONTINUOUS\n0\nENDTAB\n0\nENDSEC\n\
         0\nSECTION\n2\nENTITIES\n\
         0\nTEXT\n5\n80\n100\nAcDbEntity\n8\n0\n100\nAcDbText\n10\n0\n20\n0\n30\n0\n40\n1\n\
         1\nA^JB^ C^IT^\n100\nAcDbText\n\
         0\nMTEXT\n5\n81\n100\nAcDbEntity\n8\n0\n100\nAcDbMText\n10\n0\n20\n0\n30\n0\n40\n1\n\
         3\n{\\S1^ 2;} X^\n1\nJY\n0\nENDSEC\n",
    );
    assert!(d.layers.iter().any(|l| l.name == "L^1"));
    let texts: Vec<String> = d
        .blocks
        .iter()
        .flat_map(|b| &b.entities)
        .filter_map(|e| match &e.kind {
            EntityKind::Text(t) => Some(t.value.clone()),
            EntityKind::MText(m) => Some(m.text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["A\nB^C\tT^", "{\\S1^2;} X\nY"]);
}

/// The blocks of inactive layouts have no group 67: their entities are in
/// paper space all the same, an INSERT's attributes too (as the DWG reader
/// has them; a converted AutoCAD 2018 title block's ATTRIBs differed).
#[test]
fn attributes_in_an_inactive_layout_are_in_paper_space() {
    let d = drawing(
        "0\nSECTION\n2\nBLOCKS\n0\nBLOCK\n5\n20\n330\n1F\n100\nAcDbEntity\n8\n0\n\
         100\nAcDbBlockBegin\n2\n*Paper_Space0\n70\n0\n10\n0\n20\n0\n30\n0\n3\n*Paper_Space0\n1\n\n\
         0\nINSERT\n5\n80\n330\n1F\n100\nAcDbEntity\n8\n0\n100\nAcDbBlockReference\n66\n1\n2\nB\n\
         10\n0\n20\n0\n30\n0\n\
         0\nATTRIB\n5\n81\n330\n80\n100\nAcDbEntity\n8\n0\n100\nAcDbText\n10\n0\n20\n0\n30\n0\n\
         40\n1\n1\nV\n100\nAcDbAttribute\n2\nT\n70\n0\n\
         0\nSEQEND\n5\n82\n330\n80\n100\nAcDbEntity\n8\n0\n\
         0\nENDBLK\n5\n21\n330\n1F\n100\nAcDbEntity\n8\n0\n100\nAcDbBlockEnd\n0\nENDSEC\n",
    );
    let insert = d
        .blocks
        .iter()
        .flat_map(|b| &b.entities)
        .find(|e| matches!(e.kind, EntityKind::Insert(_)))
        .expect("the INSERT");
    assert!(insert.paper_space);
    let EntityKind::Insert(i) = &insert.kind else {
        unreachable!()
    };
    assert_eq!(i.attributes.len(), 1);
    assert!(i.attributes.iter().all(|a| a.paper_space));
}

/// A LEADER's own colour (77) is dumped beside its entity colour (62), not
/// over it: both oracles compare the dump, and with one key a LEADER's
/// entity colour was never compared.
#[test]
fn a_leader_dumps_its_entity_colour_and_its_own() {
    let d = drawing(
        "0\nSECTION\n2\nENTITIES\n0\nLEADER\n5\n80\n100\nAcDbEntity\n8\n0\n62\n2\n\
         100\nAcDbLeader\n3\nSTANDARD\n76\n2\n10\n0\n20\n0\n30\n0\n10\n1\n20\n1\n30\n0\n\
         77\n5\n0\nENDSEC\n",
    );
    let json = super::super::to_json(&d);
    let leader = &json[json.find(r#""type":"LEADER""#).expect("the LEADER")..];
    assert!(leader.contains(r#""color":2,"#), "{leader}");
    assert!(leader.contains(r#""leader_color":5,"#), "{leader}");
    assert!(!leader.contains(r#""color":5"#), "{leader}");
}

/// A DIMSTYLE's second 70 (DIMTFILLCLR, from 2007) is not its flags.
#[test]
fn table_flags_are_the_first_70() {
    let d = drawing(
        "0\nSECTION\n2\nTABLES\n0\nTABLE\n2\nDIMSTYLE\n\
         0\nDIMSTYLE\n105\nBF\n100\nAcDbSymbolTableRecord\n100\nAcDbDimStyleTableRecord\n\
         2\nDS\n70\n0\n69\n1\n70\n256\n0\nENDTAB\n0\nENDSEC\n",
    );
    let s = d.dim_styles.first().expect("a dimension style");
    assert_eq!(s.name, "DS");
    assert_eq!(s.flags, 0);
}

/// An IMAGEDEF's pixel size is 11 and 21 in files (the 2012 reference says
/// 12 for the second).
#[test]
fn an_image_definition_pixel_size_is_11_and_21() {
    let d = drawing(
        "0\nSECTION\n2\nOBJECTS\n0\nIMAGEDEF\n5\n80F\n100\nAcDbRasterImageDef\n90\n0\n\
         1\npicture.jpeg\n10\n300\n20\n168\n11\n0.25\n21\n0.5\n280\n1\n0\nENDSEC\n",
    );
    let def = d.image_defs.first().expect("an image definition");
    assert_eq!((def.pixel_size.x, def.pixel_size.y), (0.25, 0.5));
    assert_eq!((def.size.x, def.size.y), (300.0, 168.0));
}

/// Entities of an inactive layout's block are in paper space, though their
/// group 67 is left out.
#[test]
fn a_paper_space_block_holds_paper_space_entities() {
    let d = drawing(
        "0\nSECTION\n2\nBLOCKS\n0\nBLOCK\n5\n20\n8\n0\n2\n*Paper_Space0\n70\n0\n\
         10\n0\n20\n0\n30\n0\n0\nPOINT\n5\n21\n8\n0\n10\n1\n20\n1\n30\n0\n\
         0\nENDBLK\n5\n22\n8\n0\n0\nENDSEC\n",
    );
    let b = d.block("*Paper_Space0").expect("the block");
    assert!(b.entities.iter().all(|e| e.paper_space));
}

/// The frozen layers of a 2000 viewport are in group 341.
#[test]
fn a_viewport_freezes_layers_by_331_or_341() {
    for code in [331, 341] {
        let kind = first_entity(&format!(
            "0\nVIEWPORT\n5\n30\n100\nAcDbEntity\n8\n0\n100\nAcDbViewport\n\
             10\n0\n20\n0\n30\n0\n40\n10\n41\n10\n68\n1\n69\n2\n{code}\n8A\n"
        ));
        let EntityKind::Viewport(v) = kind else {
            panic!("not a VIEWPORT");
        };
        assert_eq!(v.frozen_layers.len(), 1, "group {code}");
    }
}

/// From 2018 an MTEXT's columns are in its embedded object (after 101), as
/// the converter writes them; 71, 72, 44, 45, 73 and 74 mean other things
/// before it.
#[test]
fn mtext_columns_of_2018_are_read_from_the_embedded_object() {
    let kind = first_entity(
        "0\nMTEXT\n5\n1C0\n100\nAcDbEntity\n8\n0\n100\nAcDbMText\n10\n7\n20\n14\n30\n0\n\
         40\n0.2\n41\n13\n46\n0\n71\n1\n72\n5\n1\ntext\n73\n1\n44\n1.0\n\
         101\nEmbedded Object\n70\n1\n10\n1\n20\n0\n30\n0\n11\n7\n21\n14\n31\n0\n\
         40\n13\n41\n0\n42\n11\n43\n0.26\n71\n2\n72\n3\n44\n4.5\n45\n0.75\n73\n0\n74\n1\n\
         46\n1.5\n46\n2.5\n46\n3.5\n",
    );
    let EntityKind::MText(m) = kind else {
        panic!("not an MTEXT");
    };
    assert_eq!(m.attachment, 1);
    assert_eq!(m.drawing_direction, 5);
    assert_eq!(m.line_spacing_factor, 1.0);
    let c = m.columns.expect("columns");
    assert_eq!((c.kind, c.count), (2, 3));
    assert_eq!((c.width, c.gutter), (4.5, 0.75));
    assert!(!c.auto_height);
    assert!(c.flow_reversed);
    assert_eq!(c.heights, [1.5, 2.5, 3.5]);
}

/// Before 2018 an MTEXT's columns are in its ACAD extended data, as group
/// code and value pairs.
#[test]
fn mtext_columns_before_2018_are_read_from_the_extended_data() {
    let kind = first_entity(
        "0\nMTEXT\n5\n8B\n100\nAcDbEntity\n8\n0\n100\nAcDbMText\n10\n20\n20\n0\n30\n0\n\
         40\n0.5\n41\n6\n71\n1\n72\n5\n1\ntext\n\
         1001\nACAD\n1000\nACAD_MTEXT_COLUMN_INFO_BEGIN\n1070\n75\n1070\n2\n1070\n79\n1070\n0\n\
         1070\n76\n1070\n3\n1070\n78\n1070\n0\n1070\n48\n1040\n6.0\n1070\n49\n1040\n0.5\n\
         1070\n50\n1070\n3\n1040\n4.0\n1040\n5.0\n1040\n6.0\n1000\nACAD_MTEXT_COLUMN_INFO_END\n",
    );
    let EntityKind::MText(m) = kind else {
        panic!("not an MTEXT");
    };
    let c = m.columns.expect("columns");
    assert_eq!((c.kind, c.count), (2, 3));
    assert_eq!((c.width, c.gutter), (6.0, 0.5));
    assert!(!c.auto_height && !c.flow_reversed);
    assert_eq!(c.heights, [4.0, 5.0, 6.0]);
}

/// An R12 VIEWPORT's view lives in its ACAD MVIEW extended data.
#[test]
fn an_r12_viewport_view_is_read_from_its_extended_data() {
    let kind = first_entity(
        "0\nVIEWPORT\n5\n2D7\n67\n1\n8\n0\n10\n5\n20\n4\n30\n0\n40\n8.4\n41\n6.4\n68\n1\n69\n2\n\
         1001\nACAD\n1000\nMVIEW\n1002\n{\n1070\n16\n\
         1010\n1\n1020\n2\n1030\n3\n1010\n0\n1020\n0\n1030\n1\n\
         1040\n0\n1040\n2.78\n1040\n17.6\n1040\n14.8\n1040\n50\n1040\n0\n1040\n0\n\
         1070\n16\n1070\n1000\n1070\n0\n1070\n3\n1070\n0\n1070\n1\n1070\n0\n1070\n0\n\
         1040\n0\n1040\n0\n1040\n0\n1040\n0.5\n1040\n0.5\n1040\n0.5\n1040\n0.5\n1070\n0\n\
         1002\n{\n1002\n}\n1002\n}\n",
    );
    let EntityKind::Viewport(v) = kind else {
        panic!("not a VIEWPORT");
    };
    assert_eq!(
        (v.view_target.x, v.view_target.y, v.view_target.z),
        (1.0, 2.0, 3.0)
    );
    assert_eq!(v.view_height, 2.78);
    assert_eq!((v.view_center.x, v.view_center.y), (17.6, 14.8));
    assert_eq!(v.circle_zoom, 1000);
    // View mode 16 (front clip not at eye) and the grid flag; not a render mode.
    assert_eq!(v.render_mode, 0);
    assert_eq!(v.flags & 0x1F, 16);
    assert_ne!(v.flags & 0x200, 0);
    assert_eq!((v.grid_spacing.x, v.grid_spacing.y), (0.5, 0.5));
}
