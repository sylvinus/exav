//! OfficeArt shape types ([MS-ODRAW] 2.4.24, MSOSPT) to DrawingML preset
//! geometries (ECMA-376 presetShapeDefinitions), with the adjust values
//! whose meaning carries over. OfficeArt adjusts are in the shape's 21600
//! unit square; DrawingML's in 1/100000 of a side or of the shorter side.

use super::escher::Props;
use crate::formats::office::slides::model::{Emu, Geometry};

pub fn name(spt: u16) -> Option<&'static str> {
    Some(match spt {
        1 | 202 | 24 | 136 => "rect",
        2 => "roundRect",
        3 => "ellipse",
        4 => "diamond",
        5 => "triangle",
        6 => "rtTriangle",
        7 => "parallelogram",
        8 => "trapezoid",
        9 => "hexagon",
        10 => "octagon",
        11 => "plus",
        12 => "star5",
        13 | 14 => "rightArrow",
        15 => "homePlate",
        16 => "cube",
        17 => "wedgeRoundRectCallout",
        18 => "star16",
        19 => "arc",
        20 => "line",
        21 => "plaque",
        22 => "can",
        23 => "donut",
        32 => "straightConnector1",
        33 => "bentConnector2",
        34 => "bentConnector3",
        35 => "bentConnector4",
        36 => "bentConnector5",
        37 => "curvedConnector2",
        38 => "curvedConnector3",
        39 => "curvedConnector4",
        40 => "curvedConnector5",
        41 => "callout1",
        42 => "callout2",
        43 => "callout3",
        44 => "accentCallout1",
        45 => "accentCallout2",
        46 => "accentCallout3",
        47 => "borderCallout1",
        48 => "borderCallout2",
        49 => "borderCallout3",
        50 => "accentBorderCallout1",
        51 => "accentBorderCallout2",
        52 => "accentBorderCallout3",
        53 => "ribbon",
        54 => "ribbon2",
        55 => "chevron",
        56 => "pentagon",
        57 => "noSmoking",
        58 => "star8",
        59 => "star16",
        60 => "star32",
        61 => "wedgeRectCallout",
        62 => "wedgeRoundRectCallout",
        63 => "wedgeEllipseCallout",
        64 => "wave",
        65 => "foldedCorner",
        66 => "leftArrow",
        67 => "downArrow",
        68 => "upArrow",
        69 => "leftRightArrow",
        70 => "upDownArrow",
        71 => "irregularSeal1",
        72 => "irregularSeal2",
        73 => "lightningBolt",
        74 => "heart",
        75 => "frame",
        76 => "quadArrow",
        77 => "leftArrowCallout",
        78 => "rightArrowCallout",
        79 => "upArrowCallout",
        80 => "downArrowCallout",
        81 => "leftRightArrowCallout",
        82 => "upDownArrowCallout",
        83 => "quadArrowCallout",
        84 => "bevel",
        85 => "leftBracket",
        86 => "rightBracket",
        87 => "leftBrace",
        88 => "rightBrace",
        89 => "leftUpArrow",
        90 => "bentUpArrow",
        91 => "bentArrow",
        92 => "star24",
        93 => "stripedRightArrow",
        94 => "notchedRightArrow",
        95 => "blockArc",
        96 => "smileyFace",
        97 => "verticalScroll",
        98 => "horizontalScroll",
        99 | 100 => "circularArrow",
        101 => "uturnArrow",
        102 => "curvedRightArrow",
        103 => "curvedLeftArrow",
        104 => "curvedUpArrow",
        105 => "curvedDownArrow",
        106 => "cloudCallout",
        107 => "ellipseRibbon",
        108 => "ellipseRibbon2",
        109 => "flowChartProcess",
        110 => "flowChartDecision",
        111 => "flowChartInputOutput",
        112 => "flowChartPredefinedProcess",
        113 => "flowChartInternalStorage",
        114 => "flowChartDocument",
        115 => "flowChartMultidocument",
        116 => "flowChartTerminator",
        117 => "flowChartPreparation",
        118 => "flowChartManualInput",
        119 => "flowChartManualOperation",
        120 => "flowChartConnector",
        121 => "flowChartPunchedCard",
        122 => "flowChartPunchedTape",
        123 => "flowChartSummingJunction",
        124 => "flowChartOr",
        125 => "flowChartCollate",
        126 => "flowChartSort",
        127 => "flowChartExtract",
        128 => "flowChartMerge",
        129 => "flowChartOfflineStorage",
        130 => "flowChartOnlineStorage",
        131 => "flowChartMagneticTape",
        132 => "flowChartMagneticDisk",
        133 => "flowChartMagneticDrum",
        134 => "flowChartDisplay",
        135 => "flowChartDelay",
        176 => "flowChartAlternateProcess",
        177 => "flowChartOffpageConnector",
        178 => "callout1",
        179 => "accentCallout1",
        180 => "borderCallout1",
        181 => "accentBorderCallout1",
        182 => "leftRightUpArrow",
        183 => "sun",
        184 => "moon",
        185 => "bracketPair",
        186 => "bracePair",
        187 => "star4",
        188 => "doubleWave",
        189 => "actionButtonBlank",
        190 => "actionButtonHome",
        191 => "actionButtonHelp",
        192 => "actionButtonInformation",
        193 => "actionButtonForwardNext",
        194 => "actionButtonBackPrevious",
        195 => "actionButtonEnd",
        196 => "actionButtonBeginning",
        197 => "actionButtonReturn",
        198 => "actionButtonDocument",
        199 => "actionButtonSound",
        200 => "actionButtonMovie",
        // WordArt (text effects) draws its text in a plain box.
        25..=31 | 137..=175 => "rect",
        _ => return None,
    })
}

/// Adjust values of `spt` from the shape's properties, for a shape `w` by
/// `h`. Only those whose meaning is the same in both systems are given.
pub fn adjusts(spt: u16, p: &Props, w: Emu, h: Emu) -> Vec<(&'static str, i64)> {
    let a = |i: u16| p.int(0x0147 + i).map(i64::from);
    let ss = w.min(h).max(1) as f64;
    // A fraction of the 21600 square to 1/100000.
    let frac = |v: i64| (v as f64 / 21600.0 * 100_000.0).round() as i64;
    // A horizontal length (in 21600 of the width) relative to the shorter side.
    let horiz = |v: i64| (v as f64 / 21600.0 * w as f64 / ss * 100_000.0).round() as i64;
    let vert = |v: i64| (v as f64 / 21600.0 * h as f64 / ss * 100_000.0).round() as i64;
    let mut out = vec![];
    match spt {
        2 | 11 | 16 | 22 | 23 | 84 => {
            if let Some(v) = a(0) {
                out.push(("adj", frac(v).clamp(0, 50_000)));
            }
        }
        5 => {
            if let Some(v) = a(0) {
                out.push(("adj", frac(v).clamp(0, 100_000)));
            }
        }
        7..=9 => {
            if let Some(v) = a(0) {
                out.push(("adj", horiz(v).max(0)));
            }
        }
        10 => {
            if let Some(v) = a(0) {
                out.push(("adj", frac(v).clamp(0, 50_000)));
            }
        }
        15 | 55 => {
            if let Some(v) = a(0) {
                out.push(("adj", horiz(21600 - v).max(0)));
            }
        }
        65 => {
            if let Some(v) = a(0) {
                out.push(("adj", frac(21600 - v).clamp(0, 50_000)));
            }
        }
        13 | 14 | 66 | 69 => {
            let head = a(0);
            let shaft = a(1);
            if let Some(s) = shaft {
                out.push(("adj1", frac(21600 - 2 * s).clamp(0, 100_000)));
            }
            if let Some(hd) = head {
                let len = match spt {
                    66 | 69 => hd,
                    _ => 21600 - hd,
                };
                out.push(("adj2", horiz(len).max(0)));
            }
        }
        67 | 68 | 70 => {
            if let Some(s) = a(1) {
                out.push(("adj1", frac(21600 - 2 * s).clamp(0, 100_000)));
            }
            if let Some(hd) = a(0) {
                let len = if spt == 67 { 21600 - hd } else { hd };
                out.push(("adj2", vert(len).max(0)));
            }
        }
        61..=63 => {
            if let Some(x) = a(0) {
                out.push(("adj1", frac(x - 10800)));
            }
            if let Some(y) = a(1) {
                out.push(("adj2", frac(y - 10800)));
            }
        }
        // Start and end angles (16.16 degrees, clockwise, as DrawingML's).
        19 => {
            let deg = |v: i64| ((v as i32) as f64 / 65536.0).rem_euclid(360.0);
            out.push((
                "adj1",
                (deg(a(0).unwrap_or(270 << 16)) * 60000.0).round() as i64,
            ));
            out.push(("adj2", (deg(a(1).unwrap_or(0)) * 60000.0).round() as i64));
        }
        // Connectors: each adjust a position along the box, in 21600 of
        // its side, as in DrawingML (in 1/100000).
        34..=36 | 38..=40 => {
            let n = match spt {
                34 | 38 => 1,
                35 | 39 => 2,
                _ => 3,
            };
            for (i, name) in ["adj1", "adj2", "adj3"].into_iter().enumerate().take(n) {
                if let Some(v) = a(i as u16).filter(|v| v.abs() <= 216_000) {
                    out.push((name, frac(v)));
                }
            }
        }
        _ => {}
    }
    out
}

pub fn geometry(spt: u16, p: &Props, w: Emu, h: Emu) -> Option<Geometry> {
    let name = name(spt)?;
    Some(Geometry::Preset {
        name,
        adj: adjusts(spt, p, w, h),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::office::slides::ppt::escher::Prop;

    #[test]
    fn rounded_rectangle_and_arrow_adjusts() {
        let p = Props(vec![Prop {
            id: 0x0147,
            value: 3600,
            complex: None,
        }]);
        assert_eq!(adjusts(2, &p, 100, 100), vec![("adj", 16667)]);
        // A right arrow, twice as wide as high: head at 16200, shaft at 5400.
        let p = Props(vec![
            Prop {
                id: 0x0147,
                value: 16200,
                complex: None,
            },
            Prop {
                id: 0x0148,
                value: 5400,
                complex: None,
            },
        ]);
        assert_eq!(
            adjusts(13, &p, 200, 100),
            vec![("adj1", 50000), ("adj2", 50000)]
        );
        assert_eq!(name(202), Some("rect"));
        assert_eq!(name(0), None);
    }
}
