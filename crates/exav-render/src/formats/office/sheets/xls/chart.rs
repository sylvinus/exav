//! BIFF chart substreams ([MS-XLS] 2.2.3, 2.4.3 to 2.4.324): an embedded
//! chart's or a chart sheet's records to the chart model. The values are
//! references to cells, read once the workbook is (`charts::fill`), or the
//! chart's own cached data where it has some.

use super::Globals;
use super::formula;
use super::stream::Rec;
use crate::formats::office::common::bytes::{Cur, u16_at};
use crate::formats::office::sheets::model::*;

/// What a Begin/End block is about.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Ctx {
    Chart,
    Series(usize),
    /// A text: what it is attached to, and its flags.
    Text(Option<u16>, u16),
    AxisParent(bool),
    Axis(u16),
    ChartFormat(usize),
    Frame(bool),
    Legend,
    DataFormat(Option<usize>, Option<u32>),
    Other,
}

#[derive(Default)]
struct Group {
    kind: Option<ChartKind>,
    horizontal: bool,
    grouping: &'static str,
    three_d: bool,
    vary: bool,
    gap: Option<u32>,
    overlap: Option<i32>,
    hole: Option<u32>,
    first_slice: Option<u32>,
    secondary: bool,
    legend: Option<&'static str>,
}

/// A LongRGB: red, green, blue, reserved.
fn rgb(d: &[u8], at: usize) -> Rgb {
    let b = |i: usize| u32::from(d.get(at + i).copied().unwrap_or(0));
    b(0) << 16 | b(1) << 8 | b(2)
}

fn short_string(d: &[u8], at: usize) -> String {
    let mut c = Cur::at(d, at);
    let n = c.u8() as usize;
    let f = c.u8();
    formula::read_chars(&mut c, n, f & 1 != 0)
}

/// The chart of a chart substream; `anchor` places an embedded one.
pub(crate) fn read_chart(
    g: &Globals,
    recs: &[Rec],
    anchor: Option<Anchor>,
    wb: &mut Workbook,
) -> Option<Chart> {
    let ctx = g.book.ctx(&[]);
    let mut stack: Vec<Ctx> = vec![];
    let mut last = Ctx::Other;
    let mut series: Vec<ChartSeries> = vec![];
    let mut ser_group: Vec<usize> = vec![];
    let mut groups: Vec<Group> = vec![];
    let mut secondary = false;
    let mut title: Option<String> = None;
    let mut auto_title = false;
    let mut cat_title: Option<String> = None;
    let mut val_title: Option<String> = None;
    let mut text_string: Option<String> = None;
    let mut major_grid = false;
    let mut legend: Option<&'static str> = None;
    let mut plot_fill: Option<Rgb> = None;
    let mut area_fill: Option<Rgb> = None;
    // Cached data: (kind, point, series) values after SIINDEX records.
    let mut cache_kind = 0u16;
    let mut cached_vals: Vec<(u16, u32, u32, Value)> = vec![];
    let mut depth = 0;
    let mut plot_next = false;
    let mut axis_line: Option<u16> = None;
    for r in recs.iter().take(1 << 20) {
        let d = &r.data;
        match r.id {
            id if super::stream::BOF_IDS.contains(&id) => depth += 1,
            0x000A => depth -= 1,
            _ => {}
        }
        if depth > 1 {
            continue;
        }
        let top = stack.last().copied().unwrap_or(Ctx::Other);
        match r.id {
            0x1033 => {
                stack.push(last);
                if stack.len() > 64 {
                    return None;
                }
            }
            0x1034 => {
                if let Some(Ctx::Text(link, flags)) = stack.pop() {
                    let t = text_string.take();
                    // fDeleted: not shown; fAutoText without a string: the
                    // text the application makes.
                    let deleted = flags & 0x40 != 0;
                    match (link, t) {
                        (Some(1), Some(t)) if !deleted => title = Some(t),
                        (Some(1), None) if !deleted && flags & 0x10 != 0 => auto_title = true,
                        (Some(2), Some(t)) if !deleted => val_title = Some(t),
                        (Some(3), Some(t)) if !deleted => cat_title = Some(t),
                        _ => {}
                    }
                }
                last = Ctx::Other;
            }
            0x1002 => last = Ctx::Chart,
            0x1003 => {
                if series.len() >= 256 {
                    last = Ctx::Other;
                    continue;
                }
                series.push(ChartSeries {
                    line: true,
                    ..Default::default()
                });
                ser_group.push(0);
                // Numeric or text categories.
                if u16_at(d, 0) == 1
                    && let Some(s) = series.last_mut()
                {
                    s.cat_nums = Some(vec![]);
                }
                last = Ctx::Series(series.len() - 1);
            }
            0x1051 => {
                let Ctx::Series(i) = top else { continue };
                let id = d.first().copied().unwrap_or(0);
                let rt = d.get(1).copied().unwrap_or(0);
                let cce = u16_at(d, 6) as usize;
                let rgce = d.get(8..8 + cce).unwrap_or(&[]);
                let text = if rt == 2 && !rgce.is_empty() {
                    formula::decode(&ctx, rgce, &[], 0, 0).ok().map(|x| x.text)
                } else {
                    None
                };
                if let (Some(s), Some(f)) = (series.get_mut(i), text) {
                    match id {
                        0 => s.name_ref = Some(f),
                        1 => s.val_ref = Some(f),
                        2 => s.cat_ref = Some(f),
                        3 => s.size_ref = Some(f),
                        _ => {}
                    }
                }
            }
            0x100D => {
                let t = short_string(d, 2);
                match top {
                    Ctx::Series(i) => {
                        if let Some(s) = series.get_mut(i) {
                            s.name = Some(t);
                        }
                    }
                    Ctx::Text(..) => text_string = Some(t),
                    _ => {}
                }
            }
            0x1045 => {
                if let Ctx::Series(i) = top
                    && let Some(x) = ser_group.get_mut(i)
                {
                    *x = u16_at(d, 0) as usize;
                }
            }
            0x1006 => {
                let xi = u16_at(d, 0);
                let yi = u16_at(d, 2) as usize;
                let point = (xi != 0xFFFF).then_some(u32::from(xi));
                last = Ctx::DataFormat(
                    Some(yi).filter(|&y| y < series.len()).or(match top {
                        Ctx::Series(i) => Some(i),
                        _ => None,
                    }),
                    point,
                );
            }
            0x100A => {
                let auto = u16_at(d, 10) & 1 != 0;
                let fls = u16_at(d, 8);
                let color = if auto {
                    g.color(u16_at(d, 12)).unwrap_or_else(|| rgb(d, 0))
                } else {
                    rgb(d, 0)
                };
                match top {
                    Ctx::DataFormat(Some(i), point) => {
                        if let Some(s) = series.get_mut(i)
                            && fls != 0
                        {
                            match point {
                                Some(p) => s.point_colors.push((p, color)),
                                None if !auto => s.color = Some(color),
                                None => {}
                            }
                        }
                    }
                    Ctx::Frame(true) if fls != 0 && !auto => plot_fill = Some(color),
                    Ctx::Frame(false) if fls != 0 && !auto => area_fill = Some(color),
                    _ => {}
                }
            }
            0x1007 => {
                let lns = u16_at(d, 4);
                let auto = u16_at(d, 8) & 1 != 0;
                if let Ctx::DataFormat(Some(i), None) = top
                    && let Some(s) = series.get_mut(i)
                {
                    if lns == 5 {
                        s.line = false;
                    } else if !auto && s.color.is_none() {
                        s.color = Some(rgb(d, 0));
                    }
                }
                if top == Ctx::Axis(1) && axis_line == Some(1) && lns != 5 {
                    major_grid = true;
                }
            }
            0x1009 => {
                if let Ctx::DataFormat(Some(i), None) = top
                    && let Some(s) = series.get_mut(i)
                {
                    s.marker = u16_at(d, 8) != 0;
                }
            }
            0x1032 => {
                last = Ctx::Frame(plot_next);
                plot_next = false;
            }
            // The next Frame is the plot area's.
            0x1035 => plot_next = true,
            0x1041 => {
                secondary = u16_at(d, 0) == 1;
                last = Ctx::AxisParent(secondary);
            }
            0x101D => last = Ctx::Axis(u16_at(d, 0)),
            0x1014 => {
                groups.push(Group {
                    grouping: "standard",
                    secondary,
                    vary: u16_at(d, 16) & 1 != 0,
                    ..Default::default()
                });
                last = Ctx::ChartFormat(groups.len() - 1);
            }
            0x1017 | 0x1018 | 0x1019 | 0x101A | 0x101B | 0x103E | 0x103F | 0x1040 | 0x1061 => {
                let Ctx::ChartFormat(gi) = top else { continue };
                let Some(gr) = groups.get_mut(gi) else {
                    continue;
                };
                let f = |at: usize| u16_at(d, at);
                match r.id {
                    0x1017 => {
                        let flags = f(4);
                        gr.kind = Some(ChartKind::Bar);
                        gr.overlap = Some(i32::from(f(0) as i16));
                        gr.gap = Some(u32::from(f(2)));
                        gr.horizontal = flags & 1 != 0;
                        gr.grouping = if flags & 4 != 0 {
                            "percentStacked"
                        } else if flags & 2 != 0 {
                            "stacked"
                        } else {
                            "clustered"
                        };
                    }
                    0x1018 | 0x101A => {
                        let flags = f(0);
                        gr.kind = Some(if r.id == 0x1018 {
                            ChartKind::Line
                        } else {
                            ChartKind::Area
                        });
                        gr.grouping = if flags & 2 != 0 {
                            "percentStacked"
                        } else if flags & 1 != 0 {
                            "stacked"
                        } else {
                            "standard"
                        };
                    }
                    0x1019 | 0x1061 => {
                        let hole = f(2);
                        gr.kind = Some(if hole > 0 && r.id == 0x1019 {
                            ChartKind::Doughnut
                        } else {
                            ChartKind::Pie
                        });
                        gr.first_slice = Some(u32::from(f(0)).min(360));
                        gr.hole = (hole > 0).then_some(u32::from(hole));
                    }
                    0x101B => {
                        gr.kind = Some(if f(4) & 1 != 0 {
                            ChartKind::Bubble
                        } else {
                            ChartKind::Scatter
                        })
                    }
                    0x103E => gr.kind = Some(ChartKind::Radar),
                    0x1040 => gr.kind = Some(ChartKind::FilledRadar),
                    _ => gr.kind = Some(ChartKind::Surface),
                }
            }
            0x103A => {
                if let Ctx::ChartFormat(gi) = top
                    && let Some(gr) = groups.get_mut(gi)
                {
                    gr.three_d = true;
                }
            }
            0x1015 => {
                let pos = match d.get(16).copied().unwrap_or(3) {
                    0 => "b",
                    1 => "tr",
                    2 => "t",
                    4 => "l",
                    _ => "r",
                };
                if let Ctx::ChartFormat(gi) = top
                    && let Some(gr) = groups.get_mut(gi)
                {
                    gr.legend = Some(pos);
                }
                legend = legend.or(Some(pos));
                last = Ctx::Legend;
            }
            0x1025 => last = Ctx::Text(None, u16_at(d, 24)),
            0x1027 => {
                if let Some(Ctx::Text(link, _)) = stack.last_mut() {
                    *link = Some(u16_at(d, 0));
                }
            }
            0x1065 => cache_kind = u16_at(d, 0),
            0x0203 | 0x0204 | 0x0205 | 0x027E if cache_kind != 0 && cached_vals.len() < 1 << 20 => {
                let point = u32::from(u16_at(d, 0));
                let ser = u32::from(u16_at(d, 2));
                let mut c = Cur::at(d, 6);
                let v = match r.id {
                    0x0203 => Value::Number(c.f64()),
                    0x0204 => Value::text(g.book.string(&mut c, 2)),
                    0x027E => Value::Number(super::sheet::rk(c.u32())),
                    _ => Value::Empty,
                };
                cached_vals.push((cache_kind, point, ser, v));
            }
            0x1021 => {}
            _ => last = Ctx::Other,
        }
        axis_line = (r.id == 0x1021).then(|| u16_at(d, 0));
    }
    // The chart's kind is its first group's; series of other groups are
    // drawn as theirs.
    let first = groups.iter().find(|g| g.kind.is_some())?;
    let kind = first.kind?;
    let mut chart = Chart::new(
        anchor.unwrap_or(Anchor {
            from: (0, 0, 0, 0),
            to: (10, 20, 0, 0),
        }),
        kind,
    );
    chart.horizontal = first.horizontal;
    chart.grouping = first.grouping;
    chart.three_d = first.three_d;
    chart.vary_colors = first.vary || matches!(kind, ChartKind::Pie | ChartKind::Doughnut);
    chart.gap_width = first.gap;
    chart.overlap = first.overlap;
    chart.hole_size = first.hole;
    chart.first_slice = first.first_slice;
    chart.legend = legend;
    // A series without data is not drawn.
    let keep: Vec<bool> = series
        .iter()
        .enumerate()
        .map(|(i, s)| {
            s.val_ref.is_some() || cached_vals.iter().any(|c| c.0 == 1 && c.2 as usize == i)
        })
        .collect();
    if auto_title && title.is_none() {
        let named: Vec<&ChartSeries> = series
            .iter()
            .zip(&keep)
            .filter(|x| *x.1)
            .map(|x| x.0)
            .collect();
        title = Some(match named.as_slice() {
            [one] => one.name.clone().unwrap_or_else(|| "Chart Title".into()),
            _ => "Chart Title".into(),
        });
    }
    chart.title = title;
    chart.cat_title = cat_title;
    chart.val_title = val_title;
    chart.major_grid = major_grid;
    chart.plot_fill = plot_fill;
    chart.area_fill = area_fill;
    for (i, mut s) in series.into_iter().enumerate() {
        if !keep[i] {
            continue;
        }
        let gi = ser_group.get(i).copied().unwrap_or(0);
        if let Some(gr) = groups.get(gi).filter(|g| g.kind.is_some() && gi != 0) {
            if gr.kind != Some(kind) {
                s.kind = gr.kind;
            }
            s.secondary = gr.secondary;
        }
        // The chart's own copy of its data.
        for (k, point, ser, v) in cached_vals.iter().filter(|c| c.2 as usize == i) {
            let p = *point as usize;
            if p > 65_535 {
                continue;
            }
            let _ = ser;
            match (k, v) {
                (1, Value::Number(n)) => put(&mut s.vals, p, Some(*n), None),
                (2, Value::Number(n)) => match s.cat_nums.as_mut() {
                    Some(c) => put(c, p, Some(*n), None),
                    None => put(
                        &mut s.cats,
                        p,
                        crate::formats::office::sheets::numtext::shortest(*n),
                        String::new(),
                    ),
                },
                (2, v) => put(&mut s.cats, p, v.display(), String::new()),
                (3, Value::Number(n)) => put(&mut s.sizes, p, Some(*n), None),
                _ => {}
            }
        }
        chart.series.push(s);
    }
    let _ = wb;
    Some(chart)
}

fn put<T: Clone>(v: &mut Vec<T>, at: usize, x: T, fill: T) {
    if v.len() <= at {
        v.resize(at + 1, fill);
    }
    v[at] = x;
}
