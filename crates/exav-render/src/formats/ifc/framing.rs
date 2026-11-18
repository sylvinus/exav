//! The box a model is framed by: around its elements, less those far from
//! all the others, such as an object an export left a kilometre from the
//! building.
//!
//! The core is the elements whose centre is within Tukey's outer fences on
//! every axis: three interquartile ranges beyond the quartiles of the
//! centres, the range being at least the median element's size, as a flat
//! model has none on its height. The others count when they connect to the
//! core: within reach of what already counts, the reach being half the
//! core's diagonal and at least [`REACH_METRES`]. Growing is done on a
//! k-d tree of the others, which prunes what is out of reach, so that the
//! time stays near linear in the element count whatever the order of the
//! elements.

use crate::formats::mesh::Scene;

/// min x, y, z, max x, y, z.
type Box6 = [f64; 6];

/// What `union` starts from.
const NOTHING: Box6 = [
    f64::INFINITY,
    f64::INFINITY,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NEG_INFINITY,
    f64::NEG_INFINITY,
];

/// Below this many elements, every one counts: too few to tell a stray from the rest.
const MIN_ELEMENTS: usize = 8;

/// What is this close to the rest of a model belongs with it, however small the model.
const REACH_METRES: f64 = 10.0;

/// The box to frame `scene` by, relative to its origin; `None` without elements.
pub(super) fn scene_framing(scene: &Scene) -> Option<[[f32; 3]; 2]> {
    let [x0, y0, z0, x1, y1, z1] = framing_box(&element_boxes(scene))?.map(|v| v as f32);
    Some([[x0, y0, z0], [x1, y1, z1]])
}

/// Each element's box; elements without triangles are left out.
fn element_boxes(scene: &Scene) -> Vec<Box6> {
    let mut boxes = Vec::with_capacity(scene.elements.len());
    for e in &scene.elements {
        let mut b = NOTHING;
        for r in &e.ranges {
            let Some(batch) = scene.batches.get(r.batch as usize) else {
                continue;
            };
            let first = r.first as usize;
            for &i in &batch.indices[first..first + r.count as usize] {
                let at = i as usize * 3;
                for (a, &v) in batch.positions[at..at + 3].iter().enumerate() {
                    b[a] = b[a].min(f64::from(v));
                    b[a + 3] = b[a + 3].max(f64::from(v));
                }
            }
        }
        if b[0] <= b[3] {
            boxes.push(b);
        }
    }
    boxes
}

fn union(list: impl Iterator<Item = Box6>) -> Box6 {
    list.fold(NOTHING, |u, b| {
        let min = |a: usize| u[a].min(b[a]);
        let max = |a: usize| u[a].max(b[a]);
        [min(0), min(1), min(2), max(3), max(4), max(5)]
    })
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    sorted[((q * sorted.len() as f64) as usize).min(sorted.len() - 1)]
}

fn sorted(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_unstable_by(f64::total_cmp);
    values
}

fn norm(d: [f64; 3]) -> f64 {
    (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt()
}

/// Distance between two boxes, 0 when they touch.
fn gap(a: &Box6, b: &Box6) -> f64 {
    norm([0, 1, 2].map(|i| (a[i] - b[i + 3]).max(b[i] - a[i + 3]).max(0.0)))
}

fn framing_box(boxes: &[Box6]) -> Option<Box6> {
    if boxes.is_empty() {
        return None;
    }
    if boxes.len() < MIN_ELEMENTS {
        return Some(union(boxes.iter().copied()));
    }
    let sizes = boxes
        .iter()
        .map(|b| (b[3] - b[0]).max(b[4] - b[1]).max(b[5] - b[2]));
    let size = quantile(&sorted(sizes.collect()), 0.5);
    let fences = [0, 1, 2].map(|a| {
        let centres = sorted(boxes.iter().map(|b| (b[a] + b[a + 3]) / 2.0).collect());
        let (q1, q3) = (quantile(&centres, 0.25), quantile(&centres, 0.75));
        let reach = 3.0 * (q3 - q1).max(size);
        (q1 - reach, q3 + reach)
    });
    let in_core = |b: &Box6| {
        fences.iter().enumerate().all(|(a, &(low, high))| {
            let c = (b[a] + b[a + 3]) / 2.0;
            c >= low && c <= high
        })
    };
    let (core, rest): (Vec<Box6>, Vec<Box6>) = boxes.iter().partition(|b| in_core(b));
    if core.is_empty() {
        return Some(union(boxes.iter().copied()));
    }
    let mut region = union(core.iter().copied());
    let diagonal = norm([0, 1, 2].map(|a| region[a + 3] - region[a]));
    let reach = (0.5 * diagonal).max(REACH_METRES);
    // Grown from the core by what is within reach of it, until nothing more is.
    let mut tree = Tree::new(&rest);
    while tree.take(0, rest.len(), &mut region, reach) > 0 {}
    Some(region)
}

/// A k-d tree over the six coordinates of boxes, laid out in an array: the
/// node of the range `a..b` is at its middle, its children are the ranges
/// on either side. Boxes are taken out as they join the region.
struct Tree<'a> {
    boxes: &'a [Box6],
    order: Vec<u32>,
    /// By node: the smallest minimum and the largest maximum of the subtree, per axis.
    low: Vec<[f64; 3]>,
    high: Vec<[f64; 3]>,
    /// By node: the boxes of the subtree not yet taken.
    left: Vec<u32>,
    taken: Vec<bool>,
}

impl<'a> Tree<'a> {
    fn new(boxes: &'a [Box6]) -> Self {
        let n = boxes.len();
        let mut t = Tree {
            boxes,
            order: (0..n as u32).collect(),
            low: vec![[0.0; 3]; n],
            high: vec![[0.0; 3]; n],
            left: vec![0; n],
            taken: vec![false; n],
        };
        t.build(0, n, 0);
        t
    }

    fn build(&mut self, a: usize, b: usize, depth: usize) {
        if a >= b {
            return;
        }
        let mid = (a + b) / 2;
        let axis = depth % 6;
        let boxes = self.boxes;
        self.order[a..b].select_nth_unstable_by(mid - a, |&x, &y| {
            boxes[x as usize][axis].total_cmp(&boxes[y as usize][axis])
        });
        self.build(a, mid, depth + 1);
        self.build(mid + 1, b, depth + 1);
        let own = &self.boxes[self.order[mid] as usize];
        let mut low = [own[0], own[1], own[2]];
        let mut high = [own[3], own[4], own[5]];
        for (ca, cb) in [(a, mid), (mid + 1, b)] {
            if ca < cb {
                let c = (ca + cb) / 2;
                for k in 0..3 {
                    low[k] = low[k].min(self.low[c][k]);
                    high[k] = high[k].max(self.high[c][k]);
                }
            }
        }
        self.low[mid] = low;
        self.high[mid] = high;
        self.left[mid] = (b - a) as u32;
    }

    /// Takes the boxes of `a..b` within `reach` of `region`, which grows by
    /// each. Returns how many.
    fn take(&mut self, a: usize, b: usize, region: &mut Box6, reach: f64) -> u32 {
        if a >= b {
            return 0;
        }
        let mid = (a + b) / 2;
        if self.left[mid] == 0 {
            return 0;
        }
        // The least distance any box of the subtree can have to the region.
        let least = norm([0, 1, 2].map(|i| {
            let (low, high) = (self.low[mid][i], self.high[mid][i]);
            (low - region[i + 3]).max(region[i] - high).max(0.0)
        }));
        if least > reach {
            return 0;
        }
        let mut n = self.take(a, mid, region, reach);
        let own = self.boxes[self.order[mid] as usize];
        if !self.taken[mid] && gap(&own, region) <= reach {
            self.taken[mid] = true;
            *region = union([*region, own].into_iter());
            n += 1;
        }
        n += self.take(mid + 1, b, region, reach);
        self.left[mid] -= n;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::mesh::{Batch, Element, Range};
    use std::time::Instant;

    /// A building: rooms of 4 x 4 x 3 m on a 5 m grid, `n` by `n`, on two floors.
    fn building(n: usize) -> Vec<Box6> {
        let mut boxes = Vec::new();
        for i in 0..n {
            for j in 0..n {
                for f in 0..2 {
                    let (x, y, z) = (i as f64 * 5.0, j as f64 * 5.0, f as f64 * 3.0);
                    boxes.push([x, y, z, x + 4.0, y + 4.0, z + 3.0]);
                }
            }
        }
        boxes
    }

    fn with(mut a: Vec<Box6>, b: impl IntoIterator<Item = Box6>) -> Vec<Box6> {
        a.extend(b);
        a
    }

    #[test]
    fn leaves_out_an_element_a_kilometre_from_the_building() {
        let beam = [1243.0, 148.0, 12.0, 1245.0, 148.5, 12.2];
        let framed = framing_box(&with(building(4), [beam]));
        assert_eq!(framed, Some([0.0, 0.0, 0.0, 19.0, 19.0, 6.0]));
    }

    #[test]
    fn keeps_the_whole_of_a_model_with_nothing_far_out() {
        // A wing 30 m on, a terrain under all of it.
        let wing = building(2)
            .into_iter()
            .map(|b| [b[0] + 50.0, b[1], b[2], b[3] + 50.0, b[4], b[5]]);
        let terrain = [-20.0, -20.0, -1.0, 90.0, 40.0, 0.0];
        let boxes = with(with(building(4), wing), [terrain]);
        let framed = framing_box(&boxes);
        assert_eq!(framed, Some([-20.0, -20.0, -1.0, 90.0, 40.0, 6.0]));
    }

    #[test]
    fn keeps_the_beams_at_the_edge_of_a_model_whose_columns_all_stand_on_one_spot() {
        // 25 columns at the origin, and beams across 16 m, the farthest 14 m out.
        let columns = (0..25).map(|_| [-0.1, -0.1, 0.0, 0.1, 0.1, 2.8]);
        let beams =
            [-14.0, -10.0, -6.0, -2.0, 2.0].map(|x| [x - 0.1, 4.0, 2.6, x + 0.1, 16.0, 2.8]);
        let framed = framing_box(&with(columns.collect(), beams));
        assert_eq!(framed, Some([-14.1, -0.1, 0.0, 2.1, 16.0, 2.8]));
    }

    #[test]
    fn leaves_out_a_marker_standing_apart() {
        let marker = [-36.0, -18.0, -1.3, -34.0, -16.0, -1.2];
        let framed = framing_box(&with(building(2), [marker]));
        assert_eq!(framed, Some([0.0, 0.0, 0.0, 9.0, 9.0, 6.0]));
    }

    #[test]
    fn keeps_a_flat_model_whole() {
        let slabs: Vec<Box6> = (0..10)
            .map(|i| [i as f64 * 6.0, 0.0, 0.0, i as f64 * 6.0 + 5.0, 5.0, 0.2])
            .collect();
        assert_eq!(framing_box(&slabs), Some([0.0, 0.0, 0.0, 59.0, 5.0, 0.2]));
    }

    #[test]
    fn keeps_everything_when_there_are_too_few_elements_to_tell() {
        let few = [
            [0.0, 0.0, 0.0, 1.0, 1.0, 1.0],
            [2.0, 0.0, 0.0, 3.0, 1.0, 1.0],
            [5000.0, 0.0, 0.0, 5001.0, 1.0, 1.0],
        ];
        assert_eq!(framing_box(&few), Some([0.0, 0.0, 0.0, 5001.0, 1.0, 1.0]));
        assert_eq!(framing_box(&[]), None);
    }

    /// A scene of one triangle per box, from two of its corners.
    fn scene(boxes: &[Box6]) -> Scene {
        let mut batch = Batch::default();
        let mut elements = Vec::new();
        for (n, b) in boxes.iter().enumerate() {
            for p in [[b[0], b[1], b[2]], [b[3], b[4], b[5]], [b[0], b[1], b[2]]] {
                batch.positions.extend(p.map(|v| v as f32));
            }
            let first = n as u32 * 3;
            batch.indices.extend([first, first + 1, first + 2]);
            let ranges = vec![Range {
                batch: 0,
                first,
                count: 3,
            }];
            elements.push(Element {
                ranges,
                ..Element::default()
            });
        }
        Scene {
            batches: vec![batch],
            elements,
            ..Scene::default()
        }
    }

    #[test]
    fn frames_100000_elements_in_under_a_second() {
        // A building of 56,000 rooms, and a chain of 22,000 markers 300 m
        // apart leading away from it on each side, the farthest first. The
        // reach is about 560 m, so each marker joins only once the one
        // before it has.
        let mut boxes = Vec::new();
        for i in 0..40 {
            for j in 0..35 {
                for k in 0..40 {
                    let (x, y, z) = (i as f64 * 5.0, j as f64 * 5.0, k as f64 * 3.0);
                    boxes.push([x, y, z, x + 4.0, y + 4.0, z + 3.0]);
                }
            }
        }
        let east = |i: u32| {
            let x = 250.0 + 300.0 * f64::from(i);
            [x, 0.0, 0.0, x + 1.0, 1.0, 1.0]
        };
        let west = |i: u32| {
            let x = -250.0 - 300.0 * f64::from(i);
            [x - 1.0, 0.0, 0.0, x, 1.0, 1.0]
        };
        for i in (0..22_000).rev() {
            boxes.extend([east(i), west(i)]);
        }
        let scene = scene(&boxes);
        let start = Instant::now();
        let framed = scene_framing(&scene);
        let took = start.elapsed();
        let end = 300.0 * 21_999.0 + 251.0;
        assert_eq!(framed, Some([[-end, 0.0, 0.0], [end, 174.0, 120.0]]));
        assert!(took.as_secs_f64() < 1.0, "framed in {took:?}");
    }
}
