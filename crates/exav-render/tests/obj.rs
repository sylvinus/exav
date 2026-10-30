//! The OBJ reader on shapes built here from known geometry: triangle
//! counts, enclosed volume, extents, colours, normals, groups; and on
//! hostile files.

mod mesh_common;

use std::fmt::Write;
use std::time::Duration;

use exav_render::mesh::Scene;
use exav_render::obj::{Error, read};
use mesh_common::*;

fn parse(text: &str) -> Scene {
    read(text.as_bytes(), usize::MAX).unwrap()
}

fn vertices(out: &mut String, points: &[P]) {
    for p in points {
        writeln!(out, "v {} {} {}", p[0], p[1], p[2]).unwrap();
    }
}

fn cube(prefix: &str) -> String {
    let mut s = String::from(prefix);
    vertices(&mut s, &CUBE);
    for q in CUBE_QUADS {
        writeln!(s, "f {} {} {} {}", q[0] + 1, q[1] + 1, q[2] + 1, q[3] + 1).unwrap();
    }
    s
}

#[test]
fn a_cube_of_quads_is_twelve_triangles_enclosing_one() {
    let s = parse(&cube("# a cube\nmtllib cube.mtl\nusemtl wood\n"));
    assert_eq!(s.triangles(), 12);
    assert_near(volume(&s), 1.0, "volume");
    assert_near(area(&s), 6.0, "area");
    assert_eq!(extent(&s), [[0.; 3], [1.; 3]]);
    assert_eq!(s.bounds, Some([[0.; 3], [1.; 3]]));
    assert_eq!(s.warnings, Default::default());
    assert_sound(&s);
    // No vertex colours, and so none in the batch.
    assert!(s.batches[0].colors.is_none());
    // Flat faces: every normal is the face's own, pointing out.
    for t in s.batches[0].indices.chunks(3) {
        let k = t[0] as usize * 3;
        let (p, n) = (&s.batches[0].positions, &s.batches[0].normals);
        let out = (f64::from(p[k]) - 0.5) * f64::from(n[k])
            + (f64::from(p[k + 1]) - 0.5) * f64::from(n[k + 1])
            + (f64::from(p[k + 2]) - 0.5) * f64::from(n[k + 2]);
        assert!(out > 0.0);
    }
}

#[test]
fn indices_count_back_from_the_vertices_read_so_far() {
    let mut text = String::new();
    vertices(&mut text, &TETRA);
    for f in TETRA_FACES {
        writeln!(
            text,
            "f {} {} {}",
            f[0] as i32 - 4,
            f[1] as i32 - 4,
            f[2] as i32 - 4
        )
        .unwrap();
    }
    let s = parse(&text);
    assert_eq!(s.triangles(), 4);
    assert_near(volume(&s), 1.0 / 6.0, "volume");
    // A relative index depends on where the face is: a second tetrahedron
    // after eight more vertices is the same shape at the same place.
    let mut text = String::new();
    vertices(&mut text, &TETRA);
    vertices(&mut text, &TETRA.map(|p| [p[0] + 5.0, p[1], p[2]]));
    for f in TETRA_FACES {
        writeln!(
            text,
            "f {} {} {}",
            f[0] as i32 - 4,
            f[1] as i32 - 4,
            f[2] as i32 - 4
        )
        .unwrap();
    }
    let s = parse(&text);
    assert_eq!(s.triangles(), 4);
    assert_eq!(extent(&s), [[5., 0., 0.], [6., 1., 1.]]);
}

#[test]
fn the_face_forms_all_name_the_same_corners() {
    let forms = [
        "f 1 2 3",
        "f 1/1 2/2 3/3",
        "f 1//1 2//1 3//1",
        "f 1/1/1 2/2/1 3/3/1",
        "f -3 -2 -1",
        "f -3/-3/-1 -2/-2/-1 -1/-1/-1",
    ];
    for f in forms {
        let s = parse(&format!(
            "v 0 0 0\nv 1 0 0\nv 0 1 0\nvt 0 0\nvt 1 0\nvt 0 1\nvn 0 0 1\n{f}\n"
        ));
        assert_eq!(s.triangles(), 1, "{f}");
        assert_eq!(
            triangles(&s)[0],
            [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]],
            "{f}"
        );
        assert!(s.warnings.invalid == 0, "{f}");
    }
}

#[test]
fn a_quad_is_two_triangles_and_a_pentagon_three() {
    let quad = parse("v 0 0 0\nv 1 0 0\nv 1 1 0\nv 0 1 0\nf 1 2 3 4\n");
    assert_eq!(quad.triangles(), 2);
    assert_near(area(&quad), 1.0, "quad area");
    let mut text = String::new();
    let pentagon: Vec<P> = (0..5)
        .map(|k| {
            let a = f64::from(k) * std::f64::consts::TAU / 5.0;
            [a.cos(), a.sin(), 0.0]
        })
        .collect();
    vertices(&mut text, &pentagon);
    text.push_str("f 1 2 3 4 5\n");
    let s = parse(&text);
    assert_eq!(s.triangles(), 3);
    // The area of a regular pentagon of circumradius 1.
    assert_near(
        area(&s),
        2.5 * (std::f64::consts::TAU / 5.0).sin(),
        "pentagon",
    );
}

#[test]
fn a_concave_polygon_is_covered_without_overlap() {
    // A U, area 5: a fan from its first corner would cover part of the
    // notch.
    let u: [P; 8] = [
        [0., 0., 0.],
        [3., 0., 0.],
        [3., 2., 0.],
        [2., 2., 0.],
        [2., 1., 0.],
        [1., 1., 0.],
        [1., 2., 0.],
        [0., 2., 0.],
    ];
    let mut text = String::new();
    vertices(&mut text, &u);
    text.push_str("f 1 2 3 4 5 6 7 8\n");
    let s = parse(&text);
    assert_eq!(s.triangles(), 6);
    assert_near(area(&s), 5.0, "area");
    // Every triangle faces the same way as the polygon.
    for t in triangles(&s) {
        let z =
            (t[1][0] - t[0][0]) * (t[2][1] - t[0][1]) - (t[1][1] - t[0][1]) * (t[2][0] - t[0][0]);
        assert!(z > 0.0);
    }
}

#[test]
fn groups_and_objects_are_elements() {
    let mut text = String::new();
    vertices(&mut text, &TETRA);
    vertices(&mut text, &TETRA.map(|p| [p[0] + 3.0, p[1], p[2]]));
    text.push_str("o first\ng left\n");
    for f in TETRA_FACES {
        writeln!(text, "f {} {} {}", f[0] + 1, f[1] + 1, f[2] + 1).unwrap();
    }
    text.push_str("g\ng empty one\ng right side\n");
    for f in TETRA_FACES {
        writeln!(text, "f {} {} {}", f[0] + 5, f[1] + 5, f[2] + 5).unwrap();
    }
    let s = parse(&text);
    let names: Vec<_> = s.elements.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["left", "right side"]);
    for (e, x) in s.elements.iter().zip([0.0, 3.0]) {
        assert_eq!(e.ranges.len(), 1);
        assert_eq!(e.ranges[0].count, 12);
        let b = &s.batches[0];
        let (first, count) = (e.ranges[0].first as usize, e.ranges[0].count as usize);
        for &i in &b.indices[first..first + count] {
            let px = f64::from(b.positions[i as usize * 3]);
            assert!((x..=x + 1.0).contains(&px), "{} at {px}", e.name);
        }
    }
    // Faces before any group belong to an unnamed element.
    let s = parse("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\ng later\n");
    assert_eq!(s.elements.len(), 1);
    assert_eq!(s.elements[0].name, "");
}

#[test]
fn vertex_colours_colour_the_faces_and_a_fourth_number_is_a_weight() {
    let s = parse("v 0 0 0 1 0 0\nv 1 0 0 0 1 0\nv 0 1 0 0 0 0.5\nf 1 2 3\n");
    let c = s.batches[0].colors.as_ref().unwrap();
    assert_eq!(c.len(), 9);
    assert_eq!(&c[..], &[255, 0, 0, 0, 255, 0, 0, 0, 128]);
    // x y z w: no colour.
    let s = parse("v 0 0 0 2\nv 1 0 0 2\nv 0 1 0 2\nf 1 2 3\n");
    assert!(s.batches[0].colors.is_none());
    assert_eq!(triangles(&s)[0], [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]]);
    // Some vertices coloured: the others get a default, none are left out.
    let s = parse("v 0 0 0\nv 1 0 0\nv 0 1 0 0 0 1\nf 1 2 3\n");
    let c = s.batches[0].colors.as_ref().unwrap();
    assert_eq!(c.len(), 9);
    assert_eq!(&c[6..], &[0, 0, 255]);
}

#[test]
fn normals_are_used_when_given_and_computed_when_not() {
    let given =
        parse("v 0 0 0\nv 1 0 0\nv 0 1 0\nvn 0 0 2\nvn 0 0 2\nvn 0 0 2\nf 1//1 2//2 3//3\n");
    for n in given.batches[0].normals.chunks(3) {
        assert_eq!(n, [0.0, 0.0, 1.0]);
    }
    // Pointing the other way than the winding says: the file is believed.
    let flipped = parse("v 0 0 0\nv 1 0 0\nv 0 1 0\nvn 0 0 -1\nf 1//1 2//1 3//1\n");
    assert_eq!(&flipped.batches[0].normals[..3], &[0.0, 0.0, -1.0]);
    // None given, a zero one and one that does not exist: the face's.
    for f in ["f 1 2 3", "f 1//1 2//1 3//1", "f 1//9 2//9 3//9"] {
        let s = parse(&format!("v 0 0 0\nv 1 0 0\nv 0 1 0\nvn 0 0 0\n{f}\n"));
        assert_eq!(&s.batches[0].normals[..3], &[0.0, 0.0, 1.0], "{f}");
    }
}

#[test]
fn continuation_lines_and_crlf_are_read() {
    let s = parse("v 0 0 0\r\nv 1 0 0\r\nv 1 1 0\r\nv 0 1 0\r\nf 1 2 \\\r\n 3 4\r\n");
    assert_eq!(s.triangles(), 2);
}

#[test]
fn lines_points_and_curves_are_counted_not_drawn() {
    let s = parse("v 0 0 0\nv 1 0 0\nv 0 1 0\nl 1 2\nl 2 3\np 1\ncurv 0 1 1 2\nf 1 2 3\n");
    assert_eq!(s.triangles(), 1);
    assert_eq!(s.warnings.unsupported["l"], 2);
    assert_eq!(s.warnings.unsupported["p"], 1);
    assert_eq!(s.warnings.unsupported["curv"], 1);
    // Vertices only: nothing to show, and no error.
    let s = parse("v 0 0 0\nv 1 0 0\n");
    assert_eq!(s.triangles(), 0);
    assert!(s.bounds.is_none());
}

#[test]
fn what_is_not_an_obj_file_is_refused() {
    assert_eq!(read(b"", 10).unwrap_err(), Error::NotObj);
    assert_eq!(read(b"hello world\n", 10).unwrap_err(), Error::NotObj);
    assert_eq!(read(b"# only a comment\n", 10).unwrap_err(), Error::NotObj);
    assert_eq!(read(b"v 0 0 0\0\0\0\n", 10).unwrap_err(), Error::NotObj);
    assert_eq!(
        read(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0", 10).unwrap_err(),
        Error::NotObj
    );
    assert_eq!(
        read(b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 9\nf 0 1 2\n", 10).unwrap_err(),
        Error::NoValidFaces
    );
}

#[test]
fn faces_that_cannot_be_drawn_are_dropped_and_counted() {
    let s =
        parse("v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\nf 1 2 4\nf 0 1 2\nf -9 1 2\nf 1 2\nf 1 2 x\n");
    assert_eq!(s.triangles(), 1);
    assert_eq!(s.warnings.invalid, 5);
}

#[test]
fn coordinates_that_are_not_numbers_or_not_sizes_drop_their_faces() {
    for bad in ["nan", "inf", "-inf", "1e999", "1e300", "-1e13"] {
        let s = parse(&format!(
            "v 0 0 0\nv 1 0 0\nv 0 1 0\nv {bad} 0 0\nf 1 2 3\nf 1 2 4\n"
        ));
        assert_eq!(s.triangles(), 1, "{bad}");
        assert_eq!(s.warnings.invalid, 1, "{bad}");
        assert_eq!(s.bounds, Some([[0.; 3], [1., 1., 0.]]), "{bad}");
        assert_sound(&s);
    }
    // A vertex line with a missing coordinate keeps the numbering.
    let s = parse("v 0 0 0\nv 1 0\nv 1 0 0\nv 0 1 0\nf 1 3 4\nf 1 2 3\n");
    assert_eq!(s.triangles(), 1);
    assert!(s.warnings.damaged);
}

#[test]
fn the_budget_stops_the_reading() {
    let mut text = String::new();
    vertices(&mut text, &CUBE);
    for _ in 0..10 {
        for q in CUBE_QUADS {
            writeln!(
                text,
                "f {} {} {} {}",
                q[0] + 1,
                q[1] + 1,
                q[2] + 1,
                q[3] + 1
            )
            .unwrap();
        }
    }
    let s = read(text.as_bytes(), 5).unwrap();
    assert_eq!(s.triangles(), 5);
    assert_eq!(s.warnings.truncated, 1);
    let s = read(text.as_bytes(), 0).unwrap();
    assert_eq!(s.triangles(), 0);
    let s = read(text.as_bytes(), 120).unwrap();
    assert_eq!(s.triangles(), 120);
    assert_eq!(s.warnings.truncated, 0);
}

#[test]
fn a_polygon_of_a_million_corners_is_cut_at_the_budget_in_linear_time() {
    let n = 1_000_000;
    let mut text = String::new();
    // A zigzag: every triangle of the fan has an area.
    for k in 0..n {
        writeln!(text, "v {k} {} 0", k % 2).unwrap();
    }
    text.push('f');
    for k in 1..=n {
        write!(text, " {k}").unwrap();
    }
    text.push('\n');
    let s = within(Duration::from_secs(20), "the million-gon", || {
        read(text.as_bytes(), 200_000).unwrap()
    });
    assert_eq!(s.triangles(), 200_000);
    assert_eq!(s.warnings.truncated, 1);
    assert_sound(&s);
    // Without a cap on the budget the polygon is fanned whole.
    let s = within(Duration::from_secs(20), "the million-gon, whole", || {
        read(text.as_bytes(), usize::MAX).unwrap()
    });
    assert_eq!(s.triangles(), n as usize - 2);
}

#[test]
fn polygons_past_the_triangulation_work_limit_are_fanned() {
    // A U of area 5, 300,000 times: ear-clipping them all is more work than
    // one file may ask for. The first is covered exactly; the last is fanned
    // from its first corner, which overlaps itself over the notch.
    let mut text = String::new();
    for (x, y) in [
        (0, 0),
        (3, 0),
        (3, 2),
        (2, 2),
        (2, 1),
        (1, 1),
        (1, 2),
        (0, 2),
    ] {
        writeln!(text, "v {x} {y} 0").unwrap();
    }
    for _ in 0..300_000 {
        text.push_str("f 1 2 3 4 5 6 7 8\n");
    }
    let s = within(Duration::from_secs(20), "300,000 U polygons", || {
        parse(&text)
    });
    assert_eq!(s.triangles(), 300_000 * 6);
    let all = triangles(&s);
    let signed = |t: &[P; 3]| {
        (t[1][0] - t[0][0]) * (t[2][1] - t[0][1]) - (t[1][1] - t[0][1]) * (t[2][0] - t[0][0])
    };
    let polygon = |k: usize| {
        all[k * 6..k * 6 + 6]
            .iter()
            .map(|t| signed(t).abs() / 2.0)
            .sum::<f64>()
    };
    assert_near(polygon(0), 5.0, "the first polygon");
    assert!(
        polygon(299_999) > 5.5,
        "the last polygon: {}",
        polygon(299_999)
    );
}

#[test]
fn many_polygons_cost_a_bounded_amount_of_triangulation() {
    // Thousands of 64-gons with a notch: each would be ear-clipped, and in
    // all they would take far longer than the limit allows.
    let mut text = String::new();
    for k in 0..64 {
        let a = f64::from(k) * std::f64::consts::TAU / 64.0;
        let r = if k % 2 == 0 { 1.0 } else { 0.6 };
        writeln!(text, "v {} {} 0", r * a.cos(), r * a.sin()).unwrap();
    }
    for _ in 0..4000 {
        text.push('f');
        for k in 1..=64 {
            write!(text, " {k}").unwrap();
        }
        text.push('\n');
    }
    let s = within(Duration::from_secs(20), "4000 star polygons", || {
        read(text.as_bytes(), usize::MAX).unwrap()
    });
    assert_eq!(s.triangles(), 4000 * 62);
    assert_sound(&s);
}

#[test]
fn extreme_numbers_in_faces_are_errors_not_panics() {
    let mut text = String::from("v 0 0 0\nv 1 0 0\nv 0 1 0\n");
    for token in [
        "9223372036854775807",
        "-9223372036854775808",
        "99999999999999999999999",
        "-99999999999999999999999",
        "4294967296",
        "-4294967297",
        "1/",
        "//",
        "///",
        "1/2/3/4",
        "+1",
        "-",
        "1e5",
        "0x1",
    ] {
        writeln!(text, "f 1 2 {token}").unwrap();
        writeln!(text, "f {token} {token} {token}").unwrap();
        writeln!(text, "f 1//{token} 2//{token} 3//{token}").unwrap();
    }
    let s = parse(&text);
    assert_sound(&s);
    // Only the `1//n` faces are whole: a normal that cannot be found is
    // the face's own.
    assert_eq!(s.triangles(), 14);
}

#[test]
fn a_file_cut_anywhere_or_changed_anywhere_is_read_soundly() {
    let bytes = cube("# c\ng cube\nvn 0 0 1\nvt 0 0\n").into_bytes();
    sweep(&bytes, |b| read(b, 1000).ok());
}

#[test]
fn a_hundred_thousand_groups_make_a_bounded_number_of_elements() {
    let mut text = String::from("v 0 0 0\nv 1 0 0\nv 0 1 0\n");
    for k in 0..100_000 {
        writeln!(text, "g group number {k}\nf 1 2 3").unwrap();
    }
    let s = within(Duration::from_secs(20), "the groups", || parse(&text));
    assert_eq!(s.triangles(), 100_000);
    assert!(s.elements.len() <= 10_000);
    // The triangles past the last element's own belong to it.
    let covered: u32 = s
        .elements
        .iter()
        .flat_map(|e| &e.ranges)
        .map(|r| r.count)
        .sum();
    assert_eq!(covered as usize, 3 * s.triangles());
}

#[test]
fn a_long_name_is_cut() {
    let s = parse(&format!(
        "v 0 0 0\nv 1 0 0\nv 0 1 0\ng {}\nf 1 2 3\n",
        "n".repeat(100_000)
    ));
    assert_eq!(s.elements[0].name.len(), 128);
}
