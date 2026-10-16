//! The PLY reader on files written here from known geometry in every
//! encoding, with the lists, the properties and the elements PLY files
//! vary in; and on hostile files.

mod mesh_common;

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::Duration;

use exav_render::mesh::Scene;
use exav_render::ply::{read, Error};
use mesh_common::*;

#[derive(Clone, Copy, PartialEq)]
enum Enc {
    Ascii,
    Little,
    Big,
}

/// A property: its name, its type, and the type of its list's count.
type Prop = (&'static str, &'static str, Option<&'static str>);

/// One element: its name, its properties and its rows, each row a list of
/// values for every property (one value for a scalar).
struct El {
    name: &'static str,
    props: Vec<Prop>,
    rows: Vec<Vec<Vec<f64>>>,
}

fn put(out: &mut Vec<u8>, enc: Enc, ty: &str, v: f64) {
    if enc == Enc::Ascii {
        write!(out, "{v} ").unwrap();
        return;
    }
    macro_rules! num {
        ($t:ty) => {{
            let n = v as $t;
            out.extend_from_slice(&if enc == Enc::Big {
                n.to_be_bytes()
            } else {
                n.to_le_bytes()
            });
        }};
    }
    match ty {
        "char" | "int8" => num!(i8),
        "uchar" | "uint8" => num!(u8),
        "short" | "int16" => num!(i16),
        "ushort" | "uint16" => num!(u16),
        "int" | "int32" => num!(i32),
        "uint" | "uint32" => num!(u32),
        "float" | "float32" => num!(f32),
        "double" | "float64" => num!(f64),
        _ => panic!("{ty}"),
    }
}

fn file(enc: Enc, elements: &[El]) -> Vec<u8> {
    let mut out = b"ply\n".to_vec();
    out.extend_from_slice(
        match enc {
            Enc::Ascii => "format ascii 1.0\n",
            Enc::Little => "format binary_little_endian 1.0\n",
            Enc::Big => "format binary_big_endian 1.0\n",
        }
        .as_bytes(),
    );
    out.extend_from_slice(b"comment made by the tests\n");
    for e in elements {
        writeln!(out, "element {} {}", e.name, e.rows.len()).unwrap();
        for (name, ty, count) in &e.props {
            match count {
                Some(c) => writeln!(out, "property list {c} {ty} {name}").unwrap(),
                None => writeln!(out, "property {ty} {name}").unwrap(),
            }
        }
    }
    out.extend_from_slice(b"end_header\n");
    for e in elements {
        for row in &e.rows {
            for ((_, ty, count), values) in e.props.iter().zip(row) {
                if let Some(c) = count {
                    put(&mut out, enc, c, values.len() as f64);
                }
                for &v in values {
                    put(&mut out, enc, ty, v);
                }
            }
            if enc == Enc::Ascii {
                out.push(b'\n');
            }
        }
    }
    out
}

fn vertex_element(points: &[P], with_color: bool) -> El {
    let mut props: Vec<Prop> = vec![
        ("x", "float", None),
        ("y", "float", None),
        ("z", "float", None),
    ];
    if with_color {
        props.extend([
            ("red", "uchar", None),
            ("green", "uchar", None),
            ("blue", "uchar", None),
        ]);
    }
    El {
        name: "vertex",
        props,
        rows: points
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut row = vec![vec![p[0]], vec![p[1]], vec![p[2]]];
                if with_color {
                    row.extend(color_of(i).map(|c| vec![f64::from(c)]));
                }
                row
            })
            .collect(),
    }
}

fn face_element(faces: &[Vec<usize>], count: &'static str, index: &'static str) -> El {
    El {
        name: "face",
        props: vec![("vertex_indices", index, Some(count))],
        rows: faces
            .iter()
            .map(|f| vec![f.iter().map(|&i| i as f64).collect()])
            .collect(),
    }
}

fn color_of(i: usize) -> [u8; 3] {
    [(i * 30) as u8, 255 - (i * 30) as u8, (i * 7) as u8]
}

fn cube_faces() -> Vec<Vec<usize>> {
    CUBE_QUADS.iter().map(|q| q.to_vec()).collect()
}

fn cube(enc: Enc) -> Vec<u8> {
    file(
        enc,
        &[
            vertex_element(&CUBE, true),
            face_element(&cube_faces(), "uchar", "int"),
        ],
    )
}

fn parse(bytes: &[u8]) -> Scene {
    read(bytes, usize::MAX).unwrap()
}

#[test]
fn a_cube_is_the_same_in_ascii_and_both_binary_orders() {
    for enc in [Enc::Ascii, Enc::Little, Enc::Big] {
        let s = parse(&cube(enc));
        assert_eq!(s.triangles(), 12);
        assert_near(volume(&s), 1.0, "volume");
        assert_near(area(&s), 6.0, "area");
        assert_eq!(extent(&s), [[0.; 3], [1.; 3]]);
        assert_eq!(s.warnings, Default::default());
        assert_sound(&s);
        // Each corner has the colour its vertex was given.
        let b = &s.batches[0];
        let colors = b.colors.as_ref().unwrap();
        for (i, p) in b.positions.chunks(3).enumerate() {
            let v = CUBE
                .iter()
                .position(|c| (0..3).all(|k| f64::from(p[k]) == c[k]))
                .unwrap();
            assert_eq!(&colors[i * 3..i * 3 + 3], &color_of(v), "vertex {v}");
        }
    }
}

#[test]
fn list_counts_and_indices_of_every_integer_type_are_read() {
    for enc in [Enc::Ascii, Enc::Little, Enc::Big] {
        for count in [
            "uchar", "char", "ushort", "short", "uint", "int", "uint8", "int32",
        ] {
            for index in [
                "uchar", "char", "ushort", "short", "uint", "int", "uint16", "int8",
            ] {
                let bytes = file(
                    enc,
                    &[
                        vertex_element(&CUBE, false),
                        face_element(&cube_faces(), count, index),
                    ],
                );
                let s = parse(&bytes);
                assert_eq!(s.triangles(), 12, "{count} {index}");
                assert_near(volume(&s), 1.0, "volume");
            }
        }
    }
}

#[test]
fn coordinates_of_every_type_are_read() {
    for ty in ["float", "double", "int", "short", "uchar"] {
        let points = TETRA;
        let el = El {
            name: "vertex",
            props: vec![("x", ty, None), ("y", ty, None), ("z", ty, None)],
            rows: points
                .iter()
                .map(|p| p.iter().map(|&v| vec![v]).collect())
                .collect(),
        };
        let faces: Vec<Vec<usize>> = TETRA_FACES.iter().map(|f| f.to_vec()).collect();
        for enc in [Enc::Ascii, Enc::Little, Enc::Big] {
            let s = parse(&file(
                enc,
                &[
                    El {
                        name: el.name,
                        props: el.props.clone(),
                        rows: el.rows.clone(),
                    },
                    face_element(&faces, "uchar", "uint"),
                ],
            ));
            assert_eq!(s.triangles(), 4, "{ty}");
            assert_near(volume(&s), 1.0 / 6.0, ty);
        }
    }
}

#[test]
fn a_pentagon_is_three_triangles_and_a_notched_polygon_is_covered_once() {
    let pentagon: Vec<P> = (0..5)
        .map(|k| {
            let a = f64::from(k) * std::f64::consts::TAU / 5.0;
            [a.cos(), a.sin(), 0.0]
        })
        .collect();
    let bytes = file(
        Enc::Little,
        &[
            vertex_element(&pentagon, false),
            El {
                name: "face",
                props: vec![("vertex_index", "int", Some("uchar"))],
                rows: vec![vec![vec![0., 1., 2., 3., 4.]]],
            },
        ],
    );
    let s = parse(&bytes);
    assert_eq!(s.triangles(), 3);
    assert_near(
        area(&s),
        2.5 * (std::f64::consts::TAU / 5.0).sin(),
        "pentagon",
    );
    // A U in the xz plane, facing the other way.
    let u: Vec<P> = [
        [0., 0.],
        [3., 0.],
        [3., 2.],
        [2., 2.],
        [2., 1.],
        [1., 1.],
        [1., 2.],
        [0., 2.],
    ]
    .iter()
    .map(|p| [p[0], 0.0, p[1]])
    .collect();
    let bytes = file(
        Enc::Ascii,
        &[
            vertex_element(&u, false),
            face_element(&[(0..8).rev().collect()], "uchar", "int"),
        ],
    );
    let s = parse(&bytes);
    assert_eq!(s.triangles(), 6);
    assert_near(area(&s), 5.0, "area");
}

#[test]
fn other_elements_and_properties_are_skipped_by_their_types() {
    for enc in [Enc::Ascii, Enc::Little, Enc::Big] {
        let mut vertex = vertex_element(&CUBE, true);
        // Properties before, among and after the ones read, one a list.
        vertex.props.insert(0, ("confidence", "double", None));
        vertex.props.insert(2, ("tex", "short", Some("uchar")));
        vertex.props.push(("flags", "uint", None));
        for (i, row) in vertex.rows.iter_mut().enumerate() {
            row.insert(0, vec![0.25]);
            row.insert(2, vec![1.0; i % 3]);
            row.push(vec![4_000_000_000.0]);
        }
        let mut face = face_element(&cube_faces(), "uchar", "int");
        face.props.insert(0, ("material", "short", None));
        face.props.push(("texcoord", "float", Some("uchar")));
        for (i, row) in face.rows.iter_mut().enumerate() {
            row.insert(0, vec![-3.0]);
            row.push(vec![0.5; 2 * (i % 4)]);
        }
        let camera = El {
            name: "camera",
            props: vec![("fov", "float", None), ("name", "uchar", Some("uchar"))],
            rows: vec![vec![vec![60.0], vec![65.0, 66.0, 67.0]]; 3],
        };
        let edge = El {
            name: "edge",
            props: vec![("vertex1", "int", None), ("vertex2", "int", None)],
            rows: vec![vec![vec![0.0], vec![1.0]]; 12],
        };
        let s = parse(&file(enc, &[camera, vertex, face, edge]));
        assert_eq!(s.triangles(), 12);
        assert_near(volume(&s), 1.0, "volume");
        assert_eq!(extent(&s), [[0.; 3], [1.; 3]]);
        assert!(s.batches[0].colors.is_some());
        assert_eq!(s.warnings, Default::default());
    }
}

#[test]
fn normals_are_used_when_the_file_has_them() {
    let mut vertex = vertex_element(&TETRA[..3], false);
    vertex.props.extend([
        ("nx", "float", None),
        ("ny", "float", None),
        ("nz", "float", None),
    ]);
    for row in &mut vertex.rows {
        row.extend([vec![0.0], vec![0.0], vec![-4.0]]);
    }
    let s = parse(&file(
        Enc::Little,
        &[vertex, face_element(&[vec![0, 1, 2]], "uchar", "int")],
    ));
    for n in s.batches[0].normals.chunks(3) {
        assert_eq!(n, [0.0, 0.0, -1.0]);
    }
    let s = parse(&file(
        Enc::Little,
        &[
            vertex_element(&TETRA[..3], false),
            face_element(&[vec![0, 1, 2]], "uchar", "int"),
        ],
    ));
    assert_eq!(&s.batches[0].normals[..3], &[0.0, 0.0, 1.0]);
}

#[test]
fn colours_of_each_type_are_scaled_to_bytes() {
    let cases: [(&str, [f64; 3], [u8; 3]); 4] = [
        ("uchar", [255., 128., 0.], [255, 128, 0]),
        ("ushort", [65535., 32896., 0.], [255, 128, 0]),
        ("float", [1.0, 0.5, 0.0], [255, 128, 0]),
        ("double", [2.0, -1.0, 0.2], [255, 0, 51]),
    ];
    for (ty, value, want) in cases {
        let vertex = El {
            name: "vertex",
            props: vec![
                ("x", "float", None),
                ("y", "float", None),
                ("z", "float", None),
                ("r", ty, None),
                ("g", ty, None),
                ("b", ty, None),
                ("alpha", ty, None),
            ],
            rows: TETRA[..3]
                .iter()
                .map(|p| {
                    vec![
                        vec![p[0]],
                        vec![p[1]],
                        vec![p[2]],
                        vec![value[0]],
                        vec![value[1]],
                        vec![value[2]],
                        vec![0.0],
                    ]
                })
                .collect(),
        };
        let s = parse(&file(
            Enc::Little,
            &[vertex, face_element(&[vec![0, 1, 2]], "uchar", "int")],
        ));
        let c = s.batches[0].colors.as_ref().unwrap();
        assert_eq!(&c[..3], &want, "{ty}");
    }
}

#[test]
fn a_point_cloud_is_reported_as_unsupported() {
    let bytes = file(Enc::Little, &[vertex_element(&CUBE, true)]);
    let e = read(&bytes, 100).unwrap_err();
    assert!(matches!(e, Error::Unsupported(_)));
    assert!(e.to_string().contains("point cloud"), "{e}");
    // A face element that holds no faces is the same.
    let bytes = file(
        Enc::Ascii,
        &[
            vertex_element(&CUBE, false),
            face_element(&[], "uchar", "int"),
        ],
    );
    assert!(matches!(
        read(&bytes, 100).unwrap_err(),
        Error::Unsupported(_)
    ));
}

#[test]
fn what_is_not_a_ply_file_is_refused() {
    for bad in [
        &b""[..],
        b"ply",
        b"ply\n",
        b"plyx\nformat ascii 1.0\nend_header\n",
        b"ply\nformat ascii 1.0\nelement vertex 1\n",
        b"hello\n",
        b"\x7fELF",
        b"ply\r",
    ] {
        assert_eq!(read(bad, 10).unwrap_err(), Error::NotPly, "{bad:?}");
    }
    let cases: [(&[u8], &str); 5] = [
        (b"ply\nformat ebcdic 1.0\nend_header\n", "format"),
        (
            b"ply\nproperty float x\nend_header\n",
            "property before element",
        ),
        (
            b"ply\nformat ascii 1.0\nelement vertex 1\nproperty quad x\nend_header\n",
            "property type",
        ),
        (
            b"ply\nformat ascii 1.0\nelement vertex -1\nend_header\n",
            "element count",
        ),
        (b"ply\nelement vertex 1\nend_header\n", "no format line"),
    ];
    for (bad, what) in cases {
        let e = read(bad, 10).unwrap_err();
        assert!(e.to_string().contains(what), "{e}");
    }
    // CRLF headers are fine.
    let crlf = String::from_utf8(cube(Enc::Ascii))
        .unwrap()
        .replace('\n', "\r\n");
    assert_eq!(parse(crlf.as_bytes()).triangles(), 12);
}

#[test]
fn faces_that_cannot_be_drawn_are_dropped_and_counted() {
    let faces = vec![vec![0, 1, 2], vec![0, 1, 99], vec![0, 1], vec![3, 2, 1, 0]];
    let s = parse(&file(
        Enc::Ascii,
        &[
            vertex_element(&CUBE, false),
            face_element(&faces, "uchar", "int"),
        ],
    ));
    assert_eq!(s.triangles(), 3);
    assert_eq!(s.warnings.invalid, 1);
    // A negative index is out of range too.
    let el = El {
        name: "face",
        props: vec![("vertex_indices", "int", Some("uchar"))],
        rows: vec![vec![vec![0., 1., 2.]], vec![vec![0., -1., 2.]]],
    };
    let s = parse(&file(Enc::Little, &[vertex_element(&CUBE, false), el]));
    assert_eq!(s.triangles(), 1);
    assert_eq!(s.warnings.invalid, 1);
    // Every face bad: an error, not an empty picture.
    let bad = vec![vec![0, 1, 99]];
    let bytes = file(
        Enc::Ascii,
        &[
            vertex_element(&CUBE, false),
            face_element(&bad, "uchar", "int"),
        ],
    );
    assert!(matches!(read(&bytes, 10).unwrap_err(), Error::Invalid(_)));
    // Vertices without a z.
    let mut v = vertex_element(&CUBE, false);
    v.props.remove(2);
    v.rows.iter_mut().for_each(|r| drop(r.remove(2)));
    let bytes = file(
        Enc::Ascii,
        &[v, face_element(&cube_faces(), "uchar", "int")],
    );
    assert!(matches!(read(&bytes, 10).unwrap_err(), Error::Invalid(_)));
}

#[test]
fn a_file_that_ends_early_gives_what_it_holds() {
    let whole = cube(Enc::Little);
    // Cut in the faces: the first faces are kept.
    let s = parse(&whole[..whole.len() - 7]);
    assert!(s.warnings.damaged);
    assert!(
        s.triangles() >= 8 && s.triangles() < 12,
        "{}",
        s.triangles()
    );
    // Cut in the vertices: no face can be read.
    let cut = whole.len() - 6 * 8 - 8 * 15;
    assert!(read(&whole[..cut], 100).is_err());
}

#[test]
fn coordinates_that_are_not_numbers_or_not_sizes_drop_their_faces() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e300, -1e13] {
        let mut points = CUBE.to_vec();
        points[6] = [bad, 0.0, 0.0];
        let s = parse(&file(
            Enc::Little,
            &[
                vertex_element(&points, false),
                face_element(&cube_faces(), "uchar", "int"),
            ],
        ));
        // The three quads at corner 6 are gone, three are whole.
        assert_eq!(s.triangles(), 6, "{bad}");
        assert_eq!(s.warnings.invalid, 3, "{bad}");
        assert_sound(&s);
    }
}

#[test]
fn the_budget_stops_the_reading() {
    let s = read(&cube(Enc::Ascii), 5).unwrap();
    assert_eq!(s.triangles(), 5);
    assert_eq!(s.warnings.truncated, 1);
    assert_eq!(read(&cube(Enc::Ascii), 12).unwrap().warnings.truncated, 0);
}

#[test]
fn counts_that_the_data_cannot_hold_are_cut_to_the_data() {
    // Four billion vertices and faces, a few bytes of data.
    for (enc, tail) in [
        (Enc::Ascii, "0 0 0\n1 0 0\n0 1 0\n3 0 1 2\n"),
        (Enc::Little, ""),
    ] {
        let mut text = format!(
            "ply\nformat {} 1.0\nelement vertex 4294967295\nproperty float x\nproperty float y\nproperty float z\nelement face 18446744073709551615\nproperty list uchar int vertex_indices\nend_header\n",
            if enc == Enc::Ascii { "ascii" } else { "binary_little_endian" },
        )
        .into_bytes();
        text.extend_from_slice(tail.as_bytes());
        let started = std::time::Instant::now();
        let r = read(&text, 1000);
        assert!(started.elapsed() < Duration::from_secs(5));
        if let Ok(s) = r {
            assert_sound(&s);
            assert!(s.warnings.damaged);
        }
    }
    // A list that claims four billion items.
    let mut b = b"ply\nformat binary_little_endian 1.0\nelement vertex 3\nproperty float x\nproperty float y\nproperty float z\nelement face 2\nproperty list uint int vertex_indices\nend_header\n".to_vec();
    for p in &TETRA[..3] {
        for v in p {
            b.extend_from_slice(&(*v as f32).to_le_bytes());
        }
    }
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&[0; 12]);
    let r = within(Duration::from_secs(5), "the long list", || read(&b, 1000));
    assert!(r.is_err());
    // An element with no properties and four billion rows has nothing to read.
    let b = b"ply\nformat binary_little_endian 1.0\nelement junk 4000000000\nelement vertex 0\nproperty float x\nproperty float y\nproperty float z\nend_header\n";
    within(Duration::from_secs(5), "the empty element", || read(b, 10)).unwrap_err();
}

#[test]
fn headers_with_too_much_in_them_are_refused() {
    let mut text = String::from("ply\nformat ascii 1.0\nelement vertex 1\n");
    for k in 0..100_000 {
        writeln!(text, "property float p{k}").unwrap();
    }
    text.push_str("end_header\n0\n");
    let r = within(Duration::from_secs(5), "many properties", || {
        read(text.as_bytes(), 10)
    });
    assert!(r.is_err());
    let mut text = String::from("ply\nformat ascii 1.0\n");
    for k in 0..10_000 {
        writeln!(text, "element e{k} 1\nproperty float x").unwrap();
    }
    text.push_str("end_header\n");
    assert!(read(text.as_bytes(), 10).is_err());
    // A header that never ends.
    let mut text = String::from("ply\nformat ascii 1.0\n");
    text.push_str(&"comment ".repeat(100_000));
    assert_eq!(read(text.as_bytes(), 10).unwrap_err(), Error::NotPly);
}

#[test]
fn a_polygon_of_a_million_corners_is_cut_at_the_budget_in_linear_time() {
    let n = 1_000_000usize;
    let points: Vec<P> = (0..n).map(|k| [k as f64, (k % 2) as f64, 0.0]).collect();
    let face = El {
        name: "face",
        props: vec![("vertex_indices", "int", Some("uint"))],
        rows: vec![vec![(0..n).map(|k| k as f64).collect()]],
    };
    let bytes = file(Enc::Little, &[vertex_element(&points, false), face]);
    let s = within(Duration::from_secs(20), "the million-gon", || {
        read(&bytes, 200_000).unwrap()
    });
    assert_eq!(s.triangles(), 200_000);
    assert_eq!(s.warnings.truncated, 1);
    assert_sound(&s);
}

#[test]
fn a_file_cut_anywhere_or_changed_anywhere_is_read_soundly() {
    for enc in [Enc::Ascii, Enc::Little, Enc::Big] {
        sweep(&cube(enc), |b| read(b, 1000).ok());
    }
}
