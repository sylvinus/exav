//! The glTF reader on documents and GLB files written here from known
//! geometry: transforms against hand-worked bounds and volumes, colours,
//! normals, accessor layouts; and on hostile files.

mod mesh_common;

use std::fmt::Write as _;
use std::time::Duration;

use exav_render::gltf::{Error, MAX_DEPTH, external_buffers, read, read_with};
use exav_render::mesh::Scene;
use mesh_common::*;

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for k in 0..=chunk.len() {
            out.push(TABLE[(n >> (18 - 6 * k) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

fn floats(values: &[f64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|&v| (v as f32).to_le_bytes())
        .collect()
}

fn pad(mut v: Vec<u8>) -> Vec<u8> {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

/// The cube's 36 indices, from its quads.
fn cube_indices() -> Vec<u32> {
    CUBE_QUADS
        .iter()
        .flat_map(|q| [q[0], q[1], q[2], q[0], q[2], q[3]])
        .map(|i| i as u32)
        .collect()
}

fn encode(indices: &[u32], ty: &str) -> Vec<u8> {
    indices
        .iter()
        .flat_map(|&i| match ty {
            "u8" => vec![i as u8],
            "u16" => (i as u16).to_le_bytes().to_vec(),
            _ => i.to_le_bytes().to_vec(),
        })
        .collect()
}

fn component(ty: &str) -> u32 {
    match ty {
        "u8" => 5121,
        "u16" => 5123,
        _ => 5125,
    }
}

/// The cube's data: positions, then indices of type `ty`.
fn cube_data(ty: &str) -> Vec<u8> {
    let mut data = floats(&CUBE.iter().flatten().copied().collect::<Vec<_>>());
    data.extend(pad(encode(&cube_indices(), ty)));
    data
}

/// A document with the cube as mesh 0 (accessor 0 positions, 1 indices) and
/// whatever `rest` adds at the top level (nodes, scenes, materials...).
fn cube_doc(ty: &str, rest: &str) -> String {
    let data = cube_data(ty);
    document(
        &format!(
            "\"uri\":\"data:application/octet-stream;base64,{}\"",
            base64(&data)
        ),
        data.len(),
        &format!(
            "\"bufferViews\":[{{\"buffer\":0,\"byteOffset\":0,\"byteLength\":96}},{{\"buffer\":0,\"byteOffset\":96,\"byteLength\":{}}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"}},{{\"bufferView\":1,\"componentType\":{},\"count\":36,\"type\":\"SCALAR\"}}],\
             \"meshes\":[{{\"name\":\"cube\",\"primitives\":[{{\"attributes\":{{\"POSITION\":0}},\"indices\":1}}]}}]",
            data.len() - 96,
            component(ty)
        ),
        rest,
    )
}

fn document(buffer_uri: &str, length: usize, parts: &str, rest: &str) -> String {
    let comma = if rest.is_empty() { "" } else { "," };
    let uri = if buffer_uri.is_empty() {
        String::new()
    } else {
        format!("{buffer_uri},")
    };
    format!(
        "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{{uri}\"byteLength\":{length}}}],{parts}{comma}{rest}}}"
    )
}

fn glb(json: &str, bin: &[u8]) -> Vec<u8> {
    let mut json = json.as_bytes().to_vec();
    while !json.len().is_multiple_of(4) {
        json.push(b' ');
    }
    let bin = pad(bin.to_vec());
    let total = 12 + 8 + json.len() + if bin.is_empty() { 0 } else { 8 + bin.len() };
    let mut out = b"glTF".to_vec();
    out.extend(2u32.to_le_bytes());
    out.extend((total as u32).to_le_bytes());
    out.extend((json.len() as u32).to_le_bytes());
    out.extend(0x4E4F534Au32.to_le_bytes());
    out.extend(json);
    if !bin.is_empty() {
        out.extend((bin.len() as u32).to_le_bytes());
        out.extend(0x004E4942u32.to_le_bytes());
        out.extend(bin);
    }
    out
}

fn node(extra: &str) -> String {
    format!(
        "{{\"mesh\":0{}{extra}}}",
        if extra.is_empty() { "" } else { "," }
    )
}

fn parse(text: &str) -> Scene {
    read(text.as_bytes(), usize::MAX).unwrap()
}

fn with_nodes(nodes: &[String]) -> String {
    let list: Vec<String> = (0..nodes.len()).map(|i| i.to_string()).collect();
    format!(
        "\"nodes\":[{}],\"scenes\":[{{\"nodes\":[{}]}}]",
        nodes.join(","),
        list.join(",")
    )
}

fn bounds_of(s: &Scene) -> [[f64; 3]; 2] {
    extent(s)
}

#[test]
fn a_cube_is_twelve_triangles_enclosing_one_with_indices_of_every_size() {
    for ty in ["u8", "u16", "u32"] {
        let s = parse(&cube_doc(ty, &with_nodes(&[node("")])));
        assert_eq!(s.triangles(), 12, "{ty}");
        assert_near(volume(&s), 1.0, ty);
        assert_near(area(&s), 6.0, ty);
        assert_eq!(bounds_of(&s), [[0.; 3], [1.; 3]]);
        assert_eq!(s.warnings, Default::default());
        assert_sound(&s);
        assert!(s.batches[0].colors.is_none());
    }
}

#[test]
fn a_glb_holds_the_same_cube() {
    for ty in ["u8", "u16", "u32"] {
        let data = cube_data(ty);
        let json = document(
            "",
            data.len(),
            &format!(
                "\"bufferViews\":[{{\"buffer\":0,\"byteLength\":96}},{{\"buffer\":0,\"byteOffset\":96,\"byteLength\":{}}}],\
                 \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"}},{{\"bufferView\":1,\"componentType\":{},\"count\":36,\"type\":\"SCALAR\"}}],\
                 \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}},\"indices\":1}}]}}]",
                data.len() - 96,
                component(ty)
            ),
            &with_nodes(&[node("")]),
        );
        let file = glb(&json, &data);
        let s = read(&file, usize::MAX).unwrap();
        assert_eq!(s.triangles(), 12, "{ty}");
        assert_near(volume(&s), 1.0, ty);
        assert_eq!(bounds_of(&s), [[0.; 3], [1.; 3]]);
    }
}

/// A GLB of the cube whose JSON chunk is 2 bytes over a multiple of 4: its
/// length counts the padding (`counted`) or not, and the padding is in the
/// file (`present`) or not. Only the first is valid; the others are what some
/// writers made.
fn glb_of_cube_with_json_padding(counted: bool, present: bool) -> Vec<u8> {
    let data = cube_data("u16");
    let mut json = document(
        "",
        data.len(),
        &format!(
            "\"bufferViews\":[{{\"buffer\":0,\"byteLength\":96}},{{\"buffer\":0,\"byteOffset\":96,\"byteLength\":{}}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"}},{{\"bufferView\":1,\"componentType\":{},\"count\":36,\"type\":\"SCALAR\"}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}},\"indices\":1}}]}}]",
            data.len() - 96,
            component("u16")
        ),
        &with_nodes(&[node("")]),
    )
    .into_bytes();
    while json.len() % 4 != 2 {
        json.push(b' ');
    }
    let bin = pad(data);
    let padding = if present { 2 } else { 0 };
    let mut out = b"glTF".to_vec();
    out.extend(2u32.to_le_bytes());
    out.extend(((12 + 8 + json.len() + padding + 8 + bin.len()) as u32).to_le_bytes());
    out.extend(((json.len() + if counted { 2 } else { 0 }) as u32).to_le_bytes());
    out.extend(0x4E4F534Au32.to_le_bytes());
    out.extend(json);
    out.extend(vec![b' '; padding]);
    out.extend((bin.len() as u32).to_le_bytes());
    out.extend(0x004E4942u32.to_le_bytes());
    out.extend(bin);
    out
}

#[test]
fn a_glb_whose_json_chunk_is_not_padded_as_it_says_is_read() {
    for (counted, present) in [(true, true), (false, true), (false, false)] {
        let file = glb_of_cube_with_json_padding(counted, present);
        let s = read(&file, usize::MAX).unwrap_or_else(|e| panic!("{counted} {present}: {e:?}"));
        assert_eq!(s.triangles(), 12, "{counted} {present}");
    }
}

#[test]
fn a_mesh_without_indices_is_read_three_vertices_to_a_triangle() {
    let data = floats(&[0., 0., 0., 1., 0., 0., 0., 1., 0., 5., 5., 5.]);
    let json = document(
        &format!("\"uri\":\"data:;base64,{}\"", base64(&data)),
        data.len(),
        "\"bufferViews\":[{\"buffer\":0,\"byteLength\":48}],\
         \"accessors\":[{\"bufferView\":0,\"componentType\":5126,\"count\":4,\"type\":\"VEC3\"}],\
         \"meshes\":[{\"primitives\":[{\"attributes\":{\"POSITION\":0}}]}]",
        "\"nodes\":[{\"mesh\":0}]",
    );
    // No scenes: every node that is nobody's child is drawn.
    let s = parse(&json);
    assert_eq!(s.triangles(), 1);
    assert_eq!(triangles(&s)[0], [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]]);
}

/// The cube's corners as three shorts each, padded to 8 bytes a vertex,
/// scaled by `scale`; then its indices as u16.
fn quantized_cube(scale: f64) -> Vec<u8> {
    let mut data = Vec::new();
    for p in CUBE {
        for v in p {
            data.extend(((v * scale).round() as i16).to_le_bytes());
        }
        data.extend([0, 0]);
    }
    data.extend(pad(encode(&cube_indices(), "u16")));
    data
}

fn quantized_doc(data: &[u8], accessor_extra: &str, rest: &str) -> String {
    document(
        &format!(
            "\"uri\":\"data:application/octet-stream;base64,{}\"",
            base64(data)
        ),
        data.len(),
        &format!(
            "\"bufferViews\":[{{\"buffer\":0,\"byteOffset\":0,\"byteLength\":64,\"byteStride\":8}},{{\"buffer\":0,\"byteOffset\":64,\"byteLength\":{}}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5122,\"count\":8,\"type\":\"VEC3\"{accessor_extra}}},{{\"bufferView\":1,\"componentType\":5123,\"count\":36,\"type\":\"SCALAR\"}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}},\"indices\":1}}]}}],\
             \"extensionsUsed\":[\"KHR_mesh_quantization\"],\"extensionsRequired\":[\"KHR_mesh_quantization\"]",
            data.len() - 64
        ),
        rest,
    )
}

#[test]
fn a_cube_of_shorts_is_the_cube_the_node_scale_restores() {
    // Normalized: -1..1 of the type's range, so 32767 is 1, and the node
    // scales the unit cube up to 4 across.
    let s = parse(&quantized_doc(
        &quantized_cube(32767.0),
        ",\"normalized\":true",
        &with_nodes(&[node("\"scale\":[4,4,4]")]),
    ));
    assert_eq!(s.triangles(), 12);
    let b = bounds_of(&s);
    for k in 0..3 {
        assert!(
            (b[0][k]).abs() < 1e-4 && (b[1][k] - 4.0).abs() < 1e-3,
            "{b:?}"
        );
    }
    // Not normalized: the shorts are the coordinates, scaled by the node.
    let s = parse(&quantized_doc(
        &quantized_cube(1000.0),
        "",
        &with_nodes(&[node("\"scale\":[0.001,0.001,0.001]")]),
    ));
    assert_eq!(s.triangles(), 12);
    assert_near(volume(&s), 1.0, "volume");
    assert_sound(&s);
}

#[test]
fn a_translation_and_a_scale_move_and_grow_the_cube() {
    let s = parse(&cube_doc(
        "u16",
        &with_nodes(&[node("\"translation\":[10,-2,3],\"scale\":[2,3,4]")]),
    ));
    assert_eq!(bounds_of(&s), [[10., -2., 3.], [12., 1., 7.]]);
    assert_near(volume(&s), 24.0, "volume");
    assert_sound(&s);
}

#[test]
fn a_rotation_turns_the_cube_and_a_matrix_says_the_same() {
    let h = std::f64::consts::FRAC_1_SQRT_2;
    // 90 degrees about z, scaled by 2, then moved: x becomes -y.
    let trs = format!("\"translation\":[10,0,0],\"rotation\":[0,0,{h},{h}],\"scale\":[2,2,2]");
    let a = parse(&cube_doc("u8", &with_nodes(&[node(&trs)])));
    let [lo, hi] = bounds_of(&a);
    for (got, want) in lo.iter().chain(&hi).zip([8., 0., 0., 10., 2., 2.]) {
        assert_near(*got, want, "bounds");
    }
    assert_near(volume(&a), 8.0, "volume");
    // Column-major: the x axis goes to (0,2,0), the y axis to (-2,0,0).
    let m = "\"matrix\":[0,2,0,0,-2,0,0,0,0,0,2,0,10,0,0,1]";
    let b = parse(&cube_doc("u8", &with_nodes(&[node(m)])));
    let (ta, tb) = (triangles(&a), triangles(&b));
    assert_eq!(ta.len(), tb.len());
    for (x, y) in ta.iter().zip(&tb) {
        for (p, q) in x.iter().zip(y) {
            for k in 0..3 {
                assert_near(p[k], q[k], "matrix against TRS");
            }
        }
    }
}

#[test]
fn a_rotation_of_all_zeros_is_no_rotation() {
    let s = parse(&cube_doc(
        "u16",
        &with_nodes(&[node("\"rotation\":[0,0,0,0],\"translation\":[10,0,0]")]),
    ));
    assert_eq!(bounds_of(&s), [[10., 0., 0.], [11., 1., 1.]]);
    assert_sound(&s);
}

#[test]
fn child_nodes_compose_with_their_parents() {
    let doc = cube_doc(
        "u16",
        "\"nodes\":[{\"translation\":[0,5,0],\"children\":[1]},{\"scale\":[3,3,3],\"translation\":[1,0,0],\"mesh\":0}],\"scenes\":[{\"nodes\":[0]}]",
    );
    let s = parse(&doc);
    // The child's scale and offset first, the parent's offset after.
    assert_eq!(bounds_of(&s), [[1., 5., 0.], [4., 8., 3.]]);
    assert_near(volume(&s), 27.0, "volume");
}

#[test]
fn a_mirror_keeps_the_cube_outward() {
    let s = parse(&cube_doc("u16", &with_nodes(&[node("\"scale\":[-1,1,1]")])));
    assert_eq!(bounds_of(&s), [[-1., 0., 0.], [0., 1., 1.]]);
    // A mirror turns triangles inside out unless they are turned back.
    assert_near(volume(&s), 1.0, "volume");
    let b = &s.batches[0];
    for (p, n) in b.positions.chunks(3).zip(b.normals.chunks(3)) {
        let out = (f64::from(p[0]) + 0.5) * f64::from(n[0])
            + (f64::from(p[1]) - 0.5) * f64::from(n[1])
            + (f64::from(p[2]) - 0.5) * f64::from(n[2]);
        assert!(out > 0.0);
    }
    // Scaled to nothing: nothing to draw, and nothing wrong.
    let s = parse(&cube_doc("u16", &with_nodes(&[node("\"scale\":[0,1,1]")])));
    assert_eq!(s.triangles(), 0);
}

#[test]
fn each_node_with_a_mesh_is_an_element_and_a_mesh_can_be_used_twice() {
    let nodes = [
        node("\"name\":\"left\""),
        node("\"name\":\"right\",\"translation\":[5,0,0]"),
        node("\"translation\":[0,5,0]"),
    ];
    let s = parse(&cube_doc("u16", &with_nodes(&nodes)));
    assert_eq!(s.triangles(), 36);
    let names: Vec<_> = s.elements.iter().map(|e| e.name.as_str()).collect();
    // The third has no name of its own: the mesh's.
    assert_eq!(names, ["left", "right", "cube"]);
    let b = &s.batches[0];
    for (e, (x, y)) in s.elements.iter().zip([(0.0, 0.0), (5.0, 0.0), (0.0, 5.0)]) {
        assert_eq!(e.ranges.len(), 1);
        assert_eq!(e.ranges[0].count, 36);
        let first = e.ranges[0].first as usize;
        for &i in &b.indices[first..first + 36] {
            let p = &b.positions[i as usize * 3..];
            assert!((x..=x + 1.0).contains(&f64::from(p[0])));
            assert!((y..=y + 1.0).contains(&f64::from(p[1])));
        }
    }
}

#[test]
fn a_material_colours_the_mesh_in_srgb() {
    let with = |material: &str| {
        let d = cube_doc(
            "u16",
            &format!("{},\"materials\":[{material}]", with_nodes(&[node("")])),
        );
        parse(&d.replace("\"indices\":1}", "\"indices\":1,\"material\":0}"))
    };
    let red = with("{\"pbrMetallicRoughness\":{\"baseColorFactor\":[1,0,0,1]}}");
    let c = red.batches[0].colors.as_ref().unwrap();
    assert_eq!(c.len(), 36 * 3);
    assert!(c.chunks(3).all(|v| v == [255, 0, 0]));
    // Linear one half is 188 of 255 in sRGB.
    let grey = with("{\"pbrMetallicRoughness\":{\"baseColorFactor\":[0.5,0.5,0.5,0.1]}}");
    assert!(
        grey.batches[0]
            .colors
            .as_ref()
            .unwrap()
            .chunks(3)
            .all(|v| v == [188, 188, 188])
    );
    // No colour factor, or white: the renderer's colour.
    assert!(with("{}").batches[0].colors.is_none());
    assert!(
        with("{\"pbrMetallicRoughness\":{\"baseColorFactor\":[1,1,1,1]}}").batches[0]
            .colors
            .is_none()
    );
}

#[test]
fn vertex_colours_multiply_the_material() {
    // Triangle, COLOR_0 as float VEC3, VEC4 normalized bytes, material 0.5.
    let positions = floats(&[0., 0., 0., 1., 0., 0., 0., 1., 0.]);
    let float_colors = floats(&[1., 0.5, 0., 1., 0.5, 0., 1., 0.5, 0.]);
    let byte_colors: Vec<u8> = vec![255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255];
    let mut data = positions;
    data.extend(&float_colors);
    data.extend(&byte_colors);
    let doc = |color: usize| {
        format!(
            "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{\"uri\":\"data:;base64,{}\",\"byteLength\":{}}}],\
             \"bufferViews\":[{{\"buffer\":0,\"byteLength\":36}},{{\"buffer\":0,\"byteOffset\":36,\"byteLength\":36}},{{\"buffer\":0,\"byteOffset\":72,\"byteLength\":12}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}},\
             {{\"bufferView\":1,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}},\
             {{\"bufferView\":2,\"componentType\":5121,\"normalized\":true,\"count\":3,\"type\":\"VEC4\"}}],\
             \"materials\":[{{\"pbrMetallicRoughness\":{{\"baseColorFactor\":[0.5,1,1,1]}}}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0,\"COLOR_0\":{color}}},\"material\":0}}]}}],\
             \"nodes\":[{{\"mesh\":0}}]}}",
            base64(&data),
            data.len()
        )
    };
    // (0.5, 0.5, 0) linear: 188, 188, 0.
    let s = parse(&doc(1));
    let c = s.batches[0].colors.as_ref().unwrap();
    assert!(c.chunks(3).all(|v| v == [188, 188, 0]), "{c:?}");
    // Bytes 255, 0, 0 times (0.5, 1, 1): 188, 0, 0.
    let s = parse(&doc(2));
    let c = s.batches[0].colors.as_ref().unwrap();
    assert!(c.chunks(3).all(|v| v == [188, 0, 0]), "{c:?}");
}

#[test]
fn normals_follow_the_inverse_transpose_of_the_transform() {
    // A triangle in the plane whose normal is (0,1,1), stretched in y: the
    // normal must stay the new triangle's normal.
    let h = std::f64::consts::FRAC_1_SQRT_2;
    let rows = [
        [0., 0., 0.],
        [1., 0., 0.],
        [0., 1., -1.],
        [0., h, h],
        [0., h, h],
        [0., h, h],
    ];
    let data = floats(&rows.concat());
    let doc = |transform: &str| {
        format!(
            "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{\"uri\":\"data:;base64,{}\",\"byteLength\":{}}}],\
             \"bufferViews\":[{{\"buffer\":0,\"byteLength\":36}},{{\"buffer\":0,\"byteOffset\":36,\"byteLength\":36}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}},{{\"bufferView\":1,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0,\"NORMAL\":1}}}}]}}],\
             \"nodes\":[{{\"mesh\":0{transform}}}]}}",
            base64(&data),
            data.len()
        )
    };
    for transform in [
        "",
        ",\"scale\":[1,2,1]",
        ",\"scale\":[3,0.5,2]",
        ",\"scale\":[-1,2,1]",
    ] {
        let s = parse(&doc(transform));
        assert_eq!(s.triangles(), 1);
        let t = triangles(&s)[0];
        let n = {
            let (a, b) = (
                [t[1][0] - t[0][0], t[1][1] - t[0][1], t[1][2] - t[0][2]],
                [t[2][0] - t[0][0], t[2][1] - t[0][1], t[2][2] - t[0][2]],
            );
            let c = [
                a[1] * b[2] - a[2] * b[1],
                a[2] * b[0] - a[0] * b[2],
                a[0] * b[1] - a[1] * b[0],
            ];
            let l = (c[0] * c[0] + c[1] * c[1] + c[2] * c[2]).sqrt();
            c.map(|v| v / l)
        };
        for v in s.batches[0].normals.chunks(3) {
            // The file's normal and the triangle's agree on a side: the
            // mirror turned the triangle back, so they agree after it too.
            for k in 0..3 {
                assert!(
                    (f64::from(v[k]) - n[k]).abs() < 1e-5,
                    "{transform}: {v:?} against {n:?}"
                );
            }
        }
    }
}

#[test]
fn sparse_accessors_replace_elements_and_zero_the_rest() {
    // Three vertices that are all zero but for a sparse list of three.
    let mut data = vec![0u8, 1, 2, 0];
    data.extend(floats(&[0., 0., 0., 1., 0., 0., 0., 2., 0.]));
    let doc = |count: usize, bad_index: u8| {
        let mut d = data.clone();
        d[2] = bad_index;
        format!(
            "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{\"uri\":\"data:;base64,{}\",\"byteLength\":{}}}],\
             \"bufferViews\":[{{\"buffer\":0,\"byteLength\":3}},{{\"buffer\":0,\"byteOffset\":4,\"byteLength\":36}}],\
             \"accessors\":[{{\"componentType\":5126,\"count\":{count},\"type\":\"VEC3\",\
             \"sparse\":{{\"count\":3,\"indices\":{{\"bufferView\":0,\"componentType\":5121}},\"values\":{{\"bufferView\":1}}}}}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}}}}]}}],\
             \"nodes\":[{{\"mesh\":0}}]}}",
            base64(&d),
            d.len()
        )
    };
    let s = parse(&doc(3, 2));
    assert_eq!(triangles(&s)[0], [[0., 0., 0.], [1., 0., 0.], [0., 2., 0.]]);
    // The same list over a longer accessor: the extra vertices are the
    // origin, and make a triangle with no area.
    let s = parse(&doc(6, 2));
    assert_eq!(s.triangles(), 1);
    // A sparse index past the end is damage.
    assert!(read(doc(3, 3).as_bytes(), 100).is_err());
    assert!(read(doc(3, 255).as_bytes(), 100).is_err());
}

#[test]
fn interleaved_attributes_are_read_through_the_stride() {
    // Position and normal of each of three vertices, 24 bytes apart.
    let data = floats(&[
        0., 0., 0., 0., 0., 7., //
        1., 0., 0., 0., 0., 7., //
        0., 1., 0., 0., 0., 7.,
    ]);
    let doc = format!(
        "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{\"uri\":\"data:;base64,{}\",\"byteLength\":{}}}],\
         \"bufferViews\":[{{\"buffer\":0,\"byteLength\":72,\"byteStride\":24}}],\
         \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}},{{\"bufferView\":0,\"byteOffset\":12,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}}],\
         \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0,\"NORMAL\":1}}}}]}}],\
         \"nodes\":[{{\"mesh\":0}}]}}",
        base64(&data),
        data.len()
    );
    let s = parse(&doc);
    assert_eq!(triangles(&s)[0], [[0., 0., 0.], [1., 0., 0.], [0., 1., 0.]]);
    assert_eq!(&s.batches[0].normals[..3], &[0., 0., 1.]);
}

#[test]
fn what_is_not_drawn_is_counted() {
    let d = cube_doc("u16", &with_nodes(&[node("")]));
    let lines = d.replace("\"indices\":1}", "\"indices\":1,\"mode\":1}");
    let s = parse(&lines);
    assert_eq!(s.triangles(), 0);
    assert_eq!(s.warnings.unsupported["lines"], 1);
    let strip = d.replace("\"indices\":1}", "\"indices\":1,\"mode\":5}");
    assert_eq!(parse(&strip).warnings.unsupported["triangle strips"], 1);
    let draco = d.replace(
        "\"indices\":1}",
        "\"indices\":1,\"extensions\":{\"KHR_draco_mesh_compression\":{}}}",
    );
    assert_eq!(
        parse(&draco).warnings.unsupported["KHR_draco_mesh_compression"],
        1
    );
    let meshopt = d.replace(
        "\"byteLength\":96}",
        "\"byteLength\":96,\"extensions\":{\"EXT_meshopt_compression\":{}}}",
    );
    let s = parse(&meshopt);
    assert_eq!(s.warnings.unsupported["EXT_meshopt_compression"], 1);
    assert_eq!(s.warnings.invalid, 0);
}

#[test]
fn textures_animations_and_cameras_are_ignored_and_nothing_is_fetched() {
    let rest = format!(
        "{},\"images\":[{{\"uri\":\"http://example.com/a.png\"}},{{\"uri\":\"textures/b.png\"}}],\"textures\":[{{\"source\":0}}],\
         \"animations\":[{{\"channels\":[],\"samplers\":[]}}],\"cameras\":[{{\"type\":\"perspective\"}}],\"extensionsUsed\":[\"KHR_lights_punctual\"]",
        with_nodes(&[node("")])
    );
    let s = parse(&cube_doc("u16", &rest));
    assert_eq!(s.triangles(), 12);
    assert_eq!(s.warnings, Default::default());
}

/// A buffer in a file next to the document is read from the bytes the caller
/// gives for its URI, named as the document writes it.
#[test]
fn a_buffer_in_another_file_is_read_from_what_it_is_given() {
    let d = cube_doc("u16", &with_nodes(&[node("")]));
    let uri_start = d.find("data:application").unwrap();
    let uri_end = uri_start + d[uri_start..].find('"').unwrap();
    let doc = format!("{}cube%20one.bin{}", &d[..uri_start], &d[uri_end..]);
    assert_eq!(
        external_buffers(doc.as_bytes()).unwrap(),
        ["cube%20one.bin"]
    );
    assert_eq!(read(doc.as_bytes(), 100).unwrap_err(), Error::External);
    let bin = cube_data("u16");
    let s = read_with(doc.as_bytes(), 100, &[("cube%20one.bin", &bin)]).unwrap();
    assert_eq!(s.triangles(), 12);
    assert_eq!(bounds_of(&s), [[0.; 3], [1.; 3]]);
    // Another name is not this buffer; one too short is refused.
    assert_eq!(
        read_with(doc.as_bytes(), 100, &[("other.bin", &bin)]).unwrap_err(),
        Error::External
    );
    assert!(matches!(
        read_with(doc.as_bytes(), 100, &[("cube%20one.bin", &bin[..40])]),
        Err(Error::Invalid(_))
    ));
    // A document whose buffers are all inside it names no file.
    assert!(external_buffers(d.as_bytes()).unwrap().is_empty());
    assert_eq!(external_buffers(b"not gltf").unwrap_err(), Error::NotGltf);
}

#[test]
fn buffers_in_other_files_are_refused_not_fetched() {
    let d = cube_doc("u16", &with_nodes(&[node("")]));
    let uri_start = d.find("data:application").unwrap();
    let uri_end = uri_start + d[uri_start..].find('"').unwrap();
    for uri in [
        "cube.bin",
        "../cube.bin",
        "http://example.com/cube.bin",
        "https://example.com/cube.bin",
        "file:///etc/passwd",
        "//host/cube.bin",
        "ftp://x/y",
        "",
    ] {
        let doc = format!("{}{uri}{}", &d[..uri_start], &d[uri_end..]);
        assert_eq!(
            read(doc.as_bytes(), 100).unwrap_err(),
            Error::External,
            "{uri}"
        );
    }
    assert!(Error::External.to_string().contains("external files"));
    // A GLB whose buffer has neither a URI nor a binary chunk.
    let json = d.replace(&d[uri_start - 7..uri_end + 2], "");
    assert_eq!(read(&glb(&json, &[]), 100).unwrap_err(), Error::External);
    // A buffer nothing draws from is no reason to refuse the file.
    let doc = d.replacen(
        "}],\"bufferViews\"",
        "},{\"uri\":\"unused.bin\",\"byteLength\":4}],\"bufferViews\"",
        1,
    );
    assert_ne!(doc, d);
    assert_eq!(read(doc.as_bytes(), 100).unwrap().triangles(), 12);
}

#[test]
fn documents_that_are_not_gltf_are_refused() {
    for bad in [
        &b""[..],
        b"hello",
        b"{",
        b"{}",
        b"[]",
        b"{\"asset\":{}}",
        b"{\"asset\":{\"version\":2}}",
        b"\x89PNG\r\n",
    ] {
        assert_eq!(read(bad, 10).unwrap_err(), Error::NotGltf, "{bad:?}");
    }
    let v1 = b"{\"asset\":{\"version\":\"1.0\"}}";
    assert!(matches!(read(v1, 10).unwrap_err(), Error::Unsupported(_)));
    // A document with nothing in it draws nothing.
    let s = read(b"{\"asset\":{\"version\":\"2.0\"}}", 10).unwrap();
    assert_eq!(s.triangles(), 0);
    // A byte-order mark and trailing zeros are fine.
    let mut d = b"\xEF\xBB\xBF".to_vec();
    d.extend(b"{\"asset\":{\"version\":\"2.0\"}}\0\0");
    assert!(read(&d, 10).is_ok());
}

#[test]
fn a_glb_with_a_broken_container_is_refused() {
    let good = glb(&cube_doc("u16", &with_nodes(&[node("")])), &[]);
    // A chunk longer than the file, a file shorter than it says, a version.
    let mut b = good.clone();
    b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(read(&b, 10).unwrap_err(), Error::Invalid(_)));
    let mut b = good.clone();
    b[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(read(&b, 10).unwrap_err(), Error::Invalid(_)));
    let mut b = good.clone();
    b[4] = 1;
    assert!(matches!(read(&b, 10).unwrap_err(), Error::Unsupported(_)));
    let mut b = good.clone();
    b[8..12].copy_from_slice(&4u32.to_le_bytes());
    assert!(read(&b, 10).is_err());
    assert!(read(&good[..11], 10).is_err());
    assert!(read(b"glTF", 10).is_err());
    // The length is what ends the file: bytes after it are not read.
    let mut b = good;
    b.extend_from_slice(&[0xff; 100]);
    assert_eq!(read(&b, 100).unwrap().triangles(), 12);
}

#[test]
fn the_budget_stops_the_reading() {
    let d = cube_doc(
        "u16",
        &with_nodes(&[node(""), node("\"translation\":[2,0,0]")]),
    );
    let s = read(d.as_bytes(), 15).unwrap();
    assert_eq!(s.triangles(), 15);
    assert_eq!(s.warnings.truncated, 1);
    let s = read(d.as_bytes(), 24).unwrap();
    assert_eq!(s.triangles(), 24);
    assert_eq!(s.warnings.truncated, 0);
}

fn must_fail_quickly(doc: &str, what: &str) {
    let r = within(Duration::from_secs(10), what, || {
        read(doc.as_bytes(), 200_000)
    });
    assert!(r.is_err(), "{what}: {:?}", r.map(|s| s.triangles()));
}

#[test]
fn accessors_that_do_not_fit_their_buffers_are_errors() {
    let d = cube_doc("u16", &with_nodes(&[node("")]));
    let acc0 = "\"bufferView\":0,\"componentType\":5126,\"count\":8";
    let acc1 = "\"bufferView\":1,\"componentType\":5123,\"count\":36";
    let cases = [
        // Counts of billions over a few hundred bytes.
        (
            acc0,
            "\"bufferView\":0,\"componentType\":5126,\"count\":4294967295",
        ),
        (
            acc1,
            "\"bufferView\":1,\"componentType\":5123,\"count\":4294967295",
        ),
        (
            acc0,
            "\"bufferView\":0,\"componentType\":5126,\"count\":9007199254740992",
        ),
        (
            acc1,
            "\"bufferView\":1,\"componentType\":5123,\"count\":1e300",
        ),
        // Offsets past, or wrapping around, the end.
        (
            acc0,
            "\"bufferView\":0,\"byteOffset\":9007199254740992,\"componentType\":5126,\"count\":8",
        ),
        (
            acc0,
            "\"bufferView\":0,\"byteOffset\":18446744073709551615,\"componentType\":5126,\"count\":8",
        ),
        (
            acc1,
            "\"bufferView\":1,\"byteOffset\":-4,\"componentType\":5123,\"count\":36",
        ),
        (
            acc0,
            "\"bufferView\":0,\"byteOffset\":1,\"componentType\":5126,\"count\":8",
        ),
        // A view that is not there, or wrong.
        (acc0, "\"bufferView\":99,\"componentType\":5126,\"count\":8"),
        (acc0, "\"bufferView\":-1,\"componentType\":5126,\"count\":8"),
        (
            acc0,
            "\"bufferView\":0.5,\"componentType\":5126,\"count\":8",
        ),
        // Types that are not positions (a 16-bit one is a quantized position).
        (acc0, "\"bufferView\":0,\"componentType\":9999,\"count\":8"),
        (
            acc0,
            "\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"MAT4\"",
        ),
        // No view and a count of a billion: zeros are not made.
        (acc0, "\"componentType\":5126,\"count\":1000000000"),
    ];
    for (from, to) in cases {
        let doc = d.replacen(from, to, 1);
        assert_ne!(doc, d);
        must_fail_quickly(&doc, to);
    }
    // The same on views and buffers.
    let views = [
        (
            "\"byteOffset\":96,\"byteLength\":72",
            "\"byteOffset\":96,\"byteLength\":4294967296",
        ),
        (
            "\"byteOffset\":96,\"byteLength\":72",
            "\"byteOffset\":9007199254740992,\"byteLength\":9007199254740992",
        ),
        (
            "\"byteLength\":96}",
            "\"byteLength\":96,\"byteStride\":9007199254740992}",
        ),
        ("\"byteLength\":96}", "\"byteLength\":96,\"byteStride\":4}"),
        (
            "\"byteLength\":96}",
            "\"byteLength\":96,\"byteStride\":\"x\"}",
        ),
        (
            "\"buffer\":0,\"byteOffset\":0",
            "\"buffer\":7,\"byteOffset\":0",
        ),
    ];
    for (from, to) in views {
        let doc = d.replacen(from, to, 1);
        assert_ne!(doc, d, "{from}");
        must_fail_quickly(&doc, to);
    }
    // A stride and a count whose product wraps a 64-bit number.
    let doc = d
        .replacen(
            "\"byteLength\":96}",
            "\"byteLength\":96,\"byteStride\":9007199254740992}",
            1,
        )
        .replacen(
            acc0,
            "\"bufferView\":0,\"componentType\":5126,\"count\":9007199254740992",
            1,
        );
    must_fail_quickly(&doc, "wrapping product");
    // 100 MB declared, a few bytes held.
    let held = cube_data("u16").len();
    let doc = d.replacen(
        &format!("\"byteLength\":{held}}}"),
        "\"byteLength\":100000000}",
        1,
    );
    assert_ne!(doc, d);
    must_fail_quickly(&doc, "a declared buffer of 100 MB");
}

#[test]
fn sparse_accessors_with_hostile_numbers_are_errors() {
    let base = |sparse: &str| {
        format!(
            "{{\"asset\":{{\"version\":\"2.0\"}},\"buffers\":[{{\"uri\":\"data:;base64,{}\",\"byteLength\":48}}],\
             \"bufferViews\":[{{\"buffer\":0,\"byteLength\":12}},{{\"buffer\":0,\"byteOffset\":12,\"byteLength\":36}}],\
             \"accessors\":[{{\"componentType\":5126,\"count\":3,\"type\":\"VEC3\",\"sparse\":{sparse}}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}}}}]}}],\"nodes\":[{{\"mesh\":0}}]}}",
            base64(&[0u8; 48])
        )
    };
    for sparse in [
        "{\"count\":4294967295,\"indices\":{\"bufferView\":0,\"componentType\":5125},\"values\":{\"bufferView\":1}}",
        "{\"count\":4,\"indices\":{\"bufferView\":0,\"componentType\":5125},\"values\":{\"bufferView\":1}}",
        "{\"count\":2,\"indices\":{\"bufferView\":0,\"byteOffset\":9007199254740992,\"componentType\":5125},\"values\":{\"bufferView\":1}}",
        "{\"count\":2,\"indices\":{\"bufferView\":0,\"componentType\":5126},\"values\":{\"bufferView\":1}}",
        "{\"count\":2,\"indices\":{\"bufferView\":9,\"componentType\":5125},\"values\":{\"bufferView\":1}}",
        "{\"count\":2,\"indices\":{\"bufferView\":0,\"componentType\":5125},\"values\":{\"bufferView\":1,\"byteOffset\":30}}",
        "{\"count\":-1,\"indices\":{\"bufferView\":0,\"componentType\":5125},\"values\":{\"bufferView\":1}}",
        "{\"count\":1}",
        "7",
    ] {
        must_fail_quickly(&base(sparse), sparse);
    }
}

#[test]
fn nodes_that_loop_or_share_a_child_are_refused() {
    let cyc = |nodes: &str| format!("{{\"asset\":{{\"version\":\"2.0\"}},{nodes}}}");
    for nodes in [
        "\"nodes\":[{\"children\":[1]},{\"children\":[0]}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{\"children\":[0]}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{\"children\":[1,1]},{}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{\"children\":[2]},{\"children\":[2]},{}],\"scenes\":[{\"nodes\":[0,1]}]",
        "\"nodes\":[{},{}],\"scenes\":[{\"nodes\":[0,0]}]",
        "\"nodes\":[{\"children\":[1]},{\"children\":[2]},{\"children\":[0]}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{\"children\":[7]}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{\"children\":[-1]}],\"scenes\":[{\"nodes\":[0]}]",
        "\"nodes\":[{}],\"scenes\":[{\"nodes\":[3]}]",
        "\"nodes\":[{}],\"scenes\":[{\"nodes\":[0]}],\"scene\":5",
    ] {
        let r = read(cyc(nodes).as_bytes(), 10);
        assert!(
            matches!(r, Err(Error::Invalid(_))),
            "{nodes}: {:?}",
            r.map(|s| s.triangles())
        );
    }
    // A diamond that doubles at every level would be 2^60 visits.
    let mut nodes = String::from("\"nodes\":[");
    for k in 0..60 {
        write!(nodes, "{{\"children\":[{},{}]}},", k + 1, k + 1).unwrap();
    }
    nodes.push_str("{}],\"scenes\":[{\"nodes\":[0]}]");
    let r = within(Duration::from_secs(5), "the diamonds", || {
        read(cyc(&nodes).as_bytes(), 10)
    });
    assert!(r.is_err());
}

fn chain(depth: usize) -> String {
    let mut nodes = String::new();
    for k in 0..depth {
        if k > 0 {
            nodes.push(',');
        }
        if k + 1 < depth {
            write!(nodes, "{{\"children\":[{}]}}", k + 1).unwrap();
        } else {
            nodes.push_str("{\"mesh\":0}");
        }
    }
    cube_doc(
        "u16",
        &format!("\"nodes\":[{nodes}],\"scenes\":[{{\"nodes\":[0]}}]"),
    )
}

#[test]
fn a_tree_nested_too_deep_is_refused_and_one_at_the_limit_is_drawn() {
    let s = read(chain(MAX_DEPTH).as_bytes(), 100).unwrap();
    assert_eq!(s.triangles(), 12);
    let r = read(chain(MAX_DEPTH + 1).as_bytes(), 100);
    assert!(matches!(r, Err(Error::Invalid(_))));
    let r = within(Duration::from_secs(10), "a chain of 200,000 nodes", || {
        read(chain(200_000).as_bytes(), 100)
    });
    assert!(matches!(r, Err(Error::Invalid(_))));
}

#[test]
fn json_nested_or_sized_without_limit_is_refused() {
    let deep = format!(
        "{{\"asset\":{{\"version\":\"2.0\"}},\"extras\":{}",
        "[".repeat(200_000)
    );
    assert_eq!(read(deep.as_bytes(), 10).unwrap_err(), Error::NotGltf);
    let deep = format!(
        "{{\"asset\":{{\"version\":\"2.0\"}},\"extras\":{}{}}}",
        "{\"a\":".repeat(100_000),
        "1}".repeat(100_000)
    );
    assert_eq!(read(deep.as_bytes(), 10).unwrap_err(), Error::NotGltf);
    let wide = format!(
        "{{\"asset\":{{\"version\":\"2.0\"}},\"extras\":[{}1]}}",
        "1,".repeat(3_000_000)
    );
    let r = within(Duration::from_secs(20), "three million values", || {
        read(wide.as_bytes(), 10)
    });
    assert_eq!(r.unwrap_err(), Error::NotGltf);
}

#[test]
fn instancing_a_mesh_of_nothing_many_times_costs_a_bounded_amount() {
    // A million zero-area triangles (three equal indices), used by 20,000
    // nodes: twenty billion triangles looked at, if nothing stopped it.
    let n = 1_000_000usize;
    let data = {
        let mut d = floats(&[0., 0., 0., 1., 0., 0., 0., 1., 0.]);
        d.extend(vec![0u8; n]);
        d
    };
    let nodes: Vec<String> = (0..20_000).map(|_| node("")).collect();
    let doc = document(
        &format!("\"uri\":\"data:;base64,{}\"", base64(&data)),
        data.len(),
        &format!(
            "\"bufferViews\":[{{\"buffer\":0,\"byteLength\":36}},{{\"buffer\":0,\"byteOffset\":36,\"byteLength\":{n}}}],\
             \"accessors\":[{{\"bufferView\":0,\"componentType\":5126,\"count\":3,\"type\":\"VEC3\"}},{{\"bufferView\":1,\"componentType\":5121,\"count\":{},\"type\":\"SCALAR\"}}],\
             \"meshes\":[{{\"primitives\":[{{\"attributes\":{{\"POSITION\":0}},\"indices\":1}}]}}]",
            n / 3 * 3
        ),
        &with_nodes(&nodes),
    );
    let s = within(Duration::from_secs(20), "the instances", || {
        read(doc.as_bytes(), 200_000).unwrap()
    });
    assert_eq!(s.triangles(), 0);
    assert_eq!(s.warnings.truncated, 1);
}

#[test]
fn triangles_with_indices_past_the_vertices_are_dropped() {
    let mut idx = cube_indices();
    idx[0] = 8;
    idx[10] = 4_000_000;
    let mut data = floats(&CUBE.iter().flatten().copied().collect::<Vec<_>>());
    data.extend(pad(idx.iter().flat_map(|i| i.to_le_bytes()).collect()));
    let doc = document(
        &format!("\"uri\":\"data:;base64,{}\"", base64(&data)),
        data.len(),
        "\"bufferViews\":[{\"buffer\":0,\"byteLength\":96},{\"buffer\":0,\"byteOffset\":96,\"byteLength\":144}],\
         \"accessors\":[{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"},{\"bufferView\":1,\"componentType\":5125,\"count\":36,\"type\":\"SCALAR\"}],\
         \"meshes\":[{\"primitives\":[{\"attributes\":{\"POSITION\":0},\"indices\":1}]}]",
        &with_nodes(&[node("")]),
    );
    let s = parse(&doc);
    assert_eq!(s.triangles(), 10);
    assert_eq!(s.warnings.invalid, 2);
    assert_sound(&s);
}

#[test]
fn coordinates_that_are_not_numbers_or_not_sizes_drop_their_triangles() {
    for bad in [f64::NAN, f64::INFINITY, 1e30, -1e13] {
        let mut points: Vec<f64> = CUBE.iter().flatten().copied().collect();
        points[18] = bad;
        let mut data = floats(&points);
        data.extend(pad(encode(&cube_indices(), "u16")));
        let doc = document(
            &format!("\"uri\":\"data:;base64,{}\"", base64(&data)),
            data.len(),
            "\"bufferViews\":[{\"buffer\":0,\"byteLength\":96},{\"buffer\":0,\"byteOffset\":96,\"byteLength\":72}],\
             \"accessors\":[{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"},{\"bufferView\":1,\"componentType\":5123,\"count\":36,\"type\":\"SCALAR\"}],\
             \"meshes\":[{\"primitives\":[{\"attributes\":{\"POSITION\":0},\"indices\":1}]}]",
            &with_nodes(&[node("")]),
        );
        let s = parse(&doc);
        // Corner 6 is in five of the twelve triangles.
        assert_eq!(s.triangles(), 7, "{bad}");
        assert_eq!(s.warnings.invalid, 5, "{bad}");
        assert_sound(&s);
    }
    // A transform that sends the cube beyond what a camera can frame.
    let r = read(
        cube_doc("u16", &with_nodes(&[node("\"scale\":[1e300,1e300,1e300]")])).as_bytes(),
        100,
    );
    assert!(matches!(r, Err(Error::Invalid(_))));
}

#[test]
fn transforms_that_are_not_valid_are_errors() {
    for transform in [
        "\"rotation\":[0,0,0]",
        "\"scale\":[1,1]",
        "\"translation\":\"x\"",
        "\"matrix\":[1,2,3]",
        "\"matrix\":[1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,\"1\"]",
    ] {
        let r = read(
            cube_doc("u16", &with_nodes(&[node(transform)])).as_bytes(),
            100,
        );
        assert!(matches!(r, Err(Error::Invalid(_))), "{transform}");
    }
}

#[test]
fn a_file_cut_anywhere_or_changed_anywhere_is_read_soundly() {
    let doc = cube_doc("u16", &with_nodes(&[node("\"scale\":[2,2,2]")]));
    sweep(doc.as_bytes(), |b| read(b, 1000).ok());
    let data = cube_data("u16");
    let json = document(
        "",
        data.len(),
        "\"bufferViews\":[{\"buffer\":0,\"byteLength\":96},{\"buffer\":0,\"byteOffset\":96,\"byteLength\":72}],\
         \"accessors\":[{\"bufferView\":0,\"componentType\":5126,\"count\":8,\"type\":\"VEC3\"},{\"bufferView\":1,\"componentType\":5123,\"count\":36,\"type\":\"SCALAR\"}],\
         \"meshes\":[{\"primitives\":[{\"attributes\":{\"POSITION\":0},\"indices\":1}]}]",
        &with_nodes(&[node("")]),
    );
    sweep(&glb(&json, &data), |b| read(b, 1000).ok());
}
