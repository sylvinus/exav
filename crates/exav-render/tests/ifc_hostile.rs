//! IFC files written to make the reader work too hard or loop: curved faces
//! with degenerate radii and broken knot vectors, boundaries that are huge
//! or off their surface, placements that refer to each other, and sweeps
//! with absurd parameters. The reader must finish quickly, stay inside its
//! triangle budget, and say what it did not draw.

use std::time::{Duration, Instant};

use exav_render::ifc::{read, Limits};
use exav_render::mesh::Scene;

/// Instances numbered from #100 under a context, a placement (#5) and a
/// point (#1), a direction (#2, #3) and an axis (#4).
struct File {
    schema: &'static str,
    lines: Vec<String>,
}

impl File {
    fn new() -> Self {
        File {
            schema: "IFC4X3_ADD2",
            lines: Vec::new(),
        }
    }

    /// The number the next instance will have.
    fn next(&self) -> String {
        format!("#{}", 100 + self.lines.len())
    }

    /// Adds an instance, and says its number.
    fn add(&mut self, text: impl AsRef<str>) -> String {
        let n = self.next();
        self.lines.push(text.as_ref().to_string());
        n
    }

    /// A product whose body is the items `items`, placed at `placement`.
    fn product(&mut self, items: &str, placement: &str) {
        let rep = self.add(format!(
            "IFCSHAPEREPRESENTATION(#6,'Body','Brep',({items}))"
        ));
        let shape = self.add(format!("IFCPRODUCTDEFINITIONSHAPE($,$,({rep}))"));
        self.add(format!(
            "IFCBUILDINGELEMENTPROXY('0000000000000000000001',$,'x',$,$,{placement},{shape},$,$)"
        ));
    }

    fn bytes(&self) -> Vec<u8> {
        let mut s = format!(
            "ISO-10303-21;\nHEADER;\nFILE_SCHEMA(('{}'));\nENDSEC;\nDATA;\n\
             #1=IFCCARTESIANPOINT((0.,0.,0.));\n#2=IFCDIRECTION((0.,0.,1.));\n#3=IFCDIRECTION((1.,0.,0.));\n\
             #4=IFCAXIS2PLACEMENT3D(#1,#2,#3);\n#5=IFCLOCALPLACEMENT($,#4);\n\
             #6=IFCGEOMETRICREPRESENTATIONCONTEXT($,'Model',3,1.E-05,#4,$);\n",
            self.schema
        );
        for (i, l) in self.lines.iter().enumerate() {
            s.push_str(&format!("#{}={};\n", 100 + i, l));
        }
        s.push_str("ENDSEC;\nEND-ISO-10303-21;\n");
        s.into_bytes()
    }

    /// Reads it, which must take no longer than a moment and stay inside
    /// the budget.
    fn read(&self, what: &str) -> Scene {
        let bytes = self.bytes();
        let started = Instant::now();
        let scene = read(
            &bytes,
            &Limits {
                max_triangles: 200_000,
            },
        )
        .unwrap();
        let took = started.elapsed();
        assert!(took < Duration::from_secs(20), "{what}: {took:?}");
        assert!(scene.triangles() <= 200_000, "{what}");
        scene
    }
}

/// A face on `surface` bounded by one circle (an edge loop), a shell-based
/// surface model of it, as a product.
fn circle_face(f: &mut File, surface: &str) {
    let circle = f.add("IFCCIRCLE(#4,1.)");
    let at = f.add("IFCCARTESIANPOINT((1.,0.,0.))");
    let v = f.add(format!("IFCVERTEXPOINT({at})"));
    let e = f.add(format!("IFCEDGECURVE({v},{v},{circle},.T.)"));
    let oe = f.add(format!("IFCORIENTEDEDGE(*,*,{e},.T.)"));
    let lp = f.add(format!("IFCEDGELOOP(({oe}))"));
    let b = f.add(format!("IFCFACEOUTERBOUND({lp},.T.)"));
    let face = f.add(format!("IFCADVANCEDFACE(({b}),{surface},.T.)"));
    let shell = f.add(format!("IFCOPENSHELL(({face}))"));
    let model = f.add(format!("IFCSHELLBASEDSURFACEMODEL(({shell}))"));
    f.product(&model, "#5");
}

#[test]
fn spheres_of_no_radius_are_counted() {
    for radius in ["0.", "-3."] {
        let mut f = File::new();
        let sphere = f.add(format!("IFCSPHERICALSURFACE(#4,{radius})"));
        circle_face(&mut f, &sphere);
        let s = f.read(radius);
        assert_eq!(
            s.warnings.unsupported.get("IFCSPHERICALSURFACE"),
            Some(&1),
            "{radius}: {:?}",
            s.warnings
        );
    }
}

#[test]
fn spheres_and_tori_of_absurd_radii_stay_inside_their_bounds() {
    for radius in ["1.E-300", "1.E300", "1.E-12", "1.E12", "1.E999"] {
        let mut f = File::new();
        let sphere = f.add(format!("IFCSPHERICALSURFACE(#4,{radius})"));
        circle_face(&mut f, &sphere);
        f.read(radius);
        let mut f = File::new();
        let torus = f.add(format!("IFCTOROIDALSURFACE(#4,{radius},{radius})"));
        circle_face(&mut f, &torus);
        f.read(radius);
        let mut f = File::new();
        let cylinder = f.add(format!("IFCCYLINDRICALSURFACE(#4,{radius})"));
        circle_face(&mut f, &cylinder);
        f.read(radius);
    }
}

#[test]
fn a_torus_whose_minor_radius_is_not_smaller_is_counted() {
    let mut f = File::new();
    let torus = f.add("IFCTOROIDALSURFACE(#4,1.,2.)");
    circle_face(&mut f, &torus);
    let s = f.read("torus");
    assert_eq!(s.warnings.unsupported.get("IFCTOROIDALSURFACE"), Some(&1));
}

/// A B-spline surface over a 2 x 2 net with `mults` and `values` for both
/// knot vectors, as a face bounded by a triangle `height` above the net.
fn spline_face(mults: &str, values: &str, degree: usize, height: f64) -> File {
    let mut f = File::new();
    let net: Vec<String> = (0..4)
        .map(|i| f.add(format!("IFCCARTESIANPOINT(({}.,{}.,0.))", i / 2, i % 2)))
        .collect();
    let surface = f.add(format!(
        "IFCBSPLINESURFACEWITHKNOTS({degree},{degree},(({},{}),({},{})),.UNSPECIFIED.,.F.,.F.,.F.,({mults}),({mults}),({values}),({values}),.UNSPECIFIED.)",
        net[0], net[1], net[2], net[3]
    ));
    let tri: Vec<String> = [(0.2, 0.2), (0.8, 0.2), (0.5, 0.8)]
        .iter()
        .map(|(x, y)| f.add(format!("IFCCARTESIANPOINT(({x},{y},{height}))")))
        .collect();
    let lp = f.add(format!("IFCPOLYLOOP(({}))", tri.join(",")));
    let b = f.add(format!("IFCFACEOUTERBOUND({lp},.T.)"));
    let face = f.add(format!("IFCADVANCEDFACE(({b}),{surface},.T.)"));
    let shell = f.add(format!("IFCOPENSHELL(({face}))"));
    let model = f.add(format!("IFCSHELLBASEDSURFACEMODEL(({shell}))"));
    f.product(&model, "#5");
    f
}

#[test]
fn spline_surfaces_with_huge_or_broken_knot_vectors_are_refused_without_allocating() {
    for (mults, values, degree) in [
        ("1000000000", "0.", 1),
        ("2,2", "1.,0.", 1),
        ("2,2,2,2,2,2,2,2", "0.,1.", 1),
        ("4611686018427387904,4611686018427387904", "0.,1.", 1),
        ("17,17", "0.,1.", 16),
        ("3,3", "0.,1.", 2),
        ("2,2", "0.,0.", 1),
    ] {
        let s = spline_face(mults, values, degree, 0.0).read(mults);
        // The surface is unusable: the face is the triangle through its
        // points, counted as what it is.
        assert_eq!(
            s.warnings.unsupported.get("IFCBSPLINESURFACEWITHKNOTS"),
            Some(&1),
            "{mults} {values}: {:?}",
            s.warnings
        );
    }
}

#[test]
fn a_spline_face_whose_bounds_are_on_another_surface_is_drawn_whole_and_counted() {
    let s = spline_face("2,2", "0.,1.", 1, 5.0).read("off the surface");
    assert_eq!(
        s.warnings.unsupported.get("IFCBSPLINESURFACEWITHKNOTS"),
        Some(&1)
    );
    // The whole net: a square of 1 x 1.
    assert!(s.triangles() >= 2);
    let b = s.bounds.unwrap();
    assert!((b[1][0] - b[0][0] - 1.0).abs() < 1e-5);
}

#[test]
fn a_spline_face_whose_bounds_are_on_it_is_cut() {
    let s = spline_face("2,2", "0.,1.", 1, 0.0).read("on the surface");
    assert!(s.warnings.unsupported.is_empty(), "{:?}", s.warnings);
    // The triangle (0.2, 0.2), (0.8, 0.2), (0.5, 0.8) of the unit square.
    let b = s.bounds.unwrap();
    assert!((b[1][0] - b[0][0] - 0.6).abs() < 1e-5 && (b[1][1] - b[0][1] - 0.6).abs() < 1e-5);
}

#[test]
fn a_loop_that_lists_one_edge_a_great_many_times_is_given_up() {
    let mut f = spline_face("2,2", "0.,1.", 1, 0.0);
    f.lines.truncate(5);
    let surface = "#104";
    let p1 = f.add("IFCCARTESIANPOINT((0.5,0.5,0.))");
    let p2 = f.add("IFCCARTESIANPOINT((0.6,0.5,0.))");
    let line = f.add(format!("IFCPOLYLINE(({p1},{p2}))"));
    let v1 = f.add(format!("IFCVERTEXPOINT({p1})"));
    let v2 = f.add(format!("IFCVERTEXPOINT({p2})"));
    let e = f.add(format!("IFCEDGECURVE({v1},{v2},{line},.T.)"));
    let oe = f.add(format!("IFCORIENTEDEDGE(*,*,{e},.T.)"));
    let lp = f.add(format!("IFCEDGELOOP(({}))", vec![oe; 400_000].join(",")));
    let b = f.add(format!("IFCFACEOUTERBOUND({lp},.T.)"));
    let face = f.add(format!("IFCADVANCEDFACE(({b}),{surface},.T.)"));
    let shell = f.add(format!("IFCOPENSHELL(({face}))"));
    let model = f.add(format!("IFCSHELLBASEDSURFACEMODEL(({shell}))"));
    f.product(&model, "#5");
    let s = f.read("long loop");
    // The loop was not read, and said so; the points it cost are what is
    // left of the budget for the rest of the file.
    assert!(
        s.warnings.unsupported.get("IFCBSPLINESURFACEWITHKNOTS") >= Some(&1),
        "{:?}",
        s.warnings
    );
    // The points were charged until the evaluation budget of a file this
    // small was gone, and the face that followed was left out, counted.
    assert!(s.warnings.invalid >= 1, "{:?}", s.warnings);
}

/// A grid with one axis each way, and a placement `at` (a number ahead of
/// the instance that needs it).
fn grid(f: &mut File, placement: &str) -> String {
    let a = f.add("IFCCARTESIANPOINT((0.,0.))");
    let b = f.add("IFCCARTESIANPOINT((5.,0.))");
    let c = f.add("IFCCARTESIANPOINT((2.,-1.))");
    let d = f.add("IFCCARTESIANPOINT((2.,1.))");
    let u = f.add(format!("IFCPOLYLINE(({a},{b}))"));
    let v = f.add(format!("IFCPOLYLINE(({c},{d}))"));
    let ua = f.add(format!("IFCGRIDAXIS('a',{u},.T.)"));
    let va = f.add(format!("IFCGRIDAXIS('b',{v},.T.)"));
    f.add(format!(
        "IFCGRID('0000000000000000000002',$,'g',$,$,{placement},$,({ua}),({va}),$,$)"
    ));
    f.add(format!(
        "IFCVIRTUALGRIDINTERSECTION(({ua},{va}),(0.,0.,0.))"
    ))
}

fn block_product(f: &mut File, placement: &str) {
    let block = f.add("IFCBLOCK(#4,1.,1.,1.)");
    let solid = f.add(format!("IFCCSGSOLID({block})"));
    f.product(&solid, placement);
}

#[test]
fn a_grid_placed_by_a_placement_of_its_own_grid_does_not_loop() {
    for schema in ["IFC4X3_ADD2", "IFC4"] {
        let mut f = File::new();
        f.schema = schema;
        // The grid is placed by the grid placement that sits on it: its
        // number is the next but one.
        let own = format!("#{}", 100 + 9 + 1);
        let at = grid(&mut f, &own);
        let placement = if schema == "IFC4X3_ADD2" {
            f.add(format!("IFCGRIDPLACEMENT({own},{at},$)"))
        } else {
            f.add(format!("IFCGRIDPLACEMENT({at},$)"))
        };
        assert_eq!(placement, own);
        block_product(&mut f, &placement);
        let s = f.read(schema);
        assert!(s.elements.is_empty(), "{schema}");
        assert!(s.warnings.invalid >= 1, "{schema}: {:?}", s.warnings);
    }
}

#[test]
fn linear_placements_relative_to_each_other_do_not_loop() {
    let mut f = File::new();
    let rel = f.add("IFCAXIS2PLACEMENTLINEAR($,$,$)");
    f.add(format!("IFCLINEARPLACEMENT(#102,{rel},$)"));
    f.add(format!("IFCLINEARPLACEMENT(#101,{rel},$)"));
    block_product(&mut f, "#101");
    let s = f.read("linear loop");
    assert!(s.elements.is_empty());
    assert!(s.warnings.invalid >= 1);
    assert!(s.warnings.unsupported.contains_key("IFCLINEARPLACEMENT"));
}

#[test]
fn a_grid_placement_whose_axes_do_not_cross_is_counted() {
    // Two parallel axes.
    let mut f = File::new();
    let a = f.add("IFCCARTESIANPOINT((0.,0.))");
    let b = f.add("IFCCARTESIANPOINT((5.,0.))");
    let c = f.add("IFCCARTESIANPOINT((0.,1.))");
    let d = f.add("IFCCARTESIANPOINT((5.,1.))");
    let u = f.add(format!("IFCPOLYLINE(({a},{b}))"));
    let v = f.add(format!("IFCPOLYLINE(({c},{d}))"));
    let ua = f.add(format!("IFCGRIDAXIS('a',{u},.T.)"));
    let va = f.add(format!("IFCGRIDAXIS('b',{v},.T.)"));
    f.add(format!(
        "IFCGRID('0000000000000000000002',$,'g',$,$,#5,$,({ua}),({va}),$,$)"
    ));
    let at = f.add(format!(
        "IFCVIRTUALGRIDINTERSECTION(({ua},{va}),(0.,0.,0.))"
    ));
    let p = f.add(format!("IFCGRIDPLACEMENT($,{at},$)"));
    block_product(&mut f, &p);
    let s = f.read("parallel");
    assert!(s.warnings.unsupported.contains_key("IFCGRIDPLACEMENT"));
}

#[test]
fn polylines_of_a_great_many_segments_cross_within_the_budget() {
    // Two axes of 3000 segments each: nine million pairs, past the bound
    // that is tried; the placement is counted, not worked out, though they
    // do cross, at the very last pair.
    let mut f = File::new();
    let n = 3000;
    let ids: Vec<String> = (0..=n)
        .map(|i| f.add(format!("IFCCARTESIANPOINT(({i}.,0.))")))
        .collect();
    let u = f.add(format!("IFCPOLYLINE(({}))", ids.join(",")));
    let mut ids: Vec<String> = (0..n)
        .map(|i| f.add(format!("IFCCARTESIANPOINT(({i}.,5.))")))
        .collect();
    ids.push(f.add(format!("IFCCARTESIANPOINT(({n}.,-5.))")));
    let v = f.add(format!("IFCPOLYLINE(({}))", ids.join(",")));
    let ua = f.add(format!("IFCGRIDAXIS('a',{u},.T.)"));
    let va = f.add(format!("IFCGRIDAXIS('b',{v},.T.)"));
    f.add(format!(
        "IFCGRID('0000000000000000000002',$,'g',$,$,#5,$,({ua}),({va}),$,$)"
    ));
    let at = f.add(format!(
        "IFCVIRTUALGRIDINTERSECTION(({ua},{va}),(0.,0.,0.))"
    ));
    let p = f.add(format!("IFCGRIDPLACEMENT($,{at},$)"));
    block_product(&mut f, &p);
    let s = f.read("many pairs");
    assert!(
        s.warnings.unsupported.contains_key("IFCGRIDPLACEMENT"),
        "{:?}",
        s.warnings
    );
}

#[test]
fn huge_sweep_ranges_do_not_run_away() {
    for (start, end) in [
        ("-1.E300", "1.E300"),
        ("0.", "1.E999"),
        ("1.E-300", "1.E-299"),
        ("5.", "5."),
        ("4611686018427387904.", "-4611686018427387904."),
    ] {
        let mut f = File::new();
        let a = f.add("IFCCARTESIANPOINT((0.,0.,0.))");
        let b = f.add("IFCCARTESIANPOINT((2.,0.,0.))");
        let c = f.add("IFCCARTESIANPOINT((2.,2.,0.))");
        let line = f.add(format!("IFCPOLYLINE(({a},{b},{c}))"));
        let d1 = f.add(format!("IFCSWEPTDISKSOLID({line},0.1,$,{start},{end})"));
        let circle = f.add("IFCCIRCLE(#4,2.)");
        let d2 = f.add(format!("IFCSWEPTDISKSOLID({circle},0.1,$,{start},{end})"));
        f.product(&format!("{d1},{d2}"), "#5");
        f.read(&format!("{start} {end}"));
    }
}

#[test]
fn a_sweep_with_a_parameter_that_is_no_number_is_counted_invalid() {
    let mut f = File::new();
    let a = f.add("IFCCARTESIANPOINT((0.,0.,0.))");
    let b = f.add("IFCCARTESIANPOINT((2.,0.,0.))");
    let line = f.add(format!("IFCPOLYLINE(({a},{b}))"));
    let d = f.add(format!("IFCSWEPTDISKSOLID({line},0.1,$,'text',1.)"));
    f.product(&d, "#5");
    let s = f.read("text parameter");
    assert!(s.elements.is_empty());
    assert!(s.warnings.invalid >= 1);
}

#[test]
fn a_sweep_along_a_curve_whose_parameters_are_unknown_is_whole_and_counted() {
    // A composite curve of an indexed poly curve with an arc has no
    // published parameter: the sweep takes it whole and says so.
    let mut f = File::new();
    let list = f.add("IFCCARTESIANPOINTLIST3D(((0.,0.,0.),(1.,1.,0.),(2.,0.,0.)))");
    let curve = f.add(format!(
        "IFCINDEXEDPOLYCURVE({list},(IFCARCINDEX((1,2,3))),$)"
    ));
    let d = f.add(format!("IFCSWEPTDISKSOLID({curve},0.1,$,0.,1.)"));
    f.product(&d, "#5");
    let s = f.read("arc");
    assert_eq!(
        s.warnings.unsupported.get("IFCINDEXEDPOLYCURVE"),
        Some(&1),
        "{:?}",
        s.warnings
    );
    assert_eq!(s.elements.len(), 1);
}

#[test]
fn curve_segments_of_absurd_length_and_start_stay_bounded() {
    for (start, length) in [
        ("0.", "1.E300"),
        ("1.E300", "10."),
        ("0.", "-1.E300"),
        ("1.E15", "1.E15"),
        ("0.", "0."),
    ] {
        for parent in [
            "IFCCLOTHOID(#7,100.)",
            "IFCCIRCLE(#7,50.)",
            "IFCCLOTHOID(#7,1.E-300)",
            "IFCCIRCLE(#7,1.E-300)",
            "IFCLINE(#1,#8)",
        ] {
            let mut f = File::new();
            // #100..: a placement, a vector, then the parent; the numbers
            // #7 and #8 are the placement and the vector.
            f.lines.clear();
            let place = f.add("IFCAXIS2PLACEMENT2D(#1,$)");
            let dir = f.add("IFCDIRECTION((1.,0.))");
            let vector = f.add(format!("IFCVECTOR({dir},1.)"));
            let parent = parent.replace("#7", &place).replace("#8", &vector);
            let parent = f.add(parent);
            let segment = f.add(format!(
                "IFCCURVESEGMENT(.CONTINUOUS.,{place},IFCLENGTHMEASURE({start}),IFCLENGTHMEASURE({length}),{parent})"
            ));
            let composite = f.add(format!(
                "IFCCOMPOSITECURVE(({segment},{segment},{segment},{segment}),.F.)"
            ));
            let d = f.add(format!("IFCSWEPTDISKSOLID({composite},0.1,$,$,$)"));
            f.product(&d, "#5");
            f.read(&format!("{parent} {start} {length}"));
        }
    }
}

#[test]
fn a_composite_curve_of_a_great_many_segments_is_refused() {
    let mut f = File::new();
    let place = f.add("IFCAXIS2PLACEMENT2D(#1,$)");
    let circle = f.add(format!("IFCCIRCLE({place},50.)"));
    let segment = f.add(format!(
        "IFCCURVESEGMENT(.CONTINUOUS.,{place},IFCLENGTHMEASURE(0.),IFCLENGTHMEASURE(10.),{circle})"
    ));
    let composite = f.add(format!(
        "IFCCOMPOSITECURVE(({}),.F.)",
        vec![segment; 20_000].join(",")
    ));
    let d = f.add(format!("IFCSWEPTDISKSOLID({composite},0.1,$,$,$)"));
    f.product(&d, "#5");
    let s = f.read("many segments");
    assert!(s.elements.is_empty());
    assert!(s.warnings.invalid >= 1);
}

#[test]
fn a_gradient_curve_that_runs_backwards_is_refused() {
    let mut f = File::new();
    let place = f.add("IFCAXIS2PLACEMENT2D(#1,$)");
    let dir = f.add("IFCDIRECTION((1.,0.))");
    let vector = f.add(format!("IFCVECTOR({dir},1.)"));
    let line = f.add(format!("IFCLINE(#1,{vector})"));
    let seg = |f: &mut File, x: f64, len: f64| {
        let at = f.add(format!("IFCCARTESIANPOINT(({x},0.))"));
        let p = f.add(format!("IFCAXIS2PLACEMENT2D({at},{dir})"));
        f.add(format!(
            "IFCCURVESEGMENT(.CONTINUOUS.,{p},IFCLENGTHMEASURE(0.),IFCLENGTHMEASURE({len}),{line})"
        ))
    };
    let plan_segment = f.add(format!(
        "IFCCURVESEGMENT(.CONTINUOUS.,{place},IFCLENGTHMEASURE(0.),IFCLENGTHMEASURE(10.),{line})"
    ));
    let plan = f.add(format!("IFCCOMPOSITECURVE(({plan_segment}),.F.)"));
    // A profile that starts at 10 and goes back to 0 for 10 (a negative run).
    let first = seg(&mut f, 10.0, 5.0);
    let second = seg(&mut f, 0.0, 5.0);
    let gradient = f.add(format!("IFCGRADIENTCURVE(({first},{second}),.F.,{plan},$)"));
    let d = f.add(format!("IFCSWEPTDISKSOLID({gradient},0.1,$,$,$)"));
    f.product(&d, "#5");
    let s = f.read("backwards profile");
    assert!(s.elements.is_empty());
}
