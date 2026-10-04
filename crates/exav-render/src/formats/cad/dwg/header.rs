//! The header variables (ODA spec 9): one bit stream, every variable in a
//! fixed order, some only in some versions; from R2007 the strings and the
//! handles in streams of their own (spec 5.9). Each is read, kept or not,
//! so that the next is found.

use exav_unpack::dwg::{BitResult, HeaderStreams, Version};

use super::Ctx;
use crate::formats::cad::model::{
    Handle, Header, Vec2, Vec3, Version as ModelVersion, WarningKind,
};

/// What the header gives besides the model's header: the handles the
/// rest of the file is found from.
#[derive(Clone, Debug, Default)]
pub(crate) struct Vars {
    pub header: Header,
    pub clayer: u64,
    pub textstyle: u64,
    pub celtype: u64,
    pub dimstyle: u64,
    pub block_control: u64,
    pub layer_control: u64,
    pub style_control: u64,
    pub ltype_control: u64,
    pub view_control: u64,
    pub ucs_control: u64,
    pub vport_control: u64,
    pub appid_control: u64,
    pub dimstyle_control: u64,
    pub named_objects: u64,
    pub layouts: u64,
    pub paper_space: u64,
    pub model_space: u64,
    pub bylayer: u64,
    pub byblock: u64,
    pub continuous: u64,
}

fn model_version(v: Version) -> ModelVersion {
    match v {
        Version::R13 => ModelVersion::R13,
        Version::R14 => ModelVersion::R14,
        Version::R2000 => ModelVersion::R2000,
        Version::R2004 => ModelVersion::R2004,
        Version::R2007 => ModelVersion::R2007,
        Version::R2010 => ModelVersion::R2010,
        Version::R2013 => ModelVersion::R2013,
        Version::R2018 => ModelVersion::R2018,
    }
}

fn v3(p: [f64; 3]) -> Vec3 {
    Vec3::new(p[0], p[1], p[2])
}

fn v2(p: [f64; 2]) -> Vec2 {
    Vec2::new(p[0], p[1])
}

pub(crate) fn read(ctx: &mut Ctx<'_, '_>, code_page: &str) -> Vars {
    let version = ctx.version;
    let mut vars = Vars {
        header: Header {
            version: model_version(version),
            acadver: version.acadver().to_string(),
            code_page: code_page.to_string(),
            ..Header::default()
        },
        ..Vars::default()
    };
    if let Some(m) = ctx.dwg.measurement() {
        vars.header.measurement = m;
    }
    let mut s = ctx.dwg.header_variables();
    if let Err(e) = variables(&mut s, version, &mut vars) {
        ctx.warn(
            WarningKind::Malformed,
            format!("the header variables stop early: {e}"),
        );
    }
    vars
}

/// A handle's value: header handles are absolute (spec 9).
fn h(s: &mut HeaderStreams<'_>) -> BitResult<u64> {
    Ok(s.h()?.value)
}

/// A CMC colour (spec 2.11), skipped.
fn cmc(s: &mut HeaderStreams<'_>, version: Version) -> BitResult<()> {
    s.data.bs()?;
    if version >= Version::R2004 {
        s.data.bl()?;
        let flags = s.data.rc()?;
        if flags & 1 != 0 {
            s.tv()?;
        }
        if flags & 2 != 0 {
            s.tv()?;
        }
    }
    Ok(())
}

fn skip_bs(s: &mut HeaderStreams<'_>, n: usize) -> BitResult<()> {
    for _ in 0..n {
        s.data.bs()?;
    }
    Ok(())
}

fn skip_bd(s: &mut HeaderStreams<'_>, n: usize) -> BitResult<()> {
    for _ in 0..n {
        s.data.bd()?;
    }
    Ok(())
}

fn skip_b(s: &mut HeaderStreams<'_>, n: usize) -> BitResult<()> {
    for _ in 0..n {
        s.data.b()?;
    }
    Ok(())
}

fn skip_bl(s: &mut HeaderStreams<'_>, n: usize) -> BitResult<()> {
    for _ in 0..n {
        s.data.bl()?;
    }
    Ok(())
}

fn skip_bd3(s: &mut HeaderStreams<'_>, n: usize) -> BitResult<()> {
    for _ in 0..n {
        s.data.bd3()?;
    }
    Ok(())
}

/// The variables in the order of spec 9.
fn variables(s: &mut HeaderStreams<'_>, v: Version, vars: &mut Vars) -> BitResult<()> {
    let r13_14 = v <= Version::R14;
    let r2000 = v >= Version::R2000;
    let r2004 = v >= Version::R2004;
    let r2007 = v >= Version::R2007;
    let r2010 = v >= Version::R2010;
    let r2013 = v >= Version::R2013;
    let hd = &mut vars.header;

    // R2007 on, the data's size in bits comes first: `header_variables`
    // has read it.
    if r2013 {
        s.data.bll()?; // REQUIREDVERSIONS
    }
    skip_bd(s, 4)?;
    for _ in 0..4 {
        s.tv()?;
    }
    skip_bl(s, 2)?;
    if r13_14 {
        s.data.bs()?;
    }
    if v < Version::R2004 {
        h(s)?;
    }
    // DIMASO, DIMSHO
    skip_b(s, 2)?;
    if r13_14 {
        s.data.b()?; // DIMSAV
    }
    // PLINEGEN, ORTHOMODE, REGENMODE
    skip_b(s, 3)?;
    hd.fillmode = s.data.b()?;
    s.data.b()?; // QTEXTMODE
    hd.psltscale = s.data.b()?;
    s.data.b()?; // LIMCHECK
    if r13_14 {
        s.data.b()?; // BLIPMODE
    }
    if r2004 {
        s.data.b()?;
    }
    // USRTIMER, SKPOLY
    skip_b(s, 2)?;
    hd.angdir = i16::from(s.data.b()?);
    s.data.b()?; // SPLFRAME
    if r13_14 {
        skip_b(s, 2)?; // ATTREQ, ATTDIA
    }
    hd.mirrtext = s.data.b()?;
    s.data.b()?; // WORLDVIEW
    if r13_14 {
        s.data.b()?; // WIREFRAME
    }
    hd.tilemode = s.data.b()?;
    // PLIMCHECK, VISRETAIN
    skip_b(s, 2)?;
    if r13_14 {
        s.data.b()?; // DELOBJ
    }
    // DISPSILH, PELLIPSE
    skip_b(s, 2)?;
    s.data.bs()?; // PROXYGRAPHICS
    if r13_14 {
        s.data.bs()?; // DRAGMODE
    }
    s.data.bs()?; // TREEDEPTH
    hd.lunits = s.data.bs()?;
    hd.luprec = s.data.bs()?;
    // AUNITS, AUPREC
    skip_bs(s, 2)?;
    if r13_14 {
        s.data.bs()?; // OSMODE
    }
    s.data.bs()?; // ATTMODE
    if r13_14 {
        s.data.bs()?; // COORDS
    }
    hd.pdmode = s.data.bs()?;
    if r13_14 {
        s.data.bs()?; // PICKSTYLE
    }
    if r2004 {
        skip_bl(s, 3)?;
    }
    // USERI1-5, SPLINESEGS, SURFU, SURFV, SURFTYPE, SURFTAB1, SURFTAB2,
    // SPLINETYPE, SHADEDGE, SHADEDIF, UNITMODE, MAXACTVP, ISOLINES,
    // CMLJUST, TEXTQLTY
    skip_bs(s, 19)?;
    hd.ltscale = s.data.bd()?;
    hd.textsize = s.data.bd()?;
    // TRACEWID, SKETCHINC, FILLETRAD, THICKNESS
    skip_bd(s, 4)?;
    hd.angbase = s.data.bd()?;
    hd.pdsize = s.data.bd()?;
    // PLINEWID, USERR1-5, CHAMFERA-D, FACETRES, CMLSCALE
    skip_bd(s, 12)?;
    hd.celtscale = s.data.bd()?;
    // MENUNAME. The spec has it to R2004 only; R2010 to R2018 files have
    // it too: their string stream reads as the DXF the converter writes
    // ($MENU ".", then the empty DIMPOST, DIMAPOST...) with it, and is one
    // string off without.
    s.tv()?;
    // TDCREATE, TDUPDATE
    skip_bl(s, 4)?;
    if r2004 {
        skip_bl(s, 3)?;
    }
    // TDINDWG, TDUSRTIMER
    skip_bl(s, 4)?;
    cmc(s, v)?; // CECOLOR
                // HANDSEED is in the data stream, also from R2007.
    hd.handle_seed = Handle(s.data.h()?.value);
    vars.clayer = h(s)?;
    vars.textstyle = h(s)?;
    vars.celtype = h(s)?;
    if r2007 {
        h(s)?; // CMATERIAL
    }
    vars.dimstyle = h(s)?;
    h(s)?; // CMLSTYLE
    if r2000 {
        s.data.bd()?; // PSVPSCALE
    }
    let hd = &mut vars.header;
    hd.pinsbase = v3(s.data.bd3()?);
    hd.pextmin = v3(s.data.bd3()?);
    hd.pextmax = v3(s.data.bd3()?);
    hd.plimmin = v2(s.data.rd2()?);
    hd.plimmax = v2(s.data.rd2()?);
    s.data.bd()?; // PELEVATION
    skip_bd3(s, 3)?; // PUCSORG, PUCSXDIR, PUCSYDIR
    h(s)?; // PUCSNAME
    if r2000 {
        h(s)?; // PUCSORTHOREF
        s.data.bs()?; // PUCSORTHOVIEW
        h(s)?; // PUCSBASE
        skip_bd3(s, 6)?;
    }
    let hd = &mut vars.header;
    hd.insbase = v3(s.data.bd3()?);
    hd.extmin = v3(s.data.bd3()?);
    hd.extmax = v3(s.data.bd3()?);
    hd.limmin = v2(s.data.rd2()?);
    hd.limmax = v2(s.data.rd2()?);
    s.data.bd()?; // ELEVATION
    skip_bd3(s, 3)?; // UCSORG, UCSXDIR, UCSYDIR
    h(s)?; // UCSNAME
    if r2000 {
        h(s)?; // UCSORTHOREF
        s.data.bs()?; // UCSORTHOVIEW
        h(s)?; // UCSBASE
        skip_bd3(s, 6)?;
        s.tv()?; // DIMPOST
        s.tv()?; // DIMAPOST
    }
    if r13_14 {
        // DIMTOL to DIMSOXD
        skip_b(s, 11)?;
        // DIMALTD, DIMZIN
        s.data.rc()?;
        s.data.rc()?;
        // DIMSD1, DIMSD2
        skip_b(s, 2)?;
        // DIMTOLJ, DIMJUST, DIMFIT
        for _ in 0..3 {
            s.data.rc()?;
        }
        s.data.b()?; // DIMUPT
                     // DIMTZIN, DIMALTZ, DIMALTTZ, DIMTAD
        for _ in 0..4 {
            s.data.rc()?;
        }
        // DIMUNIT, DIMAUNIT, DIMDEC, DIMTDEC, DIMALTU, DIMALTTD
        skip_bs(s, 6)?;
        h(s)?; // DIMTXSTY
    }
    let hd = &mut vars.header;
    hd.dimscale = s.data.bd()?;
    hd.dimasz = s.data.bd()?;
    // DIMEXO, DIMDLI, DIMEXE, DIMRND, DIMDLE, DIMTP, DIMTM
    skip_bd(s, 7)?;
    if r2007 {
        skip_bd(s, 2)?; // DIMFXL, DIMJOGANG
        s.data.bs()?; // DIMTFILL
        cmc(s, v)?; // DIMTFILLCLR
    }
    if r2000 {
        // DIMTOL, DIMLIM, DIMTIH, DIMTOH, DIMSE1, DIMSE2
        skip_b(s, 6)?;
        // DIMTAD, DIMZIN, DIMAZIN
        skip_bs(s, 3)?;
    }
    if r2007 {
        s.data.bs()?; // DIMARCSYM
    }
    vars.header.dimtxt = s.data.bd()?;
    // DIMCEN, DIMTSZ, DIMALTF, DIMLFAC, DIMTVP, DIMTFAC
    skip_bd(s, 6)?;
    vars.header.dimgap = s.data.bd()?;
    if r13_14 {
        // DIMPOST, DIMAPOST, DIMBLK, DIMBLK1, DIMBLK2
        for _ in 0..5 {
            s.data.t()?;
        }
    }
    if r2000 {
        s.data.bd()?; // DIMALTRND
        s.data.b()?; // DIMALT
        s.data.bs()?; // DIMALTD
                      // DIMTOFL, DIMSAH, DIMTIX, DIMSOXD
        skip_b(s, 4)?;
    }
    // DIMCLRD, DIMCLRE, DIMCLRT
    for _ in 0..3 {
        cmc(s, v)?;
    }
    if r2000 {
        // DIMADEC, DIMDEC, DIMTDEC, DIMALTU, DIMALTTD, DIMAUNIT, DIMFRAC,
        // DIMLUNIT, DIMDSEP, DIMTMOVE, DIMJUST
        skip_bs(s, 11)?;
        skip_b(s, 2)?; // DIMSD1, DIMSD2
                       // DIMTOLJ, DIMTZIN, DIMALTZ, DIMALTTZ
        skip_bs(s, 4)?;
        s.data.b()?; // DIMUPT
        s.data.bs()?; // DIMATFIT
    }
    if r2007 {
        s.data.b()?; // DIMFXLON
    }
    if r2010 {
        s.data.b()?; // DIMTXTDIRECTION
        s.data.bd()?; // DIMALTMZF
        s.tv()?; // DIMALTMZS
        s.data.bd()?; // DIMMZF
        s.tv()?; // DIMMZS
    }
    if r2000 {
        // DIMTXSTY, DIMLDRBLK, DIMBLK, DIMBLK1, DIMBLK2
        for _ in 0..5 {
            h(s)?;
        }
    }
    if r2007 {
        // DIMLTYPE, DIMLTEX1, DIMLTEX2
        for _ in 0..3 {
            h(s)?;
        }
    }
    if r2000 {
        skip_bs(s, 2)?; // DIMLWD, DIMLWE
    }
    vars.block_control = h(s)?;
    vars.layer_control = h(s)?;
    vars.style_control = h(s)?;
    vars.ltype_control = h(s)?;
    vars.view_control = h(s)?;
    vars.ucs_control = h(s)?;
    vars.vport_control = h(s)?;
    vars.appid_control = h(s)?;
    vars.dimstyle_control = h(s)?;
    if v <= Version::R2000 {
        h(s)?; // VIEWPORT ENTITY HEADER CONTROL
    }
    h(s)?; // ACAD_GROUP
    h(s)?; // ACAD_MLINESTYLE
    vars.named_objects = h(s)?;
    if r2000 {
        // TSTACKALIGN, TSTACKSIZE
        skip_bs(s, 2)?;
        s.tv()?; // HYPERLINKBASE
        s.tv()?; // STYLESHEET
        vars.layouts = h(s)?;
        h(s)?; // PLOTSETTINGS
        h(s)?; // PLOTSTYLES
    }
    if r2004 {
        h(s)?; // MATERIALS
        h(s)?; // COLORS
    }
    if r2007 {
        h(s)?; // VISUALSTYLE
    }
    if r2013 {
        h(s)?;
    }
    if r2000 {
        let flags = s.data.bl()?;
        vars.header.lwdisplay = flags & 0x200 == 0;
        vars.header.insunits = s.data.bs()?;
        let cepsntype = s.data.bs()?;
        if cepsntype == 3 {
            h(s)?; // CPSNID
        }
        s.tv()?; // FINGERPRINTGUID
        s.tv()?; // VERSIONGUID
    }
    if r2004 {
        // SORTENTS, INDEXCTL, HIDETEXT, XCLIPFRAME, DIMASSOC, HALOGAP
        for _ in 0..6 {
            s.data.rc()?;
        }
        // OBSCUREDCOLOR, INTERSECTIONCOLOR
        skip_bs(s, 2)?;
        // OBSCUREDLTYPE, INTERSECTIONDISPLAY
        s.data.rc()?;
        s.data.rc()?;
        s.tv()?; // PROJECTNAME
    }
    vars.paper_space = h(s)?;
    vars.model_space = h(s)?;
    vars.bylayer = h(s)?;
    vars.byblock = h(s)?;
    vars.continuous = h(s)?;
    Ok(())
}
