//! A DWG file's sections: R13 to R2000 (ODA spec chapter 3), a file header
//! whose section locators point at the header variables, the classes and
//! the object map; R2004 on (chapter 4, [`super::r2004`]; R2007 chapter 5,
//! [`super::r2007`]), the same sections by name in a paged container, most
//! of them compressed. The objects are where the object map points.

use std::borrow::Cow;

use super::bits::{BitError, Bits};
use super::object::{split_strings, HeaderStreams, Object, Text};
use super::{r2004, r2007};
use super::{Error, Version};

/// The named sections of an R2004 to R2018 file: R2007's container (spec
/// 5) or the others' (spec 4).
enum Sections<'a> {
    R2004(r2004::Container<'a>),
    R2007(r2007::Container<'a>),
}

impl Sections<'_> {
    /// Whether the file has the section, and it is encrypted.
    fn is_encrypted(&self, name: &str) -> bool {
        match self {
            Sections::R2004(c) => c.section_info(name).is_some_and(|s| s.is_encrypted()),
            Sections::R2007(c) => c.section_info(name).is_some_and(|s| s.is_encrypted()),
        }
    }

    fn has(&self, name: &str) -> bool {
        match self {
            Sections::R2004(c) => c.section_info(name).is_some(),
            Sections::R2007(c) => c.section_info(name).is_some(),
        }
    }

    fn section(
        &mut self,
        name: &str,
        problems: &mut Vec<String>,
    ) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Sections::R2004(c) => c.section(name, problems),
            Sections::R2007(c) => c.section(name, problems),
        }
    }
}

/// The sentinel after the file header's locators (spec 3.2.6).
const LOCATORS_END: [u8; 16] = [
    0x95, 0xA0, 0x4E, 0x28, 0x99, 0x82, 0x1A, 0xE5, 0x5E, 0x41, 0xE0, 0x5F, 0x9D, 0x3A, 0x4D, 0x00,
];
/// The sentinel before the header variables (spec 9).
const HEADER_START: [u8; 16] = [
    0xCF, 0x7B, 0x1F, 0x23, 0xFD, 0xDE, 0x38, 0xA9, 0x5F, 0x7C, 0x68, 0xB8, 0x4E, 0x6D, 0x33, 0x5F,
];
/// The sentinel before the classes (spec 10.1).
const CLASSES_START: [u8; 16] = [
    0x8D, 0xA1, 0xC4, 0xB8, 0xC4, 0xA9, 0xF8, 0xC5, 0xC0, 0xDC, 0xF4, 0x5F, 0xE7, 0xCF, 0xB6, 0x8A,
];
/// The sentinel before the preview images (spec 14.2).
const PREVIEW_START: [u8; 16] = [
    0x1F, 0x25, 0x6D, 0x07, 0xD4, 0x36, 0x28, 0x28, 0x9D, 0x57, 0xCA, 0x3F, 0x9D, 0x44, 0x10, 0x2B,
];

/// What [`Dwg::open`] lets the compressed sections of an R2004 to R2018
/// file decompress to, together.
pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;

/// The CRC-16 of spec 2.14.1 (its table is the reflected 0xA001 one).
pub(crate) fn crc8(seed: u16, data: &[u8]) -> u16 {
    const TABLE: [u16; 256] = {
        let mut t = [0u16; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u16;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xA001
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut dx = seed;
    for &b in data {
        let al = (b ^ (dx & 0xFF) as u8) as usize;
        dx = (dx >> 8) ^ TABLE[al];
    }
    dx
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    let b = slice(data, at, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// `len` bytes at `at`, offsets from the file checked for overflow (a
/// 32-bit `usize` cannot add any two of them).
fn slice(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(len)?)
}

/// One section locator record of the file header (spec 3.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Locator {
    pub number: u8,
    pub offset: u32,
    pub size: u32,
}

/// A class the drawing defines (spec 10): object types from 500 on name one
/// by their number.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Class {
    pub number: i16,
    /// The version (R13) or the proxy flags (R14 on).
    pub flags: i16,
    pub app_name: Text,
    pub cpp_name: Text,
    /// The DXF record name of the class's objects, `LWPOLYLINE`, `LAYOUT`...
    pub dxf_name: Text,
    pub was_zombie: bool,
    /// 0x1F2 for classes of entities, 0x1F3 for classes of other objects.
    pub item_class_id: i16,
}

impl Class {
    /// The DXF name as text, without the terminating zero writers count.
    pub fn name(&self) -> String {
        text_string(&self.dxf_name)
    }

    /// The name of the application a class's objects belong to (DXF group
    /// 3): the ARX application a proxy or custom object demands.
    pub fn application(&self) -> String {
        text_string(&self.app_name)
    }

    pub fn is_entity(&self) -> bool {
        self.item_class_id == 0x1F2
    }
}

fn text_string(t: &Text) -> String {
    match t {
        Text::Bytes(b) => String::from_utf8_lossy(trim_zeros(b)).into_owned(),
        Text::Unicode(s) => s.clone(),
    }
}

/// A string's bytes without the trailing zeros writers count in T lengths.
pub fn trim_zeros(mut s: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = s {
        s = rest;
    }
    s
}

/// What a preview image entry holds (spec 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewKind {
    /// AutoCAD's own header data.
    Header,
    /// A device-independent bitmap: a BMP file without its 14-byte file
    /// header.
    Bmp,
    /// A Windows metafile.
    Wmf,
    /// A PNG file: code 6, which the specification does not list; 2013
    /// files hold their preview so.
    Png,
    Other(u8),
}

/// One image of the preview section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewImage<'a> {
    pub kind: PreviewKind,
    pub data: &'a [u8],
}

/// A DWG file, R13 to R2018: where its sections are, its classes
/// and its object map. Every offset and count is checked against the file
/// before use; what does not fit is left out and said in [`Dwg::problems`].
#[derive(Clone, Debug)]
pub struct Dwg<'a> {
    data: &'a [u8],
    version: Version,
    maintenance: u8,
    code_page: u16,
    locators: Vec<Locator>,
    /// The bytes object offsets count from: the file to R2000, the
    /// AcDb:AcDbObjects section from R2004.
    objects: Cow<'a, [u8]>,
    /// The bytes the header variables are in, and their bit windows: data
    /// (to the handles from R2007), handles (R2007 on).
    header: Cow<'a, [u8]>,
    header_data: (u64, u64),
    header_handles: Option<(u64, u64)>,
    measurement: Option<i16>,
    classes: Vec<Class>,
    /// Handle and offset, sorted by handle, one per handle.
    map: Vec<(u64, usize)>,
    /// The AcDb:VBAProject section (R2004 on, spec 15), when the file has
    /// one: its 16-byte header and the project data (an OLE2 compound file).
    vba: Option<Vec<u8>>,
    problems: Vec<String>,
}

impl<'a> Dwg<'a> {
    /// Read the file header, the classes and the object map, with at most
    /// [`DEFAULT_MAX_BYTES`] decompressed.
    pub fn open(data: &'a [u8]) -> Result<Dwg<'a>, Error> {
        Dwg::open_with(data, DEFAULT_MAX_BYTES)
    }

    /// [`Dwg::open`], with at most `max_bytes` decompressed from the
    /// sections of an R2004 to R2018 file, all together. The decompressed
    /// sections stay in memory while the `Dwg` lives.
    pub fn open_with(data: &'a [u8], max_bytes: u64) -> Result<Dwg<'a>, Error> {
        let version =
            Version::from_magic(data).ok_or_else(|| match super::pre_r13_version(data) {
                Some(v) => Error::UnsupportedVersion(v.to_string()),
                None => Error::NotDwg,
            })?;
        let mut dwg = Dwg {
            data,
            version,
            maintenance: data.get(0x0B).copied().unwrap_or(0),
            code_page: data
                .get(0x13..0x15)
                .map_or(0, |b| u16::from_le_bytes([b[0], b[1]])),
            locators: Vec::new(),
            objects: Cow::Borrowed(data),
            header: Cow::Borrowed(data),
            header_data: (0, 0),
            header_handles: None,
            measurement: None,
            classes: Vec::new(),
            map: Vec::new(),
            vba: None,
            problems: Vec::new(),
        };
        if version <= Version::R2000 {
            dwg.locators = locators(data).ok_or(Error::NotDwg)?;
            dwg.check_locator_crc();
            dwg.read_header_range()?;
            if let Some((start, _)) = dwg.locator(1) {
                let classes = data.get(start..).unwrap_or(&[]);
                dwg.classes = read_classes(classes, version, 0, &mut dwg.problems);
            } else {
                dwg.problem("no classes section");
            }
            if let Some((start, size)) = dwg.locator(2) {
                let end = start.saturating_add(size).min(data.len());
                let map = data.get(start..end).unwrap_or(&[]);
                dwg.map = read_object_map(map, data.len(), &mut dwg.problems);
            } else {
                dwg.problem("no object map");
            }
            dwg.measurement = dwg.r15_measurement();
        } else {
            dwg.open_sections(max_bytes)?;
        }
        if dwg.map.is_empty() {
            return Err(Error::Damaged(
                "the object map is empty or unreadable".into(),
            ));
        }
        Ok(dwg)
    }

    /// R2004 on: the sections by name (spec 4.5; 5.2 for R2007).
    fn open_sections(&mut self, max_bytes: u64) -> Result<(), Error> {
        let mut problems = Vec::new();
        let mut c = if self.version == Version::R2007 {
            Sections::R2007(r2007::Container::open(self.data, max_bytes, &mut problems)?)
        } else {
            Sections::R2004(r2004::Container::open(self.data, max_bytes, &mut problems)?)
        };
        for name in ["AcDb:Header", "AcDb:AcDbObjects", "AcDb:Classes"] {
            if c.is_encrypted(name) {
                return Err(Error::Damaged(format!(
                    "section {name} is encrypted (a password-protected drawing)"
                )));
            }
        }
        let header = c
            .section("AcDb:Header", &mut problems)?
            .ok_or_else(|| Error::Damaged("no AcDb:Header section".into()))?;
        let objects = c
            .section("AcDb:AcDbObjects", &mut problems)?
            .ok_or_else(|| Error::Damaged("no AcDb:AcDbObjects section".into()))?;
        let handles = c.section("AcDb:Handles", &mut problems)?;
        let classes = c.section("AcDb:Classes", &mut problems)?;
        let template = c.section("AcDb:Template", &mut problems)?;
        // Optional, and rare: a VBA-enabled drawing (spec 15).
        if c.has("AcDb:VBAProject") && !c.is_encrypted("AcDb:VBAProject") {
            self.vba = c.section("AcDb:VBAProject", &mut problems)?;
        }
        self.problems.append(&mut problems);

        self.header = Cow::Owned(header);
        self.read_r2004_header()?;
        match classes {
            Some(classes) => {
                let hi = self.has_high_size();
                self.classes = read_classes(&classes, self.version, hi, &mut self.problems);
            }
            None => self.problem("no AcDb:Classes section"),
        }
        match handles {
            Some(handles) => {
                self.map = read_object_map(&handles, objects.len(), &mut self.problems);
            }
            None => self.problem("no AcDb:Handles section"),
        }
        self.objects = Cow::Owned(objects);
        self.measurement = template.and_then(|t| template_measurement(&t, self.version));
        Ok(())
    }

    /// Whether the header and classes sections have the unknown long after
    /// their size: R2010 and R2013 from maintenance version 4, R2018 always
    /// (spec 8, 9, 10.2).
    fn has_high_size(&self) -> usize {
        let present = match self.version {
            Version::R2010 | Version::R2013 => self.maintenance > 3,
            v => v >= Version::R2018,
        };
        usize::from(present) * 4
    }

    /// The header variables section of R2004 on (spec 9; 5.9 for the
    /// streams R2007 adds).
    fn read_r2004_header(&mut self) -> Result<(), Error> {
        let h = &self.header[..];
        if h.get(..16) != Some(&HEADER_START[..]) {
            return Err(Error::Damaged(
                "the header variables do not start with their sentinel".into(),
            ));
        }
        let size = le32(h, 16)
            .ok_or_else(|| Error::Damaged("the header variables are cut short".into()))?;
        let begin = 20 + self.has_high_size();
        let end = begin.saturating_add(size as usize).min(h.len());
        if self.version < Version::R2007 {
            self.header_data = (begin as u64 * 8, end as u64 * 8);
            return Ok(());
        }
        // R2007 on: the data's size in bits, counted from where it is
        // (spec 9 says R2007 only; R2010 to R2018 files have it as well),
        // the handles after it.
        let bits = le32(h, begin)
            .ok_or_else(|| Error::Damaged("the header variables are cut short".into()))?;
        let base = begin as u64 * 8;
        let handles = base.saturating_add(u64::from(bits)).min(end as u64 * 8);
        self.header_data = (base + 32, handles);
        self.header_handles = Some((handles, end as u64 * 8));
        Ok(())
    }

    pub fn version(&self) -> Version {
        self.version
    }

    /// The byte at 0x0B: `ACADMAINTVER` in the files that set it.
    pub fn maintenance(&self) -> u8 {
        self.maintenance
    }

    /// The code page number at 0x13 (spec 3.2.5); [`code_page_name`]
    /// names it.
    ///
    /// [`code_page_name`]: super::code_page_name
    pub fn code_page(&self) -> u16 {
        self.code_page
    }

    /// The section locators of an R13 to R2000 file; none from R2004.
    pub fn locators(&self) -> &[Locator] {
        &self.locators
    }

    /// Damage found while opening the file: data that was left out.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    /// The file.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The bytes object offsets count from: the file to R2000, the
    /// decompressed AcDb:AcDbObjects section from R2004 (spec 23.2).
    pub fn objects(&self) -> &[u8] {
        &self.objects
    }

    /// The header variables (spec 9): their data from just after the
    /// section size (R2007 on: after the data's size) to the CRC, or to the
    /// strings and handles R2007 puts after the data.
    pub fn header_variables(&self) -> HeaderStreams<'_> {
        let h = &self.header[..];
        let (start, end) = self.header_data;
        let mut data = Bits::window(h, start, end);
        let mut strings = None;
        if self.version >= Version::R2007 {
            match split_strings(h, start, end) {
                Ok((data_end, s)) => {
                    data.set_end(data_end);
                    strings = s;
                }
                Err(_) => data.set_end(start),
            }
        }
        HeaderStreams {
            data,
            strings,
            handles: self
                .header_handles
                .map(|(start, end)| Bits::window(h, start, end)),
            unicode: self.version >= Version::R2007,
        }
    }

    pub fn classes(&self) -> &[Class] {
        &self.classes
    }

    /// The class of an object type from 500 on.
    pub fn class(&self, type_code: u16) -> Option<&Class> {
        let i = usize::from(type_code.checked_sub(500)?);
        self.classes.get(i)
    }

    /// The DXF record name of an object type: the fixed types' (spec 20.3),
    /// or the class's.
    pub fn type_name(&self, type_code: u16) -> Option<String> {
        match super::fixed_type_name(type_code) {
            Some(n) => Some(n.to_string()),
            None => self.class(type_code).map(Class::name),
        }
    }

    /// Whether objects of this type are entities, with the common entity
    /// data (spec 20.2).
    pub fn is_entity(&self, type_code: u16) -> bool {
        super::fixed_type_is_entity(type_code)
            .unwrap_or_else(|| self.class(type_code).is_some_and(Class::is_entity))
    }

    /// Every handle of the object map, with the offset of its object in
    /// [`Dwg::objects`], in handle order.
    pub fn object_map(&self) -> &[(u64, usize)] {
        &self.map
    }

    /// The offset of an object in [`Dwg::objects`].
    pub fn offset(&self, handle: u64) -> Option<usize> {
        self.map
            .binary_search_by_key(&handle, |(h, _)| *h)
            .ok()
            .and_then(|i| self.map.get(i))
            .map(|(_, at)| *at)
    }

    /// The object of a handle; `None` when the map does not have it.
    pub fn object(&self, handle: u64) -> Option<Result<Object<'_>, BitError>> {
        self.offset(handle).map(|at| self.object_at(at))
    }

    /// The object at an offset in [`Dwg::objects`].
    pub fn object_at(&self, offset: usize) -> Result<Object<'_>, BitError> {
        Object::read(self, offset)
    }

    /// The type of the object at an offset, without reading the rest.
    pub fn type_at(&self, offset: usize) -> Result<u16, BitError> {
        super::object::type_at(self, offset)
    }

    /// MEASUREMENT (spec 22): 0 imperial, 1 metric. R13 to R2000 keep it
    /// in a section of their own (locator 4), R2004 on in AcDb:Template.
    pub fn measurement(&self) -> Option<i16> {
        self.measurement
    }

    fn r15_measurement(&self) -> Option<i16> {
        let l = self.locators.iter().find(|l| l.number == 4)?;
        let at = usize::try_from(l.offset).ok()?;
        let b = self
            .data
            .get(at..at.checked_add(usize::try_from(l.size).ok()?)?)?;
        let len = usize::from(u16::from_le_bytes([*b.first()?, *b.get(1)?]));
        let v = b.get(2 + len..4 + len)?;
        Some(i16::from_le_bytes([v[0], v[1]]))
    }

    /// The AcDb:VBAProject section (spec 15), R2004 on: its 16-byte header
    /// and the project data (an OLE2 compound file). `None` when the file
    /// has no VBA project, or it is R13 to R2000 (where VBA is a
    /// VBA_PROJECT object of the object map instead).
    pub fn vba_project(&self) -> Option<&[u8]> {
        self.vba.as_deref()
    }

    /// The bytes of the object at `offset`: its record from the size field
    /// to the end of its data, within [`Dwg::objects`]. For scanning an
    /// object whose payload is not bit-packed (a VBA_PROJECT's compound
    /// file), without reading its fields.
    pub fn object_bytes(&self, offset: usize) -> Option<&[u8]> {
        let mut b = Bits::window(
            &self.objects,
            offset as u64 * 8,
            self.objects.len() as u64 * 8,
        );
        let size = usize::try_from(b.ms().ok()?).ok()?;
        let start = (b.position() / 8) as usize;
        self.objects.get(start..start.checked_add(size)?)
    }

    /// The preview images (spec 14.2), from the address at 0x0D.
    pub fn preview(&self) -> Vec<PreviewImage<'a>> {
        preview(self.data)
    }

    fn locator(&self, number: u8) -> Option<(usize, usize)> {
        let l = self.locators.iter().find(|l| l.number == number)?;
        let start = usize::try_from(l.offset).ok()?;
        let size = usize::try_from(l.size).ok()?;
        (l.offset != 0).then_some((start, size))
    }

    fn problem(&mut self, what: impl Into<String>) {
        self.problems.push(what.into());
    }

    /// The CRC after the locators (spec 3.2.6), XORed with a constant that
    /// depends on their number.
    fn check_locator_crc(&mut self) {
        let n = self.locators.len();
        let at = 0x19 + 9 * n;
        let (Some(head), Some(stored)) = (self.data.get(..at), self.data.get(at..at + 2)) else {
            return;
        };
        let magic = match n {
            3 => 0xA598,
            4 => 0x8101,
            5 => 0x3CC4,
            6 => 0x8461,
            _ => return,
        };
        if crc8(0, head) ^ magic != u16::from_le_bytes([stored[0], stored[1]]) {
            self.problem("the file header's CRC does not match");
        }
    }

    fn read_header_range(&mut self) -> Result<(), Error> {
        let (start, _) = self
            .locator(0)
            .ok_or_else(|| Error::Damaged("no header variables section".into()))?;
        if slice(self.data, start, 16) != Some(&HEADER_START[..]) {
            return Err(Error::Damaged(
                "the header variables do not start with their sentinel".into(),
            ));
        }
        let size = le32(self.data, start.saturating_add(16))
            .and_then(|s| usize::try_from(s).ok())
            .ok_or_else(|| Error::Damaged("the header variables are cut short".into()))?;
        let begin = start.saturating_add(20);
        let end = begin.saturating_add(size).min(self.data.len());
        if end < begin.saturating_add(size) {
            self.problem("the header variables run past the end of the file");
        }
        self.header_data = (begin as u64 * 8, end as u64 * 8);
        Ok(())
    }
}

/// MEASUREMENT from the AcDb:Template section (spec 22): a description's
/// length and bytes, then the value. From R2007 the length counts UTF-16
/// units: AutoCAD writes `01 00 00 00 01 00` (an empty string with its
/// terminator) in an R2013 drawing whose DXF has $MEASUREMENT 1; the ODA
/// File Converter writes `00 00 01 00`.
fn template_measurement(t: &[u8], version: Version) -> Option<i16> {
    let unit = if version >= Version::R2007 { 2 } else { 1 };
    let len = usize::from(u16::from_le_bytes([*t.first()?, *t.get(1)?])) * unit;
    let v = t.get(2 + len..4 + len)?;
    Some(i16::from_le_bytes([v[0], v[1]]))
}

/// The classes (spec 10) from their sentinel at the start of `data`: R13 to
/// R2000 a size and the classes; R2004 on (10.2) a size, `high` bytes of an
/// unknown long, R2007 on the data's size in bits, then the highest class
/// number and three fixed values before the classes, whose strings R2007
/// moves to a string stream (spec 5.8).
fn read_classes(
    data: &[u8],
    version: Version,
    high: usize,
    problems: &mut Vec<String>,
) -> Vec<Class> {
    let mut out = Vec::new();
    if slice(data, 0, 16) != Some(&CLASSES_START[..]) {
        problems.push("the classes do not start with their sentinel".into());
        return out;
    }
    let Some(size) = le32(data, 16) else {
        problems.push("the classes section is cut short".into());
        return out;
    };
    let begin = 20 + high;
    let end = (begin as u64 + u64::from(size)) * 8;
    let mut b = Bits::window(data, begin as u64 * 8, end);
    let mut strings = None;
    if version >= Version::R2007 {
        let Ok(bits) = b.rl() else {
            problems.push("the classes section is cut short".into());
            return out;
        };
        let base = begin as u64 * 8;
        let data_end = base.saturating_add(bits as u32 as u64).min(end);
        b.set_end(data_end);
        match split_strings(data, b.position(), data_end) {
            Ok((e, s)) => {
                b.set_end(e);
                strings = s;
            }
            Err(_) => {
                problems.push("the classes' strings cannot be found".into());
                return out;
            }
        }
    }
    if version >= Version::R2004 {
        // Highest class number, 0, 0, true.
        let head = (|| -> Result<(), BitError> {
            b.bs()?;
            b.rc()?;
            b.rc()?;
            b.b()?;
            Ok(())
        })();
        if head.is_err() {
            problems.push("the classes section is cut short".into());
            return out;
        }
    }
    let unicode = version >= Version::R2007;
    // The smallest class: two BS, three empty T, a B and a BS (and from
    // R2004 a BL, two BS and two BL).
    let min_bits: u64 = if version >= Version::R2004 { 23 } else { 13 };
    while b.remaining() >= min_bits {
        match read_class(&mut b, &mut strings, unicode, version) {
            Ok(c) => out.push(c),
            Err(_) => {
                problems.push("a class runs past the end of the classes section".into());
                break;
            }
        }
    }
    out
}

fn read_class(
    b: &mut Bits<'_>,
    strings: &mut Option<Bits<'_>>,
    unicode: bool,
    version: Version,
) -> Result<Class, BitError> {
    use super::object::read_tv;
    let c = Class {
        number: b.bs()?,
        flags: b.bs()?,
        app_name: read_tv(b, strings, unicode)?,
        cpp_name: read_tv(b, strings, unicode)?,
        dxf_name: read_tv(b, strings, unicode)?,
        was_zombie: b.b()?,
        item_class_id: b.bs()?,
    };
    if version >= Version::R2004 {
        // Instance count, DWG version, maintenance version, two unknowns.
        // The maintenance version is a BL, not the spec's BS: AutoCAD 2018
        // and later write 327 to 378 for some classes, and the next class
        // starts where a BL of it ends.
        b.bl()?;
        b.bs()?;
        b.bl()?;
        b.bl()?;
        b.bl()?;
    }
    Ok(c)
}

/// The object map (spec 23): sections of at most 2032 bytes, each a
/// big-endian size, handle and offset deltas as modular chars, and a CRC.
/// Deltas start from zero in each section. Offsets past `limit` are left
/// out.
fn read_object_map(data: &[u8], limit: usize, problems: &mut Vec<String>) -> Vec<(u64, usize)> {
    let mut at = 0usize;
    let mut map = Vec::new();
    loop {
        let Some(s) = slice(data, at, 2) else {
            problems.push("the object map is cut short".into());
            break;
        };
        let section = usize::from(u16::from_be_bytes([s[0], s[1]]));
        if section <= 2 {
            break;
        }
        let Some(body) = slice(data, at.saturating_add(2), section - 2) else {
            problems.push("an object map section runs past its end".into());
            break;
        };
        let mut b = Bits::new(body);
        let (mut handle, mut offset) = (0u64, 0i64);
        while b.remaining() >= 16 {
            let (Ok(dh), Ok(dl)) = (b.umc(), b.mc()) else {
                problems.push("an object map entry is cut short".into());
                break;
            };
            handle = handle.wrapping_add(dh);
            offset = offset.wrapping_add(dl);
            match usize::try_from(offset) {
                Ok(o) if o < limit => map.push((handle, o)),
                _ => problems.push(format!("object {handle:X} is outside the objects")),
            }
        }
        // The size covers itself and the entries; the CRC follows.
        at = at.saturating_add(section + 2);
        if at >= data.len() {
            break;
        }
    }
    // Later entries of a handle replace earlier ones.
    map.reverse();
    map.sort_by_key(|(h, _)| *h);
    map.dedup_by_key(|(h, _)| *h);
    map
}

/// The section locators of an R13 to R2000 file header, when it has them
/// and its sentinel follows them.
fn locators(data: &[u8]) -> Option<Vec<Locator>> {
    let n = le32(data, 0x15)?;
    if !(3..=16).contains(&n) {
        return None;
    }
    let n = n as usize;
    let mut out = Vec::with_capacity(n);
    for k in 0..n {
        let at = 0x19 + 9 * k;
        out.push(Locator {
            number: *data.get(at)?,
            offset: le32(data, at + 1)?,
            size: le32(data, at + 5)?,
        });
    }
    let sentinel = 0x19 + 9 * n + 2;
    (data.get(sentinel..sentinel + 16)? == LOCATORS_END).then_some(out)
}

/// The preview images (spec 14.2) at the address at 0x0D: entries of a
/// code, an absolute address and a size. From R2004 the address is that of
/// the AcDb:Preview section's page plus its 0x20-byte header (spec 4.1):
/// the section is stored uncompressed, so its data is in the file as is.
/// Needs no more of the file than that: a drawing's thumbnail is had
/// without reading the drawing.
pub fn preview(data: &[u8]) -> Vec<PreviewImage<'_>> {
    let mut out = Vec::new();
    let Some(start) = le32(data, 0x0D).and_then(|s| usize::try_from(s).ok()) else {
        return out;
    };
    // Past this check `start` is within the data, so what is added to it
    // below cannot overflow.
    if start == 0 || slice(data, start, 16) != Some(&PREVIEW_START[..]) {
        return out;
    }
    let Some(&count) = data.get(start + 20) else {
        return out;
    };
    let mut at = start + 21;
    for _ in 0..count {
        let (Some(&code), Some(pos), Some(size)) =
            (data.get(at), le32(data, at + 1), le32(data, at + 5))
        else {
            break;
        };
        at += 9;
        let (Ok(pos), Ok(size)) = (usize::try_from(pos), usize::try_from(size)) else {
            continue;
        };
        let Some(image) = pos.checked_add(size).and_then(|end| data.get(pos..end)) else {
            continue;
        };
        let kind = match code {
            1 => PreviewKind::Header,
            2 => PreviewKind::Bmp,
            3 => PreviewKind::Wmf,
            6 => PreviewKind::Png,
            c => PreviewKind::Other(c),
        };
        out.push(PreviewImage { kind, data: image });
    }
    out
}

/// Whether `head` has the file header of a drawing this module reads: R13
/// to R2000 locators ending in their sentinel, or the R2004 file header
/// (spec 4.1), whose ID string decrypts.
pub(super) fn has_file_header(head: &[u8]) -> bool {
    match Version::from_magic(head) {
        Some(Version::R13 | Version::R14 | Version::R2000) => locators(head).is_some(),
        Some(Version::R2004 | Version::R2010 | Version::R2013 | Version::R2018) => {
            r2004::has_file_header(head)
        }
        Some(Version::R2007) => r2007::has_file_header(head),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_table_is_the_specifications() {
        // Spec 2.14.1's table, first and last entries.
        assert_eq!(crc8(0, &[1]), 0xC0C1);
        assert_eq!(crc8(0, &[2]), 0xC181);
        assert_eq!(crc8(0, &[3]), 0x0140);
        assert_eq!(crc8(0, &[255]), 0x4040);
    }

    /// The bytes AutoCAD and the converter write (see
    /// `template_measurement`).
    #[test]
    fn measurement_follows_a_description_of_utf16_units_from_r2007() {
        assert_eq!(
            template_measurement(&[1, 0, 0, 0, 1, 0], Version::R2013),
            Some(1)
        );
        assert_eq!(template_measurement(&[0, 0, 1, 0], Version::R2018), Some(1));
        assert_eq!(template_measurement(&[0, 0, 0, 0], Version::R2004), Some(0));
        assert_eq!(
            template_measurement(&[2, 0, b'a', b'b', 1, 0], Version::R2004),
            Some(1)
        );
        assert_eq!(template_measurement(&[9, 0, 1, 0], Version::R2004), None);
    }

    /// Bit codes written MSB first, for hand-built sections.
    #[derive(Default)]
    struct BitWriter(String);

    impl BitWriter {
        fn raw(&mut self, v: u64, n: u32) -> &mut Self {
            for i in (0..n).rev() {
                self.0.push(if v >> i & 1 == 1 { '1' } else { '0' });
            }
            self
        }
        fn rc(&mut self, v: u8) -> &mut Self {
            self.raw(u64::from(v), 8)
        }
        fn rs(&mut self, v: u16) -> &mut Self {
            self.rc(v as u8).rc((v >> 8) as u8)
        }
        fn rl(&mut self, v: u32) -> &mut Self {
            self.rs(v as u16).rs((v >> 16) as u16)
        }
        fn bs(&mut self, v: u16) -> &mut Self {
            match v {
                0 => self.raw(0b10, 2),
                256 => self.raw(0b11, 2),
                1..=255 => self.raw(0b01, 2).rc(v as u8),
                _ => self.raw(0b00, 2).rs(v),
            }
        }
        fn bl(&mut self, v: u32) -> &mut Self {
            match v {
                0 => self.raw(0b10, 2),
                1..=255 => self.raw(0b01, 2).rc(v as u8),
                _ => self.raw(0b00, 2).rl(v),
            }
        }
        fn t(&mut self, s: &str) -> &mut Self {
            self.bs(s.len() as u16);
            for b in s.bytes() {
                self.rc(b);
            }
            self
        }
        fn bytes(&self) -> Vec<u8> {
            self.0
                .as_bytes()
                .chunks(8)
                .map(|c| {
                    c.iter()
                        .enumerate()
                        .fold(0u8, |b, (i, bit)| b | (bit - b'0') << (7 - i))
                })
                .collect()
        }
    }

    /// An R2004+ class (spec 10.2) with a maintenance release past 255:
    /// AutoCAD 2018 and later write MLEADERSTYLE's, ACDBDETAILVIEWSTYLE's
    /// and others' as 327 to 378, and the class after it starts where that
    /// number is read as a BL, not the spec's BS (every R2004 to R2018 file
    /// of the local corpus then reads up to its maximum class number with
    /// no bit left; as a BS, 162 of them misread from that class on).
    #[test]
    fn a_class_maintenance_release_is_a_bitlong() {
        let mut w = BitWriter::default();
        w.bs(501).rc(0).rc(0).raw(1, 1);
        for (number, name, maintenance) in [(500, "MLEADERSTYLE", 329), (501, "SCALE", 1)] {
            w.bs(number).bs(4095);
            w.t("ObjectDBX Classes").t("AcDbX").t(name);
            w.raw(0, 1)
                .bs(0x1F3)
                .bl(1)
                .bs(33)
                .bl(maintenance)
                .bl(0)
                .bl(0);
        }
        let body = w.bytes();
        let mut section = CLASSES_START.to_vec();
        section.extend_from_slice(&(body.len() as u32).to_le_bytes());
        section.extend_from_slice(&body);
        section.extend_from_slice(&[0; 2]);
        let mut problems = Vec::new();
        let classes = read_classes(&section, Version::R2004, 0, &mut problems);
        assert_eq!(problems, Vec::<String>::new());
        let read: Vec<(i16, String)> = classes.iter().map(|c| (c.number, c.name())).collect();
        assert_eq!(
            read,
            [
                (500, "MLEADERSTYLE".to_string()),
                (501, "SCALE".to_string())
            ]
        );
    }

    #[test]
    fn trailing_zeros_are_trimmed_from_strings() {
        assert_eq!(trim_zeros(b"LAYOUT\0"), b"LAYOUT");
        assert_eq!(trim_zeros(b"\0\0"), b"");
        assert_eq!(trim_zeros(b"a\0b"), b"a\0b");
    }
}
