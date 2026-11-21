//! The predictors of `/FlateDecode` and `/LZWDecode` (PDF 32000-1:2008
//! §7.4.4.4), read from `/DecodeParms` and undone in place by
//! [`Predictor::undo`]. The output is never longer than the input.

use crate::Predictor;
use crate::formats::pdf_parse::types::Primitive;
use std::collections::HashMap;

/// What [`undo`] found in `/DecodeParms`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Undone {
    /// No predictor was asked for; the bytes are as they were.
    NoPredictor,
    /// The predictor was undone.
    Done,
    /// A predictor is asked for with parameters that cannot be read: the bytes
    /// are as they were, still predicted.
    Unreadable,
}

/// Undoes the predictor that `parm` asks for in `data`. Every row of the data
/// is read, the last one as far as it goes.
pub(crate) fn undo(data: &mut Vec<u8>, parm: Option<&HashMap<String, Primitive>>) -> Undone {
    let Some(parm) = parm else {
        return Undone::NoPredictor;
    };
    let kind = match parm.get("Predictor") {
        None | Some(Primitive::Null) => return Undone::NoPredictor,
        Some(Primitive::Integer(n)) => *n,
        Some(_) => return Undone::Unreadable,
    };
    if kind <= 1 {
        return Undone::NoPredictor;
    }
    let number = |key: &str, default: i64| match parm.get(key) {
        None | Some(Primitive::Null) => Some(default),
        Some(Primitive::Integer(n)) => Some(*n),
        Some(_) => None,
    };
    let (Some(colors), Some(bits), Some(columns)) = (
        number("Colors", 1),
        number("BitsPerComponent", 8),
        number("Columns", 1),
    ) else {
        return Undone::Unreadable;
    };
    // A number out of range is one [`Predictor::row`] refuses; a `/Columns`
    // past what the field holds is a row longer than any data.
    let predictor = Predictor {
        kind: u8::try_from(kind).unwrap_or(0),
        colors: u32::try_from(colors).unwrap_or(0),
        bits: u8::try_from(bits).unwrap_or(0),
        columns: match columns {
            ..1 => 0,
            n => u32::try_from(n).unwrap_or(u32::MAX),
        },
    };
    if predictor.undo(data) {
        Undone::Done
    } else {
        Undone::Unreadable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parm(entries: &[(&str, i64)]) -> HashMap<String, Primitive> {
        entries
            .iter()
            .map(|&(k, v)| (k.to_string(), Primitive::Integer(v)))
            .collect()
    }

    fn undone(data: &[u8], entries: &[(&str, i64)]) -> (Undone, Vec<u8>) {
        let mut data = data.to_vec();
        let found = undo(&mut data, Some(&parm(entries)));
        (found, data)
    }

    /// One row for each way a PNG row is written, worked out by hand. A tag
    /// past 4 leaves the row as it is.
    #[test]
    fn png_rows_are_undone_by_their_tags() {
        let encoded = [
            1, 10, 10, 10, // Sub: 10 20 30
            2, 5, 5, 5, // Up: 15 25 35
            3, 13, 8, 8, // Average: 20 30 40
            4, 80, 10, 10, // Paeth, the left sample once, then the one above: 100 110 120
            0, 1, 2, 3, // None
            9, 4, 5, 6, // Not a tag
        ];
        let want = [
            10, 20, 30, 15, 25, 35, 20, 30, 40, 100, 110, 120, 1, 2, 3, 4, 5, 6,
        ];
        let (found, data) = undone(&encoded, &[("Predictor", 15), ("Columns", 3)]);
        assert_eq!(found, Undone::Done);
        assert_eq!(data, want);
    }

    /// A pixel of three samples is predicted from the one three bytes back.
    #[test]
    fn png_prediction_goes_back_a_pixel() {
        let (_, data) = undone(
            &[1, 1, 2, 3, 3, 3, 3],
            &[("Predictor", 11), ("Colors", 3), ("Columns", 2)],
        );
        assert_eq!(data, [1, 2, 3, 4, 5, 6]);
    }

    /// The last row of a cut stream is read as far as it goes, and a row of
    /// no bytes but its tag adds none.
    #[test]
    fn png_last_row_is_read_as_far_as_it_goes() {
        let parms = [("Predictor", 12), ("Columns", 4)];
        let (_, data) = undone(&[0, 1, 2, 3, 4, 2, 1, 1], &parms);
        assert_eq!(data, [1, 2, 3, 4, 2, 3]);
        let (_, data) = undone(&[0, 1, 2, 3, 4, 2], &parms);
        assert_eq!(data, [1, 2, 3, 4]);
    }

    /// A row longer than the data is the data, however large `/Columns` is.
    #[test]
    fn a_row_longer_than_the_data_is_the_data() {
        let (found, data) = undone(&[1, 5, 5, 5], &[("Predictor", 12), ("Columns", i64::MAX)]);
        assert_eq!(found, Undone::Done);
        assert_eq!(data, [5, 10, 15]);
    }

    /// The TIFF predictor, for each depth: a sample is the sum of it and the
    /// one a pixel back, in its row only.
    #[test]
    fn tiff_samples_add_the_one_a_pixel_back() {
        let tiff = |data: &[u8], colors: i64, bits: i64, columns: i64| {
            undone(
                data,
                &[
                    ("Predictor", 2),
                    ("Colors", colors),
                    ("BitsPerComponent", bits),
                    ("Columns", columns),
                ],
            )
            .1
        };
        assert_eq!(tiff(&[1, 2, 3, 3, 3, 3], 3, 8, 2), [1, 2, 3, 4, 5, 6]);
        assert_eq!(tiff(&[1, 1, 1, 1], 1, 8, 2), [1, 2, 1, 2]);
        assert_eq!(
            tiff(&[0, 1, 0, 1, 0xFF, 0xFF], 1, 16, 3),
            [0, 1, 0, 2, 0, 1]
        );
        assert_eq!(tiff(&[0x11, 0x0F], 1, 4, 4), [0x12, 0x21]);
        assert_eq!(tiff(&[0xFF], 1, 1, 8), [0xAA]);
    }

    #[test]
    fn no_predictor_is_asked_for_by_default_or_by_one() {
        let mut data = vec![1, 2, 3];
        assert_eq!(undo(&mut data, None), Undone::NoPredictor);
        assert_eq!(undone(&data, &[("Columns", 3)]).0, Undone::NoPredictor);
        assert_eq!(undone(&data, &[("Predictor", 1)]).0, Undone::NoPredictor);
        assert_eq!(data, [1, 2, 3]);
    }

    /// Parameters that cannot be read leave the bytes as they are, and say so.
    #[test]
    fn unreadable_parameters_leave_the_bytes() {
        for bad in [
            &[("Predictor", 12), ("Columns", 0)][..],
            &[("Predictor", 12), ("Colors", 0)],
            &[("Predictor", 2), ("BitsPerComponent", 3)],
            &[("Predictor", 5)],
        ] {
            let (found, data) = undone(&[1, 2, 3], bad);
            assert_eq!(
                (found, data),
                (Undone::Unreadable, vec![1, 2, 3]),
                "{bad:?}"
            );
        }
        let mut data = vec![1, 2, 3];
        let mut real = parm(&[]);
        real.insert("Predictor".to_string(), Primitive::Real(12.0));
        assert_eq!(undo(&mut data, Some(&real)), Undone::Unreadable);
    }
}
