use std::convert::TryInto;

use time::PrimitiveDateTime;

pub(crate) fn datetime_from_bits(date: u16, time: u16) -> Option<PrimitiveDateTime> {
    let year = (date >> 9) as i32 + 1980;
    let month = (((date >> 5) & 0xf) as u8).try_into().ok()?;
    let day = (date & 0x1f) as u8;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;

    let hour = (time >> 11) as u8;
    let minute = ((time >> 5) & 0x3f) as u8;
    let second = 2 * (time & 0x1f) as u8;
    let time = time::Time::from_hms(hour, minute, second).ok()?;

    Some(PrimitiveDateTime::new(date, time))
}
