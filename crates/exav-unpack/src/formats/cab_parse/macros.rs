macro_rules! invalid_data {
    ($e:expr) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidData,
            $e,
        ))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidData,
            format!($fmt, $($arg)+),
        ))
    };
}

macro_rules! invalid_input {
    ($e:expr) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidInput,
            $e,
        ))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::InvalidInput,
            format!($fmt, $($arg)+),
        ))
    };
}

#[allow(unused_macros)] // part of the vendored surface; kept with its siblings
macro_rules! not_found {
    ($e:expr) => {
        return Err(::std::io::Error::new(::std::io::ErrorKind::NotFound, $e))
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(::std::io::Error::new(
            ::std::io::ErrorKind::NotFound,
            format!($fmt, $($arg)+),
        ))
    };
}
