use base64;
use std::{error, fmt};
use serde_json;

#[derive(Debug)]
pub enum Error {
    DecodeBase64(base64::Base64Error),
    DecodeJson(serde_json::Error),
    InvalidToken,
    MissingField(&'static str),
    InvalidTypeField(&'static str),
}
macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}
impl_from_error!(base64::Base64Error, Error::DecodeBase64);
impl_from_error!(serde_json::Error, Error::DecodeJson);
impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::DecodeBase64(ref err) => err.description(),
            Error::DecodeJson(ref err) => err.description(),
            Error::InvalidToken => "Invalid Token",
            Error::MissingField(_) => "Missing Field",
            Error::InvalidTypeField(_) => "Invalid type on field",
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        Some(match *self {
            Error::DecodeBase64(ref err) => err as &error::Error,
            Error::DecodeJson(ref err) => err as &error::Error,
            ref e => e as &error::Error,
        })
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeJson(ref err) => fmt::Display::fmt(err, f),
            Error::InvalidToken => write!(f, "{}", error::Error::description(self)),
            Error::MissingField(s) => write!(f, "Missing Field '{}'", s),
            Error::InvalidTypeField(s) => write!(f, "Invalid type on Field '{}'", s),
        }
    }
}
