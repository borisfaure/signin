use base64;
use std::{error, fmt};
use serde_json;
use openssl;

#[derive(Debug)]
pub enum Error {
    DecodeBase64(base64::DecodeError),
    DecodeJson(serde_json::Error),
    OpensslError(openssl::error::ErrorStack),
    InvalidToken,
    InvalidIssuer,
    InvalidAudience,
    InvalidSignature,
    NoMatchingSigningKey,
    UnsupportedAlgorithm,
    Expired,
    MissingField(&'static str),
    InvalidTypeField(&'static str),
    NoKeys
}
macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}
impl_from_error!(base64::DecodeError, Error::DecodeBase64);
impl_from_error!(serde_json::Error, Error::DecodeJson);
impl_from_error!(openssl::error::ErrorStack, Error::OpensslError);
impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::DecodeBase64(ref err) => err.description(),
            Error::DecodeJson(ref err) => err.description(),
            Error::OpensslError(ref err) => err.description(),
            Error::InvalidToken => "Invalid Token",
            Error::InvalidIssuer => "Invalid Issuer",
            Error::InvalidAudience => "Invalid Audience",
            Error::InvalidSignature => "Invalid Signature",
            Error::Expired => "Expired",
            Error::UnsupportedAlgorithm => "Unsupported Algorithm",
            Error::NoMatchingSigningKey => "No Matching Signing Key",
            Error::MissingField(_) => "Missing Field",
            Error::InvalidTypeField(_) => "Invalid type on field",
            Error::NoKeys => "No Keys found",
        }
    }
    fn cause(&self) -> Option<&error::Error> {
        Some(match *self {
                 Error::DecodeBase64(ref err) => err as &error::Error,
                 Error::DecodeJson(ref err) => err as &error::Error,
                 Error::OpensslError(ref err) => err as &error::Error,
                 ref e => e as &error::Error,
             })
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeJson(ref err) => fmt::Display::fmt(err, f),
            Error::OpensslError(ref err) => fmt::Display::fmt(err, f),
            Error::InvalidToken => write!(f, "{}", error::Error::description(self)),
            Error::InvalidIssuer => write!(f, "{}", error::Error::description(self)),
            Error::InvalidAudience => write!(f, "{}", error::Error::description(self)),
            Error::InvalidSignature => write!(f, "{}", error::Error::description(self)),
            Error::Expired => write!(f, "{}", error::Error::description(self)),
            Error::UnsupportedAlgorithm => write!(f, "{}", error::Error::description(self)),
            Error::NoMatchingSigningKey => write!(f, "{}", error::Error::description(self)),
            Error::MissingField(s) => write!(f, "Missing Field '{}'", s),
            Error::InvalidTypeField(s) => write!(f, "Invalid type on Field '{}'", s),
            Error::NoKeys => write!(f, "{}", error::Error::description(self)),
        }
    }
}
