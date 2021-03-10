use base64;
use openssl;
use serde_json;
use std::fmt;

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
    NoKeys,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::DecodeBase64(e) => Some(e),
            Error::DecodeJson(e) => Some(e),
            Error::OpensslError(e) => Some(e),
            _ => None,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::DecodeBase64(ref err) => fmt::Display::fmt(err, f),
            Error::DecodeJson(ref err) => fmt::Display::fmt(err, f),
            Error::OpensslError(ref err) => fmt::Display::fmt(err, f),
            Error::InvalidToken => write!(f, "Invalid Token"),
            Error::InvalidIssuer => write!(f, "Invalid Issuer"),
            Error::InvalidAudience => write!(f, "Invalid Audience"),
            Error::InvalidSignature => write!(f, "Invalid Signature"),
            Error::Expired => write!(f, "Expired"),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported Algorithm"),
            Error::NoMatchingSigningKey => write!(f, "No Matching Signing Key"),
            Error::MissingField(s) => write!(f, "Missing Field '{}'", s),
            Error::InvalidTypeField(s) => write!(f, "Invalid type on Field '{}'", s),
            Error::NoKeys => write!(f, "No Keys found"),
        }
    }
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(error: base64::DecodeError) -> Error {
        Error::DecodeBase64(error)
    }
}
impl From<serde_json::Error> for Error {
    #[inline]
    fn from(error: serde_json::Error) -> Error {
        Error::DecodeJson(error)
    }
}
impl From<openssl::error::ErrorStack> for Error {
    #[inline]
    fn from(error: openssl::error::ErrorStack) -> Error {
        Error::OpensslError(error)
    }
}
