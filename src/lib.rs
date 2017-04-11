//! Library to valide google-sign-in tokens
//!
//! See https://developers.google.com/identity/sign-in/web/backend-auth
//!


#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate base64;
extern crate time;
extern crate openssl;

/// Error types and their utilities
pub mod errors;

use errors::Error;
use std::io::Read;
use time::Timespec;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use std::collections::HashMap;

type JsonValue = serde_json::value::Value;
type JsonObject = serde_json::map::Map<String, JsonValue>;

#[derive(Deserialize)]
struct Header {
    pub alg: String,
    pub kid: String,
}

struct Payload {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: Timespec,
}

#[derive(Deserialize)]
struct JsonKey {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Deserialize)]
struct JsonKeys {
    pub keys: Vec<JsonKey>,
}

struct Key {
    alg: String,
    pkey: PKey,
    digest: MessageDigest,
}

type KeysMap = HashMap<String, Key>;

/// Context used to store Client_id and google public keys
pub struct Ctx {
    client_id: String,
    keys: KeysMap,
}

impl Ctx {
    /// Instantiate a new context
    ///
    /// Use `set_keys_from_reader` to set google public keys
    pub fn new(client_id: String) -> Ctx {
        Ctx {
            client_id: client_id,
            keys: HashMap::new(),
        }
    }

    /// Set google public keys used to verify tokens' signatures
    ///
    /// Expected format is JWK and an be found at
    /// https://www.googleapis.com/oauth2/v3/certs
    pub fn set_keys_from_reader<R>(&mut self, reader: R) -> Result<(), Error>
        where R: Read
    {
        let jsonkeys: JsonKeys = serde_json::from_reader(reader)?;
        let mut map: KeysMap = HashMap::new();

        for key in jsonkeys.keys {
            if key.use_ != "sig" {
                continue;
            }
            match key.alg.as_ref() {
                "RS256" => {
                    let n_decoded = base64_decode_url(&key.n)?;
                    let n = BigNum::from_slice(&n_decoded)?;
                    let e_decoded = base64_decode_url(&key.e)?;
                    let e = BigNum::from_slice(&e_decoded)?;

                    let rsa = Rsa::from_public_components(n, e)?;
                    let pkey = PKey::from_rsa(rsa)?;

                    let digest = MessageDigest::sha256();

                    let k = Key {
                        alg: key.alg.clone(),
                        pkey: pkey,
                        digest: digest,
                    };
                    map.insert(key.kid, k);
                }
                _ => return Err(Error::UnsupportedAlgorithm),
            }
        }
        self.keys = map;
        Ok(())
    }
}

fn base64_decode_url(msg: &str) -> Result<Vec<u8>, base64::Base64Error> {
    base64::decode_config(msg, base64::URL_SAFE)
}

fn decode_header(base64_hdr: &str) -> Result<Header, Error> {
    let hdr = base64_decode_url(base64_hdr)?;
    let hdr: Header = serde_json::from_slice(&hdr)?;
    Ok(hdr)
}

fn json_get_str<'a>(obj: &'a JsonObject, name: &'static str) -> Result<&'a str, Error> {
    let o: Option<&JsonValue> = obj.get(name);
    if let Some(v) = o {
        if !v.is_string() {
            return Err(Error::InvalidTypeField(name));
        }
        return Ok(v.as_str().unwrap());
    } else {
        return Err(Error::MissingField(name));
    }
}

fn json_get_numeric_date(obj: &JsonObject, name: &'static str) -> Result<Timespec, Error> {
    let o: Option<&JsonValue> = obj.get(name);
    if let Some(v) = o {
        if !v.is_i64() {
            return Err(Error::InvalidTypeField(name));
        }
        let sec = v.as_i64().unwrap();
        return Ok(Timespec { sec: sec, nsec: 0 });
    } else {
        return Err(Error::MissingField(name));
    }
}

fn decode_payload(base64_payload: &str) -> Result<Payload, Error> {
    let payload_json = base64_decode_url(base64_payload)?;
    let obj: JsonValue = serde_json::from_slice(&payload_json)?;
    if !obj.is_object() {
        return Err(Error::InvalidTypeField(""));
    }
    let obj = obj.as_object().unwrap();

    let sub = json_get_str(obj, "sub")?;
    let iss = json_get_str(obj, "iss")?;
    let aud = json_get_str(obj, "aud")?;
    let exp = json_get_numeric_date(obj, "exp")?;

    Ok(Payload {
           sub: sub.to_string(),
           iss: iss.to_string(),
           aud: aud.to_string(),
           exp: exp,
       })
}

fn verify_payload(ctx: &Ctx, payload: &Payload) -> Result<(), Error> {
    if payload.aud != ctx.client_id {
        return Err(Error::InvalidAudience);
    }
    if payload.iss != "accounts.google.com" && payload.iss != "https://accounts.google.com" {
        return Err(Error::InvalidIssuer);
    }
    let now = time::now_utc().to_timespec();
    if payload.exp.sec + 3600 < now.sec {
        return Err(Error::Expired);
    }
    Ok(())
}

fn verify_rs256(txt: &str, key: &Key, sig: &[u8]) -> Result<(), Error> {
    let mut verifier = Verifier::new(key.digest, &key.pkey)?;
    verifier.update(txt.as_bytes())?;
    let res = verifier.finish(sig);

    match res {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::InvalidSignature),
        Err(_) => Err(Error::InvalidSignature),
    }
}

fn verify_signature(ctx: &Ctx,
                    hdr: &Header,
                    hdr_base64: &str,
                    payload_base64: &str,
                    sig: &[u8])
                    -> Result<(), Error> {
    let txt = format!("{}.{}", hdr_base64, payload_base64);

    let key = ctx.keys.get(&hdr.kid);
    if key.is_none() {
        return Err(Error::NoMatchingSigningKey);
    }
    let key = key.unwrap();
    if key.alg != hdr.alg {
        return Err(Error::NoMatchingSigningKey);
    }

    match key.alg.as_ref() {
        "RS256" => verify_rs256(&txt, key, sig),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Validate a google sign-in token
///
/// What is checked:
///
///  -  The ID token is properly signed by Google using Google's public keys
///  -  The value of `aud` in the token is equal to the client ID.
///  -  The value of `iss` in the token is equal to accounts.google.com or
///     https://accounts.google.com.
///  -  The expiry time (exp) of the token has not passed, with an hour delay
///     to handle time skews
///
/// Returns the `sub` field as a `String` or an `Error`
pub fn google_signin_from_str(ctx: &Ctx, token: &str) -> Result<String, Error> {
    let arr: Vec<&str> = token.split(".").collect();
    if arr.len() != 3 {
        return Err(Error::InvalidToken);
    }

    let hdr_base64 = arr[0];
    let payload_base64 = arr[1];
    let sig_base64 = arr[2];

    let hdr = decode_header(hdr_base64)?;
    let payload = decode_payload(payload_base64)?;
    let sig = base64_decode_url(sig_base64)?;
    let sig_slice: &[u8] = &sig;

    verify_payload(&ctx, &payload)?;
    verify_signature(&ctx, &hdr, &hdr_base64, &payload_base64, sig_slice)?;

    Ok(payload.sub)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    fn content_from_file(filename: &str) -> String {
        let mut file = File::open(filename).unwrap();
        let mut buf = String::new();
        assert!(file.read_to_string(&mut buf).is_ok());
        buf.pop(); // remove trailing \n
        buf
    }

    #[test]
    fn from_token_file() {
        let token = content_from_file("token");
        let client_id = content_from_file("client_id");
        let mut ctx = Ctx::new(client_id);

        let keys = File::open("google_keys.json").unwrap();
        assert!(ctx.set_keys_from_reader(keys).is_ok());
        let res = google_signin_from_str(&ctx, &token);
        assert!(res.is_ok());
    }
}
