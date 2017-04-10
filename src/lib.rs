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
use std::fs::File;
use time::Timespec;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;

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
struct Key {
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Deserialize)]
struct Keys {
    pub keys: Vec<Key>,
}


/// Context used to store Client_id and google public keys
pub struct Ctx {
    client_id: String,
    keys: Keys,
}

impl Ctx {
    pub fn new(keys_path: String, client_id: String) -> Ctx {
        let file = File::open(keys_path).unwrap();
        let keys : Result<Keys, serde_json::Error> = serde_json::from_reader(&file);
        let keys = keys.unwrap();

        Ctx {
            client_id: client_id,
            keys: keys,
        }
    }
}

fn base64_decode_url(msg: &str) -> Result<Vec<u8>, base64::Base64Error> {
    base64::decode_config(msg, base64::URL_SAFE)
}

fn decode_header(base64_hdr: &str) -> Result<Header, Error> {
    let hdr = base64_decode_url(base64_hdr)?;
    let hdr : Header = serde_json::from_slice(&hdr)?;
    Ok(hdr)
}

fn json_get_str<'a>(obj: &'a JsonObject, name: &'static str) -> Result<&'a str, Error> {
    let o : Option<&JsonValue> = obj.get(name);
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
    let o : Option<&JsonValue> = obj.get(name);
    if let Some(v) = o {
        if !v.is_i64() {
            return Err(Error::InvalidTypeField(name));
        }
        let sec = v.as_i64().unwrap();
        return Ok(Timespec{sec: sec, nsec: 0});
    } else {
        return Err(Error::MissingField(name));
    }
}

fn decode_payload(base64_payload: &str) -> Result<Payload, Error> {
    let payload_json = base64_decode_url(base64_payload)?;
    let obj : JsonValue = serde_json::from_slice(&payload_json)?;
    if !obj.is_object() {
        return Err(Error::InvalidTypeField(""));
    }
    let obj = obj.as_object().unwrap();

    let sub = json_get_str(obj, "sub")?;
    let iss = json_get_str(obj, "iss")?;
    let aud = json_get_str(obj, "aud")?;
    let exp = json_get_numeric_date(obj, "exp")?;

    Ok(Payload{
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
    //let now = time::now_utc().to_timespec();
    //if payload.exp.sec + 3600 < now.sec {
    //    return Err(Error::Expired);
    //}
    Ok(())
}

fn find_key<'a>(ctx: &'a Ctx, hdr: &Header) -> Result<&'a Key, Error> {
    for key in &ctx.keys.keys {
        if key.kid == hdr.kid && key.alg == hdr.alg && key.use_ == "sig" {
            return Ok(key);
        }
    }
    Err(Error::NoMatchingSigningKey)
}

fn verify_rs256(txt: &str, key: &Key, sig: &[u8]) -> Result<(), Error> {

    let n_decoded = base64_decode_url(&key.n)?;
    let n = BigNum::from_slice(&n_decoded).unwrap();
    let e_decoded = base64_decode_url(&key.e)?;
    let e = BigNum::from_slice(&e_decoded).unwrap();

    let rsa = Rsa::from_public_components(n, e).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();

    let digest = MessageDigest::sha256();
    let mut verifier = Verifier::new(digest, &key).unwrap();
    verifier.update(txt.as_bytes()).unwrap();
    let res = verifier.finish(sig);

    match res {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::InvalidSignature),
        Err(_) => Err(Error::InvalidSignature),
    }
}

fn verify_signature(ctx: &Ctx, hdr: &Header, hdr_base64: &str,
                    payload_base64: &str, sig: &[u8]) -> Result<(), Error> {
    let txt = format!("{}.{}", hdr_base64, payload_base64);

    let key = find_key(ctx, hdr)?;

    match key.alg.as_ref() {
        "RS256" => {
            verify_rs256(&txt, key, sig)
        },
        _ => {
            Err(Error::UnsupportedAlgorithm)
        }
    }
}

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
    let sig_slice : &[u8] = &sig;

    verify_payload(&ctx, &payload)?;
    verify_signature(&ctx, &hdr, &hdr_base64, &payload_base64, sig_slice)?;

    Ok(payload.sub)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::io;
    use std::io::prelude::*;

    fn content_from_file(filename: &str) -> String {
        let mut file = File::open(filename).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf);
        buf.pop(); // remove trailing \n
        buf
    }

    #[test]
    fn from_token_file() {
        let token = content_from_file("token");
        let client_id = content_from_file("client_id");
        let ctx = Ctx::new("google_keys.json".to_owned(), client_id);

        let res = google_signin_from_str(&ctx, &token);
        assert!(res.is_ok());
    }
}
