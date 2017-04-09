#[macro_use]
extern crate debug_macros;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate base64;

pub mod errors;

use errors::Error;

type JsonValue = serde_json::value::Value;
type JsonObject = serde_json::map::Map<String, JsonValue>;

#[derive(Deserialize, Debug)]
pub struct Header {
    pub alg: String,
    pub kid: String,
}

#[derive(Deserialize, Debug)]
pub struct Payload {
    pub sub: String,
    pub iss: String,
    pub aud: String,
}

fn decode_header(base64_hdr: &str) -> Result<Header, Error> {
    let hdr = base64::decode(base64_hdr)?;
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

fn decode_payload(base64_payload: &str) -> Result<Payload, Error> {
    let payload_json = base64::decode(base64_payload)?;
    let obj : JsonValue = serde_json::from_slice(&payload_json)?;
    if !obj.is_object() {
        return Err(Error::InvalidTypeField(""));
    }
    let obj = obj.as_object().unwrap();

    let sub = json_get_str(obj, "sub")?;
    let iss = json_get_str(obj, "iss")?;
    let aud = json_get_str(obj, "aud")?;


    dbg!("obj:{:?}", obj);
    dbg!("sub:{:?}", sub);
    dbg!("iss:{:?}", iss);
    dbg!("aud:{:?}", aud);

    Ok(Payload{
        sub: sub.to_string(),
        iss: iss.to_string(),
        aud: aud.to_string(),
    })
}

pub fn google_signin_from_str(token: &str, secret: &[u8]) -> Result<String, Error> {
    dbg!("token:{:?}", token);
    let mut arr: Vec<&str> = token.split(".").collect();
    dbg!("arr:{:?}", arr);
    if arr.len() != 3 {
        return Err(Error::InvalidToken);
    }

    let hdr = arr[0];
    let payload = arr[1];
    let sig  = arr[2];

    // Work on header
    let hdr = decode_header(hdr)?;
    let payload = decode_payload(payload)?;


    dbg!("hdr={:?}", hdr);
    dbg!("payload={:?}", payload);

    Ok("42".to_string())
}


#[cfg(test)]
mod tests {
    use std::io;
    use std::io::prelude::*;
    use std::fs::File;
    use super::*;

    #[test]
    fn from_token_file() {
        let mut file = File::open("token").unwrap();
        let mut token = String::new();
        file.read_to_string(&mut token);
        token.pop(); // remove trailing \n

        file = File::open("secret").unwrap();
        let mut secret = String::new();
        file.read_to_string(&mut secret);
        secret.pop(); // remove trailing \n

        let res = google_signin_from_str(&token, &secret.as_bytes());
        dbg!("res={:?}", res);
    }
}
