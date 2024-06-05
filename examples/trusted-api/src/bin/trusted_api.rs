use http_req::{
    request::{HttpVersion, Method, RequestBuilder},
    tls,
    uri::Uri,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use topk8::from_sec1_pem;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    nbf: usize,
    exp: usize,
    uri: String,
}

fn build_jwt(
    uri: &str,
    key_name: &str,
    key_secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let key = from_sec1_pem(key_secret).unwrap();
    let key = EncodingKey::from_ec_pem(key.as_bytes()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp = now + 120;

    let claims = Claims {
        sub: key_name.to_string(),
        iss: "cdp".to_string(),
        nbf: now as usize,
        exp: exp as usize,
        uri: uri.to_string(),
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_name.to_string());
    // Generate a random 16 bytes long nonce, hex coded
    let mut rng = rand::thread_rng();
    let nonce: [u8; 16] = rng.gen();
    let nonce_hex = hex::encode(nonce);
    header.nonce = Some(nonce_hex);
    encode(&header, &claims, &key)
}

fn main() {
    let request_method = "GET";
    let request_host = "api.coinbase.com";
    let request_path = "/api/v3/brokerage/accounts";
    // load the key from a file
    let key_data = include_str!("cdp_api_key.json");
    let key_json: serde_json::Value = serde_json::from_str(key_data).unwrap();
    let key_name = key_json["name"].as_str().unwrap();
    let key_secret = key_json["privateKey"].as_str().unwrap();
    let req = format!("{} {}{}", request_method, request_host, request_path);
    let jwt = build_jwt(&req, key_name, key_secret).unwrap();
    let tls_connector = tls::Config::default();
    let stream = TcpStream::connect(format!("{}:{}", request_host, 443)).unwrap();
    let mut tls_stream = tls_connector.connect(&request_host, &stream).unwrap();
    let mut data = Vec::new();
    let uri = format!("https://{}{}", request_host, request_path);
    let uri = Uri::try_from(uri.as_str()).unwrap();
    let response = RequestBuilder::new(&uri)
        .method(Method::GET)
        .version(HttpVersion::Http11)
        .header("Authorization", &format!("Bearer {}", jwt))
        .send(&mut tls_stream, &mut data)
        .unwrap();

    println!("{}", response.status_code());
    println!("{}", response.reason());
    println!("{}", std::str::from_utf8(&data).unwrap());
}
