// Protocol example. cargo run --manifest-path apps/web/src/examples/rust/Cargo.toml
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, error::Error};

const API: &str = "https://api.kernauth.com";
const APP_ID: &str = "__PUBLIC_APP_ID__";
const KEY_ID: &str = "__KEY_ID__";
const PUBLIC_KEY: &str = "__PUBLIC_KEY__";
const FIELDS: [&str; 12] = ["protocol_version", "entitlement_id", "application_id", "license_id",
    "status", "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"];

fn canonical(ent: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = String::new();
    for name in FIELDS {
        let value = if name == "features" {
            let feature = &ent[name];
            let parsed = if let Some(raw) = feature.as_str() { serde_json::from_str::<Value>(raw)? } else { feature.clone() };
            serde_json::to_string(&parsed)?
        } else if name == "protocol_version" { ent[name].to_string() }
        else { ent[name].as_str().ok_or("missing entitlement field")?.to_owned() };
        if value.contains('\n') || value.contains('\r') { return Err("invalid entitlement field".into()); }
        output.push_str(name); output.push('='); output.push_str(&value); output.push('\n');
    }
    Ok(output.into_bytes())
}

fn verify_grant(grant: &Value, nonce: &str, app: &str, key_id: &str, public_key: &str, now: DateTime<Utc>) -> bool {
    let ent = &grant["entitlement"];
    let expiry = ent["expires_at"].as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok());
    if ent["protocol_version"] != 1 || ent["application_id"] != app || ent["key_id"] != key_id ||
        ent["nonce"] != nonce || ent["status"] != "active" ||
        !expiry.is_some_and(|date| date.with_timezone(&Utc) > now) { return false; }
    let message = match canonical(ent) { Ok(value) => value, Err(_) => return false };
    let key = match STANDARD.decode(public_key).ok().and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|v| VerifyingKey::from_bytes(&v).ok()) { Some(value) => value, None => return false };
    let signature = match grant["signature"].as_str().and_then(|s| STANDARD.decode(s).ok())
        .and_then(|v| Signature::from_slice(&v).ok()) { Some(value) => value, None => return false };
    key.verify(&message, &signature).is_ok()
}

fn request(mode: &str, license: &str, installation: &str) -> Result<(), Box<dyn Error>> {
    let mut random = [0u8; 24]; rand::thread_rng().fill_bytes(&mut random);
    let nonce = URL_SAFE_NO_PAD.encode(random);
    let fingerprint = format!("{:x}", Sha256::digest(format!("kernauth-device-v1:{installation}").as_bytes()));
    let body = json!({ "protocol_version": 1, "public_app_id": APP_ID, "client_version": "1.0.0",
        "license_key": license, "fingerprint_version": 1, "device_fingerprint": fingerprint,
        "installation_id": installation, "nonce": nonce });
    let client = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
    let response = client.post(format!("{API}/v1/client/{mode}")).json(&body).send()?.error_for_status()?;
    let grant: Value = response.json()?;
    if mode == "deactivate" {
        if grant["deactivated"] != true { return Err("deactivation not confirmed".into()); }
    } else if !verify_grant(&grant, &nonce, APP_ID, KEY_ID, PUBLIC_KEY, Utc::now()) {
        return Err("invalid or expired signed entitlement".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let license = env::var("KERN_LICENSE_KEY")?;
    let installation = env::var("KERN_INSTALLATION_ID")?; // Persist once per device.
    for mode in ["activate", "validate", "deactivate"] { request(mode, &license, &installation)?; }
    println!("Signed entitlement verified and device deactivated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_vectors() {
        let fixture: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:01:00Z").unwrap().with_timezone(&Utc);
        for vector in fixture["vectors"].as_array().unwrap() {
            let ent = &vector["fields"];
            assert_eq!(canonical(ent).unwrap(), vector["canonical"].as_str().unwrap().as_bytes());
            let grant = json!({ "entitlement": ent, "signature": vector["signature"] });
            let nonce = ent["nonce"].as_str().unwrap();
            let app = ent["application_id"].as_str().unwrap();
            let key = ent["key_id"].as_str().unwrap();
            let public = vector["public_key"].as_str().unwrap();
            assert!(verify_grant(&grant, nonce, app, key, public, now));
            assert!(!verify_grant(&grant, "wrong", app, key, public, now));
            assert!(!verify_grant(&grant, nonce, "pub_other_app", key, public, now));
            assert!(!verify_grant(&grant, nonce, app, "wrong-key", public, now));
            let mut bad_sig = grant.clone();
            bad_sig["signature"] = json!(format!("{}AA", vector["signature"].as_str().unwrap()));
            assert!(!verify_grant(&bad_sig, nonce, app, key, public, now));
            assert!(!verify_grant(&grant, nonce, app, key, public, now + chrono::Duration::minutes(20)));
            let mut altered = grant.clone(); altered["entitlement"]["device_id"] = json!("other");
            assert!(!verify_grant(&altered, nonce, app, key, public, now));
        }
    }
}
