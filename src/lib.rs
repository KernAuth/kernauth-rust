use serde_json::{json, Value};

pub fn check_body(app_id: &str, license_key: &str) -> Value {
    json!({
        "protocol_version": 1,
        "public_app_id": app_id,
        "client_version": "1.0.0",
        "license_key": license_key,
    })
}

pub fn api_message(payload: &Value, fallback: &str) -> String {
    payload
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .filter(|message| !message.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

pub struct KernAuth {
    pub api: String,
    pub app_id: String,
    pub message: String,
    pub expires_at: Option<String>,
}

impl KernAuth {
    pub fn check(&mut self, license_key: &str) -> bool {
        let client = match reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
            Ok(client) => client,
            Err(error) => {
                self.message = error.to_string();
                return false;
            }
        };
        let response = match client
            .post(format!("{}/v1/client/check", self.api))
            .json(&check_body(&self.app_id, license_key))
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                self.message = error.to_string();
                return false;
            }
        };
        let status = response.status();
        let payload = response.json::<Value>().unwrap_or(Value::Null);
        if !status.is_success() || payload.get("valid").and_then(|value| value.as_bool()) != Some(true) {
            self.message = api_message(&payload, &format!("check failed ({})", status.as_u16()));
            self.expires_at = None;
            return false;
        }
        self.message = "License is active".to_string();
        self.expires_at = payload.get("expires_at").and_then(|value| value.as_str()).map(str::to_string);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_body_and_message() {
        assert_eq!(
            check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP"),
            json!({
                "protocol_version": 1,
                "public_app_id": "pub_harbor_desktop",
                "client_version": "1.0.0",
                "license_key": "KERN-ABCD-EFGH-IJKL-MNOP",
            })
        );
        let payload = json!({"error": {"message": "Update required"}});
        assert_eq!(api_message(&payload, "no"), "Update required");
        assert_eq!(api_message(&json!({}), "no"), "no");
    }
}
