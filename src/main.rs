use kernauth_example::KernAuth;
use std::io::{self, BufRead, Write};

fn license_key() -> String {
    if let Ok(value) = std::env::var("KERN_LICENSE_KEY") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    print!("Enter license: ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    line.trim().to_string()
}

fn main() {
    let mut app = KernAuth {
        api: "https://api.kernauth.com".to_string(),
        app_id: "__PUBLIC_APP_ID__".to_string(),
        message: String::new(),
        expires_at: None,
    };
    if !app.check(&license_key()) {
        println!("{}", app.message);
        std::process::exit(1);
    }
    println!("Status: active");
    match app.expires_at {
        Some(expires) => println!("Expires: {expires}"),
        None => println!("Expires: Lifetime"),
    }
}
