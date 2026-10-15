# KernAuth Rust example

Paste the public app ID from Developers into `src/main.rs`. Build with the Cargo.toml in this repository.

## Start

```rust
let mut app = KernAuth {
    api: "https://api.kernauth.com".to_string(),
    app_id: "__PUBLIC_APP_ID__".to_string(),
    message: String::new(),
    expires_at: None,
};
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
cargo test
cargo run
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
