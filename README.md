# KernAuth Rust example

Paste the public app ID, key ID, and public key from Developers into `src/main.rs`. Build with the Cargo.toml in this repository.

## Instance

```rust
let mut app = KernAuth::new(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__",
);
```

## Validate

```rust
if !app.validate(&license, &installation) {
    return Err(app.message.into());
}
println!("Status: {}", app.status);
println!("Features: {}", app.features);
println!("License: {}", app.license_id);
println!("Check expires: {}", app.expires_at);
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program saves an installation id in `kernauth-install` and reuses it. `KERN_INSTALLATION_ID` overrides that file.

## Run

```
cargo test
cargo run
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
