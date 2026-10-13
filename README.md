# KernAuth Rust example

Protocol example. This is not the official SDK. The official client is the C++ SDK. This file calls the same activate, validate, and deactivate routes and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `src/main.rs`.

```
cargo test
```

Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```rust
let mut app = KernAuth::new(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__",
);
```

## Activate

```rust
if !app.activate(&license, &installation) {
    return Err(app.message.into());
}
```

## Validate

```rust
if !app.validate(&license, &installation) {
    return Err(app.message.into());
}
```

## Deactivate

```rust
if !app.deactivate(&license, &installation) {
    return Err(app.message.into());
}
```

`app.message` is `Device deactivated` after a successful deactivate.

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
