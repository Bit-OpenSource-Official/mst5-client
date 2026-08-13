# Server integration tests

These tests use the neighbouring `micro-chat` checkout. Run them explicitly:

```sh
cargo test --manifest-path interop-tests/Cargo.toml
```

Keeping the server-only dependency in this separate test crate lets the public
MST5 client build from a standalone checkout.
