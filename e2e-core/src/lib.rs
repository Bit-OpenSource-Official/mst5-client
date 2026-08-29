//! Shared E2E implementation.  It deliberately has no dependency on MST5
//! transports so native and WebAssembly adapters cannot diverge in crypto or
//! media-container formats.
#[path = "../../src/e2e.rs"]
mod implementation;

pub use implementation::*;
