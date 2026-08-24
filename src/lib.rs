//! Standalone dotenv secrets vault: per-value ECIES encryption of `.env` files,
//! a local keyring, a trust store, and a managed git pre-commit plaintext guard.
//!
//! Extracted from the `si` monorepo (`si vault`). This crate has no dependency on
//! the `si` codebase; see `support` for the local reimplementations of the three
//! couplings it previously had.
pub mod support;
pub mod trust;
pub mod vault;

pub use support::OutputFormat;
pub use trust::{TrustEntry, TrustStore, TrustStoreError};
