//! Arkion HSM-backed signing and key-management service.
//!
//! Module layout:
//! - [`backend`]  — the `CryptoBackend` abstraction plus the PKCS#11 (HSM) and in-memory mock implementations.
//! - [`service`]  — bounded concurrency / backpressure in front of a backend, plus metrics.
//! - [`api`]      — Axum HTTP layer (request validation, error mapping, logging).
//! - [`config`]   — runtime configuration (env / CLI).

pub mod api;
pub mod backend;
pub mod config;
pub mod service;
