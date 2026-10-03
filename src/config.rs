//! Runtime configuration. Every option is a CLI flag with an environment-variable fallback,
//! except the token PIN, which is deliberately *not* a flag (it would show up in `ps`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use cryptoki::types::AuthPin;

use crate::backend::{KeySpec, parse_key_specs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendKind {
    /// PKCS#11 module (SoftHSM2, cloud HSM, network HSM...).
    Hsm,
    /// In-memory keys. Development only.
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(version, about = "Arkion HSM-backed signing service")]
pub struct Config {
    #[arg(long, env = "BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: SocketAddr,

    #[arg(long, env = "BACKEND", value_enum, default_value = "hsm")]
    pub backend: BackendKind,

    /// Path to the PKCS#11 shared library.
    #[arg(long, env = "PKCS11_MODULE", default_value = default_module())]
    pub pkcs11_module: PathBuf,

    /// CKA_LABEL of the token to use.
    #[arg(long, env = "HSM_TOKEN_LABEL", default_value = "arkion")]
    pub token_label: String,

    /// File containing the user PIN (e.g. a mounted Docker/K8s secret). Falls back to $HSM_PIN.
    #[arg(long, env = "HSM_PIN_FILE")]
    pub pin_file: Option<PathBuf>,

    /// Keys to load: comma-separated `<key_id>:<ec-p256|rsa-3072|aes-256>`.
    #[arg(
        long,
        env = "HSM_KEYS",
        default_value = "arkion-intermediate-prod:ec-p256,arkion-rsa-prod:rsa-3072,arkion-kek:aes-256",
        value_parser = parse_key_specs
    )]
    pub keys: std::vec::Vec<KeySpec>,

    /// Generate configured keys that are missing from the token (dev/test only).
    #[arg(long, env = "HSM_PROVISION_KEYS", default_value_t = false, action = clap::ArgAction::Set)]
    pub provision_keys: bool,

    /// HSM sessions kept open == max concurrent HSM operations.
    #[arg(long, env = "HSM_POOL_SIZE", default_value_t = 8)]
    pub pool_size: usize,

    /// Requests allowed to wait for a session before shedding load with 503.
    #[arg(long, env = "MAX_QUEUE", default_value_t = 512)]
    pub max_queue: usize,

    /// Maximum time a request waits for an HSM session.
    #[arg(long, env = "ACQUIRE_TIMEOUT_MS", default_value_t = 2000)]
    pub acquire_timeout_ms: u64,

    /// Maximum decoded payload size in bytes.
    #[arg(long, env = "MAX_PAYLOAD_BYTES", default_value_t = 1024 * 1024)]
    pub max_payload_bytes: usize,

    #[arg(long, env = "LOG_FORMAT", value_enum, default_value = "text")]
    pub log_format: LogFormat,
}

impl Config {
    pub fn acquire_timeout(&self) -> Duration {
        Duration::from_millis(self.acquire_timeout_ms)
    }

    /// Reads the PIN from `pin_file`, else `$HSM_PIN`. Never logged, never a CLI argument.
    pub fn load_pin(&self) -> anyhow::Result<AuthPin> {
        let raw = match &self.pin_file {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading PIN file {}: {e}", path.display()))?,
            None => std::env::var("HSM_PIN").map_err(|_| anyhow::anyhow!("set HSM_PIN_FILE or HSM_PIN"))?,
        };
        let pin = raw.trim_end_matches(['\r', '\n']).to_string();
        anyhow::ensure!(!pin.is_empty(), "HSM PIN is empty");
        Ok(AuthPin::from(pin))
    }
}

fn default_module() -> &'static str {
    if cfg!(target_os = "macos") {
        "/opt/homebrew/lib/softhsm/libsofthsm2.so"
    } else {
        "/usr/lib/softhsm/libsofthsm2.so"
    }
}
