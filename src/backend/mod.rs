//! Cryptographic backend abstraction.
//!
//! [`CryptoBackend`] is deliberately synchronous: PKCS#11 calls block the calling thread, so the
//! service layer runs them on Tokio's blocking pool behind a bounded semaphore. Implementations
//! never return private or secret key material — only signatures, ciphertexts, wrapped keys and
//! public keys cross this boundary.

pub mod hsm;
pub mod mock;

use std::fmt;
use std::str::FromStr;

use p256::ecdsa::signature::Verifier;
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};

/// Signing algorithms exposed by the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignAlgorithm {
    /// ECDSA over P-256 with SHA-256. Signature is DER-encoded (as used in X.509).
    #[serde(rename = "ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    #[serde(rename = "RSA_PSS_SHA256")]
    RsaPssSha256,
}

impl SignAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            Self::RsaPssSha256 => "RSA_PSS_SHA256",
        }
    }

    pub fn required_key_kind(self) -> KeyKind {
        match self {
            Self::EcdsaP256Sha256 => KeyKind::EcP256,
            Self::RsaPssSha256 => KeyKind::Rsa3072,
        }
    }
}

/// Kind of key held under a `key_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    EcP256,
    Rsa3072,
    Aes256,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcP256 => "ec-p256",
            Self::Rsa3072 => "rsa-3072",
            Self::Aes256 => "aes-256",
        }
    }
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for KeyKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ec-p256" => Ok(Self::EcP256),
            "rsa-3072" => Ok(Self::Rsa3072),
            "aes-256" => Ok(Self::Aes256),
            other => Err(format!("unknown key kind '{other}' (expected ec-p256, rsa-3072 or aes-256)")),
        }
    }
}

/// A key the service expects to find (or provision) in the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    pub key_id: String,
    pub kind: KeyKind,
}

/// Parses `"id-a:ec-p256,id-b:aes-256"`.
pub fn parse_key_specs(s: &str) -> Result<Vec<KeySpec>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|part| {
            let (id, kind) =
                part.split_once(':').ok_or_else(|| format!("invalid key spec '{part}', expected <key_id>:<kind>"))?;
            if !is_valid_key_id(id) {
                return Err(format!("invalid key id '{id}'"));
            }
            Ok(KeySpec { key_id: id.to_string(), kind: kind.parse()? })
        })
        .collect()
}

/// Key identifiers are restricted so they are safe to log and to use as CKA_LABEL / CKA_ID.
pub fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Output of an AEAD encryption. `ciphertext` includes the 16-byte GCM tag.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key '{0}' not found")]
    KeyNotFound(String),
    #[error("key '{key_id}' is a {actual} key, operation requires {expected}")]
    WrongKeyType { key_id: String, expected: KeyKind, actual: KeyKind },
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("decryption failed: ciphertext, IV or AAD is not authentic")]
    DecryptionFailed,
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The token / sessions are unusable (device error, logged out, removed...). Retryable.
    #[error("HSM unavailable: {0}")]
    Unavailable(String),
    /// Any other PKCS#11 failure. `detail` contains the CKR_* code, never key material.
    #[error("HSM operation '{op}' failed: {detail}")]
    Hsm { op: &'static str, detail: String },
}

pub trait CryptoBackend: Send + Sync + 'static {
    fn backend_name(&self) -> &'static str;

    /// Signs `payload` (the message, not a digest) with the private key `key_id`.
    fn sign(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Verifies `signature` over `payload` using the public half of `key_id`.
    fn verify(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;

    /// SubjectPublicKeyInfo PEM of an asymmetric key.
    fn public_key_pem(&self, key_id: &str) -> Result<String, CryptoError>;

    /// AES-256-GCM encryption with a non-exportable symmetric key.
    fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError>;

    fn decrypt(&self, key_id: &str, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Envelope encryption: generates a fresh AES-256 data key inside the HSM and returns it
    /// wrapped (RFC 5649) under the key-encryption key `kek_id`. Plaintext DEK never leaves the HSM.
    fn generate_data_key(&self, kek_id: &str) -> Result<Vec<u8>, CryptoError>;

    /// Unwraps `wrapped_dek` into an ephemeral HSM session object, encrypts, destroys it.
    fn encrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Sealed, CryptoError>;

    fn decrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Cheap liveness probe of the underlying device.
    fn health_check(&self) -> Result<(), CryptoError>;
}

/// Public halves of asymmetric keys. Public keys are not secret, so verification is done in
/// software: it is independent of the HSM (a real cross-check) and costs no HSM capacity.
#[derive(Debug, Clone)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    pub fn kind(&self) -> KeyKind {
        match self {
            Self::P256(_) => KeyKind::EcP256,
            Self::Rsa(_) => KeyKind::Rsa3072,
        }
    }

    pub fn to_pem(&self) -> Result<String, CryptoError> {
        let pem = match self {
            Self::P256(k) => k.to_public_key_pem(p256::pkcs8::LineEnding::LF),
            Self::Rsa(k) => rsa::pkcs8::EncodePublicKey::to_public_key_pem(k, rsa::pkcs8::LineEnding::LF),
        };
        pem.map_err(|e| CryptoError::Hsm { op: "encode_public_key", detail: e.to_string() })
    }

    /// Returns `Ok(false)` for a well-formed but wrong signature, and also for malformed
    /// signature encodings (callers should not be able to distinguish the two).
    pub fn verify(&self, alg: SignAlgorithm, payload: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        match (self, alg) {
            (Self::P256(vk), SignAlgorithm::EcdsaP256Sha256) => {
                // Accept DER (what we emit) and raw r||s (what PKCS#11 emits).
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .or_else(|_| p256::ecdsa::Signature::from_slice(signature));
                Ok(sig.is_ok_and(|sig| vk.verify(payload, &sig).is_ok()))
            }
            (Self::Rsa(pk), SignAlgorithm::RsaPssSha256) => {
                use rsa::signature::Verifier as _;
                let vk = rsa::pss::VerifyingKey::<sha2::Sha256>::new(pk.clone());
                let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
                    return Ok(false);
                };
                Ok(vk.verify(payload, &sig).is_ok())
            }
            (_, alg) => Err(CryptoError::WrongKeyType {
                key_id: String::new(),
                expected: alg.required_key_kind(),
                actual: self.kind(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_specs() {
        let specs = parse_key_specs("a:ec-p256, b.c:aes-256,").unwrap();
        assert_eq!(
            specs,
            vec![
                KeySpec { key_id: "a".into(), kind: KeyKind::EcP256 },
                KeySpec { key_id: "b.c".into(), kind: KeyKind::Aes256 },
            ]
        );
        assert!(parse_key_specs("a").is_err());
        assert!(parse_key_specs("a:des").is_err());
        assert!(parse_key_specs("bad id:ec-p256").is_err());
    }

    #[test]
    fn key_id_validation() {
        assert!(is_valid_key_id("arkion-intermediate-prod"));
        assert!(!is_valid_key_id(""));
        assert!(!is_valid_key_id("a\nb"));
        assert!(!is_valid_key_id(&"x".repeat(129)));
    }

    #[test]
    fn algorithm_serde_names() {
        let a: SignAlgorithm = serde_json::from_str("\"ECDSA_P256_SHA256\"").unwrap();
        assert_eq!(a, SignAlgorithm::EcdsaP256Sha256);
        assert_eq!(serde_json::to_string(&SignAlgorithm::RsaPssSha256).unwrap(), "\"RSA_PSS_SHA256\"");
        assert!(serde_json::from_str::<SignAlgorithm>("\"MD5\"").is_err());
    }
}
