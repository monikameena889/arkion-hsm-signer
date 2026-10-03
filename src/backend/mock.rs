//! In-memory backend for unit tests and local development without a PKCS#11 module.
//!
//! **Not for production**: keys live in process memory. It exists to prove the API/service
//! layers are backend-agnostic and to test them deterministically (e.g. with injected latency).

use std::collections::HashMap;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use rand::RngCore;
use rand::rngs::OsRng;

use super::{CryptoBackend, CryptoError, KeyKind, KeySpec, PublicKey, Sealed, SignAlgorithm};

enum MockKey {
    Ec(SigningKey),
    Aes([u8; 32]),
}

impl MockKey {
    fn kind(&self) -> KeyKind {
        match self {
            Self::Ec(_) => KeyKind::EcP256,
            Self::Aes(_) => KeyKind::Aes256,
        }
    }
}

pub struct MockBackend {
    keys: HashMap<String, MockKey>,
    latency: Option<Duration>,
}

impl MockBackend {
    /// Generates random keys for each spec. RSA is not supported by the mock.
    pub fn new(specs: &[KeySpec]) -> Result<Self, CryptoError> {
        let mut keys = HashMap::new();
        for spec in specs {
            let key = match spec.kind {
                KeyKind::EcP256 => MockKey::Ec(SigningKey::random(&mut OsRng)),
                KeyKind::Aes256 => {
                    let mut k = [0u8; 32];
                    OsRng.fill_bytes(&mut k);
                    MockKey::Aes(k)
                }
                KeyKind::Rsa3072 => {
                    return Err(CryptoError::Unsupported("mock backend does not implement RSA".into()));
                }
            };
            keys.insert(spec.key_id.clone(), key);
        }
        Ok(Self { keys, latency: None })
    }

    /// Simulates HSM latency by blocking the calling thread (like a real PKCS#11 call would).
    pub fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    fn simulate_latency(&self) {
        if let Some(d) = self.latency {
            std::thread::sleep(d);
        }
    }

    fn key(&self, key_id: &str, expected: KeyKind) -> Result<&MockKey, CryptoError> {
        let key = self.keys.get(key_id).ok_or_else(|| CryptoError::KeyNotFound(key_id.into()))?;
        if key.kind() != expected {
            return Err(CryptoError::WrongKeyType { key_id: key_id.into(), expected, actual: key.kind() });
        }
        Ok(key)
    }

    fn aes(&self, key_id: &str) -> Result<Aes256Gcm, CryptoError> {
        match self.key(key_id, KeyKind::Aes256)? {
            MockKey::Aes(k) => Ok(Aes256Gcm::new(k.into())),
            MockKey::Ec(_) => unreachable!(),
        }
    }

    fn public(&self, key_id: &str, expected: KeyKind) -> Result<PublicKey, CryptoError> {
        match self.key(key_id, expected)? {
            MockKey::Ec(sk) => Ok(PublicKey::P256(*sk.verifying_key())),
            MockKey::Aes(_) => Err(CryptoError::Unsupported(format!("'{key_id}' is a symmetric key"))),
        }
    }
}

fn seal(cipher: &Aes256Gcm, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let ciphertext = cipher
        .encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::InvalidInput("encryption failed".into()))?;
    Ok(Sealed { iv: iv.to_vec(), ciphertext })
}

fn open(cipher: &Aes256Gcm, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let iv: [u8; 12] = iv.try_into().map_err(|_| CryptoError::InvalidInput("iv must be 12 bytes".into()))?;
    cipher.decrypt(&Nonce::from(iv), Payload { msg: ciphertext, aad }).map_err(|_| CryptoError::DecryptionFailed)
}

impl MockBackend {
    /// Mock "key wrap": AES-GCM(KEK, DEK) serialized as iv || ciphertext.
    fn unwrap_dek(&self, kek_id: &str, wrapped: &[u8]) -> Result<Aes256Gcm, CryptoError> {
        if wrapped.len() < 12 {
            return Err(CryptoError::InvalidInput("wrapped key is invalid for this KEK".into()));
        }
        let (iv, ct) = wrapped.split_at(12);
        let dek = open(&self.aes(kek_id)?, iv, ct, b"dek")
            .map_err(|_| CryptoError::InvalidInput("wrapped key is invalid for this KEK".into()))?;
        Aes256Gcm::new_from_slice(&dek).map_err(|_| CryptoError::InvalidInput("bad DEK length".into()))
    }
}

impl CryptoBackend for MockBackend {
    fn backend_name(&self) -> &'static str {
        "mock"
    }

    fn sign(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.simulate_latency();
        match self.key(key_id, alg.required_key_kind())? {
            MockKey::Ec(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(payload);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            MockKey::Aes(_) => unreachable!(),
        }
    }

    fn verify(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        self.public(key_id, alg.required_key_kind())?.verify(alg, payload, signature)
    }

    fn public_key_pem(&self, key_id: &str) -> Result<String, CryptoError> {
        let kind = self.keys.get(key_id).ok_or_else(|| CryptoError::KeyNotFound(key_id.into()))?.kind();
        self.public(key_id, kind)?.to_pem()
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
        self.simulate_latency();
        seal(&self.aes(key_id)?, plaintext, aad)
    }

    fn decrypt(&self, key_id: &str, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.simulate_latency();
        open(&self.aes(key_id)?, iv, ciphertext, aad)
    }

    fn generate_data_key(&self, kek_id: &str) -> Result<Vec<u8>, CryptoError> {
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let sealed = seal(&self.aes(kek_id)?, &dek, b"dek")?;
        Ok([sealed.iv, sealed.ciphertext].concat())
    }

    fn encrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Sealed, CryptoError> {
        seal(&self.unwrap_dek(kek_id, wrapped)?, plaintext, aad)
    }

    fn decrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        open(&self.unwrap_dek(kek_id, wrapped)?, iv, ciphertext, aad)
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> MockBackend {
        MockBackend::new(&[
            KeySpec { key_id: "ec".into(), kind: KeyKind::EcP256 },
            KeySpec { key_id: "aes".into(), kind: KeyKind::Aes256 },
        ])
        .unwrap()
    }

    #[test]
    fn sign_verify_roundtrip() {
        let b = backend();
        let sig = b.sign("ec", SignAlgorithm::EcdsaP256Sha256, b"hello").unwrap();
        assert!(b.verify("ec", SignAlgorithm::EcdsaP256Sha256, b"hello", &sig).unwrap());
        assert!(!b.verify("ec", SignAlgorithm::EcdsaP256Sha256, b"hellO", &sig).unwrap());
        assert!(!b.verify("ec", SignAlgorithm::EcdsaP256Sha256, b"hello", b"garbage").unwrap());
    }

    #[test]
    fn wrong_key_type_is_rejected() {
        let b = backend();
        assert!(matches!(b.sign("aes", SignAlgorithm::EcdsaP256Sha256, b"x"), Err(CryptoError::WrongKeyType { .. })));
        assert!(matches!(b.encrypt("ec", b"x", b""), Err(CryptoError::WrongKeyType { .. })));
        assert!(matches!(b.sign("nope", SignAlgorithm::EcdsaP256Sha256, b"x"), Err(CryptoError::KeyNotFound(_))));
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper() {
        let b = backend();
        let sealed = b.encrypt("aes", b"secret", b"ctx").unwrap();
        assert_eq!(b.decrypt("aes", &sealed.iv, &sealed.ciphertext, b"ctx").unwrap(), b"secret");
        assert!(matches!(
            b.decrypt("aes", &sealed.iv, &sealed.ciphertext, b"other"),
            Err(CryptoError::DecryptionFailed)
        ));
        let mut ct = sealed.ciphertext.clone();
        ct[0] ^= 1;
        assert!(matches!(b.decrypt("aes", &sealed.iv, &ct, b"ctx"), Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn envelope_roundtrip() {
        let b = backend();
        let wrapped = b.generate_data_key("aes").unwrap();
        let sealed = b.encrypt_with_data_key("aes", &wrapped, b"bulk", b"").unwrap();
        assert_eq!(b.decrypt_with_data_key("aes", &wrapped, &sealed.iv, &sealed.ciphertext, b"").unwrap(), b"bulk");
    }
}
