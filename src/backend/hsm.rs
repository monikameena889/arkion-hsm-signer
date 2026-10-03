//! PKCS#11 backend (tested against SoftHSM2; nothing here is SoftHSM-specific).
//!
//! Key handling rules enforced here:
//! - Private and secret keys are generated *inside* the token with `CKA_SENSITIVE=true` and
//!   `CKA_EXTRACTABLE=false`; at startup we refuse to use any configured key that is not.
//! - Keys are located by stable attributes (`CKA_CLASS` + `CKA_ID` + `CKA_LABEL`), never by
//!   handle numbers persisted elsewhere.
//! - Messages are hashed in software and only the digest crosses the PKCS#11 boundary. This keeps
//!   the per-call payload tiny, which matters a lot for network-attached HSMs.
//! - Data keys (envelope encryption) are session objects: `CKA_TOKEN=false`, sensitive, and only
//!   extractable in wrapped form under the KEK.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::{CryptoBackend, CryptoError, KeyKind, KeySpec, PublicKey, Sealed, SignAlgorithm};

/// DER-encoded OID 1.2.840.10045.3.1.7 (prime256v1 / secp256r1).
const P256_EC_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const RSA_BITS: u64 = 3072;
const GCM_IV_LEN: usize = 12;
const GCM_TAG_BITS: u64 = 128;
const PSS_PARAMS: PkcsPssParams = PkcsPssParams {
    hash_alg: MechanismType::SHA256,
    mgf: PkcsMgfType::MGF1_SHA256,
    s_len: cryptoki::types::Ulong::new(32),
};

pub struct HsmConfig {
    pub module_path: PathBuf,
    pub token_label: String,
    pub pin: AuthPin,
    pub keys: Vec<KeySpec>,
    /// Generate keys that are missing. Intended for dev/test; production keys are provisioned
    /// by a key ceremony and the service should fail closed if they are absent.
    pub provision_missing: bool,
    /// Number of sessions kept open. Should match the service's max in-flight operations.
    pub pool_size: usize,
}

/// Protection attributes of a key as reported by the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProtection {
    pub sensitive: bool,
    pub extractable: bool,
    pub always_sensitive: bool,
    pub never_extractable: bool,
    /// Whether `C_GetAttributeValue(CKA_VALUE)` returned anything. Must always be false.
    pub value_readable: bool,
}

struct KeyEntry {
    kind: KeyKind,
    /// Private key (asymmetric) or secret key (AES).
    handle: ObjectHandle,
    public: Option<PublicKey>,
}

pub struct HsmBackend {
    ctx: Pkcs11,
    slot: Slot,
    pin: AuthPin,
    idle: Mutex<Vec<Session>>,
    max_idle: usize,
    keys: HashMap<String, KeyEntry>,
}

impl HsmBackend {
    /// Loads the PKCS#11 module, logs in, locates (or provisions) all configured keys and
    /// pre-opens `pool_size` sessions.
    pub fn connect(cfg: HsmConfig) -> Result<Self, CryptoError> {
        let ctx = Pkcs11::new(&cfg.module_path).map_err(|e| {
            CryptoError::Unavailable(format!("loading PKCS#11 module {}: {e}", cfg.module_path.display()))
        })?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(map_ck("C_Initialize", e)),
        }
        let slot = find_slot(&ctx, &cfg.token_label)?;

        let mut backend = Self {
            ctx,
            slot,
            pin: cfg.pin,
            idle: Mutex::new(Vec::new()),
            max_idle: cfg.pool_size.max(1),
            keys: HashMap::new(),
        };

        let session = backend.open_session()?;
        for spec in &cfg.keys {
            let entry = backend.load_key(&session, spec, cfg.provision_missing)?;
            backend.keys.insert(spec.key_id.clone(), entry);
        }
        backend.checkin(session);
        for _ in 1..backend.max_idle {
            let s = backend.open_session()?;
            backend.checkin(s);
        }
        info!(
            token = %cfg.token_label,
            slot = slot.id(),
            keys = backend.keys.len(),
            sessions = backend.max_idle,
            "HSM backend ready"
        );
        Ok(backend)
    }

    /// Reports the protection attributes of a key (used by tests and for auditing).
    pub fn key_protection(&self, key_id: &str) -> Result<KeyProtection, CryptoError> {
        let handle = self.entry(key_id)?.handle;
        self.with_session("get_attributes", |s| read_protection(s, handle))
    }

    fn open_session(&self) -> Result<Session, CryptoError> {
        let session = self.ctx.open_rw_session(self.slot).map_err(|e| map_ck("C_OpenSession", e))?;
        // Login state is per-application in PKCS#11: only the first session actually logs in.
        match session.login(UserType::User, Some(&self.pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(session),
            Err(CkError::Pkcs11(RvError::PinIncorrect, _)) => {
                Err(CryptoError::Unavailable("token login failed: incorrect PIN".into()))
            }
            Err(e) => Err(map_ck("C_Login", e)),
        }
    }

    fn checkout(&self) -> Result<Session, CryptoError> {
        let pooled = self.idle.lock().unwrap_or_else(|p| p.into_inner()).pop();
        match pooled {
            Some(s) => Ok(s),
            // Only reachable if a session was discarded after a failure; the service-level
            // semaphore still bounds the total number of sessions in use.
            None => self.open_session(),
        }
    }

    fn checkin(&self, session: Session) {
        let mut idle = self.idle.lock().unwrap_or_else(|p| p.into_inner());
        if idle.len() < self.max_idle {
            idle.push(session);
        }
    }

    /// Runs `f` on a pooled session. If the session turned out to be dead (device reset,
    /// handle invalidated, logged out) it is discarded and the operation retried once on a fresh one.
    fn with_session<R>(&self, op: &'static str, f: impl Fn(&Session) -> Result<R, CkError>) -> Result<R, CryptoError> {
        let session = self.checkout()?;
        match f(&session) {
            Ok(v) => {
                self.checkin(session);
                Ok(v)
            }
            Err(e) if is_session_fatal(&e) => {
                warn!(op, error = %e, "discarding broken HSM session and retrying once");
                drop(session);
                let fresh = self.open_session()?;
                let result = f(&fresh);
                if !matches!(&result, Err(e) if is_session_fatal(e)) {
                    self.checkin(fresh);
                }
                result.map_err(|e| map_ck(op, e))
            }
            Err(e) => {
                self.checkin(session);
                Err(map_ck(op, e))
            }
        }
    }

    fn entry(&self, key_id: &str) -> Result<&KeyEntry, CryptoError> {
        self.keys.get(key_id).ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    fn entry_of_kind(&self, key_id: &str, expected: KeyKind) -> Result<&KeyEntry, CryptoError> {
        let entry = self.entry(key_id)?;
        if entry.kind != expected {
            return Err(CryptoError::WrongKeyType { key_id: key_id.into(), expected, actual: entry.kind });
        }
        Ok(entry)
    }

    fn load_key(&self, s: &Session, spec: &KeySpec, provision: bool) -> Result<KeyEntry, CryptoError> {
        let secret_class = match spec.kind {
            KeyKind::Aes256 => ObjectClass::SECRET_KEY,
            _ => ObjectClass::PRIVATE_KEY,
        };
        let existing = find_one(s, secret_class, &spec.key_id)?;
        let handle = match existing {
            Some(h) => h,
            None if provision => {
                info!(key_id = %spec.key_id, kind = %spec.kind, "key not found in token, generating");
                generate_key(s, spec)?
            }
            None => return Err(CryptoError::KeyNotFound(spec.key_id.clone())),
        };

        check_key_type(s, handle, spec)?;
        let protection = read_protection(s, handle).map_err(|e| map_ck("C_GetAttributeValue", e))?;
        if !protection.sensitive || protection.extractable || protection.value_readable {
            return Err(CryptoError::Hsm {
                op: "load_key",
                detail: format!(
                    "key '{}' is exportable (sensitive={}, extractable={}); refusing to use it",
                    spec.key_id, protection.sensitive, protection.extractable
                ),
            });
        }

        let public = match spec.kind {
            KeyKind::Aes256 => None,
            _ => {
                let pub_handle = find_one(s, ObjectClass::PUBLIC_KEY, &spec.key_id)?.ok_or_else(|| {
                    CryptoError::Hsm { op: "load_key", detail: format!("public key for '{}' missing", spec.key_id) }
                })?;
                Some(read_public_key(s, pub_handle, spec.kind)?)
            }
        };

        info!(key_id = %spec.key_id, kind = %spec.kind, "key loaded");
        Ok(KeyEntry { kind: spec.kind, handle, public })
    }

    fn gcm_encrypt(&self, s: &Session, key: ObjectHandle, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CkError> {
        // IV from the token's RNG. Random 96-bit IVs are safe up to ~2^32 messages per key.
        let iv = s.generate_random_vec(GCM_IV_LEN as u32)?;
        let mut iv_buf = iv.clone();
        let params = GcmParams::new(&mut iv_buf, aad, GCM_TAG_BITS.into())?;
        let ciphertext = s.encrypt(&Mechanism::AesGcm(params), key, plaintext)?;
        Ok(Sealed { iv, ciphertext })
    }

    fn gcm_decrypt(
        &self,
        s: &Session,
        key: ObjectHandle,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CkError> {
        let mut iv_buf = iv.to_vec();
        let params = GcmParams::new(&mut iv_buf, aad, GCM_TAG_BITS.into())?;
        s.decrypt(&Mechanism::AesGcm(params), key, ciphertext).map_err(|e| match e {
            // SoftHSM 2.6.x (OpenSSL 3 builds) reports a GCM tag mismatch as CKR_GENERAL_ERROR;
            // 2.7 correctly returns CKR_ENCRYPTED_DATA_INVALID. Treat both as an auth failure.
            CkError::Pkcs11(RvError::GeneralError, f) => CkError::Pkcs11(RvError::EncryptedDataInvalid, f),
            e => e,
        })
    }

    /// Unwraps a DEK into a session object, runs `f`, and always destroys the object afterwards.
    fn with_unwrapped_dek<R>(
        &self,
        s: &Session,
        kek: ObjectHandle,
        wrapped: &[u8],
        f: impl FnOnce(ObjectHandle) -> Result<R, CkError>,
    ) -> Result<R, CkError> {
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
        ];
        let dek = s.unwrap_key(&Mechanism::AesKeyWrapPad, kek, wrapped, &template).map_err(|e| match e {
            // SoftHSM reports a failed RFC 5649 integrity check as CKR_GENERAL_ERROR rather than
            // CKR_WRAPPED_KEY_INVALID. At this call site that can only mean a bad wrapped key.
            CkError::Pkcs11(RvError::GeneralError, f) => CkError::Pkcs11(RvError::WrappedKeyInvalid, f),
            e => e,
        })?;
        let result = f(dek);
        if let Err(e) = s.destroy_object(dek) {
            warn!(error = %e, "failed to destroy ephemeral data key session object");
        }
        result
    }
}

impl Drop for HsmBackend {
    /// Orderly shutdown: close sessions, then `C_Finalize`. The module is then deliberately left
    /// loaded: unloading it (`dlclose`) while SoftHSM/OpenSSL still have `atexit` handlers
    /// registered makes the process segfault on exit.
    fn drop(&mut self) {
        let sessions = std::mem::take(&mut *self.idle.lock().unwrap_or_else(|p| p.into_inner()));
        for s in sessions {
            let _ = s.close();
        }
        if let Err(e) = self.ctx.clone().finalize() {
            warn!(error = %e, "C_Finalize failed");
        }
        std::mem::forget(self.ctx.clone());
    }
}

impl CryptoBackend for HsmBackend {
    fn backend_name(&self) -> &'static str {
        "pkcs11"
    }

    fn sign(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.entry_of_kind(key_id, alg.required_key_kind())?.handle;
        let digest = Sha256::digest(payload);
        match alg {
            SignAlgorithm::EcdsaP256Sha256 => {
                // CKM_ECDSA returns raw r||s; convert to DER for X.509/CMS consumers.
                let raw = self.with_session("C_Sign", |s| s.sign(&Mechanism::Ecdsa, key, &digest))?;
                let sig = p256::ecdsa::Signature::from_slice(&raw).map_err(|e| CryptoError::Hsm {
                    op: "C_Sign",
                    detail: format!("malformed ECDSA signature: {e}"),
                })?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SignAlgorithm::RsaPssSha256 => {
                self.with_session("C_Sign", |s| s.sign(&Mechanism::RsaPkcsPss(PSS_PARAMS), key, &digest))
            }
        }
    }

    fn verify(&self, key_id: &str, alg: SignAlgorithm, payload: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let entry = self.entry_of_kind(key_id, alg.required_key_kind())?;
        let public = entry.public.as_ref().expect("asymmetric keys always have a public key");
        public.verify(alg, payload, signature)
    }

    fn public_key_pem(&self, key_id: &str) -> Result<String, CryptoError> {
        let entry = self.entry(key_id)?;
        match &entry.public {
            Some(pk) => pk.to_pem(),
            None => Err(CryptoError::Unsupported(format!("'{key_id}' is a symmetric key"))),
        }
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
        let key = self.entry_of_kind(key_id, KeyKind::Aes256)?.handle;
        self.with_session("C_Encrypt", |s| self.gcm_encrypt(s, key, plaintext, aad))
    }

    fn decrypt(&self, key_id: &str, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.entry_of_kind(key_id, KeyKind::Aes256)?.handle;
        check_iv(iv)?;
        self.with_session("C_Decrypt", |s| self.gcm_decrypt(s, key, iv, ciphertext, aad))
    }

    fn generate_data_key(&self, kek_id: &str) -> Result<Vec<u8>, CryptoError> {
        let kek = self.entry_of_kind(kek_id, KeyKind::Aes256)?.handle;
        self.with_session("C_WrapKey", |s| {
            let template = [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::ValueLen(32.into()),
                Attribute::Token(false),
                Attribute::Sensitive(true),
                // Extractable only so it can be wrapped; sensitive means never in plaintext.
                Attribute::Extractable(true),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
            ];
            let dek = s.generate_key(&Mechanism::AesKeyGen, &template)?;
            let wrapped = s.wrap_key(&Mechanism::AesKeyWrapPad, kek, dek);
            let _ = s.destroy_object(dek);
            wrapped
        })
    }

    fn encrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Sealed, CryptoError> {
        let kek = self.entry_of_kind(kek_id, KeyKind::Aes256)?.handle;
        self.with_session("C_UnwrapKey", |s| {
            self.with_unwrapped_dek(s, kek, wrapped_dek, |dek| self.gcm_encrypt(s, dek, plaintext, aad))
        })
    }

    fn decrypt_with_data_key(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let kek = self.entry_of_kind(kek_id, KeyKind::Aes256)?.handle;
        check_iv(iv)?;
        self.with_session("C_UnwrapKey", |s| {
            self.with_unwrapped_dek(s, kek, wrapped_dek, |dek| self.gcm_decrypt(s, dek, iv, ciphertext, aad))
        })
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        self.with_session("C_GetSessionInfo", |s| s.get_session_info().map(|_| ()))
    }
}

fn find_slot(ctx: &Pkcs11, label: &str) -> Result<Slot, CryptoError> {
    let slots = ctx.get_slots_with_initialized_token().map_err(|e| map_ck("C_GetSlotList", e))?;
    for slot in slots {
        let info = ctx.get_token_info(slot).map_err(|e| map_ck("C_GetTokenInfo", e))?;
        if info.label().trim_end() == label {
            return Ok(slot);
        }
    }
    Err(CryptoError::Unavailable(format!("no initialized token with label '{label}'")))
}

fn key_template(class: ObjectClass, key_id: &str) -> [Attribute; 3] {
    [Attribute::Class(class), Attribute::Id(key_id.as_bytes().to_vec()), Attribute::Label(key_id.as_bytes().to_vec())]
}

fn find_one(s: &Session, class: ObjectClass, key_id: &str) -> Result<Option<ObjectHandle>, CryptoError> {
    let found = s.find_objects(&key_template(class, key_id)).map_err(|e| map_ck("C_FindObjects", e))?;
    match found.as_slice() {
        [] => Ok(None),
        [h] => Ok(Some(*h)),
        many => Err(CryptoError::Hsm {
            op: "C_FindObjects",
            detail: format!("{} objects of class {class} match '{key_id}'; ids must be unique", many.len()),
        }),
    }
}

fn generate_key(s: &Session, spec: &KeySpec) -> Result<ObjectHandle, CryptoError> {
    let id = spec.key_id.as_bytes().to_vec();
    // Common attributes for the private / secret half.
    let protected = || {
        vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Modifiable(false),
            Attribute::Id(id.clone()),
            Attribute::Label(id.clone()),
        ]
    };
    let public = || {
        vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Id(id.clone()),
            Attribute::Label(id.clone()),
        ]
    };

    let result = match spec.kind {
        KeyKind::EcP256 => {
            let mut pub_t = public();
            pub_t.push(Attribute::EcParams(P256_EC_PARAMS.to_vec()));
            let mut priv_t = protected();
            priv_t.push(Attribute::Sign(true));
            s.generate_key_pair(&Mechanism::EccKeyPairGen, &pub_t, &priv_t).map(|(_, private)| private)
        }
        KeyKind::Rsa3072 => {
            let mut pub_t = public();
            pub_t.push(Attribute::ModulusBits(RSA_BITS.into()));
            pub_t.push(Attribute::PublicExponent(vec![0x01, 0x00, 0x01]));
            let mut priv_t = protected();
            priv_t.push(Attribute::Sign(true));
            s.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &pub_t, &priv_t).map(|(_, private)| private)
        }
        KeyKind::Aes256 => {
            let mut t = protected();
            t.extend([
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::ValueLen(32.into()),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
            ]);
            s.generate_key(&Mechanism::AesKeyGen, &t)
        }
    };
    result.map_err(|e| map_ck("C_GenerateKey", e))
}

fn check_key_type(s: &Session, handle: ObjectHandle, spec: &KeySpec) -> Result<(), CryptoError> {
    let attrs = s.get_attributes(handle, &[AttributeType::KeyType]).map_err(|e| map_ck("C_GetAttributeValue", e))?;
    let key_type = attrs.iter().find_map(|a| match a {
        Attribute::KeyType(t) => Some(*t),
        _ => None,
    });
    let expected = match spec.kind {
        KeyKind::EcP256 => KeyType::EC,
        KeyKind::Rsa3072 => KeyType::RSA,
        KeyKind::Aes256 => KeyType::AES,
    };
    if key_type != Some(expected) {
        return Err(CryptoError::Hsm {
            op: "load_key",
            detail: format!("key '{}' has type {key_type:?}, configured as {}", spec.key_id, spec.kind),
        });
    }
    Ok(())
}

fn read_protection(s: &Session, handle: ObjectHandle) -> Result<KeyProtection, CkError> {
    let attrs = s.get_attributes(
        handle,
        &[
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::AlwaysSensitive,
            AttributeType::NeverExtractable,
        ],
    )?;
    let flag = |want: AttributeType| {
        attrs.iter().any(|a| {
            a.attribute_type() == want
                && matches!(
                    a,
                    Attribute::Sensitive(true)
                        | Attribute::Extractable(true)
                        | Attribute::AlwaysSensitive(true)
                        | Attribute::NeverExtractable(true)
                )
        })
    };
    // A compliant token answers CKR_ATTRIBUTE_SENSITIVE for CKA_VALUE (cryptoki skips it), so
    // this must come back empty. Anything else means the key material is readable.
    let value_readable = match s.get_attributes(handle, &[AttributeType::Value]) {
        Ok(v) => v.iter().any(|a| matches!(a, Attribute::Value(bytes) if !bytes.is_empty())),
        Err(CkError::Pkcs11(RvError::AttributeSensitive, _)) => false,
        Err(e) => return Err(e),
    };
    Ok(KeyProtection {
        sensitive: flag(AttributeType::Sensitive),
        extractable: flag(AttributeType::Extractable),
        always_sensitive: flag(AttributeType::AlwaysSensitive),
        never_extractable: flag(AttributeType::NeverExtractable),
        value_readable,
    })
}

fn read_public_key(s: &Session, handle: ObjectHandle, kind: KeyKind) -> Result<PublicKey, CryptoError> {
    let bad = |detail: String| CryptoError::Hsm { op: "read_public_key", detail };
    match kind {
        KeyKind::EcP256 => {
            let attrs =
                s.get_attributes(handle, &[AttributeType::EcPoint]).map_err(|e| map_ck("C_GetAttributeValue", e))?;
            let point = attrs
                .into_iter()
                .find_map(|a| match a {
                    Attribute::EcPoint(p) => Some(p),
                    _ => None,
                })
                .ok_or_else(|| bad("CKA_EC_POINT missing".into()))?;
            // CKA_EC_POINT is a DER OCTET STRING wrapping the SEC1 point (04 41 04 X Y);
            // some tokens return the bare point.
            let sec1 = match point.as_slice() {
                [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
                p => p,
            };
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(|e| bad(e.to_string()))?;
            Ok(PublicKey::P256(vk))
        }
        KeyKind::Rsa3072 => {
            let attrs = s
                .get_attributes(handle, &[AttributeType::Modulus, AttributeType::PublicExponent])
                .map_err(|e| map_ck("C_GetAttributeValue", e))?;
            let (mut n, mut e) = (None, None);
            for a in attrs {
                match a {
                    Attribute::Modulus(v) => n = Some(v),
                    Attribute::PublicExponent(v) => e = Some(v),
                    _ => {}
                }
            }
            let (n, e) = n.zip(e).ok_or_else(|| bad("RSA modulus/exponent missing".into()))?;
            let pk = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(&n), rsa::BigUint::from_bytes_be(&e))
                .map_err(|e| bad(e.to_string()))?;
            Ok(PublicKey::Rsa(pk))
        }
        KeyKind::Aes256 => Err(bad("symmetric keys have no public half".into())),
    }
}

fn check_iv(iv: &[u8]) -> Result<(), CryptoError> {
    if iv.len() != GCM_IV_LEN {
        return Err(CryptoError::InvalidInput(format!("iv must be {GCM_IV_LEN} bytes")));
    }
    Ok(())
}

fn is_session_fatal(e: &CkError) -> bool {
    matches!(
        e,
        CkError::Pkcs11(
            RvError::SessionHandleInvalid
                | RvError::SessionClosed
                | RvError::UserNotLoggedIn
                | RvError::DeviceError
                | RvError::DeviceRemoved,
            _
        )
    )
}

fn map_ck(op: &'static str, e: CkError) -> CryptoError {
    match &e {
        CkError::Pkcs11(rv, _) => match rv {
            RvError::EncryptedDataInvalid | RvError::EncryptedDataLenRange => CryptoError::DecryptionFailed,
            RvError::WrappedKeyInvalid | RvError::WrappedKeyLenRange => {
                CryptoError::InvalidInput("wrapped key is invalid for this KEK".into())
            }
            RvError::DataLenRange => CryptoError::InvalidInput("input length out of range".into()),
            RvError::DeviceError
            | RvError::DeviceRemoved
            | RvError::DeviceMemory
            | RvError::TokenNotPresent
            | RvError::SessionHandleInvalid
            | RvError::SessionClosed
            | RvError::SessionCount
            | RvError::UserNotLoggedIn => CryptoError::Unavailable(format!("{op}: {rv}")),
            _ => CryptoError::Hsm { op, detail: e.to_string() },
        },
        _ => CryptoError::Hsm { op, detail: e.to_string() },
    }
}
