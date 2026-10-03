//! Integration tests against a real PKCS#11 module (SoftHSM2).
//!
//! Each test run creates a throw-away token in a temp directory, so nothing touches the user's
//! SoftHSM config. Tests are skipped (with a message) if SoftHSM2 isn't installed; set
//! `REQUIRE_SOFTHSM=1` (as CI and the Docker test stage do) to make that a failure instead.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arkion_hsm_signer::api::{AppState, router};
use arkion_hsm_signer::backend::hsm::{HsmBackend, HsmConfig};
use arkion_hsm_signer::backend::{CryptoBackend, CryptoError, KeyKind, KeySpec, SignAlgorithm};
use arkion_hsm_signer::service::{CryptoService, Limits};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cryptoki::types::AuthPin;
use http_body_util::BodyExt;
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use serde_json::{Value, json};
use tower::ServiceExt;

const EC_KEY: &str = "arkion-intermediate-test";
const RSA_KEY: &str = "arkion-rsa-test";
const KEK: &str = "arkion-kek-test";
const USER_PIN: &str = "test-user-pin-5678";

fn module_path() -> Option<PathBuf> {
    std::env::var_os("PKCS11_MODULE").map(PathBuf::from).or_else(|| {
        [
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
    })
}

/// One backend per test process: C_Initialize may only be called once per process.
fn backend() -> Option<Arc<HsmBackend>> {
    static BACKEND: OnceLock<Option<Arc<HsmBackend>>> = OnceLock::new();
    BACKEND.get_or_init(init_backend).clone()
}

fn init_backend() -> Option<Arc<HsmBackend>> {
    let required = std::env::var("REQUIRE_SOFTHSM").is_ok_and(|v| v == "1");
    let Some(module) = module_path() else {
        assert!(!required, "SoftHSM2 module not found and REQUIRE_SOFTHSM=1");
        eprintln!("SKIPPING: SoftHSM2 module not found (set PKCS11_MODULE)");
        return None;
    };

    let dir = tempfile::tempdir().unwrap().keep();
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n", tokens.display()),
    )
    .unwrap();
    // SAFETY: runs once, inside OnceLock initialisation, before the PKCS#11 module is loaded and
    // before any other code in this process reads SOFTHSM2_CONF.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };

    let status = Command::new("softhsm2-util")
        .args(["--init-token", "--free", "--label", "arkion-test", "--so-pin", "test-so-pin-1234", "--pin", USER_PIN])
        .env("SOFTHSM2_CONF", &conf)
        .output();
    match status {
        Ok(out) if out.status.success() => {}
        other => {
            assert!(!required, "softhsm2-util --init-token failed: {other:?}");
            eprintln!("SKIPPING: softhsm2-util unavailable or failed: {other:?}");
            return None;
        }
    }

    let backend = HsmBackend::connect(HsmConfig {
        module_path: module,
        token_label: "arkion-test".into(),
        pin: AuthPin::from(USER_PIN.to_string()),
        keys: vec![
            KeySpec { key_id: EC_KEY.into(), kind: KeyKind::EcP256 },
            KeySpec { key_id: RSA_KEY.into(), kind: KeyKind::Rsa3072 },
            KeySpec { key_id: KEK.into(), kind: KeyKind::Aes256 },
        ],
        provision_missing: true,
        pool_size: 4,
    })
    .expect("connect to SoftHSM");
    Some(Arc::new(backend))
}

macro_rules! require_hsm {
    () => {
        match backend() {
            Some(b) => b,
            None => return,
        }
    };
}

#[test]
fn ecdsa_sign_and_verify_with_exported_public_key() {
    let hsm = require_hsm!();
    let msg = b"tbsCertificate: CN=leaf.example";
    let der = hsm.sign(EC_KEY, SignAlgorithm::EcdsaP256Sha256, msg).unwrap();

    // Independent verification: only the PEM public key from the HSM + the p256 crate.
    let pem = hsm.public_key_pem(EC_KEY).unwrap();
    let vk = p256::ecdsa::VerifyingKey::from_public_key_pem(&pem).unwrap();
    let sig = p256::ecdsa::Signature::from_der(&der).unwrap();
    vk.verify(msg, &sig).expect("signature must verify with the token's public key");

    assert!(hsm.verify(EC_KEY, SignAlgorithm::EcdsaP256Sha256, msg, &der).unwrap());
    assert!(!hsm.verify(EC_KEY, SignAlgorithm::EcdsaP256Sha256, b"tampered", &der).unwrap());
}

#[test]
fn rsa_pss_sign_and_verify() {
    let hsm = require_hsm!();
    let sig = hsm.sign(RSA_KEY, SignAlgorithm::RsaPssSha256, b"hello").unwrap();
    assert_eq!(sig.len(), 384, "RSA-3072 signature length");
    assert!(hsm.verify(RSA_KEY, SignAlgorithm::RsaPssSha256, b"hello", &sig).unwrap());
    assert!(!hsm.verify(RSA_KEY, SignAlgorithm::RsaPssSha256, b"hellO", &sig).unwrap());
}

#[test]
fn private_and_secret_keys_are_non_exportable() {
    let hsm = require_hsm!();
    for key in [EC_KEY, RSA_KEY, KEK] {
        let p = hsm.key_protection(key).unwrap();
        assert!(p.sensitive, "{key}: CKA_SENSITIVE");
        assert!(!p.extractable, "{key}: CKA_EXTRACTABLE");
        assert!(p.always_sensitive, "{key}: CKA_ALWAYS_SENSITIVE");
        assert!(p.never_extractable, "{key}: CKA_NEVER_EXTRACTABLE");
        assert!(!p.value_readable, "{key}: CKA_VALUE must not be readable");
    }
}

#[test]
fn aes_gcm_inside_hsm() {
    let hsm = require_hsm!();
    let sealed = hsm.encrypt(KEK, b"customer secret", b"tenant=42").unwrap();
    assert_eq!(sealed.iv.len(), 12);
    assert_eq!(sealed.ciphertext.len(), b"customer secret".len() + 16);
    assert_eq!(hsm.decrypt(KEK, &sealed.iv, &sealed.ciphertext, b"tenant=42").unwrap(), b"customer secret");

    // Wrong AAD and flipped ciphertext bit must both fail authentication.
    let r = hsm.decrypt(KEK, &sealed.iv, &sealed.ciphertext, b"tenant=43");
    assert!(matches!(r, Err(CryptoError::DecryptionFailed)), "{r:?}");
    let mut ct = sealed.ciphertext.clone();
    ct[3] ^= 0x80;
    let r = hsm.decrypt(KEK, &sealed.iv, &ct, b"tenant=42");
    assert!(matches!(r, Err(CryptoError::DecryptionFailed)), "{r:?}");

    // Same plaintext twice -> different IV/ciphertext.
    let again = hsm.encrypt(KEK, b"customer secret", b"tenant=42").unwrap();
    assert_ne!(again.iv, sealed.iv);
}

#[test]
fn envelope_encryption_with_wrapped_data_key() {
    let hsm = require_hsm!();
    let wrapped = hsm.generate_data_key(KEK).unwrap();
    assert_eq!(wrapped.len(), 40, "RFC 5649 wrap of a 32-byte key");

    let sealed = hsm.encrypt_with_data_key(KEK, &wrapped, b"bulk data", b"").unwrap();
    let pt = hsm.decrypt_with_data_key(KEK, &wrapped, &sealed.iv, &sealed.ciphertext, b"").unwrap();
    assert_eq!(pt, b"bulk data");

    // A different DEK can't decrypt it; a corrupted wrapped key is rejected by the HSM.
    let other = hsm.generate_data_key(KEK).unwrap();
    let r = hsm.decrypt_with_data_key(KEK, &other, &sealed.iv, &sealed.ciphertext, b"");
    assert!(matches!(r, Err(CryptoError::DecryptionFailed)), "{r:?}");
    let mut bad = wrapped.clone();
    bad[0] ^= 1;
    let r = hsm.encrypt_with_data_key(KEK, &bad, b"x", b"");
    assert!(matches!(r, Err(CryptoError::InvalidInput(_))), "{r:?}");
}

#[test]
fn wrong_key_and_algorithm_errors() {
    let hsm = require_hsm!();
    assert!(matches!(hsm.sign("nope", SignAlgorithm::EcdsaP256Sha256, b"x"), Err(CryptoError::KeyNotFound(_))));
    assert!(matches!(hsm.sign(EC_KEY, SignAlgorithm::RsaPssSha256, b"x"), Err(CryptoError::WrongKeyType { .. })));
    assert!(matches!(hsm.sign(KEK, SignAlgorithm::EcdsaP256Sha256, b"x"), Err(CryptoError::WrongKeyType { .. })));
    assert!(matches!(hsm.encrypt(EC_KEY, b"x", b""), Err(CryptoError::WrongKeyType { .. })));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_sign_end_to_end_under_concurrency() {
    let hsm = require_hsm!();
    let service =
        CryptoService::new(hsm, Limits { max_in_flight: 4, max_queue: 256, acquire_timeout: Duration::from_secs(10) });
    let app = router(AppState { service, metrics: None, max_payload_bytes: 1 << 20 });

    let pem = {
        let resp = app
            .clone()
            .oneshot(Request::get(format!("/v1/keys/{EC_KEY}/public")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
        v["public_key_pem"].as_str().unwrap().to_string()
    };
    let vk = p256::ecdsa::VerifyingKey::from_public_key_pem(&pem).unwrap();

    // 64 concurrent requests through a pool of 4 sessions.
    let tasks: Vec<_> = (0..64)
        .map(|i| {
            let app = app.clone();
            tokio::spawn(async move {
                let payload = format!("certificate #{i}");
                let body = json!({"key_id": EC_KEY, "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode(&payload)});
                let req = Request::post("/v1/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap();
                let resp = app.oneshot(req).await.unwrap();
                let status = resp.status();
                let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
                (payload, status, v)
            })
        })
        .collect();

    for t in tasks {
        let (payload, status, v) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["key_id"], EC_KEY);
        assert_eq!(v["algorithm"], "ECDSA_P256_SHA256");
        assert!(v["duration_ms"].is_u64());
        let sig = p256::ecdsa::Signature::from_der(&B64.decode(v["signature"].as_str().unwrap()).unwrap()).unwrap();
        vk.verify(payload.as_bytes(), &sig).unwrap();
    }
}
