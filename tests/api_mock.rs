//! HTTP-level tests against the mock backend: request validation, error mapping, backpressure.

use std::sync::Arc;
use std::time::Duration;

use arkion_hsm_signer::api::{AppState, SignResponse, router};
use arkion_hsm_signer::backend::mock::MockBackend;
use arkion_hsm_signer::backend::{KeyKind, KeySpec};
use arkion_hsm_signer::service::{CryptoService, Limits};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn app_with(latency: Duration, limits: Limits) -> Router {
    let backend = MockBackend::new(&[
        KeySpec { key_id: "arkion-intermediate-prod".into(), kind: KeyKind::EcP256 },
        KeySpec { key_id: "arkion-kek".into(), kind: KeyKind::Aes256 },
    ])
    .unwrap()
    .with_latency(latency);
    router(AppState { service: CryptoService::new(Arc::new(backend), limits), metrics: None, max_payload_bytes: 1024 })
}

fn app() -> Router {
    app_with(Duration::ZERO, Limits { max_in_flight: 4, max_queue: 16, acquire_timeout: Duration::from_secs(1) })
}

async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    let req =
        Request::post(path).header("content-type", "application/json").body(Body::from(body.to_string())).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn sign_then_verify() {
    let app = app();
    let payload = B64.encode(b"tbsCertificate bytes");
    let (status, body) = post(
        &app,
        "/v1/sign",
        json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": payload}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let resp: SignResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.key_id, "arkion-intermediate-prod");

    let (status, body) = post(
        &app,
        "/v1/verify",
        json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "signature": resp.signature}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);

    let (_, body) = post(
        &app,
        "/v1/verify",
        json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode(b"other"), "signature": resp.signature}),
    )
    .await;
    assert_eq!(body["valid"], false);
}

#[tokio::test]
async fn error_mapping() {
    let app = app();
    let p = B64.encode(b"x");
    let cases = [
        (
            json!({"key_id": "missing", "algorithm": "ECDSA_P256_SHA256", "payload": p}),
            StatusCode::NOT_FOUND,
            "key_not_found",
        ),
        (
            json!({"key_id": "arkion-kek", "algorithm": "ECDSA_P256_SHA256", "payload": p}),
            StatusCode::BAD_REQUEST,
            "algorithm_key_mismatch",
        ),
        (
            json!({"key_id": "arkion-intermediate-prod", "algorithm": "MD5", "payload": p}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": "@@@"}),
            StatusCode::BAD_REQUEST,
            "invalid_base64",
        ),
        (
            json!({"key_id": "bad id\n", "algorithm": "ECDSA_P256_SHA256", "payload": p}),
            StatusCode::BAD_REQUEST,
            "invalid_key_id",
        ),
        (
            json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode([0u8; 2048])}),
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        ),
    ];
    for (req, status, code) in cases {
        let (got, body) = post(&app, "/v1/sign", req.clone()).await;
        assert_eq!(got, status, "request {req} -> {body}");
        assert_eq!(body["error"]["code"], code, "request {req} -> {body}");
    }
}

#[tokio::test]
async fn encrypt_decrypt_and_tamper() {
    let app = app();
    let (status, enc) = post(
        &app,
        "/v1/encrypt",
        json!({"key_id": "arkion-kek", "plaintext": B64.encode(b"pii"), "aad": B64.encode(b"tenant-1")}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enc}");

    let (status, dec) = post(&app, "/v1/decrypt", json!({"key_id": "arkion-kek", "iv": enc["iv"], "ciphertext": enc["ciphertext"], "aad": B64.encode(b"tenant-1")})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(B64.decode(dec["plaintext"].as_str().unwrap()).unwrap(), b"pii");

    let (status, body) = post(&app, "/v1/decrypt", json!({"key_id": "arkion-kek", "iv": enc["iv"], "ciphertext": enc["ciphertext"], "aad": B64.encode(b"tenant-2")})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "decryption_failed");
}

#[tokio::test]
async fn overload_returns_503_with_retry_after() {
    let app = app_with(
        Duration::from_millis(200),
        Limits { max_in_flight: 1, max_queue: 0, acquire_timeout: Duration::from_secs(1) },
    );
    let body =
        json!({"key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode(b"x")})
            .to_string();
    let send = || {
        let app = app.clone();
        let body = body.clone();
        async move {
            let req =
                Request::post("/v1/sign").header("content-type", "application/json").body(Body::from(body)).unwrap();
            app.oneshot(req).await.unwrap()
        }
    };
    let (a, b) = tokio::join!(send(), send());
    let mut statuses = [a.status(), b.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE]);
    let rejected = if a.status() == StatusCode::SERVICE_UNAVAILABLE { a } else { b };
    assert_eq!(rejected.headers()["retry-after"], "1");
}
