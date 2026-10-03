//! HTTP API.
//!
//! Logging policy: we log key ids, algorithms, sizes, durations and error codes. We never log
//! payloads, plaintexts, ciphertexts, signatures, wrapped keys, PINs or request bodies.

use std::time::Instant;

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::backend::{CryptoError, SignAlgorithm, is_valid_key_id};
use crate::service::{CryptoService, ServiceError};

#[derive(Clone)]
pub struct AppState {
    pub service: CryptoService,
    pub metrics: Option<PrometheusHandle>,
    pub max_payload_bytes: usize,
}

pub fn router(state: AppState) -> Router {
    // base64 inflates by 4/3; leave headroom for the rest of the JSON document.
    let body_limit = state.max_payload_bytes / 3 * 4 + 16 * 1024;
    Router::new()
        .route("/v1/sign", post(sign))
        .route("/v1/verify", post(verify))
        .route("/v1/keys/{key_id}/public", get(public_key))
        .route("/v1/encrypt", post(encrypt))
        .route("/v1/decrypt", post(decrypt))
        .route("/v1/data-keys", post(generate_data_key))
        .route("/v1/data-keys/encrypt", post(encrypt_with_data_key))
        .route("/v1/data-keys/decrypt", post(decrypt_with_data_key))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---------- request / response types ----------

#[derive(Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub algorithm: SignAlgorithm,
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub key_id: String,
    pub algorithm: SignAlgorithm,
    pub signature: String,
    pub duration_ms: u64,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub key_id: String,
    pub algorithm: SignAlgorithm,
    pub payload: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse {
    pub key_id: String,
    pub valid: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub key_id: String,
    pub public_key_pem: String,
}

#[derive(Deserialize)]
pub struct EncryptRequest {
    pub key_id: String,
    pub plaintext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptResponse {
    pub key_id: String,
    pub algorithm: String,
    pub iv: String,
    /// Ciphertext with the 16-byte GCM tag appended.
    pub ciphertext: String,
}

#[derive(Deserialize)]
pub struct DecryptRequest {
    pub key_id: String,
    pub iv: String,
    pub ciphertext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptResponse {
    pub key_id: String,
    pub plaintext: String,
}

#[derive(Deserialize)]
pub struct DataKeyRequest {
    pub kek_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct DataKeyResponse {
    pub kek_id: String,
    pub algorithm: String,
    pub wrapped_key: String,
}

#[derive(Deserialize)]
pub struct DataKeyEncryptRequest {
    pub kek_id: String,
    pub wrapped_key: String,
    pub plaintext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

#[derive(Deserialize)]
pub struct DataKeyDecryptRequest {
    pub kek_id: String,
    pub wrapped_key: String,
    pub iv: String,
    pub ciphertext: String,
    #[serde(default)]
    pub aad: Option<String>,
}

// ---------- handlers ----------

type JsonBody<T> = Result<Json<T>, JsonRejection>;

async fn sign(State(st): State<AppState>, body: JsonBody<SignRequest>) -> Result<Json<SignResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.key_id)?;
    let payload = decode_b64("payload", &req.payload)?;
    check_size(&st, payload.len())?;
    let payload_len = payload.len();

    let (key_id, alg) = (req.key_id.clone(), req.algorithm);
    let result = st.service.execute("sign", move |b| b.sign(&key_id, alg, &payload)).await;
    let elapsed = started.elapsed();
    let signature = log_outcome("sign", &req.key_id, Some(alg), payload_len, elapsed, result)?;

    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: alg,
        signature: B64.encode(signature),
        duration_ms: elapsed.as_millis() as u64,
    }))
}

async fn verify(State(st): State<AppState>, body: JsonBody<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.key_id)?;
    let payload = decode_b64("payload", &req.payload)?;
    check_size(&st, payload.len())?;
    let signature = decode_b64("signature", &req.signature)?;
    let payload_len = payload.len();

    // Verification uses only the cached public key, but still goes through the service so it is
    // subject to the same backpressure and metrics.
    let (key_id, alg) = (req.key_id.clone(), req.algorithm);
    let result = st.service.execute("verify", move |b| b.verify(&key_id, alg, &payload, &signature)).await;
    let valid = log_outcome("verify", &req.key_id, Some(alg), payload_len, started.elapsed(), result)?;
    Ok(Json(VerifyResponse { key_id: req.key_id, valid }))
}

async fn public_key(
    State(st): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    check_key_id(&key_id)?;
    let id = key_id.clone();
    let pem = st.service.execute("public_key", move |b| b.public_key_pem(&id)).await?;
    Ok(Json(PublicKeyResponse { key_id, public_key_pem: pem }))
}

async fn encrypt(
    State(st): State<AppState>,
    body: JsonBody<EncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.key_id)?;
    let plaintext = decode_b64("plaintext", &req.plaintext)?;
    check_size(&st, plaintext.len())?;
    let aad = decode_opt_b64("aad", req.aad.as_deref())?;
    let len = plaintext.len();

    let key_id = req.key_id.clone();
    let result = st.service.execute("encrypt", move |b| b.encrypt(&key_id, &plaintext, &aad)).await;
    let sealed = log_outcome("encrypt", &req.key_id, None, len, started.elapsed(), result)?;
    Ok(Json(EncryptResponse {
        key_id: req.key_id,
        algorithm: "AES_256_GCM".into(),
        iv: B64.encode(sealed.iv),
        ciphertext: B64.encode(sealed.ciphertext),
    }))
}

async fn decrypt(
    State(st): State<AppState>,
    body: JsonBody<DecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.key_id)?;
    let iv = decode_b64("iv", &req.iv)?;
    let ciphertext = decode_b64("ciphertext", &req.ciphertext)?;
    check_size(&st, ciphertext.len())?;
    let aad = decode_opt_b64("aad", req.aad.as_deref())?;
    let len = ciphertext.len();

    let key_id = req.key_id.clone();
    let result = st.service.execute("decrypt", move |b| b.decrypt(&key_id, &iv, &ciphertext, &aad)).await;
    let plaintext = log_outcome("decrypt", &req.key_id, None, len, started.elapsed(), result)?;
    Ok(Json(DecryptResponse { key_id: req.key_id, plaintext: B64.encode(plaintext) }))
}

async fn generate_data_key(
    State(st): State<AppState>,
    body: JsonBody<DataKeyRequest>,
) -> Result<Json<DataKeyResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.kek_id)?;
    let kek_id = req.kek_id.clone();
    let result = st.service.execute("generate_data_key", move |b| b.generate_data_key(&kek_id)).await;
    let wrapped = log_outcome("generate_data_key", &req.kek_id, None, 0, started.elapsed(), result)?;
    Ok(Json(DataKeyResponse {
        kek_id: req.kek_id,
        algorithm: "AES_256/AES_KEY_WRAP_PAD".into(),
        wrapped_key: B64.encode(wrapped),
    }))
}

async fn encrypt_with_data_key(
    State(st): State<AppState>,
    body: JsonBody<DataKeyEncryptRequest>,
) -> Result<Json<EncryptResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.kek_id)?;
    let wrapped = decode_b64("wrapped_key", &req.wrapped_key)?;
    let plaintext = decode_b64("plaintext", &req.plaintext)?;
    check_size(&st, plaintext.len())?;
    let aad = decode_opt_b64("aad", req.aad.as_deref())?;
    let len = plaintext.len();

    let kek_id = req.kek_id.clone();
    let result = st
        .service
        .execute("data_key_encrypt", move |b| b.encrypt_with_data_key(&kek_id, &wrapped, &plaintext, &aad))
        .await;
    let sealed = log_outcome("data_key_encrypt", &req.kek_id, None, len, started.elapsed(), result)?;
    Ok(Json(EncryptResponse {
        key_id: req.kek_id,
        algorithm: "AES_256_GCM".into(),
        iv: B64.encode(sealed.iv),
        ciphertext: B64.encode(sealed.ciphertext),
    }))
}

async fn decrypt_with_data_key(
    State(st): State<AppState>,
    body: JsonBody<DataKeyDecryptRequest>,
) -> Result<Json<DecryptResponse>, ApiError> {
    let started = Instant::now();
    let Json(req) = body?;
    check_key_id(&req.kek_id)?;
    let wrapped = decode_b64("wrapped_key", &req.wrapped_key)?;
    let iv = decode_b64("iv", &req.iv)?;
    let ciphertext = decode_b64("ciphertext", &req.ciphertext)?;
    check_size(&st, ciphertext.len())?;
    let aad = decode_opt_b64("aad", req.aad.as_deref())?;
    let len = ciphertext.len();

    let kek_id = req.kek_id.clone();
    let result = st
        .service
        .execute("data_key_decrypt", move |b| b.decrypt_with_data_key(&kek_id, &wrapped, &iv, &ciphertext, &aad))
        .await;
    let plaintext = log_outcome("data_key_decrypt", &req.kek_id, None, len, started.elapsed(), result)?;
    Ok(Json(DecryptResponse { key_id: req.kek_id, plaintext: B64.encode(plaintext) }))
}

async fn readyz(State(st): State<AppState>) -> Result<&'static str, ApiError> {
    st.service.execute("health_check", |b| b.health_check()).await?;
    Ok("ready")
}

async fn metrics(State(st): State<AppState>) -> Response {
    match st.metrics {
        Some(h) => ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], h.render()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---------- helpers ----------

fn check_key_id(id: &str) -> Result<(), ApiError> {
    if is_valid_key_id(id) {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid_key_id", "key_id must be 1-128 chars of [A-Za-z0-9._-]"))
    }
}

fn check_size(st: &AppState, len: usize) -> Result<(), ApiError> {
    if len > st.max_payload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("decoded payload exceeds {} bytes", st.max_payload_bytes),
        ));
    }
    Ok(())
}

fn decode_b64(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(value)
        .map_err(|_| ApiError::bad_request("invalid_base64", format!("'{field}' is not valid standard base64")))
}

fn decode_opt_b64(field: &str, value: Option<&str>) -> Result<Vec<u8>, ApiError> {
    value.map_or(Ok(Vec::new()), |v| decode_b64(field, v))
}

/// Emits one structured log line per operation. Never includes payload contents.
fn log_outcome<T>(
    op: &'static str,
    key_id: &str,
    alg: Option<SignAlgorithm>,
    input_len: usize,
    elapsed: std::time::Duration,
    result: Result<T, ServiceError>,
) -> Result<T, ApiError> {
    let algorithm = alg.map(SignAlgorithm::as_str).unwrap_or("-");
    let duration_us = elapsed.as_micros() as u64;
    match &result {
        Ok(_) => info!(op, key_id, algorithm, input_len, duration_us, "operation succeeded"),
        Err(e) => {
            let api = ApiError::from_service(e);
            if api.status.is_server_error() {
                // Full detail (CKR_* code) goes to logs; clients only get a generic message.
                error!(op, key_id, algorithm, input_len, duration_us, error = %e, "operation failed");
            } else {
                warn!(op, key_id, algorithm, input_len, duration_us, error = %e, "operation rejected");
            }
        }
    }
    result.map_err(ApiError::from)
}

// ---------- errors ----------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after: Option<u32>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), retry_after: None }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unavailable(code: &'static str, message: &str) -> Self {
        Self { retry_after: Some(1), ..Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message) }
    }

    fn from_service(e: &ServiceError) -> Self {
        match e {
            ServiceError::Overloaded => Self::unavailable("overloaded", "signing capacity exhausted, retry later"),
            ServiceError::AcquireTimeout => Self::unavailable("hsm_busy", "timed out waiting for an HSM session"),
            ServiceError::Internal(_) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"),
            ServiceError::Crypto(c) => match c {
                CryptoError::KeyNotFound(_) => Self::new(StatusCode::NOT_FOUND, "key_not_found", c.to_string()),
                CryptoError::WrongKeyType { .. } => Self::bad_request("algorithm_key_mismatch", c.to_string()),
                CryptoError::InvalidInput(_) => Self::bad_request("invalid_input", c.to_string()),
                CryptoError::DecryptionFailed => Self::bad_request("decryption_failed", c.to_string()),
                CryptoError::Unsupported(_) => Self::bad_request("unsupported", c.to_string()),
                CryptoError::Unavailable(_) => Self::unavailable("hsm_unavailable", "HSM temporarily unavailable"),
                CryptoError::Hsm { .. } => {
                    Self::new(StatusCode::INTERNAL_SERVER_ERROR, "hsm_error", "HSM operation failed")
                }
            },
        }
    }
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        Self::from_service(&e)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(r: JsonRejection) -> Self {
        // body_text() can echo serde's message (field names / expected values), not body contents.
        let status = if r.status() == StatusCode::PAYLOAD_TOO_LARGE { r.status() } else { StatusCode::BAD_REQUEST };
        Self::new(status, "invalid_request", r.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody { error: ErrorDetail { code: self.code, message: &self.message } };
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}
