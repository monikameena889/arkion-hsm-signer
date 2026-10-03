//! Bounded-concurrency execution of backend operations.
//!
//! HSM sessions are a scarce resource, so every operation goes through two gates:
//!
//! 1. **Admission** (`max_in_flight + max_queue` permits, `try_acquire`): if the service already
//!    holds that many requests it sheds load immediately with 503 instead of queueing unboundedly.
//! 2. **Execution** (`max_in_flight` permits, equal to the HSM session pool size): the request waits
//!    up to `acquire_timeout` for a session; past that it fails with 503 rather than piling latency.
//!
//! The PKCS#11 call itself runs on Tokio's blocking pool so it never stalls the async reactor.

use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics::{counter, gauge, histogram};
use tokio::sync::Semaphore;

use crate::backend::{CryptoBackend, CryptoError};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Concurrent backend operations; should equal the HSM session pool size.
    pub max_in_flight: usize,
    /// Requests allowed to wait for a session before new ones are rejected.
    pub max_queue: usize,
    /// Maximum time a request waits for a session.
    pub acquire_timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("service overloaded: request queue is full")]
    Overloaded,
    #[error("timed out waiting for an HSM session")]
    AcquireTimeout,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ServiceError {
    fn metric_label(&self) -> &'static str {
        match self {
            Self::Overloaded => "overloaded",
            Self::AcquireTimeout => "acquire_timeout",
            Self::Internal(_) => "internal",
            Self::Crypto(e) => match e {
                CryptoError::KeyNotFound(_) => "key_not_found",
                CryptoError::WrongKeyType { .. } => "wrong_key_type",
                CryptoError::InvalidInput(_) => "invalid_input",
                CryptoError::DecryptionFailed => "decryption_failed",
                CryptoError::Unsupported(_) => "unsupported",
                CryptoError::Unavailable(_) => "hsm_unavailable",
                CryptoError::Hsm { .. } => "hsm_error",
            },
        }
    }
}

#[derive(Clone)]
pub struct CryptoService {
    backend: Arc<dyn CryptoBackend>,
    admission: Arc<Semaphore>,
    in_flight: Arc<Semaphore>,
    limits: Limits,
}

impl CryptoService {
    pub fn new(backend: Arc<dyn CryptoBackend>, limits: Limits) -> Self {
        assert!(limits.max_in_flight > 0, "max_in_flight must be > 0");
        gauge!("hsm_pool_size").set(limits.max_in_flight as f64);
        Self {
            backend,
            admission: Arc::new(Semaphore::new(limits.max_in_flight + limits.max_queue)),
            in_flight: Arc::new(Semaphore::new(limits.max_in_flight)),
            limits,
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Runs `f` against the backend under the concurrency limits and records metrics.
    pub async fn execute<R, F>(&self, op: &'static str, f: F) -> Result<R, ServiceError>
    where
        R: Send + 'static,
        F: FnOnce(&dyn CryptoBackend) -> Result<R, CryptoError> + Send + 'static,
    {
        let started = Instant::now();
        let result = self.execute_inner(f).await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(e) => e.metric_label(),
        };
        histogram!("crypto_op_duration_seconds", "op" => op, "outcome" => outcome)
            .record(started.elapsed().as_secs_f64());
        counter!("crypto_op_total", "op" => op, "outcome" => outcome).increment(1);
        result
    }

    async fn execute_inner<R, F>(&self, f: F) -> Result<R, ServiceError>
    where
        R: Send + 'static,
        F: FnOnce(&dyn CryptoBackend) -> Result<R, CryptoError> + Send + 'static,
    {
        let _admitted = self.admission.clone().try_acquire_owned().map_err(|_| ServiceError::Overloaded)?;

        let wait_started = Instant::now();
        gauge!("hsm_pool_waiting").increment(1.0);
        let acquired = tokio::time::timeout(self.limits.acquire_timeout, self.in_flight.clone().acquire_owned()).await;
        gauge!("hsm_pool_waiting").decrement(1.0);
        histogram!("hsm_pool_acquire_wait_seconds").record(wait_started.elapsed().as_secs_f64());
        let permit = match acquired {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(ServiceError::Internal("semaphore closed".into())),
            Err(_) => return Err(ServiceError::AcquireTimeout),
        };

        gauge!("hsm_pool_in_use").increment(1.0);
        let backend = self.backend.clone();
        let joined = tokio::task::spawn_blocking(move || {
            let result = f(backend.as_ref());
            drop(permit);
            gauge!("hsm_pool_in_use").decrement(1.0);
            result
        })
        .await;

        match joined {
            Ok(r) => r.map_err(ServiceError::from),
            Err(e) => Err(ServiceError::Internal(format!("backend task failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::mock::MockBackend;
    use crate::backend::{KeyKind, KeySpec, SignAlgorithm};

    fn service(latency_ms: u64, limits: Limits) -> CryptoService {
        let backend = MockBackend::new(&[KeySpec { key_id: "k".into(), kind: KeyKind::EcP256 }])
            .unwrap()
            .with_latency(Duration::from_millis(latency_ms));
        CryptoService::new(Arc::new(backend), limits)
    }

    async fn sign(svc: &CryptoService) -> Result<Vec<u8>, ServiceError> {
        svc.execute("sign", |b| b.sign("k", SignAlgorithm::EcdsaP256Sha256, b"x")).await
    }

    #[tokio::test]
    async fn sheds_load_when_queue_full() {
        let svc = service(200, Limits { max_in_flight: 1, max_queue: 1, acquire_timeout: Duration::from_secs(5) });
        let (a, b, c) = tokio::join!(sign(&svc), sign(&svc), sign(&svc));
        let results = [a, b, c];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
        assert_eq!(results.iter().filter(|r| matches!(r, Err(ServiceError::Overloaded))).count(), 1);
    }

    #[tokio::test]
    async fn times_out_waiting_for_session() {
        let svc = service(300, Limits { max_in_flight: 1, max_queue: 10, acquire_timeout: Duration::from_millis(50) });
        let (a, b) = tokio::join!(sign(&svc), sign(&svc));
        assert!(a.is_ok());
        assert!(matches!(b, Err(ServiceError::AcquireTimeout)));
    }

    #[tokio::test]
    async fn bounds_concurrency() {
        let svc = service(20, Limits { max_in_flight: 4, max_queue: 100, acquire_timeout: Duration::from_secs(5) });
        let started = Instant::now();
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let s = svc.clone();
                tokio::spawn(async move { sign(&s).await })
            })
            .collect();
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        // 16 ops of 20ms through 4 lanes => at least 4 waves (~80ms).
        assert!(started.elapsed() >= Duration::from_millis(75), "{:?}", started.elapsed());
    }
}
