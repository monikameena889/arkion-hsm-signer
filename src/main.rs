use std::sync::Arc;

use anyhow::Context;
use arkion_hsm_signer::api::{AppState, router};
use arkion_hsm_signer::backend::hsm::{HsmBackend, HsmConfig};
use arkion_hsm_signer::backend::mock::MockBackend;
use arkion_hsm_signer::backend::{CryptoBackend, KeyKind};
use arkion_hsm_signer::config::{BackendKind, Config, LogFormat};
use arkion_hsm_signer::service::{CryptoService, Limits};
use clap::Parser;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();
    init_tracing(cfg.log_format);

    let metrics = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("_seconds".into()),
            &[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
        )?
        .install_recorder()
        .context("installing Prometheus recorder")?;

    let backend: Arc<dyn CryptoBackend> = match cfg.backend {
        BackendKind::Hsm => {
            let hsm_cfg = HsmConfig {
                module_path: cfg.pkcs11_module.clone(),
                token_label: cfg.token_label.clone(),
                pin: cfg.load_pin()?,
                keys: cfg.keys.clone(),
                provision_missing: cfg.provision_keys,
                pool_size: cfg.pool_size,
            };
            // PKCS#11 initialisation and key generation block; keep them off the reactor.
            let hsm = tokio::task::spawn_blocking(move || HsmBackend::connect(hsm_cfg))
                .await?
                .context("connecting to HSM")?;
            Arc::new(hsm)
        }
        BackendKind::Mock => {
            warn!("using the in-memory MOCK backend: keys are not protected, do not use in production");
            let specs: Vec<_> = cfg.keys.iter().filter(|k| k.kind != KeyKind::Rsa3072).cloned().collect();
            Arc::new(MockBackend::new(&specs)?)
        }
    };

    let limits =
        Limits { max_in_flight: cfg.pool_size, max_queue: cfg.max_queue, acquire_timeout: cfg.acquire_timeout() };
    let service = CryptoService::new(backend, limits);
    let app = router(AppState { service, metrics: Some(metrics), max_payload_bytes: cfg.max_payload_bytes });

    let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
    info!(
        addr = %cfg.bind_addr,
        backend = ?cfg.backend,
        pool_size = limits.max_in_flight,
        max_queue = limits.max_queue,
        acquire_timeout_ms = cfg.acquire_timeout_ms,
        "listening"
    );
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    info!("shut down cleanly");
    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Text => builder.init(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
