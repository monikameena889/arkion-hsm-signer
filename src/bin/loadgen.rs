//! Closed-loop load generator for `POST /v1/sign`.
//!
//! N workers each send requests back-to-back for a fixed duration. Reports throughput,
//! latency percentiles (client-observed, end to end) and error rate.
//!
//! cargo run --release --bin loadgen -- --concurrency 1,10,100,500 --duration-secs 15

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use clap::Parser;
use serde_json::json;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Comma-separated concurrency levels to run in sequence.
    #[arg(long, default_value = "1,10,100,500", value_delimiter = ',')]
    concurrency: Vec<usize>,
    #[arg(long, default_value_t = 15)]
    duration_secs: u64,
    #[arg(long, default_value_t = 2)]
    warmup_secs: u64,
    #[arg(long, default_value = "arkion-intermediate-prod")]
    key_id: String,
    #[arg(long, default_value = "ECDSA_P256_SHA256")]
    algorithm: String,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    /// Per-request client timeout.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Default)]
struct WorkerStats {
    latencies_us: Vec<u64>,
    errors: BTreeMap<String, u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let body = Arc::new(
        json!({
            "key_id": args.key_id,
            "algorithm": args.algorithm,
            "payload": base64::engine::general_purpose::STANDARD.encode(vec![0x42u8; args.payload_bytes]),
        })
        .to_string(),
    );
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(1024)
        .timeout(Duration::from_millis(args.timeout_ms))
        .build()?;
    let url = format!("{}/v1/sign", args.url.trim_end_matches('/'));

    println!(
        "| concurrency | requests | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | error rate | errors |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---|");
    for &c in &args.concurrency {
        if args.warmup_secs > 0 {
            run(&client, &url, &body, c, Duration::from_secs(args.warmup_secs)).await;
        }
        let started = Instant::now();
        let stats = run(&client, &url, &body, c, Duration::from_secs(args.duration_secs)).await;
        report(c, started.elapsed(), stats);
    }
    Ok(())
}

async fn run(
    client: &reqwest::Client,
    url: &str,
    body: &Arc<String>,
    concurrency: usize,
    duration: Duration,
) -> WorkerStats {
    let deadline = Instant::now() + duration;
    let workers: Vec<_> = (0..concurrency)
        .map(|_| {
            let (client, url, body) = (client.clone(), url.to_string(), body.clone());
            tokio::spawn(async move {
                let mut stats = WorkerStats::default();
                while Instant::now() < deadline {
                    let t = Instant::now();
                    let res = client
                        .post(&url)
                        .header("content-type", "application/json")
                        .body(body.as_str().to_owned())
                        .send()
                        .await;
                    let outcome = match res {
                        Ok(r) if r.status().is_success() => {
                            let _ = r.bytes().await;
                            None
                        }
                        Ok(r) => Some(r.status().as_u16().to_string()),
                        Err(e) if e.is_timeout() => Some("timeout".into()),
                        Err(_) => Some("connect".into()),
                    };
                    stats.latencies_us.push(t.elapsed().as_micros() as u64);
                    if let Some(kind) = outcome {
                        *stats.errors.entry(kind).or_default() += 1;
                    }
                }
                stats
            })
        })
        .collect();

    let mut total = WorkerStats::default();
    for w in workers {
        let s = w.await.expect("worker panicked");
        total.latencies_us.extend(s.latencies_us);
        for (k, v) in s.errors {
            *total.errors.entry(k).or_default() += v;
        }
    }
    total
}

fn report(concurrency: usize, elapsed: Duration, mut stats: WorkerStats) {
    stats.latencies_us.sort_unstable();
    let n = stats.latencies_us.len();
    let pct = |p: f64| -> f64 {
        if n == 0 {
            return 0.0;
        }
        let idx = ((p / 100.0) * (n as f64 - 1.0)).round() as usize;
        stats.latencies_us[idx] as f64 / 1000.0
    };
    let errors: u64 = stats.errors.values().sum();
    let ok = n as u64 - errors;
    let error_detail = if stats.errors.is_empty() {
        "-".to_string()
    } else {
        stats.errors.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(", ")
    };
    println!(
        "| {concurrency} | {n} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2}% | {error_detail} |",
        ok as f64 / elapsed.as_secs_f64(),
        pct(50.0),
        pct(95.0),
        pct(99.0),
        pct(100.0),
        if n == 0 { 0.0 } else { errors as f64 * 100.0 / n as f64 },
    );
}
