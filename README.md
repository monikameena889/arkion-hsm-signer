# Arkion HSM Signing Service

A Rust (Axum + Tokio) signing and key-management service backed by a PKCS#11 token. It is
developed and tested against **SoftHSM2**, but nothing in the code is SoftHSM-specific.

- `POST /v1/sign`: ECDSA P-256 / SHA-256 (required) and RSA-PSS / SHA-256 (optional extension). The private key never leaves the token.
- AES-256-GCM encryption and decryption with a non-exportable key inside the token.
- Envelope encryption (extension): data keys are generated in the HSM, wrapped with RFC 5649 (`CKM_AES_KEY_WRAP_PAD`), and unwrapped only into ephemeral HSM session objects.
- A bounded HSM session pool with admission control, acquire timeouts and load shedding (`503` + `Retry-After`).
- Prometheus metrics for latency, failures and pool saturation, plus structured (JSON) logs that never contain secrets.
- A swappable `CryptoBackend` trait with two implementations: PKCS#11 and an in-memory mock.
- 21 automated tests, including 7 integration tests against a real SoftHSM2 token. They pass on SoftHSM 2.7.0 (macOS) and 2.6.1 (Debian, in Docker).
- A container image that includes the SoftHSM2 test environment.

---

## Contents

1. [Quick start](#1-quick-start)
2. [API](#2-api)
3. [Code layout](#3-code-layout)
4. [HSM and key-management approach](#4-hsm-and-key-management-approach)
5. [Concurrency and session management](#5-concurrency-and-session-management)
6. [Benchmark results](#6-benchmark-results)
7. [Security considerations](#7-security-considerations)
8. [Architectural decisions, assumptions and known limitations](#8-architectural-decisions-assumptions-and-known-limitations)
9. [Production considerations](#9-production-considerations)
10. [Architecture question: 100,000 certificates per second](#10-architecture-question-100000-short-lived-certificates-per-second)

---

## 1. Quick start

### Docker (the deliverable)

```bash
# Build the runtime image
docker build -t arkion-hsm-signer:latest .

# Run the unit + SoftHSM integration tests inside the build toolchain (fails the build on test failure)
docker build --target test .

# Create a user PIN (a file, mounted as a secret; never put it on the command line)
mkdir -p secrets && (umask 077; openssl rand -hex 16 > secrets/hsm_user_pin) && chmod 644 secrets/hsm_user_pin

# Run it. The first start initialises a SoftHSM2 token in the volume and generates the keys.
docker run -d --name arkion-signer -p 8080:8080 \
  -v arkion-tokens:/var/lib/softhsm/tokens \
  -v "$PWD/secrets/hsm_user_pin:/run/secrets/hsm_user_pin:ro" \
  -e HSM_PIN_FILE=/run/secrets/hsm_user_pin \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  arkion-hsm-signer:latest

curl -s localhost:8080/readyz          # -> ready
```

Or use `docker compose up --build` after creating `secrets/hsm_user_pin`. The image also includes the load generator:
`docker exec arkion-signer loadgen --concurrency 1,10,100,500`.

> `chmod 644` is only there so the container's non-root user (uid 10001) can read a bind-mounted file.
> Docker/K8s secrets handle this for you.

### Local (macOS / Linux)

```bash
brew install rust softhsm            # or: apt install softhsm2 + rustup
cargo test                           # unit + API + SoftHSM integration tests
source <(scripts/dev-token.sh)       # isolated token in ./.softhsm, random PINs in files
HSM_PROVISION_KEYS=true cargo run --release
```

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PKCS11_MODULE` | `/usr/lib/softhsm/libsofthsm2.so` (Linux) | PKCS#11 library |
| `HSM_TOKEN_LABEL` | `arkion` | Token to use |
| `HSM_PIN_FILE` / `HSM_PIN` | – | User PIN. File preferred. Deliberately not a CLI flag |
| `HSM_KEYS` | `arkion-intermediate-prod:ec-p256,arkion-rsa-prod:rsa-3072,arkion-kek:aes-256` | Keys to load |
| `HSM_PROVISION_KEYS` | `false` (image: `true`) | Generate missing keys. Dev/test only |
| `HSM_POOL_SIZE` | `8` | Open sessions = maximum concurrent HSM operations |
| `MAX_QUEUE` | `512` | Requests allowed to wait for a session before the service sheds load |
| `ACQUIRE_TIMEOUT_MS` | `2000` | Maximum wait for a session |
| `MAX_PAYLOAD_BYTES` | `1048576` | Maximum decoded payload size |
| `LOG_FORMAT` | `text` (image: `json`) | `text` or `json` |
| `BACKEND` | `hsm` | `mock` = in-memory keys, for development only |

---

## 2. API

All binary fields are standard base64. Errors always use the shape
`{"error": {"code": "...", "message": "..."}}`.

```bash
curl -s localhost:8080/v1/sign -H 'content-type: application/json' -d '{
  "key_id": "arkion-intermediate-prod",
  "algorithm": "ECDSA_P256_SHA256",
  "payload": "aGVsbG8gYXJraW9u"
}'
# {"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","signature":"MEYCIQ...","duration_ms":0}
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/sign` | `{key_id, algorithm, payload}` → `{key_id, algorithm, signature, duration_ms}`. Algorithms: `ECDSA_P256_SHA256` (DER signature, as used in X.509) and `RSA_PSS_SHA256` (MGF1-SHA256, 32-byte salt) |
| `POST /v1/verify` | `{key_id, algorithm, payload, signature}` → `{valid}` |
| `GET /v1/keys/{key_id}/public` | SubjectPublicKeyInfo PEM |
| `POST /v1/encrypt` / `POST /v1/decrypt` | AES-256-GCM with an HSM key. Optional `aad`. `ciphertext` includes the 16-byte tag |
| `POST /v1/data-keys` | Returns a fresh AES-256 data key, wrapped under `kek_id` |
| `POST /v1/data-keys/encrypt` / `.../decrypt` | Envelope encryption with a wrapped data key |
| `GET /healthz`, `GET /readyz` | Liveness, and readiness (which round-trips to the token) |
| `GET /metrics` | Prometheus |

You can check signatures independently of the service:

```bash
curl -s localhost:8080/v1/keys/arkion-intermediate-prod/public | jq -r .public_key_pem > pub.pem
echo "$SIG" | base64 -d > sig.der && printf 'hello arkion' > msg
openssl dgst -sha256 -verify pub.pem -signature sig.der msg     # Verified OK
```

### Error mapping

| Condition | HTTP | `code` |
|---|---|---|
| Malformed JSON, unknown algorithm, bad base64, bad key id | 400 | `invalid_request` / `invalid_base64` / `invalid_key_id` |
| Algorithm does not match the key type | 400 | `algorithm_key_mismatch` |
| GCM authentication failure (tag, AAD or IV) | 400 | `decryption_failed` |
| Unknown key | 404 | `key_not_found` |
| Payload too large | 413 | `payload_too_large` |
| Queue full | 503 + `Retry-After: 1` | `overloaded` |
| No session within `ACQUIRE_TIMEOUT_MS` | 503 + `Retry-After: 1` | `hsm_busy` |
| Token removed, device error, logged out | 503 + `Retry-After: 1` | `hsm_unavailable` |
| Any other PKCS#11 error | 500 | `hsm_error`. The client gets a generic message; the `CKR_*` code is logged |

---

## 3. Code layout

```
src/
  backend/mod.rs     CryptoBackend trait, algorithm/key types, CryptoError, software public-key verification
  backend/hsm.rs     PKCS#11 implementation: login, key lookup/provisioning, session pool, sign/GCM/wrap
  backend/mock.rs    In-memory implementation (tests, local dev)
  service.rs         Admission control, bounded concurrency, timeouts, spawn_blocking, metrics
  api.rs             Axum routes, validation, error -> HTTP mapping, structured logging
  config.rs          CLI/env configuration and PIN loading
  main.rs            Wiring, Prometheus recorder, graceful shutdown
  bin/loadgen.rs     Closed-loop load generator (throughput, p50/p95/p99, error rate)
tests/
  api_mock.rs            HTTP behaviour against the mock (error mapping, 503 + Retry-After, ...)
  softhsm_integration.rs Real PKCS#11: sign/verify, RSA-PSS, non-exportability, GCM, wrapping, 64 concurrent HTTP signs
docker/                  entrypoint (token init) and SoftHSM config
scripts/dev-token.sh     Isolated local token with random PINs
```

The layers are `api → service → dyn CryptoBackend`. `CryptoBackend` is deliberately **synchronous**:
PKCS#11 calls block the calling thread, so making the trait async would only hide that. The service
layer is the single place that moves work onto Tokio's blocking pool, and it does that under a semaphore.

---

## 4. HSM and key-management approach

**Authentication.** The user PIN comes from `HSM_PIN_FILE` (a mounted secret) or from `HSM_PIN`. It is
never a CLI argument (that would expose it in `ps`), never logged, and is held in `cryptoki`'s
`AuthPin` (`secrecy::SecretString`, which is zeroized on drop). PKCS#11 login state is per application,
so the first session performs `C_Login` and later sessions treat `CKR_USER_ALREADY_LOGGED_IN` as success.

**Key generation.** All keys are generated inside the token:

| Key | Mechanism | Important attributes |
|---|---|---|
| ECDSA P-256 | `CKM_EC_KEY_PAIR_GEN` (`CKA_EC_PARAMS` = prime256v1 OID) | private key: `TOKEN, PRIVATE, SENSITIVE=true, EXTRACTABLE=false, MODIFIABLE=false, SIGN` |
| RSA-3072 | `CKM_RSA_PKCS_KEY_PAIR_GEN`, e = 65537 | same as above |
| AES-256 KEK | `CKM_AES_KEY_GEN` | `SENSITIVE=true, EXTRACTABLE=false, ENCRYPT, DECRYPT, WRAP, UNWRAP` |

**Locating keys.** Keys are found by stable attributes, `CKA_CLASS` + `CKA_ID` + `CKA_LABEL` (both
equal to the `key_id`), never by object handle. If more than one object matches, the service fails
(ambiguity is an error). Each key's `CKA_KEY_TYPE` is checked against the configuration. Object handles
are resolved once at startup and cached; this is safe because PKCS#11 handles are valid across all
sessions of the application.

**Fail-closed startup.** Every configured private or secret key must report `CKA_SENSITIVE=true`
and `CKA_EXTRACTABLE=false`, and reading `CKA_VALUE` must fail. Otherwise the service refuses to
start. The integration test `private_and_secret_keys_are_non_exportable` also checks
`CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE`, which proves the keys were never in the clear,
even at creation. In production `HSM_PROVISION_KEYS=false`: keys come from a key ceremony, and a
missing key is a startup failure rather than a silently generated replacement.

**Signing.** The service hashes the message (SHA-256) in software and sends only the digest across
the PKCS#11 boundary (`CKM_ECDSA`, `CKM_RSA_PKCS_PSS`). The digest isn't secret. This keeps each call
small and independent of payload size, which matters for network-attached HSMs. The raw `r||s`
returned by PKCS#11 is converted to DER.

**Verification.** Uses the public key read from the token (`CKA_EC_POINT`, or modulus/exponent) and
the `p256` / `rsa` crates. It is an independent cross-check of the HSM, and it costs no HSM capacity.
The tests additionally verify through the exported PEM, and the README example uses `openssl`.

**Symmetric operations.** AES-256-GCM runs inside the token (`CKM_AES_GCM`, 96-bit IV from
`C_GenerateRandom`, 128-bit tag). The application only ever handles a `CK_OBJECT_HANDLE`, never key bytes.

**Key wrapping (extension).** `POST /v1/data-keys` generates an AES-256 data key as a *session
object* (`CKA_TOKEN=false`, `SENSITIVE=true`, `EXTRACTABLE=true`; extractable means "wrappable",
never readable in plaintext). It wraps the key under the KEK with `CKM_AES_KEY_WRAP_PAD`
(RFC 5649) and destroys the object. To use the data key, it is unwrapped into a non-extractable
session object, used, and destroyed, all within one pooled session. This is the standard
KMS / envelope pattern: bulk data keys can live in a database while the root of trust stays in the HSM.

---

## 5. Concurrency and session management

```
request ─► admission semaphore (pool + MAX_QUEUE, try_acquire) ── full ──► 503 overloaded
              │
              ▼
          session semaphore (HSM_POOL_SIZE), wait ≤ ACQUIRE_TIMEOUT_MS ── timeout ──► 503 hsm_busy
              │
              ▼
          spawn_blocking ─► checkout pooled Session ─► PKCS#11 call ─► checkin
                                  └─ session-fatal error (CKR_SESSION_HANDLE_INVALID, DEVICE_ERROR,
                                     USER_NOT_LOGGED_IN, ...) → discard, reopen + re-login, retry once
```

- **Session reuse.** `HSM_POOL_SIZE` sessions are opened and logged in at startup and reused for the
  life of the process. Opening sessions per request would be expensive on real HSMs, and many HSMs
  cap sessions per partition.
- **Bounded concurrency.** The session semaphore equals the pool size, so the service never has more
  PKCS#11 calls in flight than sessions. This also bounds the blocking threads in use.
- **Backpressure.** Admission is `try_acquire`: once `pool + MAX_QUEUE` requests are inside, new
  ones get `503` with `Retry-After` immediately, instead of growing an unbounded queue (which only
  converts overload into timeouts). Queued requests wait at most `ACQUIRE_TIMEOUT_MS`.
- **Async hygiene.** HSM calls never run on the reactor. Initialisation and key generation at startup
  also run in `spawn_blocking`.
- **Shutdown.** On SIGTERM the server stops accepting connections and drains in-flight requests;
  the backend then closes its sessions and calls `C_Finalize`. (The module is intentionally left
  mapped: unloading `libsofthsm2` before its `atexit` handlers run caused a segfault on exit. I found
  this while benchmarking and fixed it. The fix was verified manually (exit code 0 after SIGTERM,
  both locally and in the container); there is no automated test for it.)
- **Pool sizing for real HSMs.** By Little's law, `sessions ≥ target_ops/s × per-op latency`. A
  network HSM with 2 ms per-op round-trip latency needs at least 20 sessions in flight to sustain
  10k ops/s, which is far more than SoftHSM, where an operation takes about 0.1 ms.

Metrics (`/metrics`): `crypto_op_duration_seconds{op,outcome}` (histogram), `crypto_op_total{op,outcome}`,
`hsm_pool_in_use`, `hsm_pool_waiting`, `hsm_pool_size`, `hsm_pool_acquire_wait_seconds`.

---

## 6. Benchmark results

**Setup:** Apple M3 Pro (11 cores), SoftHSM 2.7.0, release build. `loadgen` runs on the same machine:
closed-loop, keep-alive HTTP/1.1, 256-byte payload, 2 s warm-up, then a 10 s measurement per level.
Latency is end to end as the client sees it. Server: `HSM_POOL_SIZE=8`, `MAX_QUEUE=512`,
`ACQUIRE_TIMEOUT_MS=2000`.

### ECDSA P-256 (`POST /v1/sign`), default config

| concurrency | requests | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | error rate |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 89,219 | 8,922 | 0.11 | 0.12 | 0.14 | 5.87 | 0.00% |
| 10 | 283,362 | 28,334 | 0.34 | 0.57 | 0.77 | 13.69 | 0.00% |
| 100 | 284,861 | 28,477 | 3.40 | 4.06 | 5.68 | 33.05 | 0.00% |
| 500 | 273,462 | 27,303 | 18.70 | 19.66 | 21.03 | 25.83 | 0.00% |

The same image in Docker (Linux VM, SoftHSM 2.6.1, loadgen inside the container): 6,976 / 27,976 /
28,962 / 28,587 req/s, with p99 of 0.17 / 0.83 / 4.17 / 19.58 ms and 0 errors.

### RSA-3072 PSS

| concurrency | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | error rate |
|---:|---:|---:|---:|---:|---:|
| 1 | 550 | 1.80 | 1.88 | 1.95 | 0.00% |
| 10 | 3,356 | 2.76 | 4.80 | 5.62 | 0.00% |
| 100 | 3,397 | 29.22 | 31.38 | 32.14 | 0.00% |

### Pool-size sweep (ECDSA, 100 callers)

| pool | 1 | 2 | 4 | 8 | 11 | 16 | 32 |
|---|---:|---:|---:|---:|---:|---:|---:|
| req/s | 12,674 | 23,505 | 29,280 | 29,525 | 29,500 | 29,751 | 30,170 |
| p99 (ms) | 8.12 | 4.55 | 4.96 | 4.90 | 5.24 | 4.42 | 5.92 |

### Backpressure (pool = 2, queue = 50, acquire timeout = 20 ms)

| concurrency | successful req/s | p50 (ms) | p99 (ms) | error rate |
|---:|---:|---:|---:|---:|
| 1 | 9,481 | 0.10 | 0.13 | 0% |
| 10 | 23,381 | 0.42 | 0.52 | 0% |
| 100 | 13,880 | 0.95 | 5.62 | 76.7% (all 503) |
| 500 | 3,733 | 6.76 | 26.57 | 93.9% (all 503) |

### What the numbers show

1. **Latency grows with queueing, not with work.** Past saturation, throughput stays flat at about
   28k/s and latency rises linearly with concurrency (3.4 ms at 100 callers, 18.7 ms at 500), as
   Little's law predicts. Server-side metrics agree: about 95% of request time was spent in
   `hsm_pool_acquire_wait_seconds`; the PKCS#11 call itself takes about 0.1–0.3 ms. The default
   config produced zero errors at 500 callers because the queue (512) and the 2 s timeout absorb them.
2. **The bottleneck is inside SoftHSM, not the service or the CPU.** Throughput stops scaling at a
   pool of 4, and the server process tops out at about 4.1 cores while the machine is about 39% idle,
   with a high share of system time. Sampling the process under load (`sample`) shows the hottest
   frames in SoftHSM's global locks: `MutexLocker` / `__psynch_mutexwait`, and
   `SecureMemoryRegistry::add/remove` (one global mutex taken on every secure allocation), followed
   by `Token::decrypt` (SoftHSM decrypts the stored private key on every `C_Sign`) and
   `OSToken::index` / `ObjectFile::refresh` (filesystem consistency checks). OpenSSL alone signs
   about 77k ECDSA P-256/s per core on this machine, so the cryptography itself is not the limit.
3. **RSA-3072 is about 8× more expensive than ECDSA P-256** (about 1.8 ms per signature) and is CPU-bound.
4. **Load shedding works as intended.** With a deliberately tight configuration, excess load gets
   fast 503s (p50 under 1 ms at 100 callers) instead of piling up latency, while admitted requests
   still complete quickly. The low "successful req/s" at 500 callers comes from the closed-loop
   client: rejected callers retry immediately, so the server spends its time rejecting. Real
   clients should honour `Retry-After` with jitter.
5. **These are SoftHSM numbers.** They demonstrate the service's behaviour, not real HSM capacity.
   With a network HSM, expect 1–3 ms per operation, an appliance-level ops/s ceiling, and the need
   for a larger pool (see the Little's law note in §5).

Reproduce:

```bash
ulimit -n 10240
cargo run --release --bin loadgen -- --concurrency 1,10,100,500 --duration-secs 10
```

---

## 7. Security considerations

- **No key material in the application.** Private keys, the KEK and data keys exist only as
  PKCS#11 handles. There is no code path that reads `CKA_VALUE`, and the startup check rejects keys
  that would allow it.
- **Logging policy.** Logs contain the key id, operation, algorithm, input *length*, duration and
  error code. They never contain payloads, plaintexts, ciphertexts, signatures, wrapped keys, PINs,
  or request bodies. `key_id` is restricted to `[A-Za-z0-9._-]{1,128}` before it is logged, which
  prevents log injection. During the smoke test, `grep` confirmed that neither the PIN nor the
  payload appeared in the log output.
- **Error hygiene.** Clients get stable error codes. PKCS#11 details (`CKR_*`) are logged
  server-side only.
- **Input limits.** Body size limits apply before parsing, and the decoded size is checked
  separately (`MAX_PAYLOAD_BYTES`). GCM IVs must be 12 bytes.
- **Container.** The service runs as non-root (uid 10001) under `tini`, on a read-only root
  filesystem, with all capabilities dropped and `no-new-privileges`. The PIN arrives as a file
  secret. The SO PIN is not needed at runtime; if none is supplied, the test token gets a random SO
  PIN that is discarded.
- **SoftHSM caveat.** SoftHSM is a software token. Its "HSM boundary" is the process memory and the
  files in the token directory, protected only by the PIN. It is a stand-in for development and
  testing, not a security boundary.
- **Normalised SoftHSM quirks.** SoftHSM returns `CKR_GENERAL_ERROR` instead of
  `CKR_WRAPPED_KEY_INVALID` (for RFC 5649 unwrap) or `CKR_ENCRYPTED_DATA_INVALID` (for GCM tag
  failures on 2.6.x). The service remaps these only at those two call sites, so clients get a 400.
  The downside: a genuine device fault at exactly those calls would surface as a 400, not a 500.
- **Not implemented (needed in production):** caller authentication and authorisation (mTLS / JWT,
  plus a policy saying which callers may use which key), per-tenant rate limits, and an audit log of
  every signature. Without these, the service is a signing oracle for anyone who can reach it.
  See §9.

---

## 8. Architectural decisions, assumptions and known limitations

**Decisions**
- `cryptoki` (Parsec project) is the PKCS#11 binding: maintained, close to the spec, and `Session` is `Send` but not `Sync`, which suits a checkout pool.
- A synchronous backend trait, with all async/blocking concerns centralised in `CryptoService`. Backends stay simple and testable, and the mock can inject blocking latency to exercise the pool.
- Software prehashing plus `CKM_ECDSA` / `CKM_RSA_PKCS_PSS` instead of `CKM_ECDSA_SHA256`. This gives portable mechanism support across HSMs and a constant-size HSM payload.
- Public-key verification in software (it is not secret, and it is independent of the HSM).
- Keys are configured, not created through the API. Key lifecycle belongs to a ceremony or an admin plane, not to the request path.
- ECDSA signatures are returned in DER (the X.509/CMS encoding). Verification accepts DER or raw `r||s`.

**Assumptions**
- `payload` is the message to be signed (for example a TBSCertificate), not a precomputed digest.
- `duration_ms` is total server-side handling time, including queueing. It is an integer, as in the spec example, so sub-millisecond signatures report `0`; the exact `duration_us` is in the logs and the histogram.
- A single token/slot per process. Horizontal scale comes from more replicas or HSM partitions.

**Known limitations**
- No authentication or authorisation, rate limiting, or audit trail (see §7).
- Key handles are cached at startup, so keys created later need a restart. Object-handle invalidation (for example, a token re-plugged) surfaces as errors until restart. Session-level failures *are* self-healing.
- A PKCS#11 call can't be cancelled. A request whose client disconnects still finishes its HSM operation; the semaphore bounds the cost.
- The mock backend does not implement RSA.
- OpenTelemetry tracing is not wired up. `tower-http` tracing spans and Prometheus metrics are in place, and adding `tracing-opentelemetry` would export the existing spans.
- No key rotation or versioning (`key_id` → active version) yet.

---

## 9. Production considerations

- **HSM:** a FIPS 140-3 Level 3 device (Thales Luna, Entrust nShield, Utimaco, AWS CloudHSM, GCP Cloud HSM via PKCS#11). Use an HA group or cluster, with keys replicated by the vendor's secure cloning or backup. Set the pool size per partition using Little's law, and keep it under the vendor's session limits.
- **AuthN/Z:** mTLS between callers and the signer, with a per-key policy (caller identity → allowed `key_id`s, algorithms, maximum rate). For a CA, *what* gets signed should be decided by an issuance-policy service in front of the signer, never by arbitrary callers.
- **Audit:** an append-only log of every signature (caller, key, digest, time), shipped off-host; certificate-transparency-style logging for issued certificates.
- **Operations:** alert on `hsm_pool_waiting`, on 503 rates, on `hsm_unavailable`, and on p99 latency. Readiness checks `C_GetSessionInfo`. Use rolling deploys with graceful drain (already implemented).
- **Key lifecycle:** keys generated in a ceremony (M-of-N, `HSM_PROVISION_KEYS=false`), versioned key ids, scheduled rotation, and a documented compromise-response runbook.
- **Supply chain:** pin the base image digests, build reproducibly, generate an SBOM, sign the image (cosign), and run `cargo audit` / `cargo deny` in CI.

---

## 10. Architecture question: 100,000 short-lived certificates per second

> Arkion needs to issue **100k short-lived certs/s**, but HSM signing capacity is much lower.

### Why "every leaf signed in an HSM" doesn't work well

Network HSMs typically deliver on the order of a few thousand to ~20k ECDSA P-256 signatures per
second per appliance (it varies widely by model and licence tier; the vendor datasheet is the
source of truth). At 100k/s plus N+1 redundancy, plus enough headroom to absorb a failed region,
you need tens of appliances. Every issuance would also add an HSM network round trip and depend on
HSM availability. That is possible, but expensive, and it makes the HSM fleet the availability
bottleneck of the whole platform. On this M3 Pro, plain OpenSSL signs about 77k P-256/s **per
core**, so the cryptography itself is cheap. What's scarce is trusted signing capacity.

### Recommended design: HSMs anchor trust, short-lived delegated keys do the volume

```
                Offline Root CA (HSM, air-gapped, M-of-N ceremony, ~10-20y)
                                   │  signs rarely (yearly)
              ┌────────────────────┼────────────────────┐
     Regional Intermediate CA  Regional Intermediate CA  ...    (online HSM cluster per region,
     (EU, HSM, ~1y, pathLen=1,  (US, HSM ...)                     key never leaves HSM)
      name/EKU constrained)
              │  signs a new issuer cert every few hours  (≈ tens of HSM signatures/hour)
     ┌────────┼────────┐
  Issuing key  Issuing key  ...   ephemeral, per signer node, generated *inside* a TEE
  (cert ~24h, pathLen=0)          (Nitro Enclave / SEV-SNP / TDX), never persisted or exported
     │  signs leaves in memory, ~50-70k/s per core
  Leaf certs (minutes to hours lifetime)
```

1. **Root CA:** offline, in an HSM, used only in key ceremonies to sign regional intermediates.
   This is the crown jewel.
2. **Regional intermediates:** online, in HSMs (one cluster per region, with separate keys per
   region so a compromise stays regional), name-constrained and EKU-constrained. They sign only
   *issuing-key certificates*, not leaves. That load is negligible: N signer nodes × one rotation
   every few hours.
3. **Ephemeral issuing keys:** each signer node generates a P-256 key inside an attested enclave.
   It sends a CSR plus an attestation document to the intermediate, which signs a short (~24 h),
   `pathLen=0` sub-CA certificate only if the attestation matches the expected enclave measurement.
   The issuing key signs leaves in memory at tens of thousands per core.
   **100k/s ≈ 2–4 cores of signing**; the real cost is X.509 encoding, policy checks and TLS.
4. **Leaf certificates** are short-lived (minutes to hours), so revocation is mostly handled by
   expiry. A compromised issuing key is revoked at the intermediate (CRL/OCSP for the sub-CA) and is
   useless within ~24 h anyway.

**Where key wrapping fits.** A design that *does* persist the hot keys could generate them in the HSM
and export them wrapped (`CKA_EXTRACTABLE`, wrapped under a KEK that only attested enclaves can
unwrap), which allows restarts without re-issuance. I'd prefer generate-in-enclave plus re-issue on
restart: the private key never exists outside one enclave's memory, and re-issuing costs one HSM
signature. Wrapping is the better choice when re-issuance is constrained (rate-limited upstream, or
long-lived sub-CA certificates).

**Software signing without enclaves** (hardened hosts, key in process memory) is the same design
with a weaker boundary. It is acceptable for a private PKI if the issuing-certificate lifetime is
very short (hours) and the hosts are locked down. Enclaves remove the host operator and root user
from the trust base.

### Trade-offs and security implications

| | All leaves in HSM | Delegated ephemeral issuing keys (recommended) |
|---|---|---|
| HSM ops/s needed | ≥ 100k + headroom | ~1 per node per few hours |
| HSM fleet | tens of appliances | 2–3 per region (HA) + root |
| Issuance latency | + HSM RTT (1–3 ms), queueing | in-memory (~20–50 µs signing) |
| Blast radius of a hot-key compromise | none (keys never leave the HSM) | one issuing key, ≤ ~24 h, constrained by name/EKU/path |
| Compliance | fits WebPKI-style "CA keys in HSM" rules | fine for private PKI; **not** allowed for publicly trusted WebPKI CAs, where every CA key must live in an HSM |
| Chain | 3 levels | 4 levels (slightly larger handshakes) |

Additional controls that make the delegated model safe:
- The **issuance-policy service** authorises every request (who may get which SAN, EKU, TTL) before anything is signed.
- **Transparency:** every issuing-key certificate and every leaf is logged to an append-only log; monitor for certificates nobody requested.
- **Rate limits** per tenant and per issuing key; anomaly alerts if a node signs far beyond its expected share.
- **Attestation-gated issuance:** the intermediate signs issuing keys only for known enclave measurements and known nodes.

### Regional capacity and failover

- **Active-active regions**, each with its own intermediate (in the HSM cluster) and a stateless fleet of signer nodes behind a load balancer. Clients use the nearest region.
- **Sizing:** with 3 regions, size each region for ~50% of global peak, so losing one region still leaves 100%. Signer nodes autoscale on CPU; the HSM fleet doesn't need to scale with leaf volume at all.
- **HSM failure:** an HA group per region (≥ 2 HSMs, replicated keys). If a region's intermediate HSMs are completely unavailable, existing issuing keys keep issuing for up to their remaining lifetime (~24 h). That gives a long window to fix the HSM without affecting leaf issuance. A cross-region "standby" intermediate can be used to re-issue issuing keys.
- **Smoothing load:** clients renew at ~⅔ of the leaf lifetime with jitter, which avoids synchronised renewal storms. Signers return 503 + `Retry-After` (as this service does) instead of queueing without bound.
- **Trust bundle:** relying parties trust the root, so any region's chain validates everywhere; distributing intermediates is just part of the chain the client sends.

### Cost (order of magnitude)

- **All-HSM:** dozens of HSMs across regions. Cloud HSMs cost roughly $1–2/hour per instance
  (≈ $1–1.5k/month each); appliances cost tens of thousands of dollars each plus support and data
  centre operations. That comes to hundreds of thousands to over a million dollars per year, before
  engineering for HSM-bound latency.
- **Delegated:** about 6–9 HSMs total (2–3 per region + offline root), plus a few dozen vCPUs of
  enclave-capable compute for 100k/s, including X.509/policy/TLS overhead. That is one to two orders
  of magnitude cheaper, and leaf issuance scales with commodity compute.
- **The real costs** of the delegated model are engineering and assurance: attestation, issuance
  policy, transparency logging and compliance evidence. That is the work to budget for.

### Looking ahead

The IETF *Merkle Tree Certificates* work batches many certificates under a single signed tree head:
one HSM signature per batch instead of per certificate. If relying parties adopt it, it fits this
problem exactly, removing per-leaf signatures while keeping every signing key in the HSM. Today it
needs client support, so the delegated issuing-key design above is the practical answer.
#   a r k i o n - h s m - s i g n e r  
 