# syntax=docker/dockerfile:1.7

# ---------- build ----------
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bins \
 && mkdir -p /out \
 && cp target/release/arkion-hsm-signer target/release/loadgen /out/

# ---------- test (docker build --target test .) ----------
# Runs the unit tests and the SoftHSM2 integration tests inside the image toolchain.
FROM build AS test
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 && rm -rf /var/lib/apt/lists/*
ENV REQUIRE_SOFTHSM=1 PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 tini curl ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/arkion arkion \
 && mkdir -p /var/lib/softhsm/tokens && install -d -m 0755 /etc/arkion \
 && chown -R arkion:arkion /var/lib/softhsm

COPY --chmod=0644 docker/softhsm2.conf /etc/arkion/softhsm2.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=build /out/arkion-hsm-signer /out/loadgen /usr/local/bin/

ENV SOFTHSM2_CONF=/etc/arkion/softhsm2.conf \
    PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    HSM_TOKEN_LABEL=arkion \
    BIND_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json \
    # This image is the SoftHSM *test environment*: generate missing keys on first start.
    # A production deployment against a real HSM sets this to false.
    HSM_PROVISION_KEYS=true

USER 10001:10001
VOLUME ["/var/lib/softhsm/tokens"]
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD curl -fsS http://127.0.0.1:8080/readyz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["arkion-hsm-signer"]
