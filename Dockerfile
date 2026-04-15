# syntax = docker/dockerfile:1.7.1
# Builds a minimal image with the binary only. Buildx publishes amd64 and arm64
# variants from this Dockerfile. Frontend assets are built once on the native
# builder platform, while the server binary is compiled on the requested target
# platform so it links against the correct native system libraries.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.93.0
ARG CARGO_AUDITABLE_VERSION=0.7.0
ARG DIOXUS_CLI_VERSION=0.7.4

############################################
## Build stage that builds the frontend   ##
############################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

ARG DIOXUS_CLI_VERSION

ENV CARGO_HTTP_TIMEOUT=600
ENV CARGO_HTTP_MULTIPLEXING=false
ENV CARGO_NET_RETRY=10
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Install wasm target (with retries for flaky networks) and Dioxus CLI
# Network access: to fetch dependencies
ENV RUSTUP_HTTP_TIMEOUT=600
RUN --network=default \
  for i in 1 2 3 4 5; do rustup target add wasm32-unknown-unknown && break || sleep 10; done && \
  cargo install --locked dioxus-cli@${DIOXUS_CLI_VERSION}

WORKDIR /app
COPY ./ /app

# Pre-install binaryen (wasm-opt) so dx build doesn't need to download from GitHub
RUN --network=default \
  apt-get update && apt-get install -y binaryen && rm -rf /var/lib/apt/lists/* || true

# Pre-fetch dependencies so dx build doesn't time out on cargo-metadata
RUN --network=default \
  --mount=type=cache,id=frontend-registry,target=/root/.cargo/registry \
  cargo fetch

# Build the WASM frontend (retry for flaky esbuild downloads)
RUN --network=default \
  --mount=type=cache,id=frontend-registry,target=/root/.cargo/registry \
  --mount=type=cache,id=frontend-target,target=/app/target \
  for i in 1 2 3; do dx build -p pasion-frontend --release && break || echo "Retry $i..." && sleep 10; done \
  && cp -r target/dx/pasion-frontend/release/web/public /frontend-dist

########################################
## Build stage that builds the binary ##
########################################
FROM --platform=${TARGETPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder

ARG CARGO_AUDITABLE_VERSION
ARG RUSTC_VERSION
ARG TARGETARCH

ENV CARGO_HTTP_TIMEOUT=600
ENV CARGO_HTTP_MULTIPLEXING=false
ENV CARGO_NET_RETRY=10
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

# Install build dependencies
# Network access: to install apt packages
RUN --network=default \
  apt-get update && apt-get install -y \
  libpq-dev \
  g++

# Set the working directory
WORKDIR /app

# Copy the code
COPY ./ /app

ARG VERGEN_GIT_DESCRIBE
ENV VERGEN_GIT_DESCRIBE=${VERGEN_GIT_DESCRIBE}

# Network access: cargo auditable needs it
RUN --network=default \
  --mount=type=cache,id=builder-registry,target=/root/.cargo/registry \
  --mount=type=cache,id=builder-target-${TARGETARCH},target=/app/target \
  cargo auditable build \
    --locked \
    --release \
    --bin pasion \
    --no-default-features \
    --features docker,cedar \
  && mv "target/release/pasion" "/usr/local/bin/pasion-${TARGETARCH}"

#######################################
## Prepare /usr/local/share/pasion/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

# Cedar policies
COPY ./policies/cedar/ /share/cedar
COPY ./templates/ /share/templates
COPY ./translations/ /share/translations
COPY --from=frontend /frontend-dist/ /share/assets

##################################
## Runtime stage, debug variant ##
##################################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:debug-nonroot AS debug

ARG TARGETARCH
COPY --from=builder /usr/local/bin/pasion-${TARGETARCH} /usr/local/bin/pasion
COPY --from=share /share /usr/local/share/pasion

WORKDIR /
ENTRYPOINT ["/usr/local/bin/pasion"]

###################
## Runtime stage ##
###################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

ARG TARGETARCH
COPY --from=builder /usr/local/bin/pasion-${TARGETARCH} /usr/local/bin/pasion
COPY --from=share /share /usr/local/share/pasion

WORKDIR /
ENTRYPOINT ["/usr/local/bin/pasion"]
