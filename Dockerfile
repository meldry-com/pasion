# syntax = docker/dockerfile:1.7.1
# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.89.0
ARG CARGO_AUDITABLE_VERSION=0.7.0
ARG DIOXUS_CLI_VERSION=0.7.3

############################################
## Build stage that builds the frontend   ##
############################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

ARG DIOXUS_CLI_VERSION

# Install wasm target and Dioxus CLI
# Network access: to fetch dependencies
RUN --network=default \
  rustup target add wasm32-unknown-unknown && \
  cargo install --locked dioxus-cli@${DIOXUS_CLI_VERSION}

WORKDIR /app
COPY ./ /app

# Build the WASM frontend
# Network access: to fetch dependencies
RUN --network=default \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/app/target \
  dx build -p pasion-frontend --release \
  && cp -r target/dx/pasion-frontend/release/web/public /frontend-dist

########################################
## Build stage that builds the binary ##
########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder

ARG CARGO_AUDITABLE_VERSION
ARG RUSTC_VERSION

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
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/app/target \
  cargo auditable build \
    --locked \
    --release \
    --bin pasion \
    --no-default-features \
    --features docker \
  && mv "target/release/pasion" /usr/local/bin/pasion-amd64

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
