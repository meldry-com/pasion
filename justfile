# Pasion — development task runner
# Usage: just <recipe>
# See all recipes: just --list

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Default recipe: show available commands
default:
    @just --list

# ── Development ──────────────────────────────────────────────

# One-click: start PostgreSQL + backend with dev config
dev:
    docker compose -f .devcontainer/compose.yml up -d postgres
    @echo "Waiting for PostgreSQL..."
    @until docker compose -f .devcontainer/compose.yml exec -T postgres pg_isready -U pasion > /dev/null 2>&1; do sleep 1; done
    @if [ ! -f config.dev.yaml ]; then just config-dev-generate; fi
    cargo run -p pasion -- server -c config.dev.yaml

# Stop dev services (PostgreSQL)
dev-down:
    docker compose -f .devcontainer/docker-compose.yml down

# Generate a dev config pointing to the local Docker PostgreSQL
config-dev-generate:
    cargo run -p pasion -- config generate > config.dev.yaml.tmp
    sed -i 's|uri: postgresql://|uri: postgresql://pasion:pasion@localhost/pasion|' config.dev.yaml.tmp
    mv config.dev.yaml.tmp config.dev.yaml
    @echo "Created config.dev.yaml"

# Start the backend server (auto-migrates DB)
backend *ARGS:
    if (!(Test-Path config.dev.yaml)) { just config-dev-generate }
    cargo run -p pasion -- server -c config.dev.yaml {{ARGS}}

# Start the backend with a config file
backend-config config="config.yaml":
    cargo run -p pasion -- server -c {{config}}

# Start the frontend dev server (Dioxus hot-reload)
frontend:
    dx serve -p pasion-frontend --port 8182

# Start the frontend in hot-reload mode
frontend-hot:
    dx serve -p pasion-frontend --hot-reload

# Build the frontend for production (output → dist/)
frontend-build:
    dx build -p pasion-frontend --release
    {{ if os() == "windows" { "if (Test-Path dist) { Remove-Item -Recurse -Force dist }; Copy-Item -Recurse target/dx/pasion-frontend/release/web/public dist" } else { "rm -rf dist && cp -r target/dx/pasion-frontend/release/web/public dist" } }}

# ── Build ────────────────────────────────────────────────────

# Build the backend in release mode
build:
    cargo build --release -p pasion

# Build everything (backend + frontend)
build-all:
    just frontend-build
    cargo build --release -p pasion

# Check the entire workspace for errors
check:
    cargo check --workspace

# Run clippy on the entire workspace
lint:
    cargo clippy --workspace -- -D warnings

# Format all Rust code
fmt:
    cargo fmt --all

# Check formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# ── Database ─────────────────────────────────────────────────

# Run database migrations
db-migrate *ARGS:
    cargo run -p pasion -- database migrate {{ARGS}}

# Generate config, check, or sync
config *ARGS:
    cargo run -p pasion -- config {{ARGS}}

# ── User Management ─────────────────────────────────────────

# Register a new user
register-user *ARGS:
    cargo run -p pasion -- manage register-user {{ARGS}}

# Set or reset a user's password
set-password *ARGS:
    cargo run -p pasion -- manage set-password {{ARGS}}

# Promote a user to admin
promote-user *ARGS:
    cargo run -p pasion -- manage promote-user {{ARGS}}

# ── Testing ──────────────────────────────────────────────────

# Run all tests
test:
    cargo test --workspace

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# ── Documentation ────────────────────────────────────────────

# Build the English documentation (mdBook)
docs-en:
    mdbook build -d ../target/docs/en

# Build the Chinese documentation (mdBook)
docs-zh:
    mdbook build -d ../target/docs/zh book-zh.toml

# ── Utilities ────────────────────────────────────────────────

# Run the doctor diagnostic tool
doctor *ARGS:
    cargo run -p pasion -- doctor {{ARGS}}

# Generate a default configuration file
config-generate:
    cargo run -p pasion -- config generate

# Clean all build artifacts
clean:
    cargo clean
