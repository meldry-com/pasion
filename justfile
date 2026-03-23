# Pasion — development task runner
# Usage: just <recipe>
# See all recipes: just --list

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Default recipe: show available commands
default:
    @just --list

# ── Development ──────────────────────────────────────────────

# Start the backend server (auto-migrates DB)
backend *ARGS:
    cargo run -p pasion -- server {{ARGS}}

# Start the backend with a config file
backend-config config="config.yaml":
    cargo run -p pasion -- server -c {{config}}

# Start the frontend dev server (Dioxus hot-reload)
frontend:
    dx serve -p pasion-front

# Start the frontend in hot-reload mode
frontend-hot:
    dx serve -p pasion-front --hot-reload

# Build the frontend for production
frontend-build:
    dx build -p pasion-front --release

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
