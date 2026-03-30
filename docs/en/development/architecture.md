# Architecture

The service is meant to be easily embeddable, with only a dependency to a database.
It is also meant to stay lightweight in terms of resource usage and easily scalable horizontally.

## Scope and goals

The Pasion has been created to support the migration of Matrix to an OpenID Connect (OIDC) based architecture as per [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861).

It is not intended to be a general purpose Identity Provider (IdP) and instead focuses on the specific needs of Matrix.

Furthermore, it is only intended that it would speak OIDC for authentication and not other protocols. Instead, if you want to connect to an upstream SAML, CAS or LDAP backend then you need to pair Pasion with a separate service (such as [Dex](https://dexidp.io) or [Keycloak](https://www.keycloak.org)) which does that translation for you.

Whilst it only supports use with Palpo today, we hope that other homeservers will become supported in future.

If you need some other feature that Pasion doesn't support (such as TOTP or WebAuthn), then you should consider pairing Pasion with another IdP that does support the features you need.

## Workspace and crate split

The whole repository is a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) that includes multiple crates under the `/crates` directory.

This includes:

 - `pasion`: Command line utility, main entry point
 - [`pasion-config`][pasion-config]: Configuration parsing and loading
 - [`pasion-data-model`][pasion-data-model]: Models of objects that live in the database, regardless of the storage backend
 - [`pasion-email`][pasion-email]: High-level email sending abstraction
 - [`pasion-handlers`][pasion-handlers]: Main HTTP application logic
 - [`pasion-policy`][pasion-policy]: Policy engine abstraction layer supporting multiple backends (OPA/WASM, Cedar, Remote HTTP)
 - [`pasion-iana`][pasion-iana]: Auto-generated enums from IANA registries
 - [`pasion-iana-codegen`][pasion-iana-codegen]: Code generator for the `pasion-iana` crate
 - [`pasion-jose`][pasion-jose]: JWT/JWS/JWE/JWK abstraction
 - [`pasion-frontend`][pasion-frontend]: Frontend application (Dioxus-based Rust SPA)
 - [`pasion-storage`][pasion-storage]: Abstraction of the storage backends
 - [`pasion-storage-pg`][pasion-storage-pg]: Storage backend implementation for a PostgreSQL database
 - [`pasion-tasks`][pasion-tasks]: Asynchronous task runner and scheduler
 - [`oauth2-types`][oauth2-types]: Useful structures and types to deal with OAuth 2.0/OpenID Connect endpoints. This might end up published as a standalone library as it can be useful in other contexts.

[pasion-config]: ../rustdoc/pasion_config/index.html
[pasion-data-model]: ../rustdoc/pasion_data_model/index.html
[pasion-email]: ../rustdoc/pasion_email/index.html
[pasion-handlers]: ../rustdoc/pasion_handlers/index.html
[pasion-policy]: ../rustdoc/pasion_policy/index.html
[pasion-iana]: ../rustdoc/pasion_iana/index.html
[pasion-iana-codegen]: ../rustdoc/pasion_iana_codegen/index.html
[pasion-jose]: ../rustdoc/pasion_jose/index.html
[pasion-frontend]: ../rustdoc/pasion_frontend/index.html
[pasion-storage]: ../rustdoc/pasion_storage/index.html
[pasion-storage-pg]: ../rustdoc/pasion_storage/index.html
[pasion-tasks]: ../rustdoc/pasion_tasks/index.html
[oauth2-types]: ../rustdoc/oauth2_types/index.html

## Important crates

The project makes use of a few important crates.

### Async runtime: `tokio`

[Tokio](https://tokio.rs/) is the async runtime used by the project.
The choice of runtime does not have much impact on most of the code.

It has an impact when:

 - spawning asynchronous work (as in "not awaiting on it immediately")
 - running CPU-intensive tasks. They should be ran in a blocking context using `tokio::task::spawn_blocking`. This includes password hashing and other crypto operations.
 - when dealing with shared memory, e.g. mutexes, rwlocks, etc.

### Logging: `tracing`

Logging is handled through the [`tracing`](https://docs.rs/tracing/*/tracing/) crate.
It provides a way to emit structured log messages at various levels.

```rust
use tracing::{info, debug};

info!("Logging some things");
debug!(user = "john", "Structured stuff");
```

`tracing` also provides ways to create spans to better understand where a logging message comes from.
In the future, it will help building OpenTelemetry-compatible distributed traces to help with debugging.

`tracing` is becoming the standard to log things in Rust.
By itself it will do nothing unless a subscriber is installed to -for example- log the events to the console.

The CLI installs [`tracing-subcriber`](https://docs.rs/tracing-subscriber/*/tracing_subscriber/) on startup to log in the console.
It looks for a `RUST_LOG` environment variable to determine what event should be logged.

### Error management: `thiserror` / `anyhow`

[`thiserror`](https://docs.rs/thiserror/*/thiserror/) helps defining custom error types.
This is especially useful for errors that should be handled in a specific way, while being able to augment underlying errors with additional context.

[`anyhow`](https://docs.rs/anyhow/*/anyhow/) helps dealing with chains of errors.
It allows for quickly adding additional context around an error while it is being propagated.

Both crates work well together and complement each other.

### Database interactions: `diesel`

Interactions with the database are done through [`diesel`](https://diesel.rs/) with [`diesel-async`](https://docs.rs/diesel-async/) for async support and [`deadpool`](https://docs.rs/deadpool/) for connection pooling.
Schema migrations are managed by `diesel_migrations`.

### Templates: `minijinja`

[MiniJinja](https://github.com/mitsuhiko/minijinja) is used as the template engine. It is a Rust implementation of the Jinja2 template language, offering runtime template loading and a syntax familiar to Python developers.
The `minijinja-contrib` crate provides additional filters for Python compatibility.

### Crates from *RustCrypto*

The [RustCrypto team](https://github.com/RustCrypto) offer high quality, independent crates for dealing with cryptography.
The whole project is highly modular and APIs are coherent between crates.
