# Pasion

An OAuth 2.0 / OpenID Connect authentication and user management service for [Palpo](https://palpo.im/) Matrix homeservers.

## Overview

Pasion handles authentication for Matrix homeservers using the industry-standard OpenID Connect protocol. It replaces the legacy Matrix login system with a modern, standards-based approach as defined by [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861).

### Key Features

- **OAuth 2.0 & OpenID Connect** — Full-featured OIDC Provider with authorization code, client credentials, and device code grant flows
- **Upstream SSO** — Federate with external identity providers (Google, GitHub, GitLab, Apple, Keycloak, LDAP via Dex, and more)
- **Admin API** — RESTful JSON API for managing users, sessions, and OAuth 2.0 clients
- **Policy Engine** — Extensible OPA-based (WebAssembly) policy engine for fine-grained access control
- **Compatibility Layer** — Supports legacy Matrix `/_matrix/client/*/login` API for older clients
- **Security** — Argon2id password hashing, encrypted cookies, rate limiting, CAPTCHA support
- **Internationalization** — Multi-language UI with configurable templates
- **Observability** — OpenTelemetry tracing and Prometheus metrics export

## Quick Start

### Using Pre-built Binaries (Linux)

```bash
# Download the latest release
curl -sL https://github.com/taidge/pasion/releases/latest/download/pasion-cli-x86_64-linux.tar.gz | tar xz

# Generate a configuration file
./pasion-cli config generate > config.yaml

# Edit config.yaml to set your database, domain, and secrets
# Then run the server
./pasion-cli server -c config.yaml
```

### Using Docker

```bash
docker run -v $(pwd)/config.yaml:/config.yaml ghcr.io/taidge/pasion:latest \
  server -c /config.yaml
```

### Building from Source

```bash
git clone https://github.com/taidge/pasion.git
cd pasion
cargo build --release
```

See the [installation guide](docs/setup/installation.md) for full details.

## Architecture

Pasion is deployed alongside a Matrix homeserver, handling all authentication flows:

```
             ┌──────────────┐
Users ──────>│ Reverse Proxy │
             └──────┬───────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
   ┌────▼───┐  ┌────▼────┐  ┌──▼──────────┐
   │ Pasion │  │ Palpo   │  │ Static      │
   │ (auth) │  │ (Matrix)│  │ Assets      │
   └────────┘  └─────────┘  └─────────────┘
        │
   ┌────▼──────┐
   │ PostgreSQL │
   └───────────┘
```

## Documentation

Full documentation is available at <https://palpo-im.github.io/pasion/>.

| Section | Description |
|---------|-------------|
| [Installation](docs/setup/installation.md) | Install and configure Pasion |
| [Configuration](docs/reference/configuration.md) | Full configuration reference |
| [Admin API](docs/topics/admin-api.md) | Manage users and sessions via API |
| [Architecture](docs/development/architecture.md) | Internal design and crate structure |
| [Contributing](docs/development/contributing.md) | How to contribute to the project |

## Requirements

- **PostgreSQL** 13 or later
- **Palpo** homeserver 1.136.0 or later (or any compatible Matrix homeserver)
- A reverse proxy (nginx, Caddy, etc.) for TLS termination

## License

See [LICENSE](LICENSE) for details.
