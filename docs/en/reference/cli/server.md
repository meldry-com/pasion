# `server`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `server`

Runs the authentication service. This is the main command for production deployments.

Options:
- `--no-migrate`: Do not apply pending database migrations on start.
- `--no-worker`: Do not start the background task worker (see [`worker`](./worker.md)).
- `--no-sync`: Do not sync the configuration (OAuth 2.0 clients and upstream providers) with the database.

```
$ pasion server -c config.yaml
INFO pasion_cli::server: Starting task scheduler
INFO pasion_cli::server: Listening on http://0.0.0.0:8080
```

### Startup behavior

On startup, the server performs these steps in order:

1. **Database migrations** — Applies any pending schema migrations (unless `--no-migrate`).
2. **Configuration sync** — Syncs OAuth 2.0 client registrations and upstream provider definitions from the config file to the database (unless `--no-sync`).
3. **Key loading** — Loads signing keys from the configured secrets.
4. **Template compilation** — Loads and compiles page templates.
5. **Worker startup** — Starts the background task worker (unless `--no-worker`).
6. **HTTP listener** — Begins accepting connections on the configured addresses.

### Graceful shutdown

The server supports graceful shutdown via `SIGTERM` or `SIGINT` (Ctrl+C):

1. On the first signal, the server stops accepting new connections and waits for in-flight requests to complete.
2. On a second signal, the server forcefully terminates all connections.

### Health check

The server exposes health endpoints at `/health` and `/healthz` that return HTTP 200 when the service is ready to handle requests. These endpoints can be used for load balancer health checks and container orchestration readiness probes.

### Example: systemd service

```ini
[Unit]
Description=Pasion Authentication Service
After=network.target postgresql.service

[Service]
ExecStart=/usr/local/bin/pasion server -c /etc/pasion/config.yaml
Restart=on-failure
User=pasion

[Install]
WantedBy=multi-user.target
```

### Example: Docker Compose

```yaml
services:
  pasion:
    image: ghcr.io/taidge/pasion:latest
    command: server -c /config.yaml
    volumes:
      - ./config.yaml:/config.yaml:ro
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
```
