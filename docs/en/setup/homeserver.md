# Homeserver configuration

Pasion is designed to run alongside a Matrix homeserver. The Palpo integration
uses Palpo's `delegated_auth` configuration and Pasion's OAuth/OIDC endpoints.
The authentication service needs to be able to call the Palpo admin API to provision users through a shared secret, and Palpo needs to be able to call the service to verify access tokens using the OAuth 2.0 token introspection endpoint.

## Configure the connection to the homeserver

In the [`matrix`](../reference/configuration.md#matrix) section of the configuration file, add the following properties:

 - `kind`: the type of homeserver to connect to, currently only `palpo` is supported
 - `homeserver`: corresponds to the `server_name` in the Palpo configuration file
 - `secret`: a shared secret the service will use to call the homeserver Pasion API
 - `endpoint`: the URL to which the homeserver is accessible from the service

```yaml
matrix:
  kind: palpo
  homeserver: example.com
  endpoint: "http://localhost:8008"
  secret: "AVeryRandomSecretPleaseUseSomethingSecure"
  # Alternatively, using a file:
  #secret_path: /path/to/secret.txt
```

## Configure the homeserver to delegate authentication to the service

Set up delegated authentication **in the Palpo configuration** in the
`delegated_auth` section. The issuer is Pasion's public `http.public_base` URL;
the introspection and password exchange URLs can use internal network addresses.

```yaml
delegated_auth:
  enable: true
  issuer: https://auth.example.com/
  introspection_endpoint: http://localhost:8080/oauth2/introspect
  client_id: palpo-legacy-sso
  sso_callback_url: https://matrix.example.com/_matrix/client/v3/login/sso/callback
  sso_allowed_redirect_origins:
    - http://127.0.0.1
    - http://localhost
    - https://app.example.com

# Palpo's admin.mas_secret must match the Pasion matrix.secret above.
admin:
  mas_secret: "AVeryRandomSecretPleaseUseSomethingSecure"
```

Register `palpo-legacy-sso` as a public OAuth client in Pasion with the exact
`sso_callback_url` above as an allowed redirect URI. The callback URL is hosted
by Palpo; it exchanges the authorization code and returns a short-lived Matrix
login token to an allowed client origin. Add the actual origins of your Matrix
clients to `sso_allowed_redirect_origins`. Only enable this flow after the
callback and allowlist are configured.

The shared secret must match in Palpo and Pasion. If you need legacy Matrix
password login, additionally set Palpo's `delegated_auth.password_login_endpoint`
to Pasion's internal `/api/internal/matrix/password-login` endpoint. Palpo does
not advertise password login without this endpoint. Keep it unset when Pasion
password login is disabled.

## Matrix client endpoints

Route `/_matrix/client/*` to Palpo. Palpo serves
`/_matrix/client/v1/auth_metadata` using Pasion's OIDC discovery document and
handles the legacy Matrix SSO callback and login-token exchange. Pasion itself
does not serve the Matrix `/login`, `/logout`, or `/refresh` compatibility routes;
its `compat` listener resource is currently a no-op. The upstream providers
configured in Pasion are presented on Pasion's browser login page, not in the
OAuth authorization-server metadata. Administrators can manage database-backed
upstream providers from Padmin's **Pasion → Upstream Providers** page; providers
defined in Pasion's config file remain read-only there.


## Migrating older Palpo configuration

Replace experimental MSC3861 settings with Palpo's `delegated_auth` section.
Set the public issuer, token introspection URL, and matching shared secret as
above. Configure the SSO callback and client origins before offering legacy SSO
to Matrix clients.
