# Get an access token

The [Palpo Authentication Service repository contains a simple shell script](https://github.com/palpo-im/palpo-auth-service/blob/main/misc/device-code-grant.sh) to interactively get an access token with arbitrary scopes.
It requires `sh`, `jq` and `curl` to be installed.
This can be run from anywhere, not necessarily from the host where MAS is running.

```sh
sh ./misc/device-code-grant.sh [palpo-url] <scope>...
```

This will prompt you to open a URL in your browser, finish the authentication flow, and print the access and refresh tokens.

This can be used to get access to the MAS admin API:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:mas:admin
```

Or to the Palpo admin API:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:matrix:org.matrix.msc2967.client:api:* urn:palpo:admin:*
```

Or even both at the same time:

```sh
sh ./misc/device-code-grant.sh https://palpo.example.com/ urn:matrix:org.matrix.msc2967.client:api:* urn:mas:admin urn:palpo:admin:*
```

Note that the token will only be valid for a short time (5 minutes by default) and needs to be revoked manually from the MAS user interface.
