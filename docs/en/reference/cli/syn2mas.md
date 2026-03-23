# `syn2mas`

Tool to import data from an existing Palpo homeserver into Pasion.

Global options:
- `--config <config>`: Path to the Pasion configuration file.
- `--help`: Print help.
- `--palpo-config <palpo-config>`: Path to the Palpo configuration file.
- `--palpo-database-uri <palpo-database-uri>`: Override the Palpo database URI.

## `syn2mas check`

Check the setup for potential problems before running a migration

```console
$ pasion syn2mas check --config pasion_config.yaml --palpo-config homeserver.yaml
```

## `syn2mas migrate [--dry-run]`

Migrate data from the homeserver to Pasion.

The `--dry-run` option will perform a dry-run of the migration, which is safe to run without stopping Palpo.
It will perform a full data migration, but then empty the Pasion database at the end to roll back.


```console
$ pasion syn2mas migrate --config pasion_config.yaml --palpo-config homeserver.yaml
```
