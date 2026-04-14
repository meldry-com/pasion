# Database

Interactions with the database go through `diesel` with `diesel-async` for async support and `deadpool` for connection pooling.

## Writing database interactions

All database interactions are done through repository traits. Each repository trait usually manages one type of data, defined in the [`pasion-data-model`][pasion-data-model] crate.

Defining a new data type and associated repository looks like this:

 - Define new structs in [`pasion-data-model`][pasion-data-model] crate
 - Define the repository trait in [`pasion-storage`][pasion-storage] crate
 - Make that repository trait available via the `RepositoryAccess` trait in [`pasion-storage`][pasion-storage] crate
 - Setup the database schema by writing a migration file in [`pasion-storage-pg`][pasion-storage-pg] crate
 - Implement the new repository trait in [`pasion-storage-pg`][pasion-storage-pg] crate
 - Write tests for the PostgreSQL implementation in [`pasion-storage-pg`][pasion-storage-pg] crate

Some of those steps are documented in more details in the [`pasion-storage`][pasion-storage] and [`pasion-storage-pg`][pasion-storage-pg] crates.

[pasion-data-model]: ../rustdoc/pasion_data_model/index.html
[pasion-storage]: ../rustdoc/pasion_storage/index.html
[pasion-storage-pg]: ../rustdoc/pasion_storage_pg/index.html

## Migrations

Migration files live in the `diesel_migrations` folder in the `pasion-storage-pg` crate and are managed by `diesel_migrations`.

Note that migrations are embedded in the final binary and can be run from the service CLI tool.
