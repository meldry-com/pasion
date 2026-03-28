use tokio_postgres::Client;

/// A wrapper around a Postgres client which holds a session-wide advisory
/// lock preventing concurrent access by other syn2mas instances.
pub struct LockedMasDatabase {
    client: Client,
}

/// Result of attempting to lock the Pasion database.
/// `Left` contains the locked database, `Right` returns the client if locking failed.
pub enum LockResult {
    Locked(LockedMasDatabase),
    AlreadyLocked(Client),
}

impl LockedMasDatabase {
    /// Attempts to lock the Pasion database against concurrent access by other
    /// syn2mas instances.
    ///
    /// If the lock can be acquired, returns a `LockedMasDatabase` inside `LockResult::Locked`.
    /// If the lock cannot be acquired, returns the client back to the
    /// caller wrapped in `LockResult::AlreadyLocked`.
    ///
    /// # Errors
    ///
    /// Errors are returned for underlying database errors.
    pub async fn try_new(
        client: Client,
    ) -> Result<LockResult, tokio_postgres::Error> {
        let row = client
            .query_one(
                "SELECT pg_try_advisory_lock(hashtext('syn2mas-maswriter'))",
                &[],
            )
            .await?;

        let acquired: bool = row.get(0);
        if acquired {
            Ok(LockResult::Locked(LockedMasDatabase { client }))
        } else {
            Ok(LockResult::AlreadyLocked(client))
        }
    }

    /// Releases the advisory lock on the Pasion database, returning the
    /// underlying client.
    ///
    /// # Errors
    ///
    /// Errors are returned for underlying database errors.
    pub async fn unlock(self) -> Result<Client, tokio_postgres::Error> {
        self.client
            .execute(
                "SELECT pg_advisory_unlock(hashtext('syn2mas-maswriter'))",
                &[],
            )
            .await?;
        Ok(self.client)
    }

    /// Get a mutable reference to the underlying client.
    pub fn client_mut(&mut self) -> &Client {
        &self.client
    }

    /// Get a reference to the underlying client.
    pub fn client(&self) -> &Client {
        &self.client
    }
}
