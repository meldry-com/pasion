//! Helpers for PostgreSQL advisory locks.

/// Derive a stable `i64` advisory-lock key from a human-readable lock name
/// using CRC-32 (ISO-HDLC).
///
/// PostgreSQL advisory locks are keyed by `bigint`, so this maps an arbitrary
/// lock name to a deterministic key that is stable across processes and runs.
#[must_use]
pub fn advisory_lock_key(name: &str) -> i64 {
    const CRC_IEEE: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    i64::from(CRC_IEEE.checksum(name.as_bytes()))
}
