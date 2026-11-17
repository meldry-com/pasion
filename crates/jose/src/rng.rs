//! Preserve callers' `rand_core` 0.6 generators at the `RustCrypto` 0.10
//! boundary.

/// Borrow an existing cryptographic generator without reseeding or changing its
/// entropy. Only generators bearing the old `CryptoRng` marker receive the new
/// `TryCryptoRng` marker.
pub struct CryptoRngCompat<'a, R: ?Sized>(pub &'a mut R);

impl<R: rand_core::RngCore + ?Sized> rand::TryRng for CryptoRngCompat<'_, R> {
    type Error = rand_core::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.0.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(bytes)
    }
}

impl<R: rand_core::RngCore + rand_core::CryptoRng + ?Sized> rand::TryCryptoRng
    for CryptoRngCompat<'_, R>
{
}

#[cfg(test)]
mod tests {
    use rand::TryRng as _;

    struct Failing;
    impl rand_core::RngCore for Failing {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible path must not be called")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible path must not be called")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible path must not be called")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::new("test entropy failure"))
        }
    }
    impl rand_core::CryptoRng for Failing {}

    #[test]
    fn fallible_generator_errors_do_not_call_infallible_methods() {
        let mut rng = super::CryptoRngCompat(&mut Failing);
        assert!(rng.try_next_u32().is_err());
        assert!(rng.try_next_u64().is_err());
        assert!(rng.try_fill_bytes(&mut [0; 32]).is_err());
    }
}
