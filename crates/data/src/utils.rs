use rand_chacha::rand_core::CryptoRngCore;

use crate::clock::Clock;

/// A boxed [`Clock`]
pub type BoxClock = Box<dyn Clock + Send>;
/// A boxed random number generator
pub type BoxRng = Box<dyn CryptoRngCore + Send>;
