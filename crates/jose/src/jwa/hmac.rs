use std::marker::PhantomData;

use digest::{Digest, Mac, OutputSizeUser, crypto_common::BlockSizeUser, typenum::Unsigned};
use signature::{Signer, Verifier};
use thiserror::Error;

pub struct Signature<S> {
    signature: Vec<u8>,
    size: PhantomData<S>,
}

impl<S> PartialEq for Signature<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
    }
}

impl<S> Eq for Signature<S> {}

impl<S> std::fmt::Debug for Signature<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.signature)
    }
}

impl<S> Clone for Signature<S> {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            size: PhantomData,
        }
    }
}

impl<S> From<Signature<S>> for Vec<u8> {
    fn from(val: Signature<S>) -> Self {
        val.signature
    }
}

impl<S: Unsigned> TryFrom<&[u8]> for Signature<S> {
    type Error = InvalidLength;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != S::USIZE {
            return Err(InvalidLength);
        }
        Ok(Self {
            signature: value.to_vec(),
            size: PhantomData,
        })
    }
}

impl<S: Unsigned> signature::SignatureEncoding for Signature<S> {
    type Repr = Vec<u8>;
}

impl<S> AsRef<[u8]> for Signature<S> {
    fn as_ref(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

pub struct Hmac<D> {
    key: Vec<u8>,
    digest: PhantomData<D>,
}

impl<D> Hmac<D> {
    pub const fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: PhantomData,
        }
    }
}

#[derive(Error, Debug)]
#[error("invalid length")]
pub struct InvalidLength;

impl<D> From<Vec<u8>> for Hmac<D> {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key,
            digest: PhantomData,
        }
    }
}

impl<D: Digest + BlockSizeUser>
    Signer<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>, signature::Error>
    {
        let mut mac = <hmac::SimpleHmac<D> as Mac>::new_from_slice(&self.key)
            .map_err(signature::Error::from_source)?;
        mac.update(msg);
        let signature = mac.finalize().into_bytes().to_vec();
        Ok(Signature {
            signature,
            size: PhantomData,
        })
    }
}

impl<D: Digest + BlockSizeUser>
    Verifier<Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>> for Hmac<D>
{
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature<<hmac::SimpleHmac<D> as OutputSizeUser>::OutputSize>,
    ) -> Result<(), signature::Error> {
        let new_signature = self.try_sign(msg)?;
        if &new_signature != signature {
            return Err(signature::Error::new());
        }
        Ok(())
    }
}
