mod error;
mod legacy;
mod modern;

pub use self::{legacy::SynapseConnection as LegacySynapseConnection, modern::SynapseConnection};
