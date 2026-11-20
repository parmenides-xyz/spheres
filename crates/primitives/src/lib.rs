//! Primitive types used by the sphere.
//!
//! This crate is `no_std` compatible so it can be used inside SP1 (RISC-V) guest
//! programs and TEE enclaves, as well as in the host-side prover.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod constants;
pub mod envelope;

#[cfg(feature = "serde")]
pub mod serde_rlp;

#[cfg(feature = "reth")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpherePrimitives;

#[cfg(feature = "reth")]
impl reth_primitives_traits::NodePrimitives for SpherePrimitives {
    type Block = alloy_consensus::Block<envelope::SphereTxEnvelope>;
    type BlockHeader = alloy_consensus::Header;
    type BlockBody = alloy_consensus::BlockBody<envelope::SphereTxEnvelope>;
    type SignedTx = envelope::SphereTxEnvelope;
    type Receipt = alloy_consensus::EthereumReceipt;
}
