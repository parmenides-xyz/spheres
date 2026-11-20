//! ## Cryptography
//!
//! - **Chaum-Pedersen verification** — verifies DLOG equality proofs for ECDH shared secret
//!   derivation inside the native inbox.
//! - **AES-256-GCM decryption** — decrypts ECIES ciphertext and verifies
//!   the GCM authentication tag inside the native inbox.
//! - **ECIES** ([`ecies`]) — sequencer-side ECIES decryption logic.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;
pub mod aes_gcm;
pub mod arc_state;
pub mod inbox;
pub mod outbox;
pub mod sphere_fee_manager;
pub mod chaum_pedersen;
pub mod ecies;
pub mod storage;
pub use storage::{L1State, L1StateError, L1StorageReader};
#[cfg(feature = "std")]
pub mod tx_context;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
