//! Shared test utilities for precompile and EVM integration tests.

pub mod l1_reader;
pub use l1_reader::MockL1Reader;

mod local;
pub use local::EncryptedDepositFixture;
#[cfg(test)]
pub(crate) use local::{
    assert_cp_proof_valid, build_plaintext, compressed_x_and_parity, encrypt_plaintext,
};
