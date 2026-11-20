//! Versioned request protocol for the Arc Sphere prover service.

mod chainspec;
mod connection;
mod protocol;

pub use chainspec::{TrustedChainSpecError, TrustedChainSpecs};
pub use connection::{ProverConnection, ProverConnectionError, request_error_response};
pub use protocol::{
    ErrorCode, NO_PROOF_FALLBACK_VERIFIER, NO_PROOF_FALLBACK_VERIFIER_HASH, PROTOCOL_VERSION,
    ProofBundle, VerifierMode, VerifierModeError, VerifyRequest, VerifyResponse,
};

/// Allows batch witnesses up to 2 GiB to bound untrusted frame allocations.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024 * 1024;
