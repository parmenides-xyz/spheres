use alloy_primitives::{B256, Bytes};
use keccak_const::Keccak256;
use serde::{Deserialize, Serialize};
use sphere_spf::{BatchOutput, BatchWitness};

/// Current version of the prover request and response wire format.
pub const PROTOCOL_VERSION: u16 = 1;

/// Canonical one-byte configuration selecting temporary proofless fallback settlement.
pub const NO_PROOF_FALLBACK_VERIFIER: &[u8] = &[2];
/// Compile-time Keccak-256 hash of [`NO_PROOF_FALLBACK_VERIFIER`].
pub const NO_PROOF_FALLBACK_VERIFIER_HASH: B256 = B256::new(
    Keccak256::new()
        .update(NO_PROOF_FALLBACK_VERIFIER)
        .finalize(),
);

/// Canonical verifier configurations supported by Sphere settlement.
///
/// Each mode owns both the bytes passed to the on-chain verifier and the proof shape accepted for
/// those bytes. Decoding rejects unknown and non-canonical configurations rather than treating
/// them as fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierMode {
    /// Temporary fallback verification requiring an empty proof.
    NoProof,
}

impl VerifierMode {
    /// Exact bytes passed to the on-chain verifier.
    pub const fn config(self) -> &'static [u8] {
        match self {
            Self::NoProof => NO_PROOF_FALLBACK_VERIFIER,
        }
    }

    /// Hash committed by settlement attestations.
    pub const fn config_hash(self) -> B256 {
        match self {
            Self::NoProof => NO_PROOF_FALLBACK_VERIFIER_HASH,
        }
    }

    /// Validate that `proof` has the shape required by this verifier mode.
    ///
    pub fn validate_proof_shape(self, proof: &[u8]) -> Result<(), VerifierModeError> {
        match (self, proof.is_empty()) {
            (Self::NoProof, false) => Err(VerifierModeError::InvalidProofShape),
            _ => Ok(()),
        }
    }
}

impl TryFrom<&[u8]> for VerifierMode {
    type Error = VerifierModeError;

    /// Decode an exact configuration. Unknown and non-canonical encodings are rejected.
    fn try_from(config: &[u8]) -> Result<Self, Self::Error> {
        match config {
            NO_PROOF_FALLBACK_VERIFIER => Ok(Self::NoProof),
            _ => Err(VerifierModeError::UnknownConfig),
        }
    }
}

impl TryFrom<B256> for VerifierMode {
    type Error = VerifierModeError;

    /// Decode the hash committed by a settlement attestation.
    fn try_from(hash: B256) -> Result<Self, Self::Error> {
        match hash {
            NO_PROOF_FALLBACK_VERIFIER_HASH => Ok(Self::NoProof),
            _ => Err(VerifierModeError::UnknownConfigHash),
        }
    }
}

/// Failure to decode or validate a verifier mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifierModeError {
    /// Raw configuration bytes are not one of the canonical encodings.
    #[error("unknown verifier configuration")]
    UnknownConfig,
    /// A settlement commitment does not match any canonical configuration hash.
    #[error("unknown verifier configuration hash")]
    UnknownConfigHash,
    #[error("proof shape does not match verifier configuration")]
    InvalidProofShape,
}

/// Proof material returned by an attesting prover.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBundle {
    /// Opaque configuration passed to `IVerifier` and committed by the settlement certificate.
    pub verifier_config: Bytes,
    /// Raw COSE/CBOR Nitro attestation document.
    pub proof: Bytes,
}

/// Request to verify a Sphere batch witness against a trusted Arc chain.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyRequest {
    /// Wire-format version expected by the sender.
    pub version: u16,
    /// Caller-selected identifier echoed in the corresponding response.
    pub request_id: String,
    /// Complete input to the Sphere stateless proof function.
    pub witness: BatchWitness,
}

/// Result of processing a [`VerifyRequest`].
#[derive(Debug, Deserialize, Serialize)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum VerifyResponse {
    /// The witness was verified successfully.
    #[serde(rename = "ok")]
    Ok {
        /// Wire-format version used by the prover.
        version: u16,
        /// Identifier copied from the request.
        request_id: String,
        /// Output produced by the Sphere stateless proof function.
        output: Box<BatchOutput>,
        /// Nitro proof material returned by the attesting prover.
        proof_bundle: ProofBundle,
    },
    /// The request could not be decoded, accepted, or verified.
    #[serde(rename = "error")]
    Error {
        /// Wire-format version used by the prover.
        version: u16,
        /// Request identifier, when it could be recovered from the request.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// Stable, machine-readable error category.
        code: ErrorCode,
        /// Human-readable diagnostic detail.
        message: String,
    },
}

/// Stable error categories returned by the prover protocol.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request is not valid CBOR or does not match the request schema.
    MalformedRequest,
    /// The request uses a wire-format version unsupported by the prover.
    UnsupportedVersion,
    /// The requested Arc chain is not trusted by the prover.
    UnsupportedChain,
    /// Stateless proof execution rejected the supplied witness.
    VerificationFailed,
    /// The prover could not obtain an attestation from the Nitro Secure Module.
    AttestationUnavailable,
    /// The framed request exceeds the configured size limit.
    RequestTooLarge,
    /// The connection ended before the complete frame was received.
    TruncatedFrame,
    /// An unexpected transport or prover failure occurred.
    InternalError,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn error_variant_uses_the_wire_field_names() {
        let encoded = serde_json::to_vec(&VerifyResponse::Error {
            version: PROTOCOL_VERSION,
            request_id: Some("wire-test".into()),
            code: ErrorCode::UnsupportedChain,
            message: "unsupported".into(),
        })
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let error = &json["error"];

        assert_eq!(error["version"], PROTOCOL_VERSION);
        assert_eq!(error["requestId"], "wire-test");
        assert_eq!(error["code"], "unsupported_chain");
    }
}
