//! Sphere protocol constants shared between host and guest.

pub use sphere_contracts::spheres::{
    MAX_UNPROCESSED_DEPOSITS, MAX_UNPROCESSED_TOKEN_ENABLEMENTS, MAX_WITHDRAWAL_GAS_LIMIT,
    NO_QUEUE_INDEX, ARC_STATE_ADDRESS, SPHERE_FEE_MANAGER_ADDRESS, SPHERE_INBOX_ADDRESS,
    SPHERE_OUTBOX_ADDRESS, SPHERE_TOKEN_ADDRESS,
};

use alloy_primitives::Address;

/// Large blocks can exceed tungstenite's default 16 MiB frame limit.
pub const MAX_WS_FRAME_AND_MESSAGE_SIZE: usize = 128 * 1024 * 1024;

/// Maximum number of Arc headers authenticated by one checkpoint-only Sphere block.
pub const MAX_ARC_HEADERS_PER_SPHERE_BLOCK: usize = 1024;

/// Capacity reserved for one maximum-size withdrawal batch to bounce back.
pub const WITHDRAWAL_BOUNCEBACK_RESERVE: usize = 20;

/// Maximum RLP-encoded block size.
///
/// This follows EIP-7934's `MAX_BLOCK_SIZE - SAFETY_MARGIN` and matches
/// `reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE`.
pub const MAX_RLP_BLOCK_SIZE: usize = 8_388_608;

/// Protocol-level contract deployers permitted to create contracts on Spheres.
///
/// WARNING: Updating this list is a consensus change.
pub const CONTRACT_DEPLOYER_ALLOWLIST: &[Address] = &[];

/// Largest generic parent chain ID accepted by [`sphere_chain_id`].
pub const MAX_GENERIC_PARENT_CHAIN_ID: u64 = 5_042_002;

/// Failure to derive a unique sphere chain ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SphereChainIdError {
    /// Generic parent chain IDs must fit the supported range.
    #[error("generic parent chain ID must be in 1..={MAX_GENERIC_PARENT_CHAIN_ID}, got {0}")]
    InvalidParentChainId(u64),
    /// The chain ID is not a valid Sphere chain ID.
    #[error("chain ID {0} is not a valid sphere chain ID")]
    InvalidSphereChainId(u64),
}

/// Derives a sphere EIP-155 chain ID from its parent chain and SphereFactory ID.
pub fn sphere_chain_id(parent_chain_id: u64, sphere_id: u32) -> Result<u64, SphereChainIdError> {
    validate_chain_id(parent_chain_id)?;

    let chain_id = (parent_chain_id << 32) | u64::from(sphere_id);

    Ok(chain_id)
}

/// Decodes the parent chain ID and SphereFactory ID from a Sphere chain ID.
pub fn decode_sphere_chain_id(chain_id: u64) -> Result<(u64, u32), SphereChainIdError> {
    let (parent_chain_id, sphere_id) = if chain_id >= 1 << 32 {
        (chain_id >> 32, chain_id as u32)
    } else {
        return Err(SphereChainIdError::InvalidSphereChainId(chain_id));
    };

    if sphere_chain_id(parent_chain_id, sphere_id) == Ok(chain_id) {
        Ok((parent_chain_id, sphere_id))
    } else {
        Err(SphereChainIdError::InvalidSphereChainId(chain_id))
    }
}

/// Decodes the parent chain ID from a Sphere chain ID.
pub fn decode_l1_chain_id(chain_id: u64) -> Result<u64, SphereChainIdError> {
    decode_sphere_chain_id(chain_id).map(|(parent_chain_id, _)| parent_chain_id)
}

fn validate_chain_id(parent_chain_id: u64) -> Result<(), SphereChainIdError> {
    if parent_chain_id == 0 || parent_chain_id > MAX_GENERIC_PARENT_CHAIN_ID {
        return Err(SphereChainIdError::InvalidParentChainId(parent_chain_id));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_domain_separated_chain_ids() {
        assert_ne!(sphere_chain_id(1_337, 7), sphere_chain_id(1_338, 7));
    }

    #[test]
    fn rejects_invalid_generic_parents() {
        assert_eq!(
            sphere_chain_id(0, 1),
            Err(SphereChainIdError::InvalidParentChainId(0))
        );
        assert!(matches!(
            sphere_chain_id(MAX_GENERIC_PARENT_CHAIN_ID + 1, 1),
            Err(SphereChainIdError::InvalidParentChainId(_))
        ));

        let chain_id = sphere_chain_id(5_042_002, 7).unwrap();
        assert_eq!(chain_id, 21_655_233_696_366_599);
        assert_eq!(decode_sphere_chain_id(chain_id), Ok((5_042_002, 7)));
    }

    #[test]
    fn decodes_parent_chain_id() {
        for (parent_chain_id, sphere_id) in [
            (1_337, 9),
            (MAX_GENERIC_PARENT_CHAIN_ID, u32::MAX),
        ] {
            let chain_id = sphere_chain_id(parent_chain_id, sphere_id).unwrap();
            assert_eq!(
                decode_sphere_chain_id(chain_id),
                Ok((parent_chain_id, sphere_id))
            );
            assert_eq!(decode_l1_chain_id(chain_id), Ok(parent_chain_id));
        }

        assert!(decode_l1_chain_id(u32::MAX as u64).is_err());
        assert!(decode_l1_chain_id(1 << 31).is_err());
    }
}
