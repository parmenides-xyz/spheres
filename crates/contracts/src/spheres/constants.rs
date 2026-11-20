//! Shared Sphere contract addresses and protocol limits.

use alloy_primitives::{Address, U256, address};

pub use crate::precompiles::NATIVE_FIAT_TOKEN_ADDRESS as SPHERE_TOKEN_ADDRESS;

/// Sentinel emitted as `BatchSubmitted.withdrawalQueueIndex` when a batch carried no
/// withdrawals and therefore consumed no queue index (`NO_QUEUE_INDEX` in Solidity).
pub const NO_QUEUE_INDEX: U256 = U256::MAX;

/// Maximum callback gas a withdrawal may request.
///
/// The L1 processor adds fixed overhead, so this value keeps the outer
/// `processWithdrawals` transaction well below a 30M gas block.
pub const MAX_WITHDRAWAL_GAS_LIMIT: u64 = 10_000_000;

/// Maximum deposit entries that may remain outstanding on a SpherePortal.
pub const MAX_UNPROCESSED_DEPOSITS: usize = 230;

/// Maximum token enablements that may remain outstanding on a SpherePortal.
pub const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: usize = 8;

/// ArcState predeploy address on Sphere L2.
pub const ARC_STATE_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000000");

/// SphereInbox predeploy address on Sphere L2.
pub const SPHERE_INBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000001");

/// SphereOutbox predeploy address on Sphere L2.
pub const SPHERE_OUTBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000002");

/// Sphere-native fee manager precompile address.
pub const SPHERE_FEE_MANAGER_ADDRESS: Address =
    address!("0xfeec000000000000000000000000000000000001");

/// Packed field from SpherePortal's Foundry storage layout.
pub const TRANSFERS_ENABLED_SLOT: U256 = U256::from_limbs([28, 0, 0, 0]);
pub const TRANSFERS_ENABLED_OFFSET: usize = 9;
