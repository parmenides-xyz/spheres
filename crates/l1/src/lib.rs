use alloy_consensus::{BlockHeader as _, Header};
use alloy_eips::{BlockNumberOrTag, NumHash};
use alloy_network::{Ethereum, primitives::HeaderResponse as _};
use alloy_primitives::{Address, B256, Bloom, U256, keccak256};
use alloy_provider::ProviderBuilder;
use alloy_rpc_client::RpcClient;
use alloy_transport::Authorization;
use futures::{Stream, StreamExt, TryStreamExt as _};
use reth_storage_api::StateProviderFactory;
use std::pin::Pin;
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{BlockId, Log};
use alloy_sol_types::{SolEvent, SolEventInterface, SolValue};
use parking_lot::Mutex;
use reth_primitives_traits::SealedHeader;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};

pub mod ext;
pub mod genesis;

pub(crate) mod rpc {
    use std::time::Duration;

    use alloy_rpc_client::{ConnectionConfig, WebSocketConfig};

    const MAX_WS_FRAME_AND_MESSAGE_SIZE: usize = 128 * 1024 * 1024;

    pub(crate) fn rpc_connection_config(retry_connection_interval: Duration) -> ConnectionConfig {
        ConnectionConfig::new()
            .with_max_retries(u32::MAX)
            .with_retry_interval(retry_connection_interval)
            .with_ws_config(
                WebSocketConfig::default()
                    // Large blocks can exceed tungstenite's default 16 MiB frame limit.
                    .max_frame_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE))
                    .max_message_size(Some(MAX_WS_FRAME_AND_MESSAGE_SIZE)),
            )
    }
}

pub mod abi {
    pub use sphere_contracts::*;
}

use crate::abi::{
    Deposit as AbiDeposit, DepositPayload as AbiDepositPayload,
    SpherePortal::{
        DepositMade, LeaderUpdated, PortalPaused, PortalResumed, SequencerEncryptionKeyUpdated,
        SpherePortalEvents, TokenEnabled, WithdrawalBounceBack,
    },
};

pub(crate) mod precompiles {
    pub(crate) use sphere_precompiles::*;
}

mod block;
mod deposit;
mod encryption_keys;
mod metrics;
mod event;
mod pause;
mod queue;
pub mod state;
mod subscriber;

pub use block::{L1BlockDeposits, PreparedL1Block};
pub use deposit::{Deposit, L1Deposit, WithdrawalBounceBackDeposit};
pub use encryption_keys::{
    BoundPublicKeyFingerprint, EncryptionKeyPublicStatus, EncryptionKeyRing, PublicKeyFingerprint,
};
pub use event::{
    EnabledToken, EncryptionKeyRotation, L1PortalEvents, LeaderTransition, encryption_key_address,
};
pub use ext::{ArcStateExt, ChainArcStateExt};
pub use pause::{
    PORTAL_PAUSE_POLL_INTERVAL, initialize_portal_pause, refresh_portal_pause, watch_portal_pause,
};
pub use queue::DepositQueue;
#[cfg(test)]
pub(crate) use queue::PendingDeposits;
pub use state::L1StateCache;
pub use subscriber::{
    AuthenticatedPortalLogs, FinalizedBatchSubmission, FinalizedTarget, L1BlockTracker,
    L1Subscriber, L1SubscriberConfig, L1SubscriberError, LeadershipSink, MAX_L1_LOOKAHEAD_BLOCKS, extract_finalized_batch_submissions, verify_receipts_against_header,
};

#[cfg(test)]
mod tests;
