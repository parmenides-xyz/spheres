// Copyright 2026 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Arc payload attributes builder for dev-mode local mining.
//! Fork from https://github.com/paradigmxyz/reth/blob/v1.11.3/crates/engine/local/src/payload.rs
//! - Uses `max(parent.timestamp, wall_clock)` instead of `max(parent.timestamp + 1, wall_clock)`
//!   to allow equal timestamps, matching Arc's relaxed validation.

use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_payload_primitives::PayloadAttributesBuilder;
use reth_primitives_traits::SealedHeader;
use std::sync::Arc;

/// Payload attributes builder for Arc's dev-mode miner.
///
/// Unlike upstream's `LocalPayloadAttributesBuilder` which enforces strictly
/// increasing timestamps (`parent + 1`), this uses `max(wall_clock, parent.timestamp)`
/// to allow equal timestamps — matching Arc's sub-second block production.
#[derive(Debug)]
pub struct ArcLocalPayloadAttributesBuilder<ChainSpec> {
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> ArcLocalPayloadAttributesBuilder<ChainSpec> {
    /// Creates a new instance of the builder.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes, ChainSpec::Header>
    for ArcLocalPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    fn build(&self, parent: &SealedHeader<ChainSpec::Header>) -> EthPayloadAttributes {
        let timestamp = std::cmp::max(
            parent.timestamp(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Clock is before UNIX epoch")
                .as_secs(),
        );

        EthPayloadAttributes {
            slot_number: None,
            timestamp,
            prev_randao: B256::random(),
            // Mock CL uses genesis coinbase as suggested fee recipient
            suggested_fee_recipient: self.chain_spec.genesis_header().beneficiary(),
            withdrawals: self
                .chain_spec
                .is_shanghai_active_at_timestamp(timestamp)
                .then(Default::default),
            parent_beacon_block_root: self
                .chain_spec
                .is_cancun_active_at_timestamp(timestamp)
                .then(B256::random),
        }
    }
}
