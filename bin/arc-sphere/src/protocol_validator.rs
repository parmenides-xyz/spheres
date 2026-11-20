// Copyright 2025 Circle Internet Group, Inc. All rights reserved.
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

//! Arc validator
//! fork from https://github.com/paradigmxyz/reth/blob/main/crates/ethereum/node/src/engine.rs
//! - customize validate_payload_attributes_against_header to relax the timestamp constraint.

use alloy_consensus::{Block, BlockHeader};
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::PayloadValidator;
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_node_api::{AddOnsContext, FullNodeComponents};
use reth_node_builder::{node::NodeTypes, rpc::PayloadValidatorBuilder};
use reth_payload_primitives::{InvalidPayloadAttributesError, NewPayloadError, PayloadAttributes};
use reth_primitives_traits::{Block as BlockTr, RecoveredBlock};
use sphere_payload::{SpherePayloadAttributes, SpherePayloadTypes};
use sphere_primitives::{SpherePrimitives, envelope::SphereTxEnvelope};
use std::sync::Arc;
#[derive(Debug, Clone)]
pub struct SphereEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl<ChainSpec> SphereEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
        }
    }
}
/// Type that validates an [`ExecutionPayload`].
impl<ChainSpec> PayloadValidator<SpherePayloadTypes> for SphereEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    type Block = Block<SphereTxEnvelope>;

    fn convert_payload_to_block(
        &self,
        payload: ExecutionData,
    ) -> Result<reth_primitives_traits::SealedBlock<Self::Block>, NewPayloadError> {
        if payload
            .sidecar
            .versioned_hashes()
            .is_some_and(|v| !v.is_empty())
            || payload.payload.blob_gas_used().is_some_and(|g| g > 0)
        {
            return Err(NewPayloadError::Other(
                "Blob transactions are not supported".into(),
            ));
        }

        if payload
            .payload
            .withdrawals()
            .is_some_and(|withdrawals| !withdrawals.is_empty())
        {
            return Err(NewPayloadError::Other(
                "Withdrawals are not supported".into(),
            ));
        }

        self.inner
            .ensure_well_formed_payload(payload)
            .map_err(Into::into)
    }

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block =
            <Self as PayloadValidator<SpherePayloadTypes>>::convert_payload_to_block(
                self, payload,
            )?;
        sealed_block
            .try_recover()
            .map_err(|e| NewPayloadError::Other(e.into()))
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &SpherePayloadAttributes,
        header: &<Self::Block as BlockTr>::Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // NOTE(romac): Here we relax the check to allow the payload attributes timestamp
        //              to be greater than or equal to the header's timestamp.
        if attr.timestamp() < header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct SphereEngineValidatorBuilder;
impl<Node> PayloadValidatorBuilder<Node> for SphereEngineValidatorBuilder
where
    Node: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthereumHardforks,
            Payload = SpherePayloadTypes,
            Primitives = SpherePrimitives,
        >,
    >,
{
    type Validator = SphereEngineValidator<<Node::Types as NodeTypes>::ChainSpec>;
    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(SphereEngineValidator::new(ctx.config.chain.clone()))
    }
}
