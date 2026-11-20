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

use alloy_consensus::BlockHeader;
use alloy_rpc_types_engine::ExecutionData;
use reth_chainspec::Hardforks;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_engine_primitives::EngineTypes;
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_ethereum_payload_builder::EthereumExecutionPayloadValidator;
use reth_ethereum_primitives::Block;
use reth_ethereum_primitives::EthPrimitives;
use reth_node_api::{AddOnsContext, FullNodeComponents, PayloadTypes};
use reth_node_builder::{node::NodeTypes, rpc::PayloadValidatorBuilder};
use reth_payload_primitives::InvalidPayloadAttributesError;
use reth_payload_primitives::PayloadAttributes;
use reth_payload_primitives::{
    EngineApiMessageVersion, EngineObjectValidationError, NewPayloadError, PayloadOrAttributes,
    validate_execution_requests, validate_version_specific_fields,
};
use reth_primitives_traits::Block as BlockTr;
use reth_primitives_traits::RecoveredBlock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ArcEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    inner: EthereumExecutionPayloadValidator<ChainSpec>,
}

impl<ChainSpec> ArcEngineValidator<ChainSpec> {
    /// Instantiates a new validator.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: EthereumExecutionPayloadValidator::new(chain_spec),
        }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

/// Type that validates an [`ExecutionPayload`].
impl<ChainSpec, Types> PayloadValidator<Types> for ArcEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<ExecutionData = ExecutionData>,
    Types::PayloadAttributes: PayloadAttributes,
{
    type Block = Block;

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
            <Self as PayloadValidator<Types>>::convert_payload_to_block(self, payload)?;
        sealed_block
            .try_recover()
            .map_err(|e| NewPayloadError::Other(e.into()))
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &Types::PayloadAttributes,
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

/// Type that validates the payloads processed by the engine.
impl<ChainSpec, Types> EngineApiValidator<Types> for ArcEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
    Types: PayloadTypes<PayloadAttributes = EthPayloadAttributes, ExecutionData = ExecutionData>,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Types::ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        payload_or_attrs
            .execution_requests()
            .map(|requests| validate_execution_requests(requests))
            .transpose()?;

        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Types::ExecutionData, EthPayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

/// Builder for [`ArcEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ArcEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for ArcEngineValidatorBuilder
where
    Types: NodeTypes<
            ChainSpec: Hardforks + EthereumHardforks + Clone + 'static,
            Payload: EngineTypes<ExecutionData = ExecutionData>
                         + PayloadTypes<PayloadAttributes = EthPayloadAttributes>,
            Primitives = EthPrimitives,
        >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = ArcEngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(ArcEngineValidator::new(ctx.config.chain.clone()))
    }
}
