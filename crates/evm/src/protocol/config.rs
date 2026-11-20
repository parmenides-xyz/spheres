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

use super::SphereProtocolEvmFactory;
use crate::SphereEvmConfig;
use alloy_eips::Decodable2718;
use alloy_evm::{
    Evm,
    eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
};
use alloy_evm::{
    EvmFactory,
    block::{BlockExecutorFactory, state::StateDB},
    eth::{EthBlockExecutionCtx, EthEvmContext},
};
use alloy_primitives::Bytes;
use alloy_rpc_types_engine::ExecutionData;
use arc_evm::{assembler::ArcBlockAssembler, executor::ArcBlockExecutor};
use arc_execution_config::chainspec::{ArcChainSpec, BlockGasLimitProvider};
use arc_execution_config::protocol_config::{expected_gas_limit, retrieve_fee_params};
use reth_ethereum::{
    Receipt,
    chainspec::EthChainSpec,
    evm::{
        EthEvmConfig,
        primitives::{Database, EvmEnv, NextBlockEnvAttributes},
        revm::{
            context_interface::result::HaltReason, db::State, inspector::Inspector,
            primitives::hardfork::SpecId,
        },
    },
    node::api::ConfigureEvm,
    primitives::{Header, SealedBlock, SealedHeader},
};
use reth_evm::BlockExecutorForEvm;
use reth_evm::execute::BlockBuilder;
use reth_evm::{ConfigureEngineEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor};
use reth_primitives_traits::NodePrimitives;
use reth_primitives_traits::{SignedTransaction, TxTy};
use reth_storage_errors::any::AnyError;
use sphere_primitives::{
    SpherePrimitives,
    envelope::{SphereTxEnvelope, SphereTxType},
};
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SphereReceiptBuilder;

impl ReceiptBuilder for SphereReceiptBuilder {
    type Transaction = SphereTxEnvelope;
    type Receipt = Receipt;

    fn build_receipt<E: Evm>(&self, ctx: ReceiptBuilderCtx<'_, SphereTxType, E>) -> Self::Receipt {
        let ReceiptBuilderCtx {
            tx_type,
            result,
            cumulative_gas_used,
            ..
        } = ctx;
        Receipt {
            tx_type: alloy_consensus::TxType::try_from(u8::from(tx_type))
                .expect("supported Ethereum transaction type"),
            // Success flag was added in `EIP-658: Embedding transaction status code in
            // receipts`.
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.into_logs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SphereProtocolEvmConfig {
    dev: SphereEvmConfig,
    evm_factory_instance: SphereProtocolEvmFactory,
    block_assembler: ArcBlockAssembler<ArcChainSpec>,
}
impl SphereProtocolEvmConfig {
    pub fn with_l1_reader<P: sphere_precompiles::L1StorageReader>(
        mut self,
        l1: P,
        portal: alloy_primitives::Address,
    ) -> Self {
        self.evm_factory_instance.1 = Some((super::reader::Reader::new(l1), portal));
        self
    }
    pub fn new(chain_spec: Arc<sphere_chainspec::SphereChainSpec>) -> Self {
        let parent = sphere_primitives::constants::decode_l1_chain_id(chain_spec.chain_id())
            .ok()
            .and_then(sphere_chainspec::arc_chain_spec_for_l1);
        let denylist = parent.and_then(|spec| spec.denylist_address());
        let dev = crate::create_evm_config(chain_spec);
        Self {
            evm_factory_instance: SphereProtocolEvmFactory(
                dev.evm_factory_instance.clone(),
                None,
                denylist,
            ),
            block_assembler: dev.block_assembler.clone(),
            dev,
        }
    }
}
impl BlockExecutorFactory for SphereProtocolEvmConfig {
    type EvmFactory = SphereProtocolEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = SphereTxEnvelope;
    type Receipt = Receipt;
    type TxExecutionResult = arc_evm::executor::ArcTxResult<
        HaltReason,
        <SphereTxEnvelope as alloy_consensus::transaction::TransactionEnvelope>::TxType,
    >;
    type Executor<'a, DB: StateDB, I: Inspector<EthEvmContext<super::database::L1OverlayDB<DB>>>> =
        ArcBlockExecutor<
            'a,
            <SphereProtocolEvmFactory as EvmFactory>::Evm<DB, I>,
            &'a Arc<ArcChainSpec>,
            SphereReceiptBuilder,
        >;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.evm_factory_instance
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: <Self::EvmFactory as EvmFactory>::Evm<DB, I>,
        ctx: EthBlockExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<<Self::EvmFactory as EvmFactory>::Context<DB>>,
    {
        ArcBlockExecutor::new(evm, ctx, self.dev.inner.chain_spec(), SphereReceiptBuilder)
    }
}

impl ConfigureEvm for SphereProtocolEvmConfig {
    type Primitives = SpherePrimitives;
    type Error = <EthEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <EthEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = ArcBlockAssembler<ArcChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> Result<EvmEnv<SpecId>, Self::Error> {
        self.dev.evm_env(header)
    }

    fn builder_for_next_block<'a, DB: Database + 'a>(
        &'a self,
        db: &'a mut State<DB>,
        parent: &'a SealedHeader<<Self::Primitives as NodePrimitives>::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<
        impl BlockBuilder<Primitives = Self::Primitives, Executor = BlockExecutorForEvm<'a, Self, DB>>,
        Self::Error,
    > {
        // Query the ProtocolConfig contract for the reward beneficiary using system call
        let mut attributes = attributes.clone();

        // Create EVM environment for the system call
        let mut system_evm = self.dev.evm_with_env(
            &mut *db,
            self.dev
                .next_evm_env(parent, &attributes)
                .inspect_err(|err| {
                    tracing::error!(error = ?err, "Failed to create EVM environment");
                })?,
        );

        // Override the gas limit with the gas limit from the ProtocolConfig contract.
        // ADR-0003: use chainspec bounds; fall back to chainspec default when ProtocolConfig
        // is unavailable or returns an out-of-bounds value.
        let chain_spec = self.dev.inner.chain_spec().as_ref();
        let fee_params = retrieve_fee_params(&mut system_evm).inspect_err(|err| {
                tracing::warn!(error = ?err, "Failed to get fee params from ProtocolConfig, using default gas limit");
            }).ok();
        let next_block_height = parent.number.checked_add(1).expect("block number overflow");

        let gas_limit_config = chain_spec.block_gas_limit_config(next_block_height);
        attributes.gas_limit = expected_gas_limit(fee_params.as_ref(), &gas_limit_config);

        let evm_env = self.next_evm_env(parent, &attributes)?;
        let evm = self.evm_with_env(db, evm_env);
        let ctx = self.context_for_next_block(parent, attributes)?;

        Ok(self.create_block_builder(evm, parent, ctx))
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        self.dev.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<alloy_consensus::Block<SphereTxEnvelope>>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        Ok(EthBlockExecutionCtx {
            tx_count_hint: Some(block.transaction_count()),
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block
                .body()
                .withdrawals
                .as_ref()
                .map(|w| Cow::Borrowed(w.as_slice())),
            extra_data: block.header().extra_data.clone(),
            slot_number: block.header().slot_number,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        let mut ctx = self.dev.context_for_next_block(parent, attributes)?;
        // Clearing extra_data as the executor will supply it after execution.
        ctx.extra_data = Default::default();
        Ok(ctx)
    }
}

impl ConfigureEngineEvm<ExecutionData> for SphereProtocolEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.dev.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.dev.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let txs = payload.payload.transactions().clone();
        let convert = |tx: Bytes| {
            let tx =
                TxTy::<Self::Primitives>::decode_2718_exact(tx.as_ref()).map_err(AnyError::new)?;
            let signer = tx.try_recover().map_err(AnyError::new)?;
            Ok::<_, AnyError>(tx.with_signer(signer))
        };

        Ok((txs, convert))
    }
}
