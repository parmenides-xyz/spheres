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

use crate::sphere_evm::SphereEvm;
use alloy_evm::{
    EvmFactory,
    block::{BlockExecutorFactory, state::StateDB},
    eth::{EthBlockExecutionCtx, EthEvmContext},
    precompiles::PrecompilesMap,
};
use alloy_rpc_types_engine::ExecutionData;
use arc_evm::{ArcEvmFactory, assembler::ArcBlockAssembler, executor::ArcBlockExecutor};
use arc_execution_config::chainspec::{ArcChainSpec, BlockGasLimitProvider};
use arc_execution_config::protocol_config::{expected_gas_limit, retrieve_fee_params};
use reth_ethereum::{
    Receipt, TransactionSigned,
    evm::{
        EthEvmConfig,
        primitives::{Database, EvmEnv, NextBlockEnvAttributes},
        revm::{
            context::{BlockEnv, TxEnv},
            context_interface::result::{EVMError, HaltReason},
            db::State,
            inspector::{Inspector, NoOpInspector},
            interpreter::interpreter::EthInterpreter,
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
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SphereEvmFactory(pub(crate) ArcEvmFactory);

impl EvmFactory for SphereEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = SphereEvm<DB, I>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        SphereEvm::new(self.0.create_evm(db, input))
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        SphereEvm::new(self.0.create_evm_with_inspector(db, input, inspector))
    }
}

/// Custom EVM configuration for Spheres
#[derive(Debug, Clone)]
pub struct SphereEvmConfig {
    pub(crate) inner: EthEvmConfig<ArcChainSpec, SphereEvmFactory>,
    pub(crate) evm_factory_instance: SphereEvmFactory,
    pub(crate) block_assembler: ArcBlockAssembler<ArcChainSpec>,
}

impl SphereEvmConfig {
    /// Create a new Sphere EVM configuration
    pub fn new(inner: EthEvmConfig<ArcChainSpec, SphereEvmFactory>) -> Self {
        let chain_spec = inner.chain_spec().clone();
        let evm_factory_instance = inner.executor_factory.evm_factory().clone();
        Self {
            inner,
            evm_factory_instance,
            block_assembler: ArcBlockAssembler::new(chain_spec.clone()),
        }
    }
}

impl BlockExecutorFactory for SphereEvmConfig {
    type EvmFactory = SphereEvmFactory;
    type ExecutionCtx<'a> = EthBlockExecutionCtx<'a>;
    type Transaction = TransactionSigned;
    type Receipt = Receipt;
    type TxExecutionResult = arc_evm::executor::ArcTxResult<
        HaltReason,
        <TransactionSigned as alloy_consensus::transaction::TransactionEnvelope>::TxType,
    >;
    type Executor<'a, DB: StateDB, I: Inspector<EthEvmContext<DB>>> = ArcBlockExecutor<
        'a,
        <SphereEvmFactory as EvmFactory>::Evm<DB, I>,
        &'a Arc<ArcChainSpec>,
        &'a reth_ethereum::evm::RethReceiptBuilder,
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
        ArcBlockExecutor::new(
            evm,
            ctx,
            self.inner.chain_spec(),
            self.inner.executor_factory.receipt_builder(),
        )
    }
}

impl ConfigureEvm for SphereEvmConfig {
    type Primitives = <EthEvmConfig as ConfigureEvm>::Primitives;
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
        self.inner.evm_env(header)
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
        let mut system_evm = self.inner.evm_with_env(
            &mut *db,
            self.inner
                .next_evm_env(parent, &attributes)
                .inspect_err(|err| {
                    tracing::error!(error = ?err, "Failed to create EVM environment");
                })?,
        );

        // Override the gas limit with the gas limit from the ProtocolConfig contract.
        // ADR-0003: use chainspec bounds; fall back to chainspec default when ProtocolConfig
        // is unavailable or returns an out-of-bounds value.
        let chain_spec = self.inner.chain_spec().as_ref();
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
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<reth_ethereum::Block>,
    ) -> Result<EthBlockExecutionCtx<'a>, Self::Error> {
        self.inner.context_for_block(block)
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<EthBlockExecutionCtx<'_>, Self::Error> {
        let mut ctx = self.inner.context_for_next_block(parent, attributes)?;
        // Clearing extra_data as the executor will supply it after execution.
        ctx.extra_data = Default::default();
        Ok(ctx)
    }
}

impl ConfigureEngineEvm<ExecutionData> for SphereEvmConfig {
    fn evm_env_for_payload(&self, payload: &ExecutionData) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a ExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.inner.context_for_payload(payload)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &ExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}
