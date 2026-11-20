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

//! Arc transaction pool for Sphere consensus envelopes.

mod transaction;
pub use transaction::SpherePooledTransaction;

use arc_execution_config::addresses_denylist::AddressesDenylistConfig;
use arc_execution_txpool::{ArcTransactionValidator, InvalidTxList};
use reth_evm::ConfigureEvm;
use reth_node_builder::{
    BuilderContext,
    components::{PoolBuilder, TxPoolBuilder},
    node::{FullNodeTypes, NodeTypes},
};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    CoinbaseTipOrdering, Pool, PoolTransaction, TransactionValidationTaskExecutor,
    blobstore::DiskFileBlobStore,
};
use sphere_chainspec::SphereChainSpec;
use sphere_primitives::SpherePrimitives;
use tracing::{debug, info};

/// A basic Arc transaction pool builder.
///
/// Fork from https://github.com/paradigmxyz/reth/blob/v1.7.0/crates/ethereum/node/src/node.rs#L435-L509
/// with customization to use ArcTransactionValidator.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpherePoolBuilder {
    // TODO add options for txpool args
    invalid_tx_list: Option<InvalidTxList>,
    /// Config for addresses denylist (from/to). When None, no address denylist check in validator.
    addresses_denylist_config: AddressesDenylistConfig,
}

impl SpherePoolBuilder {
    pub fn new(
        invalid_tx_list: Option<InvalidTxList>,
        addresses_denylist_config: AddressesDenylistConfig,
    ) -> Self {
        Self {
            invalid_tx_list,
            addresses_denylist_config,
        }
    }
}

impl<Node, Evm> PoolBuilder<Node, Evm> for SpherePoolBuilder
where
    Node:
        FullNodeTypes<Types: NodeTypes<ChainSpec = SphereChainSpec, Primitives = SpherePrimitives>>,
    Evm: ConfigureEvm<Primitives = <Node::Types as NodeTypes>::Primitives> + 'static,
{
    type Pool = Pool<
        TransactionValidationTaskExecutor<
            ArcTransactionValidator<Node::Provider, SpherePooledTransaction, Evm>,
        >,
        CoinbaseTipOrdering<SpherePooledTransaction>,
        DiskFileBlobStore,
    >;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();

        // Blobs are disabled; use 0 cache size
        let blob_store = reth_node_builder::components::create_blob_store_with_cache(ctx, Some(0))?;

        let mut validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .no_eip4844()
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .build::<SpherePooledTransaction, _>(blob_store.clone());
        validator.set_additional_stateless_validation(|_origin, tx| {
            if tx.consensus_ref().is_system_tx() {
                return Err(InvalidTransactionError::TxTypeNotSupported.into());
            }
            Ok(())
        });
        let validator = TransactionValidationTaskExecutor::spawn(
            validator,
            ctx.task_executor(),
            ctx.config().txpool.additional_validation_tasks,
        )
        .map(|inner| {
            ArcTransactionValidator::new(
                inner,
                self.invalid_tx_list.clone(),
                self.addresses_denylist_config.clone(),
            )
        });

        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}
