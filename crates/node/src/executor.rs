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

use reth_ethereum_primitives::EthPrimitives;
use reth_node_builder::{
    BuilderContext,
    components::ExecutorBuilder,
    node::{FullNodeTypes, NodeTypes},
};
use sphere_chainspec::SphereChainSpec;
use sphere_evm::{SphereEvmConfig, create_evm_config};

/// A regular Arc evm and executor builder.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SphereExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for SphereExecutorBuilder
where
    Types: NodeTypes<ChainSpec = SphereChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = SphereEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(create_evm_config(ctx.chain_spec()))
    }
}

/// A Sphere protocol evm and executor builder.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SphereProtocolExecutorBuilder {
    l1: sphere_l1::state::L1StateProvider,
    portal: alloy_primitives::Address,
}
impl SphereProtocolExecutorBuilder {
    pub fn new(l1: sphere_l1::state::L1StateProvider, portal: alloy_primitives::Address) -> Self {
        Self { l1, portal }
    }
}

impl<Types, Node> ExecutorBuilder<Node> for SphereProtocolExecutorBuilder
where
    Types: NodeTypes<ChainSpec = SphereChainSpec, Primitives = sphere_primitives::SpherePrimitives>,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = sphere_evm::SphereProtocolEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        Ok(sphere_evm::SphereProtocolEvmConfig::new(ctx.chain_spec())
            .with_l1_reader(self.l1, self.portal))
    }
}
