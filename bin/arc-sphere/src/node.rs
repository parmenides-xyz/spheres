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

use arc_execution_payload::payload::ArcNetworkPayloadBuilderBuilder;
use reth_ethereum_primitives::EthPrimitives;
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes, PayloadAttributesBuilder};
use reth_node_builder::{
    DebugNode, Node, NodeAdapter,
    rpc::{BasicEngineApiBuilder, BasicEngineValidatorBuilder, RpcAddOns},
    components::{BasicPayloadServiceBuilder, ComponentsBuilder},
};
use reth_node_ethereum::{
    EthEngineTypes, EthereumAddOns, EthereumEthApiBuilder,
    EthereumNetworkBuilder, EthereumPoolBuilder,
};
use reth_payload_primitives::PayloadTypes;
use reth_provider::EthStorage;
use sphere_chainspec::SphereChainSpec;
use sphere_node::{SphereDevConsensusBuilder, SphereExecutorBuilder};
use std::sync::Arc;

use crate::engine::ArcEngineValidatorBuilder;
use crate::payload::ArcLocalPayloadAttributesBuilder;

#[derive(Debug, Default, Clone, Copy)]
pub struct SphereDevNode;

impl NodeTypes for SphereDevNode {
    type Primitives = EthPrimitives;
    type ChainSpec = SphereChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

impl<N> Node<N> for SphereDevNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<ArcNetworkPayloadBuilderBuilder>,
        EthereumNetworkBuilder,
        SphereExecutorBuilder,
        SphereDevConsensusBuilder,
    >;

    type AddOns =
        EthereumAddOns<NodeAdapter<N>, EthereumEthApiBuilder, ArcEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(SphereExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(
                ArcNetworkPayloadBuilderBuilder::new(None, None, true),
            ))
            .network(EthereumNetworkBuilder::default())
            .consensus(SphereDevConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::new(RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            ArcEngineValidatorBuilder::default(),
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
            Default::default(),
        ))
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for SphereDevNode {
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_ethereum_primitives::Block {
        rpc_block.into_consensus().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes> {
        ArcLocalPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}
