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

use crate::protocol_validator::SphereEngineValidatorBuilder;
use alloy_consensus::Header;
use reth_ethereum_primitives::PooledTransactionVariant;
use reth_eth_wire_types::primitives::BasicNetworkPrimitives;
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_builder::{
    Node, NodeAdapter,
    components::{BasicPayloadServiceBuilder, ComponentsBuilder, NoopNetworkBuilder},
    rpc::{BasicEngineValidatorBuilder, Identity, NoopEngineApiBuilder, RpcAddOns},
};
use reth_node_ethereum::EthereumEthApiBuilder;
use reth_provider::EthStorage;
use sphere_chainspec::SphereChainSpec;
use sphere_node::{SphereConsensusBuilder, SphereProtocolExecutorBuilder, pool::SpherePoolBuilder};
use sphere_payload::{SpherePayloadFactory, SpherePayloadTypes};
use sphere_primitives::{SpherePrimitives, envelope::SphereTxEnvelope};

type SphereNetworkPrimitives = BasicNetworkPrimitives<SpherePrimitives, PooledTransactionVariant>;

#[derive(Clone, Debug)]
pub struct SphereNode {
    pub pool: SpherePoolBuilder,
    pub payload: SpherePayloadFactory,
    pub executor: SphereProtocolExecutorBuilder,
}

impl NodeTypes for SphereNode {
    type Primitives = SpherePrimitives;
    type ChainSpec = SphereChainSpec;
    type Storage = EthStorage<SphereTxEnvelope, Header>;
    type Payload = SpherePayloadTypes;
}

impl<N> Node<N> for SphereNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        SpherePoolBuilder,
        BasicPayloadServiceBuilder<SpherePayloadFactory>,
        NoopNetworkBuilder<SphereNetworkPrimitives>,
        SphereProtocolExecutorBuilder,
        SphereConsensusBuilder,
    >;
    type AddOns = RpcAddOns<
        NodeAdapter<N>,
        EthereumEthApiBuilder,
        SphereEngineValidatorBuilder,
        NoopEngineApiBuilder,
        BasicEngineValidatorBuilder<SphereEngineValidatorBuilder>,
        Identity,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(self.pool.clone())
            .executor(self.executor.clone())
            .payload(BasicPayloadServiceBuilder::new(self.payload.clone()))
            .network(NoopNetworkBuilder::<SphereNetworkPrimitives>::default())
            .consensus(SphereConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            SphereEngineValidatorBuilder,
            NoopEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Identity::default(),
            Default::default(),
        )
    }
}
