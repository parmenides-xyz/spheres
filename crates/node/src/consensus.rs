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

use arc_execution_validation::ArcConsensus;
use reth_ethereum_primitives::EthPrimitives;
use reth_node_builder::{
    BuilderContext,
    components::ConsensusBuilder,
    node::{FullNodeTypes, NodeTypes},
};
use sphere_chainspec::SphereChainSpec;
use std::sync::Arc;

/// A basic Arc consensus builder.
#[derive(Debug, Default, Clone, Copy)]
pub struct SphereDevConsensusBuilder {
    // TODO add closure to modify consensus
}

impl<Node> ConsensusBuilder<Node> for SphereDevConsensusBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = SphereChainSpec, Primitives = EthPrimitives>>,
{
    type Consensus = Arc<ArcConsensus<<Node::Types as NodeTypes>::ChainSpec>>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(ArcConsensus::new(ctx.chain_spec())))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SphereConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for SphereConsensusBuilder
where
    Node:
        FullNodeTypes<Types: NodeTypes<ChainSpec = SphereChainSpec, Primitives = SpherePrimitives>>,
{
    type Consensus = Arc<SphereConsensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(SphereConsensus::new(ctx.chain_spec())))
    }
}

use alloy_consensus::{Block, BlockBody, EthereumReceipt, Header, Transaction, TxReceipt};
use alloy_evm::block::BlockExecutionResult;
use alloy_primitives::{B256, Bloom};
use alloy_sol_types::{SolCall, SolEvent};
use reth_chainspec::EthChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_primitives_traits::{RecoveredBlock, SealedBlock, SealedHeader};
use sphere_contracts::spheres::{
    ArcAdvanced, ISphereInbox, ISphereOutbox, SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS,
};
use sphere_primitives::envelope::SphereTransactionKind;
use sphere_primitives::{SpherePrimitives, envelope::SphereTxEnvelope};

#[derive(Debug)]
pub struct SphereConsensus {
    inner: ArcConsensus<SphereChainSpec>,
    chain_id: u64,
}

impl SphereConsensus {
    pub fn new(chain_spec: Arc<SphereChainSpec>) -> Self {
        Self {
            chain_id: chain_spec.chain_id(),
            inner: ArcConsensus::new(chain_spec),
        }
    }
}

impl HeaderValidator<Header> for SphereConsensus {
    fn validate_header(&self, header: &SealedHeader<Header>) -> Result<(), ConsensusError> {
        self.inner.validate_header(header)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<Header>,
        parent: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_header_against_parent(header, parent)
    }
}

impl Consensus<Block<SphereTxEnvelope>> for SphereConsensus {
    fn validate_body_against_header(
        &self,
        body: &BlockBody<SphereTxEnvelope>,
        header: &SealedHeader<Header>,
    ) -> Result<(), ConsensusError> {
        Consensus::<Block<SphereTxEnvelope>>::validate_body_against_header(
            &self.inner,
            body,
            header,
        )
    }

    fn validate_block_pre_execution(
        &self,
        block: &SealedBlock<Block<SphereTxEnvelope>>,
    ) -> Result<(), ConsensusError> {
        self.inner.validate_block_pre_execution(block)?;
        if block
            .body()
            .withdrawals
            .as_ref()
            .is_some_and(|withdrawals| !withdrawals.is_empty())
        {
            return Err(ConsensusError::msg("withdrawals are not permitted"));
        }
        validate_system_transactions(&block.body().transactions, self.chain_id)?;
        Ok(())
    }
}

fn validate_system_transactions(
    transactions: &[SphereTxEnvelope],
    chain_id: u64,
) -> Result<SphereBlockPhase, ConsensusError> {
    let mut phase = SphereBlockPhase::AwaitingAdvanceArc;
    for tx in transactions {
        if tx.is_system_tx() && !tx.is_valid_system_tx(chain_id) {
            return Err(ConsensusError::msg("invalid Sphere system transaction"));
        }
        phase = phase.validate_transaction(tx)?;
    }
    if phase == SphereBlockPhase::AwaitingAdvanceArc {
        return Err(ConsensusError::msg(
            "sphere block is missing its advanceArc system transaction",
        ));
    }
    Ok(phase)
}

impl FullConsensus<SpherePrimitives> for SphereConsensus {
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<Block<SphereTxEnvelope>>,
        result: &BlockExecutionResult<EthereumReceipt>,
        receipt_root_bloom: Option<(B256, Bloom)>,
    ) -> Result<(), ConsensusError> {
        FullConsensus::<SpherePrimitives>::validate_block_post_execution(
            &self.inner,
            block,
            result,
            receipt_root_bloom,
        )?;
        let phase = validate_system_transactions(&block.body().transactions, self.chain_id)?;
        if result.receipts.len() != block.body().transactions.len() {
            return Err(ConsensusError::msg(
                "receipt count does not match transaction count",
            ));
        }
        if block
            .body()
            .transactions
            .iter()
            .zip(&result.receipts)
            .any(|(tx, receipt)| tx.is_system_tx() && !receipt.status())
        {
            return Err(ConsensusError::msg("Sphere system transaction reverted"));
        }
        let requested_withdrawal = result
            .receipts
            .iter()
            .flat_map(|receipt| receipt.logs())
            .any(|log| {
                log.address == SPHERE_OUTBOX_ADDRESS
                    && log.topics().first()
                        == Some(&ISphereOutbox::WithdrawalRequested::SIGNATURE_HASH)
            });
        if requested_withdrawal && phase != SphereBlockPhase::WithdrawalsFinalized {
            return Err(ConsensusError::msg(
                "sphere block with withdrawal requests is missing its finalizeWithdrawalBatch \
                 system transaction",
            ));
        }

        let processed_deposit = result
            .receipts
            .iter()
            .flat_map(|receipt| receipt.logs())
            .filter(|log| {
                log.address == SPHERE_INBOX_ADDRESS
                    && log.topics().first() == Some(&ArcAdvanced::SIGNATURE_HASH)
            })
            .any(|log| {
                ArcAdvanced::decode_log(log).is_ok_and(|event| !event.depositsProcessed.is_zero())
            });
        if processed_deposit && phase != SphereBlockPhase::WithdrawalsFinalized {
            return Err(ConsensusError::msg(
                "sphere block with processed deposits is missing its finalizeWithdrawalBatch \
                 system transaction",
            ));
        }

        Ok(())
    }
}

/// The current transaction-ordering phase of a sphere block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SphereBlockPhase {
    /// The block has not yet committed its required opening `advanceArc` transaction.
    AwaitingAdvanceArc,
    /// The block has committed `advanceArc` and may execute ordinary transactions.
    Executing,
    /// The block authenticated Arc headers and must contain no further transactions.
    CheckpointOnly,
    /// The block has finalized withdrawals and cannot accept any more transactions.
    WithdrawalsFinalized,
}

impl SphereBlockPhase {
    fn validate_transaction(self, tx: &SphereTxEnvelope) -> Result<Self, ConsensusError> {
        let tx_kind = SphereTransactionKind::classify(tx);

        match (self, tx_kind) {
            (Self::AwaitingAdvanceArc, SphereTransactionKind::AdvanceArc) => Ok(Self::Executing),
            (Self::AwaitingAdvanceArc, SphereTransactionKind::AdvanceArcHeaders) => {
                Ok(Self::CheckpointOnly)
            }
            (Self::AwaitingAdvanceArc, _) => Err(ConsensusError::msg(
                "advanceArc must be the first transaction in a sphere block",
            )),
            (Self::Executing, SphereTransactionKind::AdvanceArc) => Err(ConsensusError::msg(
                "advanceArc must only execute once per sphere block",
            )),
            (Self::Executing, SphereTransactionKind::AdvanceArcHeaders) => {
                Err(ConsensusError::msg("advanceArcHeaders must only open a sphere block").into())
            }
            (Self::Executing, SphereTransactionKind::Regular) => Ok(Self::Executing),
            (Self::Executing, SphereTransactionKind::FinalizeWithdrawalBatch) => {
                Ok(Self::WithdrawalsFinalized)
            }
            (Self::Executing, SphereTransactionKind::UnexpectedSystem) => Err(ConsensusError::msg(
                "system transactions after advanceArc must call \
                     SphereOutbox.finalizeWithdrawalBatch",
            )
            .into()),
            (Self::WithdrawalsFinalized, _) => Err(ConsensusError::msg(
                "finalizeWithdrawalBatch must be the last transaction in a sphere block",
            )),
            (Self::CheckpointOnly, _) => Err(ConsensusError::msg(
                "advanceArcHeaders must be the only transaction in a sphere block",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, U256};
    use sphere_primitives::envelope::SPHERE_SYSTEM_TX_SIGNATURE;
    fn system_tx(to: Address, input: Bytes) -> SphereTxEnvelope {
        SphereTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                to: to.into(),
                input,
                ..Default::default()
            },
            SPHERE_SYSTEM_TX_SIGNATURE,
        ))
    }

    fn advance_arc_tx() -> SphereTxEnvelope {
        system_tx(
            SPHERE_INBOX_ADDRESS,
            ISphereInbox::advanceArcCall::SELECTOR.into(),
        )
    }

    fn finalize_withdrawal_batch_tx() -> SphereTxEnvelope {
        system_tx(
            SPHERE_OUTBOX_ADDRESS,
            ISphereOutbox::finalizeWithdrawalBatchCall {
                count: U256::ZERO,
                blockNumber: 1,
                encryptedSenders: vec![],
            }
            .abi_encode()
            .into(),
        )
    }

    fn ordinary_tx(to: Address, input: Bytes) -> SphereTxEnvelope {
        SphereTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                to: to.into(),
                input,
                ..Default::default()
            },
            Signature::test_signature(),
        ))
    }

    #[test]
    fn sphere_block_phase_transition_table_is_exhaustive() {
        let advance = advance_arc_tx();
        let regular = ordinary_tx(Address::ZERO, Bytes::new());
        let finalize = finalize_withdrawal_batch_tx();
        let unexpected_system = system_tx(Address::ZERO, Bytes::new());

        assert_eq!(
            SphereBlockPhase::AwaitingAdvanceArc
                .validate_transaction(&advance)
                .unwrap(),
            SphereBlockPhase::Executing
        );
        for tx in [&regular, &finalize, &unexpected_system] {
            assert_eq!(
                SphereBlockPhase::AwaitingAdvanceArc
                    .validate_transaction(tx)
                    .unwrap_err()
                    .to_string(),
                "advanceArc must be the first transaction in a sphere block"
            );
        }

        assert_eq!(
            SphereBlockPhase::Executing
                .validate_transaction(&regular)
                .unwrap(),
            SphereBlockPhase::Executing
        );
        assert_eq!(
            SphereBlockPhase::Executing
                .validate_transaction(&finalize)
                .unwrap(),
            SphereBlockPhase::WithdrawalsFinalized
        );
        assert_eq!(
            SphereBlockPhase::Executing
                .validate_transaction(&advance)
                .unwrap_err()
                .to_string(),
            "advanceArc must only execute once per sphere block"
        );
        assert_eq!(
            SphereBlockPhase::Executing
                .validate_transaction(&unexpected_system)
                .unwrap_err()
                .to_string(),
            "system transactions after advanceArc must call \
             SphereOutbox.finalizeWithdrawalBatch"
        );

        for tx in [&advance, &regular, &finalize, &unexpected_system] {
            assert_eq!(
                SphereBlockPhase::WithdrawalsFinalized
                    .validate_transaction(tx)
                    .unwrap_err()
                    .to_string(),
                "finalizeWithdrawalBatch must be the last transaction in a sphere block"
            );
        }
    }
}
