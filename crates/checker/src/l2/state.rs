//! Exact L2 state reads used by bootstrap and accounting verification.

use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::Header;
use alloy_eips::BlockNumHash;
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use reth_evm::{ConfigureEvm, Evm};
use reth_revm::{database::StateProviderDatabase, revm::handler::SYSTEM_ADDRESS};
use reth_storage_api::{StateProviderFactory, errors::provider::ProviderError};
use sphere_contracts::spheres::{
    SPHERE_FEE_MANAGER_ADDRESS, SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS,
};
use sphere_l1::ArcStateExt;
use sphere_precompiles::{inbox, outbox, sphere_fee_manager};
use sphere_primitives::SpherePrimitives;

use crate::{AttemptError, NativeFiatTokenV2_2};

/// Protocol checkpoint embedded in local Sphere genesis.
pub(crate) struct SphereGenesisEvidence {
    pub(crate) arc_block_hash: B256,
    pub(crate) arc_block_number: u64,
    pub(crate) processed_deposit_queue_hash: B256,
    pub(crate) processed_deposit_number: u64,
    pub(crate) withdrawal_queue_hash: B256,
    pub(crate) withdrawal_batch_index: u64,
    pub(crate) default_fee_token: Address,
    pub(crate) initial_token_supply: U256,
}

/// Read the protocol checkpoint encoded in exact Sphere state.
pub(crate) fn read_sphere_genesis<P>(
    provider: &P,
    hash: B256,
    header: &Header,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
) -> eyre::Result<SphereGenesisEvidence>
where
    P: StateProviderFactory + ?Sized,
{
    let state = provider.state_by_block_hash(hash)?;
    let arc = state.arc_num_hash()?;
    let default_fee_token = Address::from_word(
        state
            .storage(
                SPHERE_FEE_MANAGER_ADDRESS,
                sphere_fee_manager::slots::DEFAULT_FEE_TOKEN.into(),
            )?
            .unwrap_or_default()
            .into(),
    );
    let processed_deposit_queue_hash = state
        .storage(
            SPHERE_INBOX_ADDRESS,
            inbox::slots::PROCESSED_DEPOSIT_QUEUE_HASH.into(),
        )?
        .unwrap_or_default();
    let processed_deposit_number = state
        .storage(
            SPHERE_INBOX_ADDRESS,
            inbox::slots::PROCESSED_DEPOSIT_NUMBER.into(),
        )?
        .unwrap_or_default();
    let withdrawal_queue_hash = state
        .storage(
            SPHERE_OUTBOX_ADDRESS,
            outbox::slots::WITHDRAWAL_QUEUE_HASH.into(),
        )?
        .unwrap_or_default();
    let index_slot = state
        .storage(
            SPHERE_OUTBOX_ADDRESS,
            outbox::slots::WITHDRAWAL_BATCH_INDEX.into(),
        )?
        .unwrap_or_default();
    let mut evm = evm_config.evm_for_block(StateProviderDatabase::new(state), header)?;
    Ok(SphereGenesisEvidence {
        arc_block_hash: arc.hash,
        arc_block_number: arc.number,
        processed_deposit_queue_hash: processed_deposit_queue_hash.into(),
        processed_deposit_number: processed_deposit_number.as_limbs()[0],
        withdrawal_queue_hash: withdrawal_queue_hash.into(),
        withdrawal_batch_index: index_slot.as_limbs()[0],
        default_fee_token,
        initial_token_supply: view(
            &mut evm,
            default_fee_token,
            NativeFiatTokenV2_2::totalSupplyCall {},
        )?,
    })
}

fn view<C: SolCall>(evm: &mut impl Evm, address: Address, call: C) -> eyre::Result<C::Return> {
    let result_and_state =
        evm.transact_system_call(SYSTEM_ADDRESS, address, call.abi_encode().into())?;
    eyre::ensure!(
        result_and_state.result.is_success(),
        "system call to {address} failed: {:?}",
        result_and_state.result
    );
    let output = result_and_state
        .result
        .output()
        .ok_or_else(|| eyre::eyre!("system call to {address} returned empty output"))?;
    Ok(C::abi_decode_returns(output)?)
}

/// Exact balances and supply for one token at one Sphere block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenAccountingEvidence {
    pub(crate) token: Address,
    pub(crate) total_supply: U256,
    pub(crate) balances: BTreeMap<Address, U256>,
}

/// Failure reading exact accounting state for one Sphere block.
#[derive(Debug)]
pub(crate) enum AccountingStateError {
    /// The requested block state is not currently available.
    Unavailable(eyre::Report),
    /// Deterministic provider or checker failure prevents verification.
    Disable(eyre::Report),
}

impl From<AttemptError> for AccountingStateError {
    fn from(error: AttemptError) -> Self {
        match error {
            AttemptError::Retry(error) => Self::Unavailable(error),
            AttemptError::Disable(error) => Self::Disable(error),
        }
    }
}

/// Read exact balances and supply for affected accounts at one Sphere block.
pub(crate) fn read_accounting_state<P: StateProviderFactory>(
    provider: &P,
    accounts: &BTreeMap<Address, BTreeSet<Address>>,
    block: BlockNumHash,
    header: &Header,
    evm_config: &impl ConfigureEvm<Primitives = SpherePrimitives>,
) -> Result<Vec<TokenAccountingEvidence>, AccountingStateError> {
    let canonical_hash = provider
        .block_hash(block.number)
        .map_err(|error| classify_provider_error(error, block.hash))?;
    match canonical_hash {
        Some(hash) if hash == block.hash => {}
        Some(_) => {
            return Err(AccountingStateError::Disable(eyre::eyre!(
                "Sphere block {} ({}) is not canonical",
                block.number,
                block.hash
            )));
        }
        None => {
            return Err(AccountingStateError::Unavailable(eyre::eyre!(
                "Sphere block {} ({}) is not yet available in local canonical history",
                block.number,
                block.hash
            )));
        }
    }
    // Read by hash: a by-number read could resolve a block that replaced this one after the check.
    let state = provider
        .history_by_block_hash(block.hash)
        .map_err(|error| classify_provider_error(error, block.hash))?;
    let mut evm = evm_config
        .evm_for_block(StateProviderDatabase::new(state), header)
        .map_err(|error| AccountingStateError::Disable(error.into()))?;
    accounts
        .iter()
        .map(|(&token, accounts)| {
            let balances = accounts
                .iter()
                .map(|&account| {
                    view(
                        &mut evm,
                        token,
                        NativeFiatTokenV2_2::balanceOfCall { account },
                    )
                    .map(|balance| (account, balance))
                })
                .collect::<eyre::Result<BTreeMap<_, _>>>()?;
            Ok(TokenAccountingEvidence {
                token,
                total_supply: view(&mut evm, token, NativeFiatTokenV2_2::totalSupplyCall {})?,
                balances,
            })
        })
        .collect::<eyre::Result<Vec<_>>>()
        .map_err(|error| classify_read_error(error, block.hash))
}

fn classify_read_error(error: eyre::Report, block: B256) -> AccountingStateError {
    let database_error = error.chain().any(|cause| cause.is::<ProviderError>());
    let report = error.wrap_err(format!("failed to read accounting state for block {block}"));
    if database_error {
        AccountingStateError::Unavailable(report)
    } else {
        AccountingStateError::Disable(report)
    }
}

fn classify_provider_error(error: ProviderError, block: B256) -> AttemptError {
    let report = |error| {
        eyre::Report::new(error).wrap_err(format!("failed to obtain state for block {block}"))
    };
    match error {
        error @ (ProviderError::BlockHashNotFound(_)
        | ProviderError::HeaderNotFound(_)
        | ProviderError::UnknownBlockHash(_)
        | ProviderError::StateForHashNotFound(_)
        | ProviderError::StateForNumberNotFound(_)
        | ProviderError::BlockNotExecuted { .. }) => AttemptError::retry(report(error)),
        error @ ProviderError::StateAtBlockPruned(_) => AttemptError::disable(
            report(error).wrap_err("checker requires unpruned historical Sphere state"),
        ),
        error => AttemptError::disable(report(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_token_state_at_the_canonical_hash() -> eyre::Result<()> {
        use alloy_genesis::GenesisAccount;
        use arc_execution_config::chainspec::LOCAL_DEV;
        use reth_db_common::init::init_genesis;
        use reth_provider::{
            providers::BlockchainProvider, test_utils::create_test_provider_factory_with_chain_spec,
        };
        use sphere_chainspec::SphereChainSpec;
        use sphere_contracts::spheres::SPHERE_TOKEN_ADDRESS;
        use sphere_primitives::constants::sphere_chain_id;
        use std::sync::Arc;

        let token = SPHERE_TOKEN_ADDRESS;
        let mut genesis = LOCAL_DEV.inner.genesis.clone();
        genesis.config.chain_id = sphere_chain_id(1_337, 1)?;
        genesis.alloc.insert(
            SPHERE_FEE_MANAGER_ADDRESS,
            GenesisAccount::default().with_storage(Some([(B256::ZERO, token.into_word())].into())),
        );
        genesis.alloc.insert(
            SPHERE_OUTBOX_ADDRESS,
            GenesisAccount::default().with_storage(Some(
                [(U256::from(2).into(), U256::from_limbs([7, 42, 0, 0]).into())].into(),
            )),
        );
        let sphere = Arc::new(SphereChainSpec::from_genesis_with_l1(genesis, &LOCAL_DEV)?);
        let chain_spec = Arc::new(sphere.inner.inner.clone());
        let factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());
        let hash = init_genesis(&factory)?;
        let provider = BlockchainProvider::new(factory)?;
        let evm = sphere_evm::create_evm_config(sphere);
        let header = chain_spec.genesis_header();
        let snapshot = read_sphere_genesis(&provider, hash, header, &evm)?;
        assert_eq!(snapshot.default_fee_token, token);
        assert_eq!(
            snapshot.initial_token_supply,
            U256::from(16_000_000_000_000u64)
        );
        assert_eq!(snapshot.withdrawal_batch_index, 7);

        let account = alloy_primitives::address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let accounts = [(token, [account].into())].into();
        let observed = read_accounting_state(
            &provider,
            &accounts,
            BlockNumHash::new(0, hash),
            header,
            &evm,
        )
        .unwrap();
        assert_eq!(observed[0].total_supply, snapshot.initial_token_supply);
        assert_eq!(
            observed[0].balances[&account],
            U256::from(1_000_000_000_000u64)
        );
        assert!(matches!(
            read_accounting_state(
                &provider,
                &accounts,
                BlockNumHash::new(0, B256::ZERO),
                header,
                &evm
            ),
            Err(AccountingStateError::Disable(_))
        ));
        Ok(())
    }

    #[test]
    fn classifies_transient_and_permanent_provider_failures() {
        let block = B256::repeat_byte(1);
        assert!(matches!(
            classify_provider_error(ProviderError::StateForHashNotFound(block), block),
            AttemptError::Retry(_)
        ));

        assert!(matches!(
            classify_provider_error(ProviderError::StateAtBlockPruned(1), block),
            AttemptError::Disable(_)
        ));
    }

    #[test]
    fn retries_fatal_storage_reads_and_disables_other_read_failures() {
        let block = B256::repeat_byte(1);
        assert!(matches!(
            classify_read_error(ProviderError::StateForHashNotFound(block).into(), block),
            AccountingStateError::Unavailable(_)
        ));

        assert!(matches!(
            classify_read_error(eyre::eyre!("out of gas"), block),
            AccountingStateError::Disable(_)
        ));
    }
}
