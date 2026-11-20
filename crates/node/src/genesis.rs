use alloy_consensus::Header;
use alloy_genesis::{Genesis, GenesisAccount};
use alloy_primitives::{Address, B256, U256, b256};
use arc_execution_config::{chain_ids::TESTNET_CHAIN_ID, protocol_config::PROTOCOL_CONFIG_ADDRESS};
use sphere_contracts::runtime_bytecode::sphere_runtime_contracts;
use sphere_precompiles::{arc_state, sphere_fee_manager};
use sphere_primitives::constants::{
    ARC_STATE_ADDRESS, SPHERE_FEE_MANAGER_ADDRESS, SPHERE_TOKEN_ADDRESS, decode_l1_chain_id,
};

/// Anchors the canonical USDC-only allocation and binds the Sphere's creation-time configuration.
pub fn l1_anchored_genesis(
    supplied: Genesis,
    l1_header: &Header,
    portal: Address,
    default_fee_token: Address,
    fee_owner: Address,
    fee_recipient: Address,
) -> eyre::Result<(Genesis, u64)> {
    let parent = decode_l1_chain_id(supplied.config.chain_id)?;
    let template = match parent {
        TESTNET_CHAIN_ID => include_str!("../../../assets/testnet/sphere-genesis.json"),
        1337 | 31337 => include_str!("../../../assets/localdev/sphere-genesis.json"),
        _ => eyre::bail!("no Sphere genesis template for Arc parent {parent}"),
    };
    let mut genesis: Genesis = serde_json::from_str(template)?;
    eyre::ensure!(
        supplied.alloc == genesis.alloc,
        "unexpected Sphere genesis allocation"
    );
    eyre::ensure!(
        default_fee_token == SPHERE_TOKEN_ADDRESS,
        "the Sphere fee token must be Arc USDC"
    );
    eyre::ensure!(
        !portal.is_zero() && !fee_owner.is_zero() && !fee_recipient.is_zero(),
        "missing Sphere creation-time portal, administrator or leader"
    );
    genesis.config.chain_id = supplied.config.chain_id;
    genesis.coinbase = fee_recipient;

    for (address, code) in sphere_runtime_contracts(portal) {
        genesis.alloc.insert(
            address,
            GenesisAccount {
                nonce: Some(1),
                code: Some(code),
                ..Default::default()
            },
        );
    }

    // Arc ProtocolConfig.ts initializes the owner, controller and pauser. The original
    // testnet implementation stored controller and pauser in ordinary slots 0 and 1.
    let config = genesis
        .alloc
        .get_mut(&PROTOCOL_CONFIG_ADDRESS)
        .ok_or_else(|| eyre::eyre!("Arc ProtocolConfig not found in genesis alloc"))?;
    let storage = config.storage.get_or_insert_with(Default::default);
    let owner = b256!("9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300");
    let (controller, pauser) = if parent == TESTNET_CHAIN_ID {
        (B256::ZERO, B256::from(U256::ONE))
    } else {
        (
            b256!("958f8fec699b51a1249f513eceda5429078000657f74abd1721bba363087af00"),
            b256!("0642d7922329a434cf4fd17a3c95eb692c24fd95f9f94d0b55420a5d895f4a00"),
        )
    };
    for slot in [owner, controller, pauser] {
        storage.insert(slot, fee_owner.into_word());
    }
    let genesis_block_number = l1_header.number;

    let l1_genesis_hash = l1_header.hash_slow();

    // Patch 1: ArcState storage.
    let arc_state_account = genesis
        .alloc
        .get_mut(&ARC_STATE_ADDRESS)
        .ok_or_else(|| eyre::eyre!("ArcState not found in genesis alloc"))?;
    let storage = arc_state_account
        .storage
        .get_or_insert_with(Default::default);
    storage.insert(arc_state::slots::ARC_BLOCK_HASH.into(), l1_genesis_hash);
    storage.insert(
        arc_state::slots::ARC_BLOCK_NUMBER.into(),
        U256::from(l1_header.number).into(),
    );

    // Patch 2: canonical default fee token.
    let fee_manager_account = genesis
        .alloc
        .get_mut(&SPHERE_FEE_MANAGER_ADDRESS)
        .ok_or_else(|| eyre::eyre!("SphereFeeManager not found in genesis alloc"))?;
    fee_manager_account
        .storage
        .get_or_insert_with(Default::default)
        .insert(
            sphere_fee_manager::slots::DEFAULT_FEE_TOKEN.into(),
            default_fee_token.into_word(),
        );

    Ok((genesis, genesis_block_number))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use alloy_sol_types::SolValue;
    use sphere_contracts::{SPHERE_INBOX_ADDRESS, SPHERE_OUTBOX_ADDRESS};

    fn assert_protocol_roles(genesis: &Genesis, owner: Address) {
        use alloy_evm::revm::{
            database::InMemoryDB,
            state::{AccountInfo, Bytecode},
        };
        use alloy_evm::{Evm, EvmEnv, EvmFactory, eth::EthEvmFactory};
        let mut db = InMemoryDB::default();
        for (address, account) in &genesis.alloc {
            let code = account.code.clone().unwrap_or_default();
            db.insert_account_info(
                *address,
                AccountInfo {
                    code_hash: keccak256(&code),
                    code: Some(Bytecode::new_raw(code)),
                    ..Default::default()
                },
            );
            for (slot, value) in account.storage_slots() {
                db.insert_account_storage(*address, slot.into(), value)
                    .unwrap();
            }
        }
        let mut evm = EthEvmFactory::default().create_evm(db, EvmEnv::default());
        for getter in ["owner()", "controller()", "pauser()"] {
            let outcome = evm
                .transact_system_call(
                    Address::repeat_byte(0x44),
                    PROTOCOL_CONFIG_ADDRESS,
                    keccak256(getter.as_bytes())[..4].to_vec().into(),
                )
                .unwrap();
            assert!(
                outcome.result.is_success(),
                "{getter}: {:?}",
                outcome.result
            );
            assert_eq!(
                outcome.result.output().unwrap().as_ref(),
                owner.into_word().as_slice(),
                "{getter}"
            );
        }
    }

    #[test]
    fn anchored_genesis_has_no_prefunds_and_only_bridge_minters() {
        for template in [
            include_str!("../../../assets/localdev/sphere-genesis.json"),
            include_str!("../../../assets/testnet/sphere-genesis.json"),
        ] {
            let supplied: Genesis = serde_json::from_str(template).unwrap();
            let portal = Address::repeat_byte(0x11);
            let owner = Address::repeat_byte(0x22);
            let leader = Address::repeat_byte(0x33);
            let (anchored, _) = l1_anchored_genesis(
                supplied.clone(),
                &Header::default(),
                portal,
                SPHERE_TOKEN_ADDRESS,
                owner,
                leader,
            )
            .unwrap();
            assert_eq!(anchored.coinbase, leader);
            assert_protocol_roles(&anchored, owner);
            assert!(
                anchored
                    .alloc
                    .values()
                    .all(|account| account.balance.is_zero())
            );
            for (address, runtime) in sphere_runtime_contracts(portal) {
                assert_eq!(anchored.alloc[&address].code.as_ref(), Some(&runtime));
            }
            let storage = anchored.alloc[&SPHERE_TOKEN_ADDRESS]
                .storage
                .as_ref()
                .unwrap();
            for (minter, amount) in [
                (SPHERE_INBOX_ADDRESS, 1_000_000_000_000_000_000_000_000u128),
                (SPHERE_OUTBOX_ADDRESS, 0),
            ] {
                let enabled = keccak256((minter, U256::from(12)).abi_encode());
                let allowance = keccak256((minter, U256::from(13)).abi_encode());
                assert_eq!(storage[&enabled], B256::from(U256::ONE));
                assert_eq!(
                    storage.get(&allowance).copied().unwrap_or_default(),
                    B256::from(U256::from(amount))
                );
            }
            let mut invalid = supplied;
            invalid.alloc.entry(leader).or_default().balance = U256::ONE;
            assert!(
                l1_anchored_genesis(
                    invalid,
                    &Header::default(),
                    portal,
                    SPHERE_TOKEN_ADDRESS,
                    owner,
                    leader
                )
                .is_err()
            );
        }
    }
}
