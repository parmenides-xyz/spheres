use super::storage_io::{self, PrecompileErrorOrRevert};
use alloy_consensus::Header;
use alloy_evm::precompiles::{DynPrecompile, PrecompileInput, PrecompilesMap};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolError};
use revm::{
    context_interface::Block,
    interpreter::Gas,
    precompile::{PrecompileId, PrecompileOutput, PrecompileResult},
};
use sphere_contracts::spheres::{
    ARC_STATE_ADDRESS, ArcState, ISphereInbox, ISphereOutbox, SPHERE_INBOX_ADDRESS, finalizeArcCall,
};
use sphere_precompiles::arc_state::slots::{ARC_BLOCK_HASH, ARC_BLOCK_NUMBER};
use sphere_primitives::constants::MAX_ARC_HEADERS_PER_SPHERE_BLOCK;

pub(super) fn configure_runtime(
    precompiles: &mut PrecompilesMap,
    l1: Option<super::reader::State>,
) {
    precompiles.extend_precompiles([(
        ARC_STATE_ADDRESS,
        DynPrecompile::new_stateful(PrecompileId::Custom("ArcState".into()), move |input| {
            run(input, l1.as_ref())
        }),
    )]);
}

fn run(mut input: PrecompileInput<'_>, l1: Option<&super::reader::State>) -> PrecompileResult {
    let mut gas = Gas::new(input.gas);
    let reservoir = input.reservoir;
    let result = (|| -> Result<Bytes, PrecompileErrorOrRevert> {
        const INPUT_PER_WORD_COST: u64 = 30;
        storage_io::record_cost_or_out_of_gas(
            &mut gas,
            reservoir,
            (input.data.len() as u64)
                .div_ceil(32)
                .saturating_mul(INPUT_PER_WORD_COST),
        )?;
        if !input.is_direct_call() || !input.value.is_zero() {
            return Err(revert(&gas, reservoir, ISphereInbox::Unauthorized {}));
        }
        let (address, data) = (input.target_address, input.data);
        if address == ARC_STATE_ADDRESS && data == ArcState::arcBlockNumberCall::SELECTOR {
            return storage_io::read(
                &mut input.internals,
                address,
                ARC_BLOCK_NUMBER.into(),
                &mut gas,
                reservoir,
            );
        }
        if address == ARC_STATE_ADDRESS && data == ArcState::arcBlockHashCall::SELECTOR {
            return storage_io::read(
                &mut input.internals,
                address,
                ARC_BLOCK_HASH.into(),
                &mut gas,
                reservoir,
            );
        }
        if address == ARC_STATE_ADDRESS
            && (data.starts_with(&ArcState::readArcStorageSlotCall::SELECTOR)
                || data.starts_with(&ArcState::readArcStorageSlotsCall::SELECTOR))
        {
            use alloy_sol_types::SolValue;
            let l1 = l1.ok_or_else(|| {
                PrecompileErrorOrRevert::Fatal("Arc L1 storage reader unavailable".into())
            })?;
            let number = storage_io::read(
                &mut input.internals,
                address,
                ARC_BLOCK_NUMBER.into(),
                &mut gas,
                reservoir,
            )?;
            let number = u64::try_from(U256::from_be_slice(&number))
                .map_err(|_| revert(&gas, reservoir, ArcState::InvalidBlockNumber {}))?;
            if data.starts_with(&ArcState::readArcStorageSlotCall::SELECTOR) {
                let call = ArcState::readArcStorageSlotCall::abi_decode_validate(data)
                    .map_err(|_| revert(&gas, reservoir, ArcState::InvalidRlpData {}))?;
                storage_io::record_cost_or_out_of_gas(
                    &mut gas,
                    reservoir,
                    revm::interpreter::gas::COLD_SLOAD_COST,
                )?;
                return Ok(l1
                    .read_l1_storage_unmetered(call.account, call.slot, number)
                    .map_err(|e| PrecompileErrorOrRevert::Fatal(e.to_string()))?
                    .abi_encode()
                    .into());
            }
            let call = ArcState::readArcStorageSlotsCall::abi_decode_validate(data)
                .map_err(|_| revert(&gas, reservoir, ArcState::InvalidRlpData {}))?;
            let mut slots = Vec::with_capacity(call.slots.len());
            for slot in call.slots {
                storage_io::record_cost_or_out_of_gas(
                    &mut gas,
                    reservoir,
                    revm::interpreter::gas::COLD_SLOAD_COST,
                )?;
                slots.push(
                    l1.read_l1_storage_unmetered(call.account, slot, number)
                        .map_err(|e| PrecompileErrorOrRevert::Fatal(e.to_string()))?,
                );
            }
            return Ok(slots.abi_encode().into());
        }
        if input.is_static {
            return Err(revert(
                &gas,
                reservoir,
                ISphereOutbox::StaticCallNotAllowed {},
            ));
        }
        if input.caller != SPHERE_INBOX_ADDRESS {
            return Err(revert(&gas, reservoir, ArcState::OnlySphereInbox {}));
        }
        let headers = finalizeArcCall::abi_decode_validate(data)
            .map_err(|_| revert(&gas, reservoir, ArcState::InvalidRlpData {}))?
            .headers;
        finalize_checkpoints(&mut input, &mut gas, &headers, l1)?;
        Ok(Bytes::new())
    })();
    match result {
        Ok(bytes) => Ok(PrecompileOutput::new(gas.used(), bytes, reservoir)),
        Err(error) => error.into(),
    }
}

fn revert(gas: &Gas, reservoir: u64, error: impl SolError) -> PrecompileErrorOrRevert {
    PrecompileErrorOrRevert::Revert(PrecompileOutput::revert(
        gas.used(),
        error.abi_encode().into(),
        reservoir,
    ))
}

fn finalize_checkpoints(
    input: &mut PrecompileInput<'_>,
    gas: &mut Gas,
    headers: &[Bytes],
    l1: Option<&super::reader::State>,
) -> Result<(), PrecompileErrorOrRevert> {
    let reservoir = input.reservoir;
    if headers.is_empty() || headers.len() > MAX_ARC_HEADERS_PER_SPHERE_BLOCK {
        return Err(revert(gas, reservoir, ArcState::InvalidRlpData {}));
    }
    let number = storage_io::read(
        &mut input.internals,
        ARC_STATE_ADDRESS,
        ARC_BLOCK_NUMBER.into(),
        gas,
        reservoir,
    )?;
    let mut previous_block_number = u64::try_from(U256::from_be_slice(&number))
        .map_err(|_| revert(gas, reservoir, ArcState::InvalidBlockNumber {}))?;
    let initial_block_number = previous_block_number;
    let mut previous_block_hash = B256::from_slice(&storage_io::read(
        &mut input.internals,
        ARC_STATE_ADDRESS,
        ARC_BLOCK_HASH.into(),
        gas,
        reservoir,
    )?);
    if previous_block_hash.is_zero() {
        return Err(revert(gas, reservoir, ArcState::InvalidParentHash {}));
    }
    let mut final_state_root = B256::ZERO;
    let mut final_timestamp = 0;
    for header_rlp in headers {
        let header: Header = alloy_rlp::decode_exact(header_rlp)
            .map_err(|_| revert(gas, reservoir, ArcState::InvalidRlpData {}))?;
        if header.parent_hash != previous_block_hash {
            return Err(revert(gas, reservoir, ArcState::InvalidParentHash {}));
        }
        if previous_block_number.checked_add(1) != Some(header.number) {
            return Err(revert(gas, reservoir, ArcState::InvalidBlockNumber {}));
        }
        previous_block_hash = keccak256(header_rlp);
        previous_block_number = header.number;
        final_state_root = header.state_root;
        final_timestamp = header.timestamp;
    }
    if input.internals.block_env().timestamp() < U256::from(final_timestamp) {
        return Err(revert(gas, reservoir, ArcState::InvalidTimestamp {}));
    }
    if let Some(l1) = l1 {
        l1.advance_anchor(initial_block_number, previous_block_number)
            .map_err(|e| PrecompileErrorOrRevert::Fatal(e.to_string()))?;
    }
    storage_io::write(
        &mut input.internals,
        ARC_STATE_ADDRESS,
        ARC_BLOCK_HASH.into(),
        previous_block_hash.as_slice(),
        gas,
        reservoir,
    )?;
    storage_io::write(
        &mut input.internals,
        ARC_STATE_ADDRESS,
        ARC_BLOCK_NUMBER.into(),
        &previous_block_number.to_be_bytes(),
        gas,
        reservoir,
    )?;
    storage_io::emit_event(
        &mut input.internals,
        ARC_STATE_ADDRESS,
        &ArcState::ArcBlockFinalized {
            blockHash: previous_block_hash,
            blockNumber: previous_block_number,
            stateRoot: final_state_root,
        },
        gas,
        reservoir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SphereProtocolEvmConfig;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_evm::{Evm, EvmEnv, EvmFactory, FromRecoveredTx, block::BlockExecutorFactory};
    use arc_execution_config::chainspec::LOCAL_DEV;
    use revm::{Database, DatabaseCommit, database::InMemoryDB};
    use sphere_chainspec::SphereChainSpec;
    use sphere_primitives::envelope::{SPHERE_SYSTEM_TX_SIGNATURE, SphereTxEnvelope};
    use std::sync::Arc;

    use alloy_primitives::KECCAK256_EMPTY;
    use revm::state::{AccountInfo, Bytecode};

    fn seeded_db(portal: Address, parent: &Header) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        let genesis: alloy_genesis::Genesis = serde_json::from_str(include_str!(
            "../../../../assets/localdev/sphere-genesis.json"
        ))
        .unwrap();
        for addr in genesis.alloc.keys() {
            let data = genesis.alloc.get(addr).unwrap().clone();
            match data.code.clone() {
                Some(code) => db.insert_account_info(
                    *addr,
                    AccountInfo {
                        balance: data.balance,
                        nonce: data.nonce.unwrap_or_default(),
                        code_hash: keccak256(&code),
                        code: Some(Bytecode::new_raw(code)),
                        account_id: None,
                    },
                ),
                None => db.insert_account_info(
                    *addr,
                    AccountInfo {
                        balance: data.balance,
                        nonce: data.nonce.unwrap_or_default(),
                        code_hash: KECCAK256_EMPTY,
                        code: None,
                        account_id: None,
                    },
                ),
            }
            for (k, v) in data.storage_slots() {
                db.insert_account_storage(*addr, k.into(), v)
                    .expect("insert storage");
            }
        }
        for (address, code) in sphere_contracts::runtime_bytecode::sphere_runtime_contracts(portal)
            .into_iter()
            .chain([(ARC_STATE_ADDRESS, Bytes::from_static(&[0]))])
        {
            db.insert_account_info(
                address,
                revm::state::AccountInfo {
                    code_hash: keccak256(&code),
                    code: Some(revm::state::Bytecode::new_raw(code)),
                    ..Default::default()
                },
            );
        }
        db.insert_account_storage(ARC_STATE_ADDRESS, ARC_BLOCK_HASH, parent.hash_slow().into())
            .unwrap();
        db
    }

    fn system_tx(
        chain_id: u64,
        target: Address,
        calldata: Vec<u8>,
    ) -> super::super::SphereProtocolTx {
        let envelope = SphereTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(chain_id),
                to: target.into(),
                input: calldata.into(),
                ..Default::default()
            },
            SPHERE_SYSTEM_TX_SIGNATURE,
        ));
        super::super::SphereProtocolTx::from_recovered_tx(&envelope, Address::ZERO)
    }

    #[test]
    fn checkpoint_import_updates_arc_state_and_rejects_replay() {
        let portal = Address::repeat_byte(0x42);
        let reader = sphere_precompiles::test_utils::MockL1Reader::default();
        let config = SphereProtocolEvmConfig::new(Arc::new(SphereChainSpec {
            inner: LOCAL_DEV.clone(),
        }))
        .with_l1_reader(reader.clone(), portal);
        let parent = Header::default();
        let header = Header {
            number: 1,
            parent_hash: parent.hash_slow(),
            ..Default::default()
        };
        let db = seeded_db(portal, &parent);
        let env = EvmEnv::default();
        let chain_id = env.cfg_env.chain_id;
        let mut evm = config.evm_factory().create_evm(db, env);
        let calldata = ISphereInbox::advanceArcHeadersCall {
            headers: vec![alloy_rlp::encode(&header).into()],
        }
        .abi_encode();
        let tx = system_tx(chain_id, SPHERE_INBOX_ADDRESS, calldata);
        let outcome = evm.transact_raw(tx.clone()).unwrap();
        assert_eq!(outcome.result.gas().tx_gas_used(), 0);
        assert_eq!(outcome.result.logs().len(), 1);
        assert_eq!(outcome.result.logs()[0].address, ARC_STATE_ADDRESS);
        evm.db_mut().commit(outcome.state);
        assert_eq!(
            evm.db_mut()
                .storage(ARC_STATE_ADDRESS, ARC_BLOCK_NUMBER)
                .unwrap(),
            U256::from(1)
        );
        assert_eq!(
            evm.db_mut()
                .storage(ARC_STATE_ADDRESS, ARC_BLOCK_HASH)
                .unwrap(),
            U256::from_be_bytes(header.hash_slow().0)
        );
        assert!(evm.transact_raw(tx).is_err());

        let child = Header {
            number: 2,
            parent_hash: header.hash_slow(),
            ..Default::default()
        };
        let tx = system_tx(
            chain_id,
            SPHERE_INBOX_ADDRESS,
            ISphereInbox::advanceArcCall {
                header: alloy_rlp::encode(&child).into(),
                deposits: vec![],
                decryptions: vec![],
                enabledTokens: vec![],
            }
            .abi_encode(),
        );
        // ISphere.sol PORTAL_CURRENT_DEPOSIT_QUEUE_HASH_SLOT.
        let queue_slot = U256::from(3);
        reader.insert(portal, queue_slot, 2, U256::from(1));
        assert!(evm.transact_raw(tx.clone()).is_err());
        assert_eq!(
            evm.db_mut()
                .storage(ARC_STATE_ADDRESS, ARC_BLOCK_NUMBER)
                .unwrap(),
            U256::from(1)
        );
        reader.insert(portal, queue_slot, 2, U256::ZERO);
        let outcome = evm.transact_raw(tx).unwrap();
        assert_eq!(
            outcome.result.logs().last().unwrap().address,
            SPHERE_INBOX_ADDRESS
        );
        evm.db_mut().commit(outcome.state);
        assert_eq!(
            evm.db_mut()
                .storage(ARC_STATE_ADDRESS, ARC_BLOCK_NUMBER)
                .unwrap(),
            U256::from(2)
        );

        let block_number = evm.block().number().to::<u64>();
        let tx = system_tx(
            chain_id,
            sphere_contracts::SPHERE_OUTBOX_ADDRESS,
            ISphereOutbox::finalizeWithdrawalBatchCall {
                count: U256::ZERO,
                blockNumber: block_number,
                encryptedSenders: vec![],
            }
            .abi_encode(),
        );
        let outcome = evm.transact_raw(tx).unwrap();
        assert_eq!(outcome.result.logs().len(), 1);
        assert_eq!(
            outcome.result.logs()[0].address,
            sphere_contracts::SPHERE_OUTBOX_ADDRESS
        );
    }
    #[test]
    fn encrypted_deposit_mints_arc_usdc_and_withdrawal_burns_it() {
        use alloy_consensus::{SignableTransaction, transaction::SignerRecoverable};
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use alloy_sol_types::{SolEvent, SolValue};
        use arc_precompiles::helpers::NATIVE_FIAT_TOKEN_ADDRESS;
        use sphere_contracts::{
            DecryptionData, Deposit, DepositPayload, DepositType, QueuedDeposit,
        };
        use sphere_precompiles::ecies::{
            build_plaintext, encrypt_plaintext, hkdf_info, hkdf_sha256,
        };
        use sphere_precompiles::{
            ecies::compressed_x_and_parity,
            test_utils::{EncryptedDepositFixture, MockL1Reader},
        };

        let fixture = EncryptedDepositFixture::new();
        let parent = Header::default();
        let child = Header {
            number: 1,
            parent_hash: parent.hash_slow(),
            ..Default::default()
        };
        let reader = MockL1Reader::default();
        let config = SphereProtocolEvmConfig::new(Arc::new(SphereChainSpec {
            inner: LOCAL_DEV.clone(),
        }))
        .with_l1_reader(reader.clone(), fixture.portal);
        let mut db = seeded_db(fixture.portal, &parent);
        // Arc NativeCoinAuthority TOTAL_SUPPLY_STORAGE_KEY.
        let supply_address = arc_precompiles::NATIVE_COIN_AUTHORITY_ADDRESS;
        let supply_slot = U256::from(2);
        let starting_supply = db.storage(supply_address, supply_slot).unwrap();
        let outbox = sphere_contracts::SPHERE_OUTBOX_ADDRESS;
        let enabled = keccak256((NATIVE_FIAT_TOKEN_ADDRESS, U256::from(6)).abi_encode());
        reader.insert(fixture.portal, enabled.into(), 1, U256::ONE);

        let (x, parity) = compressed_x_and_parity(&fixture.seq_pub);
        let base: U256 = keccak256(U256::from(5).to_be_bytes::<32>()).into();
        let key_slot = base + fixture.key_index * U256::from(2);
        reader.insert(fixture.portal, key_slot, 1, x.into());
        reader.insert(fixture.portal, key_slot + U256::ONE, 1, U256::from(parity));
        let decrypted = fixture.decrypt().unwrap();
        let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x42)).unwrap();
        let sender = signer.address();
        let info = hkdf_info(
            &fixture.portal,
            &fixture.key_index,
            &fixture.eph_pub_x,
            &fixture.sender,
        );
        let key = hkdf_sha256(&decrypted.proof.shared_secret.0, b"ecies-aes-key", &info);
        let (ciphertext, nonce, tag) =
            encrypt_plaintext(&key, &build_plaintext(&sender, &fixture.memo));
        let amount = 5_000_000;
        let deposit = Deposit {
            token: NATIVE_FIAT_TOKEN_ADDRESS,
            sender: fixture.sender,
            amount,
            arcRefundRecipient: fixture.sender,
            keyIndex: fixture.key_index,
            encrypted: DepositPayload {
                ephemeralPubkeyX: fixture.eph_pub_x,
                ephemeralPubkeyYParity: fixture.eph_pub_y_parity,
                ciphertext: ciphertext.into(),
                nonce: nonce.into(),
                tag: tag.into(),
            },
        };
        let queue_hash =
            keccak256((DepositType::Deposit, deposit.clone(), B256::ZERO).abi_encode_params());
        reader.insert(fixture.portal, U256::from(3), 1, queue_hash.into());
        let call = ISphereInbox::advanceArcCall {
            header: alloy_rlp::encode(&child).into(),
            deposits: vec![QueuedDeposit {
                depositType: DepositType::Deposit,
                depositData: deposit.abi_encode().into(),
                rejected: false,
            }],
            decryptions: vec![DecryptionData {
                sharedSecret: decrypted.proof.shared_secret,
                sharedSecretYParity: decrypted.proof.shared_secret_y_parity,
                cpProof: decrypted.proof.cp_proof,
            }],
            enabledTokens: vec![],
        };
        let env = EvmEnv::default();
        let chain_id = env.cfg_env.chain_id;
        let mut evm = config.evm_factory().create_evm(db, env);
        let outcome = evm
            .transact_raw(system_tx(chain_id, SPHERE_INBOX_ADDRESS, call.abi_encode()))
            .unwrap();
        assert!(
            outcome
                .result
                .logs()
                .iter()
                .any(|log| log.topics().first()
                    == Some(&ISphereInbox::DepositProcessed::SIGNATURE_HASH)),
            "{:?}",
            outcome.result.logs()
        );
        evm.db_mut().commit(outcome.state);
        assert_eq!(
            evm.db_mut().basic(sender).unwrap().unwrap().balance,
            U256::from(amount) * U256::from(1_000_000_000_000u64)
        );

        assert_eq!(
            evm.db_mut().storage(supply_address, supply_slot).unwrap(),
            starting_supply + U256::from(5_000_000_000_000_000_000u64)
        );

        alloy_sol_types::sol! {
            function approve(address spender, uint256 value) external returns (bool);
            function transfer(address to, uint256 value) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }
        let user_tx = |nonce: u64, target: Address, data: Vec<u8>| {
            let tx = TxLegacy {
                chain_id: Some(chain_id),
                gas_limit: 1_000_000,
                nonce,
                to: target.into(),
                input: data.into(),
                ..Default::default()
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
            let envelope = SphereTxEnvelope::Legacy(tx.into_signed(signature));
            let recovered = envelope.recover_signer().unwrap();
            assert_eq!(recovered, sender);
            super::super::SphereProtocolTx::from_recovered_tx(&envelope, recovered)
        };
        let transfer = transferCall {
            to: fixture.sender,
            value: U256::ONE,
        }
        .abi_encode();
        let balance = balanceOfCall {
            account: fixture.sender,
        }
        .abi_encode();
        for data in [transfer, balance] {
            let result = evm
                .transact_raw(user_tx(0, NATIVE_FIAT_TOKEN_ADDRESS, data))
                .unwrap();
            assert!(matches!(
                result.result,
                revm::context::result::ExecutionResult::Revert { .. }
            ));
        }

        let next = Header {
            number: 2,
            parent_hash: child.hash_slow(),
            ..Default::default()
        };
        reader.insert(
            fixture.portal,
            sphere_contracts::TRANSFERS_ENABLED_SLOT,
            2,
            U256::ONE << (8 * sphere_contracts::TRANSFERS_ENABLED_OFFSET),
        );
        reader.insert(fixture.portal, enabled.into(), 2, U256::ONE);
        let checkpoint = ISphereInbox::advanceArcHeadersCall {
            headers: vec![alloy_rlp::encode(&next).into()],
        };
        let result = evm
            .transact_raw(system_tx(
                chain_id,
                SPHERE_INBOX_ADDRESS,
                checkpoint.abi_encode(),
            ))
            .unwrap();
        evm.db_mut().commit(result.state);
        let payment = transferCall {
            to: fixture.sender,
            value: U256::from(1_000_000),
        };
        let result = evm
            .transact_raw(user_tx(0, NATIVE_FIAT_TOKEN_ADDRESS, payment.abi_encode()))
            .unwrap();
        assert!(result.result.is_success(), "{:?}", result.result);
        evm.db_mut().commit(result.state);
        assert_eq!(
            evm.db_mut().basic(fixture.sender).unwrap().unwrap().balance,
            U256::from(1_000_000_000_000_000_000u64)
        );
        let amount = amount - 1_000_000;

        let approval = approveCall {
            spender: outbox,
            value: U256::from(amount),
        };
        let result = evm
            .transact_raw(user_tx(1, NATIVE_FIAT_TOKEN_ADDRESS, approval.abi_encode()))
            .unwrap();
        assert!(result.result.is_success(), "{:?}", result.result);
        evm.db_mut().commit(result.state);

        let request = ISphereOutbox::requestWithdrawalCall {
            token: NATIVE_FIAT_TOKEN_ADDRESS,
            to: fixture.sender,
            amount,
            memo: fixture.memo,
            gasLimit: 0,
            sphereFallbackRecipient: sender,
            data: Bytes::new(),
            revealTo: Bytes::new(),
        };
        let tx = user_tx(2, outbox, request.abi_encode());
        let hash = tx.tx_hash;
        let result = evm.transact_raw(tx).unwrap();
        assert!(result.result.is_success(), "{:?}", result.result);
        evm.db_mut().commit(result.state);
        assert_eq!(
            evm.db_mut().basic(sender).unwrap().unwrap().balance,
            U256::ZERO
        );

        assert_eq!(
            evm.db_mut().storage(supply_address, supply_slot).unwrap(),
            starting_supply + U256::from(1_000_000_000_000_000_000u64)
        );

        let block_number = evm.block().number().to::<u64>();
        let tx = system_tx(
            chain_id,
            outbox,
            ISphereOutbox::finalizeWithdrawalBatchCall {
                count: U256::ONE,
                blockNumber: block_number,
                encryptedSenders: vec![Bytes::new()],
            }
            .abi_encode(),
        );
        let result = evm.transact_raw(tx).unwrap();
        let withdrawal = sphere_contracts::Withdrawal {
            token: NATIVE_FIAT_TOKEN_ADDRESS,
            to: fixture.sender,
            amount,
            memo: fixture.memo,
            senderTag: sphere_contracts::Withdrawal::sender_tag(sender, hash, 1),
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: Bytes::new(),
            encryptedSender: Bytes::new(),
        };
        assert_eq!(
            result.result.logs()[0].topics()[1],
            withdrawal.hash_with_tail(B256::ZERO)
        );
    }
}
