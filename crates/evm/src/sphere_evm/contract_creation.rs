//! Contract creation runtime enforcement.

use alloy_evm::{Database, eth::EthEvmContext};
use alloy_primitives::Address;
use revm::{
    bytecode::opcode::{CREATE, CREATE2},
    handler::instructions::EthInstructions,
    interpreter::{
        Instruction, InstructionContext, instructions::contract::create as revm_create,
        interpreter::EthInterpreter, interpreter_types::InputsTr,
    },
};
use sphere_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

type SphereInstructionCtx<'a, DB> = InstructionContext<'a, EthEvmContext<DB>, EthInterpreter>;

/// Installs the Sphere contract-creation policy into the EVM instruction table.
///
/// The standard `CREATE` and `CREATE2` handlers are replaced with guarded variants that check the
/// executing storage-context address against [`CONTRACT_DEPLOYER_ALLOWLIST`]. Allowed deployers
/// delegate to revm's standard instruction implementation, preserving its gas accounting and
/// execution semantics; unlisted deployers halt with [`revm::interpreter::InstructionResult::NotActivated`].
pub fn configure_runtime<DB: Database>(
    instructions: &mut EthInstructions<EthInterpreter, EthEvmContext<DB>>,
) {
    instructions.insert_instruction(
        CREATE,
        Instruction::new(
            |ctx| create::<false, DB>(ctx, CONTRACT_DEPLOYER_ALLOWLIST),
            0,
        ),
    );
    instructions.insert_instruction(
        CREATE2,
        Instruction::new(
            |ctx| create::<true, DB>(ctx, CONTRACT_DEPLOYER_ALLOWLIST),
            0,
        ),
    );
}

fn create<const IS_CREATE2: bool, DB: Database>(
    context: SphereInstructionCtx<'_, DB>,
    allowlist: &[Address],
) {
    if !allowlist.contains(&context.interpreter.input.target_address()) {
        return context.interpreter.halt_not_activated();
    }

    revm_create::<EthInterpreter, IS_CREATE2, EthEvmContext<DB>>(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_evm::Evm;
    use alloy_evm::{EvmEnv, EvmFactory, block::BlockExecutorFactory};
    use alloy_primitives::{Address, Bytes, TxKind, bytes};
    use arc_execution_config::chainspec::LOCAL_DEV;
    use reth_ethereum::chainspec::EthChainSpec;
    use revm::{
        bytecode::Bytecode,
        context::{
            TxEnv,
            result::{ExecutionResult, HaltReason},
        },
        database::InMemoryDB,
        inspector::NoOpInspector,
        state::AccountInfo,
    };
    use revm::{
        bytecode::opcode,
        context::{BlockEnv, CfgEnv},
        primitives::hardfork::SpecId,
    };
    use sphere_chainspec::SphereChainSpec;
    use std::sync::Arc;
    type TestDb = InMemoryDB;
    type TestEvm = crate::sphere_evm::SphereEvm<TestDb, NoOpInspector>;
    const TEST_DEPLOYER: Address = Address::repeat_byte(0x42);

    fn test_create<const IS_CREATE2: bool>(context: SphereInstructionCtx<'_, TestDb>) {
        create::<IS_CREATE2, TestDb>(context, &[TEST_DEPLOYER])
    }

    fn enable_test_deployer(evm: &mut TestEvm) {
        let instructions = &mut evm.inner.inner.instruction;
        instructions.insert_instruction(CREATE, Instruction::new(test_create::<false>, 0));
        instructions.insert_instruction(CREATE2, Instruction::new(test_create::<true>, 0));
    }

    fn test_db(contracts: impl IntoIterator<Item = (Address, Bytes)>) -> TestDb {
        let mut db = InMemoryDB::default();
        for (address, code) in contracts {
            db.insert_account_info(address, AccountInfo::from_bytecode(Bytecode::new_raw(code)));
        }
        db
    }

    fn test_evm(db: TestDb, input: EvmEnv) -> TestEvm {
        let config = crate::create_evm_config(Arc::new(SphereChainSpec {
            inner: LOCAL_DEV.clone(),
        }));
        config.evm_factory().create_evm(db, input)
    }

    fn evm_env_with_spec(spec: SpecId) -> EvmEnv {
        let cfg_env = CfgEnv::new()
            .with_chain_id(LOCAL_DEV.chain_id())
            .with_spec_and_mainnet_gas_params(spec);

        EvmEnv {
            block_env: BlockEnv::default(),
            cfg_env,
        }
    }

    #[test]
    fn factory_uses_input_spec_for_instruction_tables() {
        let config = crate::create_evm_config(Arc::new(SphereChainSpec {
            inner: LOCAL_DEV.clone(),
        }));
        let factory = config.evm_factory();
        let evm = factory.create_evm(InMemoryDB::default(), evm_env_with_spec(SpecId::TANGERINE));

        assert_eq!(evm.inner.inner.instruction.spec, SpecId::TANGERINE);
        assert_eq!(
            evm.inner.inner.instruction.instruction_table[opcode::DELEGATECALL as usize]
                .static_gas(),
            700
        );

        let evm = factory.create_evm_with_inspector(
            InMemoryDB::default(),
            evm_env_with_spec(SpecId::TANGERINE),
            NoOpInspector {},
        );

        assert_eq!(evm.inner.inner.instruction.spec, SpecId::TANGERINE);
        assert_eq!(
            evm.inner.inner.instruction.instruction_table[opcode::DELEGATECALL as usize]
                .static_gas(),
            700
        );
    }

    fn evm_with_contract(addr: Address, code: &[u8]) -> TestEvm {
        let input = EvmEnv::default();
        test_evm(test_db([(addr, Bytes::copy_from_slice(code))]), input)
    }

    fn call_tx(caller: Address, contract: Address) -> TxEnv {
        TxEnv {
            caller,
            gas_price: 0,
            gas_limit: 1_000_000,
            kind: TxKind::Call(contract),
            ..Default::default()
        }
    }

    fn assert_not_activated(result: ExecutionResult<HaltReason>) {
        assert!(matches!(
            result,
            ExecutionResult::Halt {
                reason: HaltReason::NotActivated,
                ..
            }
        ));
    }

    #[test]
    fn top_level_create_respects_allowlist() {
        let caller = Address::repeat_byte(0x01);
        let tx = TxEnv {
            caller,
            kind: TxKind::Create,
            ..Default::default()
        };

        assert!(crate::sphere_evm::validate_transaction(&tx, &[]).is_err());
        assert!(crate::sphere_evm::validate_transaction(&tx, &[caller]).is_ok());
        assert!(matches!(
            test_evm(TestDb::default(), EvmEnv::default()).transact_raw(tx),
            Err(revm::context::result::EVMError::Transaction(revm::context::result::InvalidTransaction::Str(reason))) if reason == "contract creation is not supported"
        ));
    }

    #[test]
    fn runtime_create_opcodes_are_disabled_for_unlisted_deployers() {
        let (contract, caller) = (Address::repeat_byte(0x10), Address::repeat_byte(0x20));
        for bytecode in [
            // PUSH0 PUSH0 PUSH0 CREATE STOP
            bytes!("0x5f5f5ff000"),
            // PUSH0 PUSH0 PUSH0 PUSH0 CREATE2 STOP
            bytes!("0x5f5f5f5ff500"),
        ] {
            let mut evm = evm_with_contract(contract, &bytecode);
            let result = evm
                .transact_raw(call_tx(caller, contract))
                .expect("transaction should execute")
                .result;
            assert_not_activated(result);
        }
    }

    #[test]
    fn allowlisted_deployer_can_execute_create_and_create2() {
        let caller = Address::repeat_byte(0x20);
        for bytecode in [
            // CREATE, then return the created address.
            bytes!("0x5f5f5ff05f5260205ff3"),
            // CREATE2, then return the created address.
            bytes!("0x5f5f5f5ff55f5260205ff3"),
        ] {
            let mut evm = evm_with_contract(TEST_DEPLOYER, &bytecode);
            enable_test_deployer(&mut evm);

            let result = evm
                .transact_raw(call_tx(caller, TEST_DEPLOYER))
                .expect("allowlisted deployment should execute");
            let ExecutionResult::Success { output, .. } = result.result else {
                panic!("allowlisted deployment should succeed")
            };
            let created = Address::from_slice(&output.data()[12..]);
            assert_ne!(created, Address::ZERO);
            assert!(result.state.contains_key(&created));
        }
    }

    #[test]
    fn delegatecall_does_not_borrow_deployer_privilege() {
        let caller = Address::repeat_byte(0x20);
        let proxy = Address::repeat_byte(0x30);

        // DELEGATECALL the allowlisted deployer with empty calldata, then return its success flag.
        let mut proxy_code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x73];
        proxy_code.extend_from_slice(TEST_DEPLOYER.as_slice());
        proxy_code.extend_from_slice(&[0x61, 0xff, 0xff, 0xf4, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);

        let input = EvmEnv::default();
        let mut evm = test_evm(
            test_db([
                (proxy, Bytes::from(proxy_code)),
                (TEST_DEPLOYER, bytes!("0x5f5f5ff000")),
            ]),
            input,
        );
        enable_test_deployer(&mut evm);

        let result = evm
            .transact_raw(call_tx(caller, proxy))
            .expect("proxy call should execute");
        let ExecutionResult::Success { output, .. } = result.result else {
            panic!("proxy should handle the failed delegatecall")
        };
        assert_eq!(output.data()[31], 0);
    }
}
