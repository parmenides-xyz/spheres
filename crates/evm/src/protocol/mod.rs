mod checkpoint;
mod config;
mod crypto;
pub mod database;
use database::{L1OverlayDB, SphereDbError};
pub mod reader;
mod storage_io;
pub use config::SphereProtocolEvmConfig;
mod transaction;
use crate::{SphereEvmFactory, sphere_evm::SphereEvm};
use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, eth::EthEvmContext, precompiles::PrecompilesMap,
};
use alloy_primitives::{Address, Bytes};
use revm::handler::SystemCallTx;
use revm::{
    Inspector,
    context::{
        BlockEnv, TxEnv,
        result::{
            EVMError, ExecutionResult, HaltReason, InvalidTransaction, ResultAndState, ResultGas,
        },
    },
    inspector::NoOpInspector,
    interpreter::interpreter::EthInterpreter,
    primitives::hardfork::SpecId,
};
use sphere_primitives::envelope::SphereTransactionKind;

const SYSTEM_CALL_GAS_LIMIT: u64 = 250_000_000;

#[derive(Debug, Clone)]
pub struct SphereProtocolTx {
    tx_hash: alloy_primitives::B256,
    inner: TxEnv,
    system: Option<(SphereTransactionKind, bool)>,
}

pub struct SphereProtocolEvm<DB: Database, I: Inspector<EthEvmContext<L1OverlayDB<DB>>>> {
    inner: SphereEvm<L1OverlayDB<DB>, I>,
    l1: Option<reader::State>,
}

impl<DB: Database, I: Inspector<EthEvmContext<L1OverlayDB<DB>>>> SphereProtocolEvm<DB, I> {
    fn new(mut inner: SphereEvm<L1OverlayDB<DB>, I>, l1: Option<reader::State>) -> Self {
        inner
            .inner
            .enable_sphere_call_rules(l1.as_ref().map(reader::State::portal));
        checkpoint::configure_runtime(inner.precompiles_mut(), l1.clone());
        crypto::configure_runtime(inner.precompiles_mut());
        Self { inner, l1 }
    }
}

#[derive(Debug, Clone)]
pub struct SphereProtocolEvmFactory(
    pub(crate) SphereEvmFactory,
    Option<(reader::Reader, Address)>,
    Option<Address>,
);
impl SphereProtocolEvmFactory {
    fn state(&self) -> Option<reader::State> {
        self.1
            .as_ref()
            .map(|(reader, portal)| reader::State::new(reader.clone(), *portal))
    }
}
impl EvmFactory for SphereProtocolEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<L1OverlayDB<DB>>>> = SphereProtocolEvm<DB, I>;
    type Tx = SphereProtocolTx;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<L1OverlayDB<DB>>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let state = self.state();
        let db = L1OverlayDB::new(db, state.clone(), self.2);
        SphereProtocolEvm::new(self.0.create_evm(db, input), state)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let state = self.state();
        let db = L1OverlayDB::new(db, state.clone(), self.2);
        SphereProtocolEvm::new(
            self.0.create_evm_with_inspector(db, input, inspector),
            state,
        )
    }
}

impl<DB: Database, I: Inspector<EthEvmContext<L1OverlayDB<DB>>>> Evm for SphereProtocolEvm<DB, I> {
    type DB = DB;
    type Tx = SphereProtocolTx;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;
    type Inspector = I;

    fn block(&self) -> &Self::BlockEnv {
        self.inner.block()
    }

    fn cfg_env(&self) -> &revm::context::CfgEnv<Self::Spec> {
        self.inner.cfg_env()
    }

    fn chain_id(&self) -> u64 {
        self.inner.chain_id()
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        let _guard = reader::Reset(self.l1.clone());
        let _tx_guard =
            sphere_precompiles::tx_context::set_current_transaction(tx.tx_hash, tx.inner.caller);
        if !tx.inner.value.is_zero() {
            return Err(
                InvalidTransaction::Str("native value transfer is not allowed".into()).into(),
            );
        }
        let Some((kind, valid)) = tx.system else {
            let mut result = self
                .inner
                .transact_raw(tx.inner)
                .map_err(map_adapter_error)?;
            self.inner
                .db()
                .sanitize_state(&mut result.state)
                .map_err(SphereDbError::into_evm_error)?;
            return Ok(result);
        };
        if !valid
            || tx.inner.chain_id != Some(self.chain_id())
            || !tx.inner.caller.is_zero()
            || matches!(
                kind,
                SphereTransactionKind::UnexpectedSystem | SphereTransactionKind::Regular
            )
        {
            return Err(InvalidTransaction::Str("invalid Sphere system transaction".into()).into());
        }
        let Some(target) = tx.inner.kind.to().copied() else {
            return Err(InvalidTransaction::Str("system transaction must be a call".into()).into());
        };
        if self.precompiles().get(&target).is_none()
            && self
                .db_mut()
                .basic(target)
                .map_err(EVMError::Database)?
                .is_none_or(|account| account.is_empty_code_hash() || account.code_hash.is_zero())
        {
            return Err(
                InvalidTransaction::Str("Sphere system contract is unavailable".into()).into(),
            );
        }
        let mut system_tx =
            TxEnv::new_system_tx_with_caller(tx.inner.caller, target, tx.inner.data);
        system_tx.gas_limit = SYSTEM_CALL_GAS_LIMIT;
        let mut outcome = self
            .inner
            .inner
            .transact_system_tx(system_tx)
            .map_err(map_adapter_error)?;
        self.inner
            .db()
            .sanitize_state(&mut outcome.state)
            .map_err(SphereDbError::into_evm_error)?;
        let ExecutionResult::Success { gas, .. } = &mut outcome.result else {
            return Err(InvalidTransaction::Str("Sphere system transaction failed".into()).into());
        };
        *gas = ResultGas::new_with_state_gas(0, 0, 0, 0);
        Ok(outcome)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        let _guard = reader::Reset(self.l1.clone());
        let mut result = self
            .inner
            .transact_system_call(caller, contract, data)
            .map_err(map_adapter_error)?;
        self.inner
            .db()
            .sanitize_state(&mut result.state)
            .map_err(SphereDbError::into_evm_error)?;
        Ok(result)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        let (db, env) = self.inner.finish();
        (db.into_inner(), env)
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        let (db, inspector, precompiles) = self.inner.components();
        (db.inner(), inspector, precompiles)
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        let (db, inspector, precompiles) = self.inner.components_mut();
        (db.inner_mut(), inspector, precompiles)
    }
}

fn map_adapter_error<E: core::error::Error + revm::context::DBErrorMarker>(
    error: EVMError<SphereDbError<E>>,
) -> EVMError<E> {
    match error {
        EVMError::Transaction(error) => EVMError::Transaction(error),
        EVMError::Header(error) => EVMError::Header(error),
        EVMError::Database(error) => error.into_evm_error(),
        EVMError::Custom(error) => EVMError::Custom(error),
        EVMError::CustomAny(error) => EVMError::CustomAny(error),
    }
}
