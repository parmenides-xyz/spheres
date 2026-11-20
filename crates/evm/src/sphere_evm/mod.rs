//! Sphere runtime EVM and its private execution policies.

pub mod contract_creation;
mod validation;

use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory, eth::EthEvmContext, precompiles::PrecompilesMap,
};
use alloy_primitives::{Address, Bytes};
use arc_evm::ArcEvmFactory;
use revm::{
    Inspector,
    context::{
        BlockEnv, TxEnv,
        result::{EVMError, HaltReason, ResultAndState},
    },
    primitives::hardfork::SpecId,
};
use sphere_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;
pub use validation::validate_transaction;

pub struct SphereEvm<DB: Database, I: Inspector<EthEvmContext<DB>>> {
    pub(super) inner: <ArcEvmFactory as EvmFactory>::Evm<DB, I>,
}

impl<DB: Database, I: Inspector<EthEvmContext<DB>>> SphereEvm<DB, I> {
    pub(super) fn new(mut evm: <ArcEvmFactory as EvmFactory>::Evm<DB, I>) -> Self {
        contract_creation::configure_runtime(&mut evm.inner.instruction);
        Self { inner: evm }
    }
}

impl<DB: Database, I: Inspector<EthEvmContext<DB>>> Evm for SphereEvm<DB, I> {
    type DB = DB;
    type Tx = TxEnv;
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
        validate_transaction(&tx, CONTRACT_DEPLOYER_ALLOWLIST)?;
        self.inner.transact_raw(tx)
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec, Self::BlockEnv>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inner.set_inspector_enabled(enabled);
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        self.inner.components_mut()
    }
}
