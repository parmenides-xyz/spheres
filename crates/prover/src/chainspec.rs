use std::{collections::HashMap, sync::Arc};

use arc_execution_config::chainspec::{ArcChainSpec, bundled_chainspec_for_chain_id};

/// Arc chain specifications trusted by this prover in addition to built-in networks.
#[derive(Debug, Default)]
pub struct TrustedChainSpecs {
    custom: HashMap<u64, Arc<ArcChainSpec>>,
}

impl TrustedChainSpecs {
    /// Registers an immutable custom chain specification by chain ID.
    pub fn insert(
        &mut self,
        chain_id: u64,
        spec: Arc<ArcChainSpec>,
    ) -> Result<(), TrustedChainSpecError> {
        if bundled_chainspec_for_chain_id(chain_id).is_some() {
            return Err(TrustedChainSpecError::BuiltIn(chain_id));
        }
        if self.custom.insert(chain_id, spec).is_some() {
            return Err(TrustedChainSpecError::Duplicate(chain_id));
        }
        Ok(())
    }

    /// Resolves a trusted built-in or custom chain specification by chain ID.
    pub fn resolve(&self, chain_id: u64) -> Option<Arc<ArcChainSpec>> {
        self.custom
            .get(&chain_id)
            .cloned()
            .or_else(|| bundled_chainspec_for_chain_id(chain_id))
    }

    /// Returns whether this prover supports the supplied Arc chain ID.
    pub fn supports(&self, chain_id: u64) -> bool {
        self.resolve(chain_id).is_some()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustedChainSpecError {
    #[error("Arc chain ID {0} is built in and cannot be overridden")]
    BuiltIn(u64),
    #[error("duplicate custom Arc chain ID {0}")]
    Duplicate(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_chains_cannot_override_builtins() {
        let error = TrustedChainSpecs::default()
            .insert(
                arc_execution_config::chain_ids::TESTNET_CHAIN_ID,
                arc_execution_config::chainspec::TESTNET.clone(),
            )
            .unwrap_err();

        assert_eq!(
            error,
            TrustedChainSpecError::BuiltIn(arc_execution_config::chain_ids::TESTNET_CHAIN_ID)
        );
    }
}
