//! Explicit Arc fork schedules for tests, independent of dev genesis defaults.

use alloy_genesis::Genesis;
use arc_execution_config::hardforks::ArcHardfork;

/// Activates earlier Arc forks at genesis, schedules `fork`, and disables all later forks.
///
/// Later forks use explicit nulls so Sphere parent-schedule inheritance cannot re-enable them.
/// Allocations and non-Arc fork settings are preserved.
pub fn set_arc_fork(genesis: &mut Genesis, fork: ArcHardfork, activation: u64) {
    for (candidate, key) in crate::ARC_FORK_FIELDS {
        let value = if candidate < fork {
            serde_json::json!(0)
        } else if candidate == fork {
            serde_json::json!(activation)
        } else {
            serde_json::Value::Null
        };
        genesis.config.extra_fields.insert(key.to_owned(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SphereChainSpec;
    use arc_execution_config::{
        chainspec::{ArcChainSpec, LOCAL_DEV},
        hardforks::is_arc_fork_active,
    };
    use sphere_primitives::constants::sphere_chain_id;

    #[test]
    fn explicit_schedule_survives_parent_inheritance() {
        for (before, after) in [
            (ArcHardfork::Zero6, ArcHardfork::Zero7),
            (ArcHardfork::Zero7, ArcHardfork::Zero8),
        ] {
            let mut genesis = LOCAL_DEV.inner.genesis.clone();
            genesis.config.chain_id = sphere_chain_id(1_337, 1).unwrap();
            // Start with no Arc overrides, so later forks would otherwise be inherited.
            for (_, key) in crate::ARC_FORK_FIELDS {
                genesis.config.extra_fields.remove(key);
            }
            let alloc = genesis.alloc.clone();
            set_arc_fork(&mut genesis, after, 1_000);
            assert_eq!(genesis.alloc, alloc);

            let arc = ArcChainSpec::from(genesis.clone());
            let sphere = SphereChainSpec::from_genesis_with_l1(genesis, &LOCAL_DEV).unwrap();
            for (timestamp, expected) in [
                (0, before),
                (999, before),
                (1_000, after),
                (u64::MAX, after),
            ] {
                for &fork in ArcHardfork::VARIANTS {
                    assert_eq!(
                        is_arc_fork_active(&arc, fork, 0, timestamp),
                        fork <= expected
                    );
                    assert_eq!(
                        is_arc_fork_active(&sphere, fork, 0, timestamp),
                        fork <= expected
                    );
                }
            }
        }
    }
}
