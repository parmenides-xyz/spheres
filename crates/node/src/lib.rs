#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
pub mod consensus;
pub mod pool;
pub use consensus::{SphereConsensus, SphereConsensusBuilder, SphereDevConsensusBuilder};
pub mod engine;
pub mod executor;
pub mod genesis;
pub use executor::{SphereExecutorBuilder, SphereProtocolExecutorBuilder};
mod follower;
pub mod network;
mod replication;
mod role;
pub mod rpc;
mod settlement_attestation;
mod tx_forwarding;
pub mod version;
pub use engine::{EngineExit, ProductionPermit, SphereEngine};
pub use version::init_version_metadata;
