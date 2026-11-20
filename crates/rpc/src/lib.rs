//! Redacted sphere RPC types and provider.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod auth;
pub mod config;
pub mod debug;
pub mod error;
pub mod filter;
pub mod handlers;
mod metrics;
pub mod policy;
pub mod provider;
pub mod server;
pub mod subscription;
pub mod types;
mod ws;

pub use config::RedactedRpcConfig;
pub use debug::{SphereDebugApi, SphereDebugApiRpcServer};
pub use handlers::SphereRpcApi;
pub use provider::{SphereProvider, SphereProviderConfig};
pub use server::start_redacted_rpc;
pub use subscription::{BoxWsSubscriptionFut, WsSubscriptionStream};
