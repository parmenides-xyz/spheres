//! Client provider for the redacted sphere RPC.
//!
//! [`SphereProvider`] wraps an alloy provider and automatically generates
//! fresh authorization tokens, rebuilding the HTTP client when the
//! current token approaches expiry.

use std::{sync::Arc, time::Duration};

use alloy_primitives::hex;
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use parking_lot::Mutex;
use alloy_network::Ethereum;

use crate::{
    auth::{X_AUTHORIZATION_TOKEN, build_token_fields, now_unix_seconds},
    metrics::SphereProviderMetrics,
};

/// How many seconds before expiry to refresh the token.
const REFRESH_BUFFER_SECS: u64 = 30;

/// Configuration for building a [`SphereProvider`].
#[derive(Clone, Debug)]
pub struct SphereProviderConfig {
    /// Signer for generating authorization tokens.
    pub signer: PrivateKeySigner,
    /// Sphere identifier.
    pub sphere_id: u32,
    /// Chain identifier.
    pub chain_id: u64,
    /// How long each generated token is valid. Default: 600s.
    /// Must not exceed the server's configured maximum validity window
    /// (default protocol limit: 2592000s / 30 days).
    pub token_ttl: Duration,
    /// The redacted sphere RPC URL.
    pub rpc_url: url::Url,
}

/// An alloy provider that auto-refreshes its sphere authorization token.
///
/// Call [`provider()`](Self::provider) to get a `DynProvider` with a valid token.
/// The inner provider is rebuilt transparently when the current token
/// is within [`REFRESH_BUFFER_SECS`] of expiry.
#[derive(Clone)]
pub struct SphereProvider {
    config: SphereProviderConfig,
    state: Arc<Mutex<CachedState>>,
    metrics: SphereProviderMetrics,
}

struct CachedState {
    provider: DynProvider<Ethereum>,
    expires_at: u64,
}

impl SphereProvider {
    /// Create a new `SphereProvider` with the given config.
    ///
    /// Immediately builds the first provider with a fresh token.
    pub fn new(config: SphereProviderConfig) -> eyre::Result<Self> {
        let (provider, expires_at) = build_provider_with_token(&config)?;
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(CachedState {
                provider,
                expires_at,
            })),
            metrics: SphereProviderMetrics::default(),
        })
    }

    /// Get a provider with a valid authorization token.
    ///
    /// Transparently refreshes the token if it's about to expire.
    pub fn provider(&self) -> DynProvider<Ethereum> {
        let now = now_unix_seconds();
        let mut state = self.state.lock();
        if now + REFRESH_BUFFER_SECS < state.expires_at {
            return state.provider.clone();
        }
        self.metrics.token_refresh_attempts_total.increment(1);

        match build_provider_with_token(&self.config) {
            Ok((provider, expires_at)) => {
                state.provider = provider;
                state.expires_at = expires_at;
                state.provider.clone()
            }
            Err(e) => {
                self.metrics.token_refresh_failures_total.increment(1);
                tracing::warn!(target: "sphere::rpc", err = %e, "failed to refresh sphere auth token, reusing stale");
                state.provider.clone()
            }
        }
    }
}

/// Build a fresh provider with a newly-signed auth token.
fn build_provider_with_token(
    config: &SphereProviderConfig,
) -> eyre::Result<(DynProvider<Ethereum>, u64)> {
    let now = now_unix_seconds();
    let expires_at = now + config.token_ttl.as_secs();

    let (fields, digest) = build_token_fields(config.sphere_id, config.chain_id, now, expires_at);

    let sig = config
        .signer
        .sign_hash_sync(&digest)
        .map_err(|e| eyre::eyre!("failed to sign sphere auth token: {e}"))?;

    // Build blob: <65-byte sig><29-byte fields>
    let mut blob = Vec::with_capacity(65 + fields.len());
    blob.extend_from_slice(&sig.as_rsy());
    blob.extend_from_slice(&fields);

    let mut auth_header = reqwest::header::HeaderValue::from_str(&hex::encode(&blob))?;
    auth_header.set_sensitive(true);

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(X_AUTHORIZATION_TOKEN, auth_header);

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let provider = ProviderBuilder::new_with_network::<Ethereum>()
        .connect_reqwest(client, config.rpc_url.clone())
        .erased();

    Ok((provider, expires_at))
}
