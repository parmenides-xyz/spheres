use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use clap::Args;
use sphere_p2p::Role;
use sphere_payload::builder::DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS;
use sphere_rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS;
use sphere_sequencer::{
    DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES, DEFAULT_MAX_WITHDRAWAL_BATCH_GAS,
    MAX_WITHDRAWAL_BATCH_GAS,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Args)]
pub struct SphereArgs {
    /// Certified Arc follower WebSocket RPC URL for finalized L1 state, deposit events, and chain notifications.
    #[arg(
        long = "l1.rpc-url",
        env = "L1_RPC_URL",
        value_parser = parse_l1_rpc_url
    )]
    pub l1_rpc_url: Option<String>,

    /// SpherePortal contract address on L1.
    #[arg(
        long = "l1.portal-address",
        env = "L1_PORTAL_ADDRESS",
        value_parser = parse_portal_address
    )]
    pub portal_address: Option<Address>,

    /// SphereFactory contract address on Arc L1.
    #[arg(long = "l1.factory-address", env = "L1_FACTORY_ADDRESS", value_parser = parse_portal_address)]
    pub factory_address: Option<Address>,

    /// Path to a file or FIFO containing the shared sequencer private key.
    ///
    /// Required by every node that can produce blocks. Requiredness is checked after the
    /// manifest is read rather than by `clap`, because an `rpc_only` node must not hold this
    /// key: it is also the zone's ECIES private key for encrypted deposits.
    #[arg(
        long = "sequencer-key-file",
        env = "SEQUENCER_KEY_FILE",
        value_name = "PATH"
    )]
    pub sequencer_key_file: Option<PathBuf>,

    /// File containing additional deposit decryption keys, one hex key per line.
    #[arg(
        long = "deposit-decryption-keys-file",
        env = "DEPOSIT_DECRYPTION_KEYS_FILE",
        value_name = "PATH"
    )]
    pub deposit_decryption_keys_file: Option<PathBuf>,

    /// Path to the static multi-sequencer manifest. Its presence activates
    /// multi-sequencer mode and makes the manifest authoritative for role selection.
    #[arg(
        long = "sequencer.manifest",
        env = "SEQUENCER_MANIFEST",
        value_name = "PATH",
        requires = "p2p_key",
        conflicts_with = "enable_sequencer"
    )]
    pub sequencer_manifest: Option<PathBuf>,

    /// Path to a file or FIFO containing this node's hex-encoded Ed25519 P2P identity key.
    #[arg(
        long = "p2p.key",
        env = "P2P_KEY",
        value_name = "PATH",
        requires = "sequencer_manifest"
    )]
    pub p2p_key: Option<PathBuf>,

    /// Path to a file or FIFO containing this node's hex-encoded individual secp256k1 private key.
    #[arg(
        long = "secp256k1.key",
        env = "SECP256K1_KEY",
        value_name = "PATH",
        requires = "sequencer_manifest"
    )]
    pub secp256k1_key: Option<PathBuf>,

    /// Socket address bound for multi-sequencer Commonware traffic.
    #[arg(
        long = "p2p.listen",
        env = "P2P_LISTEN",
        default_value = "0.0.0.0:9200"
    )]
    pub p2p_listen: SocketAddr,

    /// Disable Commonware's pre-authentication source-IP filter.
    ///
    /// Required for DNS peer addresses whose egress IPs are not known in advance.
    /// Only enable this when network-level policy restricts access to the P2P port.
    #[arg(
        long = "p2p.bypass-ip-check",
        env = "P2P_BYPASS_IP_CHECK",
        requires = "sequencer_manifest"
    )]
    pub p2p_bypass_ip_check: bool,

    /// (Optional) Checked against the role derived from the manifest.
    ///
    /// One of `leader`, `follower`, or `rpc-follower`.
    #[arg(
        long = "sequencer.role",
        env = "SEQUENCER_ROLE",
        value_name = "ROLE",
        requires = "sequencer_manifest"
    )]
    pub sequencer_role: Option<Role>,

    #[arg(
        long = "sphere.poll-interval-secs",
        env = "SPHERE_POLL_INTERVAL_SECS",
        default_value_t = 1
    )]
    pub sphere_poll_interval_secs: u64,

    /// Number of sphere blocks between withdrawal batch boundaries.
    ///
    #[arg(
        long = "sphere.batch-interval-blocks",
        env = "SPHERE_BATCH_INTERVAL_BLOCKS",
        default_value_t = DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS
    )]
    pub sphere_batch_interval_blocks: u64,

    /// How often (in seconds) the withdrawal processor polls the L1 queue.
    #[arg(
        long = "withdrawal-poll-interval-secs",
        env = "WITHDRAWAL_POLL_INTERVAL_SECS",
        default_value_t = 5
    )]
    pub withdrawal_poll_interval_secs: u64,

    /// Maximum gas reserved by one processWithdrawals transaction, up to 20,000,000. An oversized
    /// withdrawal is submitted alone.
    #[arg(
        long = "withdrawal-max-batch-gas",
        env = "WITHDRAWAL_MAX_BATCH_GAS",
        default_value_t = DEFAULT_MAX_WITHDRAWAL_BATCH_GAS,
        value_parser = clap::builder::RangedU64ValueParser::<u64>::new()
            .range(1..=MAX_WITHDRAWAL_BATCH_GAS)
    )]
    pub withdrawal_max_batch_gas: u64,

    /// Maximum number of ordered processWithdrawals transactions kept in flight.
    #[arg(
        long = "withdrawal-max-in-flight-batches",
        env = "WITHDRAWAL_MAX_IN_FLIGHT_BATCHES",
        default_value_t = DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..)
    )]
    pub withdrawal_max_in_flight_batches: usize,

    /// Maximum number of concurrent L1 receipt fetches.
    #[arg(
        long = "l1.fetch-concurrency",
        env = "L1_FETCH_CONCURRENCY",
        default_value_t = 4
    )]
    pub l1_fetch_concurrency: usize,

    /// Interval in milliseconds between WebSocket reconnection attempts to L1.
    #[arg(
        long = "l1.retry-connection-interval",
        env = "L1_RETRY_CONNECTION_INTERVAL_MS",
        default_value_t = 100
    )]
    pub l1_retry_connection_interval_ms: u64,

    /// Port for the redacted sphere RPC server (0 for OS-assigned).
    #[arg(
        long = "redacted-rpc.port",
        alias = "private-rpc.port",
        env = "REDACTED_RPC_PORT",
        default_value_t = 8544
    )]
    pub redacted_rpc_port: u16,

    /// Maximum auth token validity window the redacted RPC accepts, in seconds.
    #[arg(
        long = "redacted-rpc.max-auth-token-validity-secs",
        env = "REDACTED_RPC_MAX_AUTH_TOKEN_VALIDITY_SECS",
        default_value_t = DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS
    )]
    pub redacted_rpc_max_auth_token_validity_secs: u64,

    #[arg(long = "sequencer", env = "SEQUENCER")]
    pub enable_sequencer: bool,

    /// Checker ExEx mode: `off` (default) or `observe`.
    #[arg(
        long = "checker.mode",
        env = "CHECKER_MODE",
        default_value = "off",
        value_parser = sphere_checker::CheckerMode::parse,
    )]
    pub checker_mode: sphere_checker::CheckerMode,
}

fn parse_l1_rpc_url(l1_rpc_url: &str) -> Result<String, String> {
    let url: url::Url = l1_rpc_url
        .parse()
        .map_err(|err| format!("failed parsing --l1.rpc-url as URL: {err}"))?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(format!(
            "--l1.rpc-url must use ws:// or wss://, got `{}`",
            url.scheme()
        ));
    }
    Ok(l1_rpc_url.to_owned())
}

fn parse_portal_address(value: &str) -> Result<Address, String> {
    let address = value
        .parse::<Address>()
        .map_err(|err| format!("invalid --l1.portal-address: {err}"))?;
    if address.is_zero() {
        return Err("--l1.portal-address must be nonzero".to_owned());
    }
    Ok(address)
}

pub async fn load_sequencer_signer(
    key_file: Option<&std::path::Path>,
) -> eyre::Result<PrivateKeySigner> {
    let path = key_file.ok_or_else(|| {
        eyre::eyre!("--sequencer-key-file is required when sequencing is enabled")
    })?;
    let path = path.to_path_buf();
    let source = format!("--sequencer-key-file {}", path.display());
    let display_path = path.display().to_string();
    let key = tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
        .await
        .map_err(|err| eyre::eyre!("sequencer key reader task failed for {display_path}: {err}"))?
        .map_err(|err| eyre::eyre!("failed to read sequencer key from {display_path}: {err}"))?;
    let key = Zeroizing::new(key);

    key.trim()
        .parse::<PrivateKeySigner>()
        .map_err(|_| eyre::eyre!("invalid sequencer key from {source}"))
}

pub async fn load_decryption_keys(
    key_file: Option<&std::path::Path>,
) -> eyre::Result<Vec<k256::SecretKey>> {
    let Some(path) = key_file else {
        return Ok(Vec::new());
    };
    let path = path.to_path_buf();
    let display_path = path.display().to_string();
    let contents = tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
        .await
        .map_err(|err| eyre::eyre!("decryption key reader task failed for {display_path}: {err}"))?
        .map_err(|err| eyre::eyre!("failed to read decryption keys from {display_path}: {err}"))?;
    let contents = Zeroizing::new(contents);
    let mut keys = Vec::new();
    for (line_index, value) in contents.lines().enumerate() {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let signer = value.parse::<PrivateKeySigner>().map_err(|_| {
            eyre::eyre!(
                "invalid decryption key on line {} of {display_path}",
                line_index + 1
            )
        })?;
        keys.push(k256::SecretKey::from(signer.credential()));
    }
    eyre::ensure!(
        !keys.is_empty(),
        "decryption key file {display_path} contains no keys"
    );
    Ok(keys)
}
