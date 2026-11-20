//! Sends a deposit to the SpherePortal on Arc L1.
//!
//! Encrypts `(to, memo)` using the sequencer's ECIES public key so the
//! recipient and memo are hidden from on-chain observers.

use alloy_network::Ethereum;
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::SolEvent;
use arc_precompiles::helpers::NATIVE_FIAT_TOKEN_ADDRESS;
use eyre::{WrapErr as _, eyre};
use sphere_contracts::{DepositPayload, ISphereInbox, SpherePortal};
use sphere_precompiles::ecies::encrypt_deposit;

use crate::sphere_utils::parse_private_key;

#[derive(Debug, clap::Parser)]
pub(crate) struct Deposit {
    /// Arc L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// SpherePortal contract address on Arc L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Private key (hex) for signing the deposit transaction.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// USDC token address to deposit.
    #[arg(long, default_value_t = NATIVE_FIAT_TOKEN_ADDRESS)]
    token: Address,

    /// Amount to deposit.
    #[arg(long)]
    amount: u128,

    /// Recipient address on the sphere (encrypted on-chain).
    #[arg(long)]
    to: Option<Address>,

    /// Memo bytes32 (encrypted on-chain).
    #[arg(long, default_value_t = B256::ZERO)]
    memo: B256,

    /// Sphere L2 RPC URL. If set, waits for the deposit to be processed on L2.
    #[arg(long, env = "SPHERE_RPC_URL")]
    sphere_rpc_url: Option<String>,
}

impl Deposit {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let signer = parse_private_key(&self.private_key)?;
        let sender = signer.address();
        let to = self.to.unwrap_or(sender);
        let provider = ProviderBuilder::new_with_network::<Ethereum>()
            .wallet(signer)
            .connect(&self.l1_rpc_url)
            .await?;

        // Capture L2 block before sending so we don't miss the event
        let l2_from_block = if let Some(ref sphere_rpc) = self.sphere_rpc_url {
            let l2 = ProviderBuilder::new().connect(sphere_rpc).await?;
            Some(l2.get_block_number().await?)
        } else {
            None
        };

        let portal = SpherePortal::new(self.portal, &provider);

        // Fetch sequencer encryption key
        println!("Fetching sequencer encryption key...");
        let (key, key_index) = portal
            .encryption_key()
            .await
            .wrap_err("failed to fetch encryption key — is one set?")?;

        let seq_pub_x = key.x;
        let seq_pub_y_parity = key.normalized_y_parity().ok_or_else(|| {
            eyre!(
                "unexpected yParity {:#x}, expected 0/1 or 0x02/0x03",
                key.yParity
            )
        })?;
        println!(
            "Encryption key index: {key_index}, x: {seq_pub_x}, parity: {seq_pub_y_parity:#x}"
        );

        // Encrypt (to, memo) to the sequencer's public key
        let enc = encrypt_deposit(
            &seq_pub_x,
            seq_pub_y_parity,
            to,
            self.memo,
            sender,
            self.portal,
            key_index,
        )
        .ok_or_else(|| eyre!("ECIES encryption failed — invalid sequencer public key?"))?;

        let payload = DepositPayload {
            ephemeralPubkeyX: enc.eph_pub_x,
            ephemeralPubkeyYParity: enc.eph_pub_y_parity,
            ciphertext: Bytes::from(enc.ciphertext),
            nonce: enc.nonce.into(),
            tag: enc.tag.into(),
        };

        println!("Sending deposit of {} to {to}...", self.amount);
        let receipt = portal
            .deposit(self.token, self.amount, key_index, payload, sender)
            .send()
            .await?
            .get_receipt()
            .await
            .wrap_err("failed to send deposit transaction")?;
        let tx_hash = receipt.transaction_hash;
        let block_number = receipt.block_number.unwrap_or_default();

        if !receipt.status() {
            return Err(eyre!("deposit reverted (tx: {tx_hash})"));
        }

        println!("Deposit sent! (block {block_number})");
        println!("Transaction: {tx_hash}");

        // Wait for L2 processing if sphere RPC is provided
        if let (Some(sphere_rpc), Some(from_block)) = (&self.sphere_rpc_url, l2_from_block) {
            let deposit = receipt
                .decoded_log::<SpherePortal::DepositMade>()
                .ok_or_else(|| eyre!("no DepositMade event"))?;
            self.wait_for_l2_processing(
                sphere_rpc,
                from_block,
                deposit.newCurrentDepositQueueHash,
                to,
            )
            .await?;
        }

        Ok(())
    }

    /// Poll the sphere L2 for the deposit terminal event.
    async fn wait_for_l2_processing(
        &self,
        sphere_rpc: &str,
        from_block: u64,
        deposit_hash: B256,
        to: Address,
    ) -> eyre::Result<()> {
        use sphere_contracts::SPHERE_INBOX_ADDRESS;

        println!("Waiting for deposit to be processed on L2...");
        let l2 = ProviderBuilder::new().connect(sphere_rpc).await?;

        let processed_filter = Filter::new()
            .address(SPHERE_INBOX_ADDRESS)
            .event_signature(ISphereInbox::DepositProcessed::SIGNATURE_HASH)
            .topic1(deposit_hash)
            .from_block(from_block);
        let failed_filter = Filter::new()
            .address(SPHERE_INBOX_ADDRESS)
            .event_signature(vec![
                ISphereInbox::DepositFailed::SIGNATURE_HASH,
                ISphereInbox::DepositRejected::SIGNATURE_HASH,
            ])
            .topic1(deposit_hash)
            .from_block(from_block);

        loop {
            let logs = l2.get_logs(&processed_filter).await?;
            for log in &logs {
                if let Ok(event) = ISphereInbox::DepositProcessed::decode_log(&log.inner)
                    && event.data.to == to
                    && event.data.token == self.token
                {
                    let block = log.block_number.unwrap_or(0);
                    println!("Deposit processed on L2! (block {block})");
                    println!("  Token:  {}", event.data.token);
                    println!("  Sender: {}", event.data.sender);
                    println!("  To:     {}", event.data.to);
                    println!("  Amount: {}", event.data.amount);
                    println!("  Memo:   {}", event.data.memo);
                    return Ok(());
                }
            }

            let logs = l2.get_logs(&failed_filter).await?;
            if let Some(log) = logs.first() {
                let block = log.block_number.unwrap_or(0);
                return Err(eyre!(
                    "deposit {deposit_hash} failed or was rejected on L2 at block {block}"
                ));
            }

            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
}
