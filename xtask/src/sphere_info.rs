use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use eyre::eyre;
use alloy_network::Ethereum;
use sphere_contracts::{SphereFactory, SpherePortal};

use crate::admin::{PortalSnapshot, read_portal_snapshot};

#[derive(Debug, clap::Parser)]
pub(crate) struct SphereInfoCmd {
    /// Sphere ID (integer) or portal address (0x...) to look up.
    identifier: String,

    /// Arc L1 HTTP RPC URL.
    #[arg(long, default_value = "https://rpc.testnet.arc.network")]
    l1_rpc_url: String,

    /// SphereFactory contract address on Arc L1.
    #[arg(long, env = "SPHERE_FACTORY")]
    sphere_factory: Address,
}

impl SphereInfoCmd {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new_with_network::<Ethereum>()
            .connect(&self.l1_rpc_url)
            .await?;

        let factory = SphereFactory::new(self.sphere_factory, &provider);

        let sphere_id = if self.identifier.starts_with("0x") {
            // Look up by portal address — scan all spheres
            let portal: Address = self.identifier.parse()?;
            let next_sphere_id = factory.nextSphereId().call().await?;

            let mut found = None;
            for id in 1..next_sphere_id {
                let info = factory.spheres(id).call().await?;
                if info.portal == portal {
                    found = Some(id);
                    break;
                }
            }
            found.ok_or_else(|| eyre!("no sphere found with portal address {portal}"))?
        } else {
            self.identifier
                .parse::<u32>()
                .map_err(|_| eyre!("expected a sphere ID (integer) or portal address (0x...)"))?
        };

        let info = factory.spheres(sphere_id).call().await?;
        if info.portal.is_zero() {
            return Err(eyre!("sphere {sphere_id} does not exist"));
        }
        println!("Sphere {}", info.sphereId);
        println!("  Portal:                {}", info.portal);
        println!("  Admin:                 {}", info.admin);
        println!("  Sequencers:            {:?}", info.sequencers);
        println!("  Threshold:             {}", info.threshold);
        println!("  Verifier:              {}", info.verifier);
        println!("  RPC URL:               {}", info.rpcUrl);

        // Reuse the same pinned finalized snapshot as `admin check` so related reads cannot mix
        // state from different blocks.
        let snapshot: PortalSnapshot =
            read_portal_snapshot(&provider, self.sphere_factory, sphere_id, Some(info.portal)).await?;

        let messenger = SpherePortal::new(info.portal, &provider)
            .messenger()
            .block(snapshot.finalized_block_number.into())
            .call()
            .await?;
        println!("  Messenger:             {messenger}");

        println!("\nPortal State");
        println!(
            "  Finalized L1 Block:    {}",
            snapshot.finalized_block_number
        );
        println!("  Active Sequencers:     {:?}", snapshot.sequencers);
        println!(
            "  Sequencer Set Version: {}",
            snapshot.sequencer_set_version
        );
        if snapshot.leader.is_zero() {
            println!("  Leader:                (uninitialized)");
        } else {
            println!("  Leader:                {}", snapshot.leader);
            println!("  Leader Epoch:          {}", snapshot.leader_epoch);
            println!(
                "  Leader Activation:     Arc block {}",
                snapshot.leader_activation_arc_block
            );
        }
        println!("  Sphere Gas Rate:         {}", snapshot.sphere_gas_rate);
        println!("  Paused:                {}", snapshot.paused);
        println!("  Pause expiry:          {}", snapshot.pause_expiry);
        println!(
            "  Pause abdication at:   {}",
            snapshot.pause_abdication_effective_at
        );
        println!(
            "  Access abdication at:  {}",
            snapshot.access_abdication_effective_at
        );
        println!(
            "  Withdrawal Batch:      {}",
            snapshot.withdrawal_batch_index
        );
        println!("  Block Hash:            {}", snapshot.block_hash);
        println!(
            "  Deposit Queue Hash:    {}",
            snapshot.current_deposit_queue_hash
        );
        println!(
            "  Last Synced Block:     {}",
            snapshot.last_synced_arc_block
        );

        // Encryption key
        match snapshot.encryption_key {
            Some(key) => {
                println!("\nEncryption Key");
                println!("  X:                     {}", key.x);
                println!("  Y Parity:              0x{:02x}", key.y_parity);
            }
            None => println!("\nEncryption Key:          (not set)"),
        }

        // Enabled tokens
        println!("\nEnabled Tokens ({})", snapshot.enabled_tokens.len());
        for (i, token) in snapshot.enabled_tokens.iter().enumerate() {
            println!("  [{i}] {token}");
        }

        Ok(())
    }
}
