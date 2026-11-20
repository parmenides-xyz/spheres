# Spheres

Spheres are privacy-preserving blockchains that settle to [Arc](https://www.arc.io/), with native support for confidential balances and transactions.

## Why Spheres?
Spheres have 2 goals:

1. **Private balances and transactions.** Reads and writes to the Sphere's EL require authentication at the RPC layer. Such a design also enables encrypted deposits + withdrawals.
2. **Scaling + performance.** Like rollups on Ethereum, Spheres scale Arc.

## Getting Started

### Sphere Local Development

Build the node and deposit CLI with Rust 1.95 or later.

```bash
git clone https://github.com/parmenides-xyz/spheres.git
cd spheres
cargo install --locked --path bin/arc-sphere
cargo install --locked --path xtask
```

```bash
arc-sphere --chain assets/localdev/sphere-genesis.json --dev --http
```

The local RPC listens on `http://localhost:8545`. The examples below use an Arc-connected Sphere and Foundry’s `cast`.

### Depositing into a Sphere

Set your Arc RPC URL, portal address, and funded wallet key. The deposit command encrypts the recipient and memo with the portal’s active key.

```bash
export L1_RPC_URL='<arc-rpc-url>'
export L1_PORTAL_ADDRESS='<portal-address>'
export PRIVATE_KEY='<wallet-private-key>'

./scripts/sphere max-approve-portal
arc-xtask deposit --amount 1000000                   # 1 USDC to yourself
arc-xtask deposit --amount 1000000 --to '<address>'  # 1 USDC to another wallet
```

### Withdrawing from a Sphere to Arc

```bash
export SPHERE_RPC_URL='<sphere-operator-rpc-url>'

./scripts/sphere max-approve-outbox
./scripts/sphere withdraw 1000000 '<arc-recipient-address>'
```

The sequencer includes the withdrawal in a batch and pays the recipient on Arc.

### Querying the Redacted RPC

Use the same Sphere operator URL and wallet key. The balance command signs a ten-minute token and reads your USDC balance in base units.

```bash
export REDACTED_RPC_URL='<sphere-redacted-rpc-url>'
./scripts/sphere balance
```
