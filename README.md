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

The standalone node serves HTTP at `http://localhost:8545`. The bridge and redacted RPC examples below require an Arc-connected Sphere and Foundry's `cast`.

### Depositing into a Sphere

Use a funded Arc wallet and the Sphere's portal address. The deposit CLI fetches the portal's active encryption key and encrypts the recipient and memo. Amounts are in USDC base units (`1000000` = 1 USDC).

```bash
export L1_RPC_URL='<arc-rpc-url>'
export L1_PORTAL_ADDRESS='<sphere-portal-address>'
export PRIVATE_KEY='<wallet-private-key>'
USDC=0x3600000000000000000000000000000000000000

cast send "$USDC" 'approve(address,uint256)' "$L1_PORTAL_ADDRESS" "$(cast max-uint)" \
  --rpc-url "$L1_RPC_URL" --private-key "$PRIVATE_KEY"

arc-xtask deposit --amount 1000000                       # to your own address
arc-xtask deposit --amount 1000000 --to '<recipient>'    # to another Sphere address
```

### Withdrawing from a Sphere to Arc

From the node host, use the Sphere's operator RPC to approve the outbox and request a withdrawal. Keep enough USDC on the Sphere to cover the amount and fees.

```bash
SPHERE_RPC_URL='<sphere-operator-rpc-url>'
OUTBOX=0x1c00000000000000000000000000000000000002
WALLET=$(cast wallet address --private-key "$PRIVATE_KEY")
RECIPIENT='<arc-recipient-address>'

cast send "$USDC" 'approve(address,uint256)' "$OUTBOX" "$(cast max-uint)" \
  --rpc-url "$SPHERE_RPC_URL" --private-key "$PRIVATE_KEY"
cast send "$OUTBOX" 'requestWithdrawal(address,address,uint128,bytes32,uint64,address,bytes,bytes)' \
  "$USDC" "$RECIPIENT" 1000000 "$(cast to-bytes32 0)" 0 "$WALLET" 0x 0x \
  --rpc-url "$SPHERE_RPC_URL" --private-key "$PRIVATE_KEY"
```

The sequencer batches the withdrawal and processes the payout on Arc.

### Querying the Redacted RPC

Sign a ten-minute authorization token with the wallet whose balance you want to read. The token includes the Sphere ID and its chain ID.

```bash
REDACTED_RPC_URL='<sphere-redacted-rpc-url>'
CHAIN_ID=$(cast chain-id --rpc-url "$SPHERE_RPC_URL")
SPHERE_ID=$((CHAIN_ID & 0xffffffff))
NOW=$(date +%s)
FIELDS=$(cast abi-encode --packed 'f(uint8,uint32,uint64,uint64,uint64)' \
  0 "$SPHERE_ID" "$CHAIN_ID" "$NOW" "$((NOW + 600))")
DOMAIN=$(cast format-bytes32-string ArcSphereRPC)
DIGEST=$(cast keccak "${DOMAIN}${FIELDS#0x}")
SIG=$(cast wallet sign --no-hash --private-key "$PRIVATE_KEY" "$DIGEST")
TOKEN="${SIG}${FIELDS#0x}"

cast call "$USDC" 'balanceOf(address)(uint256)' "$WALLET" --from "$WALLET" \
  --rpc-url "$REDACTED_RPC_URL" --rpc-headers "X-Authorization-Token: $TOKEN"
```
