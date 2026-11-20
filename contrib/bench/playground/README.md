# Spheres payment playground

Open [the local wallet](http://127.0.0.1:15151/). Select the account to spend from, choose a payment, deposit or withdrawal, enter the recipient and amount in USDC, and submit. The page reads balances from the local chains and displays the resulting transaction receipt.

The local server signs with two funded development accounts. The app uses Arc at `127.0.0.1:18549`, the Sphere operator at `127.0.0.1:18545` and the authenticated Sphere RPC at `127.0.0.1:18544`.

## Start locally

From this directory, with the local chains running, set `SPHERES_BENCH_MNEMONIC_FILE` to the operator's local development mnemonic file and `L1_PORTAL_ADDRESS` to the address of the local Sphere portal. Build the transaction generator and start the API:

```sh
cargo build --locked --manifest-path ../txgen-sphere/Cargo.toml
python3 server.py
```

In a second terminal in this directory:

```sh
pnpm install --frozen-lockfile
pnpm dev
```

The UI draws on Tempo’s [fee-payer playground](https://github.com/tempoxyz/tempo-apps/tree/0d890dc7f9a5df62d6dce526b63d6c47d452f04f/apps/fee-payer/playground) and [Explorer components](https://github.com/tempoxyz/tempo-apps/tree/0d890dc7f9a5df62d6dce526b63d6c47d452f04f/apps/explorer/src/comps). The local API connects the forms to Arc USDC, the Sphere private RPC and the bridge scenarios.
