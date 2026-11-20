# sphere-checker

An observe-only bridge-accounting checker that runs as a Reth execution
extension (ExEx) inside an Arc Sphere node. It independently derives token
balances and bridge liabilities from authenticated protocol activity, then
compares them with exact Sphere and Arc state.

## What it verifies

For every canonical Sphere block, the checker independently derives:

- token entitlements for every account named by authenticated transfer and
  bridge events.
- Each enabled token's expected Sphere supply from those entitlements.
- Portal liabilities for circulating supply, pending deposits, pending
  withdrawals, and pending refunds.
- The recipient and amount of every Inbox mint from its authenticated bridge
  lifecycle event.
- Every user withdrawal's exact token debit and burn, including sponsored
  fees.

Canonical Portal creation and enablement events establish which tokens the
checker tracks. Membership in the accounting token map is the authenticated
enablement record; other accounting effects cannot introduce tokens.

Beyond establishing membership, token enablement is not otherwise modeled: the
checker does not compare L1 and L2 enablement calldata or validate token metadata
and Inbox/Outbox issuer roles.

The accounting model also does not correlate individual L1 deposits with L2
outcomes by deposit hash or authenticate cross-layer withdrawal batch identity.
Those protocol events are still strictly decoded, but only value movements that
affect the aggregate solvency model are retained. Genesis bridge cursors are
checked only to establish the empty bootstrap baseline.

It then reads affected balances and every enabled token's supply from the exact
Sphere post-state and reads Portal custody at the exact imported Arc block. The
required invariants are:

```text
Sphere balance(account, token) == derived entitlement(account, token)
Sphere totalSupply(token)      == sum of derived entitlements(token)
Portal custody(token)        >= supply + deposits + withdrawals + refunds
```

The checker reads all enabled-token supplies every block and reads balances for
accounts touched by that block. Its durable entitlement ledger carries earlier
accounts forward and verifies their aggregate against total supply. It does not
scan arbitrary Sphere storage changes or reread every historical account balance
on every block.

Arc consensus and execution are trust boundaries. For live blocks, the checker
reuses Portal logs whose receipts and headers the node's L1 subscriber already
authenticated. It independently decodes those logs and verifies the exact block
and parent coordinates. Bootstrap and old recovery ranges fall back to fetching
and authenticating the same evidence from the configured archival Arc RPC. It
does not re-execute Arc. Sphere post-state is read through Reth's exact-block
storage provider.

Checkpoint-only blocks must contain only `advanceArcHeaders` and its successful
`ArcBlockFinalized` event. They advance the verified Sphere height and verify
unchanged token supply, while retaining the last full import's accounting state
and Arc custody anchor. The next full import authenticates every Arc block
since that anchor and applies their Portal events in order before its Sphere
events. This includes deposits and token enablements deferred across any number
of checkpoint-only blocks. The retained accounting anchor survives restarts;
`imported_arc_height` reports that anchor rather than header-only progress.

## Startup and recovery

With `--checker.mode observe`, startup is self-contained:

1. Read the Sphere ID, Portal, chain ID, and node data directory from the normal
   node configuration.
2. Read the Arc anchor, bridge cursors, initial token, and supply from exact
   local Sphere genesis state, rejecting a genesis with prior bridge progress.
3. Discover the unique matching `SphereCreated` through Arc's log index, then
   authenticate its canonical block, receipts, Sphere identity, Portal, and
   initial token.
4. Require the genesis anchor to precede Portal creation and initialize empty
   accounting. Normal Sphere replay then derives token membership when it reaches
   the creation block.
5. Create `<node datadir>/checker` atomically if it is missing, or validate and
   open it if it exists.
6. Ask Reth to replay canonical Sphere history after the durable verified tip.

The database is created in `<node datadir>/checker`; no separate checkpoint
command is required. An existing database is opened only when its Sphere, Arc,
Portal, and creation identity matches the authenticated bootstrap result.

MDBX stores current nonzero account rows, per-token accounting, metadata, and
the active finding. Storage therefore scales with the current number of nonzero
derived entitlements rather than Sphere history. Spheres are append-only; if the
saved checker tip is absent from local Sphere history or Reth reports an
unexpected revert, the checker atomically resets to authenticated genesis and
replays local history.

On normal restart, Reth replays notifications after the last durably verified
Sphere block. Each block transition is persisted before the ExEx acknowledges its
height.

## Failure behavior

Temporary Arc RPC or local-state acquisition failures retry without advancing
or acknowledging the block. Each retry budget is bounded. Arc retries use
exponential backoff, while unavailable local Sphere state retries once per second.
Pruned state disables immediately because it cannot recover.

Arc RPC codes `-32001` (resource not found), `-32002` (resource unavailable),
and `-32603` (internal error) are retried regardless of message text.

A deterministic mismatch records one durable finding, freezes the verified tip,
and continues acknowledging subsequent notifications while recording how far the
unchecked range extends. A finding remains active until the checker is rebuilt
from authenticated genesis.

An exhausted retry budget or an unrecoverable checker-local error disables the
checker and drains ExEx notifications so it cannot terminate or stall Sphere
execution. Verification then stays disabled for the life of the process; since
the checker runs as an ExEx inside the node, restarting the node attempts to
resume from the last durably verified Sphere block. Observe mode never changes
block execution or consensus behavior; operators must alert on lag or an active
divergence.

The node's existing metrics endpoint exports:

- `reth_arc_sphere_checker_verified_sphere_height`
- `reth_arc_sphere_checker_imported_arc_height`
- `reth_arc_sphere_checker_observed_sphere_height`
- `reth_arc_sphere_checker_verification_lag_blocks`
- `reth_arc_sphere_checker_divergence_active`
- `reth_arc_sphere_checker_disabled`
- `reth_arc_sphere_checker_acquisition_retries_total`
- `reth_arc_sphere_checker_verified_sphere_blocks_total`
- `reth_arc_sphere_checker_recovery_rebuilds_total`

At minimum, alert when `disabled` or `divergence_active` is `1`, verification
lag continues to grow, or the verified height stops advancing while the Sphere
head advances.

### Verified activity logs

After a Sphere block is durably verified, the checker emits structured
`sphere::checker` INFO logs for authenticated bridge activity. Zero-value Portal
refund claims are accounting no-ops and are omitted. Within that block,
`authenticated` denotes canonical protocol evidence, `accounted` denotes a
ghost-liability change, and `verified` denotes additional reconciliation
against token movements and exact post-block state.

Activity logs contain only the fields needed by log-backed activity dashboards:

- `activity_event`: the stable event name from the table below.
- `activity_id`: `v<schema_version>:<sphere_hash>:<activity_source>:<activity_index>`,
  which remains stable if recovery replays the same canonical block under the
  same schema. The ID retains version `1`, the verified Sphere block hash, source
  (`arc` or `sphere`), and zero-based canonical index within that source.
- `callback_success`: emitted only for `portal_withdrawal_processed`, allowing
  dashboards to distinguish successful and failed withdrawal callbacks.

The ID components are not repeated as separate fields. Activity logs omit
descriptive messages, block heights, Arc hashes, token and account addresses,
amounts, fees, and deposit/withdrawal numbers. Kubernetes pod and namespace
metadata supplied by the log collector still identify the verifier and Sphere.
Operational warnings and errors retain their diagnostic fields.

| `activity_event` | Meaning |
| --- | --- |
| `portal_deposit_accounted` | Authenticated Portal deposit entered accounting. |
| `portal_token_enabled` | Authenticated Portal token entered accounting coverage. |
| `portal_withdrawal_processed` | Authenticated Portal withdrawal and callback result. |
| `portal_withdrawal_bounce_back` | Authenticated Portal withdrawal bounce-back entered accounting. |
| `portal_deposit_bounce_back` | Authenticated processed Portal deposit bounce-back entered accounting. |
| `portal_deposit_bounce_back_pending` | Authenticated pending Portal deposit bounce-back entered accounting. |
| `portal_refund_accounted` | Authenticated Portal refund entered accounting. |
| `sphere_deposit_minted` | Verified Sphere deposit mint. |
| `sphere_deposit_failed` | Authenticated failed Sphere deposit. |
| `sphere_deposit_bounce_back_requested` | Authenticated Sphere deposit bounce-back request. |
| `sphere_withdrawal_burned` | Verified user withdrawal debit and burn. |
| `sphere_withdrawal_bounce_back_minted` | Verified Sphere withdrawal bounce-back mint. |
| `sphere_withdrawal_bounce_back_pending` | Authenticated pending Sphere withdrawal bounce-back. |
| `sphere_refund_minted` | Verified Sphere refund mint. |

`activity_id` lets a log consumer deduplicate replayed activities, but logs are
still retention-bound diagnostic evidence rather than the canonical accounting
ledger.

## Modes

| Mode | Behavior |
| --- | --- |
| `off` | Default. The checker is not installed. |
| `observe` | Verify, persist findings, expose metrics, and leave Sphere execution unchanged. |

Use `--checker.mode observe` or `CHECKER_MODE=observe`. The checker reuses the
node's authenticated L1 observations, Arc RPC URL, Portal address, Sphere ID,
chain specification, and data directory. No checker-specific anchor, Portal, or
database argument is needed.

## Source organization

```text
src/
  bootstrap.rs       genesis identity and authenticated Portal discovery
  l1/                shared/fallback Arc evidence and Portal event decoding
  l2/                Sphere events and exact post-state reads
  accounting/        pure account and liability transitions
  persistence/       row-oriented MDBX state and exact verified coordinates
  runtime.rs         recovery, verification, retry, and divergence handling
  telemetry.rs       operational metrics and verified-activity logs
```

## Validation

```bash
cargo test -p sphere-checker
cargo clippy -p sphere-checker --all-targets -- -D warnings
```
