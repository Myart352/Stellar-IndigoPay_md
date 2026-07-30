# Threat Model — Stellar-IndigoPay

## Scope

This document describes the threat model for the Stellar-IndigoPay platform, focusing on the Soroban smart contracts (`indigopay-contract`, `escrow-contract`, `oracle-contract`, `attestation-contract`) and the supporting Node.js backend. Frontend and wallet extensions are considered trusted execution environments.

## Assets

| Asset | Description | Confidentiality | Integrity | Availability |
|-------|-------------|---------------|-----------|-------------|
| Donation records | On-chain donation history (donor, project, amount, CO₂) | Low (public) | Critical | Low (immutable) |
| Project registry | Registered climate projects with wallet addresses | Low (public) | Critical | Medium |
| Admin keys | M-of-N admin signatures for critical operations | Critical | Critical | Medium |
| Platform fees | Accumulated fees in treasury wallet | Medium | High | Medium |
| Donor wallets | Stellar wallet addresses | Low (public) | High | N/A |
| Off-chain database | User profiles, leaderboard cache, project metadata | Medium | Medium | Medium |
| Oracle price feed | USDC→XLM conversion rate | Low (public) | Critical | Medium |

## Threat Actors

| Actor | Capabilities | Motivation |
|-------|-------------|------------|
| External attacker | Network access, no secrets | Financial gain, disruption |
| Compromised admin | Single admin key | Fund theft, contract sabotage |
| Rogue project wallet | Registered project's signing key | Inflate stats, steal donations |
| Malicious donor | Stellar wallet with XLM | Sybil attacks, gaming badges |
| Frontend MITM | Network position | Phishing, tx manipulation |

## Threat Scenarios

### T1 — Admin key compromise

**Threat**: An attacker gains access to one admin key. If M-of-N threshold is 1 (default compatible mode), they can upgrade the contract, transfer admin, pause/unpause, deactivate projects, or drain fees.

**Mitigations**:
- M-of-N threshold system (`require_admin_for_critical`) requires multiple signatures for destructive operations
- 48-hour upgrade timelock gives community reaction window
- Contract pause can be lifted even after admin set change (pause-gate exempt for admin recovery)
- Deduplication in `verify_m_of_n` prevents single key from being counted multiple times

**Residual risk**: If M keys out of N are compromised simultaneously, all admin protections are bypassed.

### T2 — Malicious contract upgrade

**Threat**: Admin (or attacker controlling admin keys) proposes a WASM hash that exfiltrates funds, mints fake records, or disables security checks.

**Mitigations**:
- 48-hour timelock (`UPGRADE_TIMELOCK_LEDGERS = 34,560`)
- `execute_upgrade` is permissionless — anyone can observe the pending hash and exit
- `LastExecutedUpgrade` stored on-chain for audit verification
- Indexers can monitor `upg_prop` events and alert community

**Residual risk**: Compromised M-of-N admins can wait for the timelock and execute a malicious upgrade.

### T3 — Integer overflow in counters

**Threat**: Accumulated donation amounts, CO₂ offsets, or donor counts overflow their integer types, corrupting state.

**Mitigations**:
- All arithmetic uses `checked_add` / `checked_sub` with `expect` panic messages
- `MAX_CO2_PER_XLM = 100,000` bounds per-donation CO₂ multiplication
- `i128` types provide 2^127 max (9.22e18 stroops — far beyond realistic volume)
- CO₂ pre-computation before accumulation

### T4 — Donation replay / double-counting

**Threat**: An attacker submits the same Stellar payment twice, inflating project stats.

**Mitigations**:
- Soroban uses sequence-number guard per address — the same transaction cannot execute twice
- `HasDonated(project, donor)` key tracked for unique donor count
- Rate limit per (donor, project, token) window prevents rapid-fire

### T5 — Rate limit bypass

**Threat**: Donor exceeds configured donation limits by switching tokens, projects, or using multiple addresses.

**Mitigations**:
- Rate limit keyed by `(donor, project_id, token_address)` — trivially bypassed by switching tokens or projects
- Anonymous donation count tracked separately
- **Known limitation**: rate limit is per-donor, not per-IP or per-human; a determined attacker with multiple wallets can bypass

### T6 — Stealth donation privacy failure

**Threat**: An attacker links a stealth address to its recipient project wallet.

**Mitigations**:
- Stealth address = SHA256(project_wallet_xdr || ephemeral_pubkey)
- Ephemeral pubkey is unique per donation
- No on-chain mapping from stealth address to project wallet
- `scan_stealth_donations` requires `project_wallet.require_auth()` — only the wallet holder can enumerate their donations

**Residual risk**: If ephemeral keys are reused or generated predictably, linkage is possible. Stealth address generation is deterministic and client-side.

### T7 — Off-chain database compromise

**Threat**: Backend database is breached, modifying leaderboard or project metadata.

**Mitigations**:
- Soroban contract is the source of truth — backend is a cache
- Project registration requires on-chain admin call
- Leaderboard rebuildable from contract events (`rebuildAllProjections`)
- Backend does not hold keys or process payments
- Donations function without backend

### T8 — Project wallet spoofing

**Threat**: Attacker registers a project with a wallet they control, collecting donations meant for a legitimate project.

**Mitigations**:
- Project registration requires `require_admin_for_routine` — only authorized admins
- `require_not_paused` gate prevents registration during incident
- Project verification feature (`project_verification`) adds multi-verifier attestation gate
- Donations to unverified projects are rejected when threshold > 0
- CO₂ rate verification against independent data sources

### T9 — Campaign goal manipulation

**Threat**: Project wallet or admin manipulates campaign parameters to create false scarcity or urgency.

**Mitigations**:
- Campaign lifecycle is a state machine: `None → Active → GoalReached | Expired | Closed`
- `deadline_ledger` is immutable once set; admin can only extend (not shorten)
- `GoalReached` auto-flips when `total_raised >= goal`
- Donations to `GoalReached`/`Expired`/`Closed` campaigns are rejected

### T10 — Refund abuse

**Threat**: Donor requests refund after badge/NFT minting, or admins collude to force-refund legitimate donations.

**Mitigations**:
- Normal refund requires both admin AND project wallet authorization
- Badges and NFTs are permanent — never downgraded on refund
- Force-refund has 72-hour timelock with single-admin cancellation
- Force-refund only draws from contract-held pool, not project wallet
- Donation CO₂ offset snapshotted at donation time for exact reversal

### T11 — zk-SNARK double-spending

**Threat**: Attacker replays a ZK proof or uses a nullifier twice to record multiple anonymous donations from one proof.

**Mitigations**:
- Nullifier stored on-chain in `DataKey::Nullifier(BytesN<32>)`
- `donate_anonymous_zk` checks nullifier freshness before processing
- `is_zk_nullifier_used` query available for callers

### T12 — Swap front-running on governance

**Threat**: Attacker swaps their own vote weight via flash-loan-like badge acquisition before a vote resolves.

**Mitigations**:
- Vote weight is snapshotted at proposal creation time (delegated weight is static)
- Quadratic voting formula `credits = sqrt(weight)` limits influence of large donors
- `create_proposal` stores snapshot; weight changes during voting do not affect existing proposals

## Data Flow Trust Boundaries

```
[Donor Wallet] → Freighter (trusted signing)
    ↓ signed tx
[Stellar Network] → Soroban Contract (trusted execution)
    ↓ events
[Indexer Service] → PostgreSQL (read replicas)
    ↓
[Node.js Backend] → REST API (authenticated admin routes)
    ↓
[Next.js Frontend] → Browser (untrusted network)
```

| Boundary | Trust Level | Controls |
|----------|-------------|----------|
| Donor → Freighter | Full trust | Local signing, no key exposure |
| Freighter → Soroban | Low trust | Sequence numbers, auth replay protection |
| Soroban → Indexer | Low trust | Event verification against contract state |
| Backend → Frontend | Low trust | No sensitive state served; projections derivable from chain |
| Frontend → User | No trust | Read-only display; user verifies against chain |

## Storage TTL Management

The contract uses two storage types:

- **Instance storage**: entries live as long as the contract instance. `ensure_min_ttl()` extends instance TTL after every state-mutating call using `VOTING_WINDOW_LEDGERS * 4` as the minimum.
- **Persistent storage**: used only by the donation module for `StealthDonation(u64)` and `ProjectDonations(Address)`. TTL is extended on every read and write via the storage accessor layer (`extend_persistent_ttl`), using a threshold of 10,000 ledgers and extending to 50,000 ledgers.

Automated keepers can call `extend_all_ttl(threshold_ledgers)` to refresh instance TTL. Persistent key TTL is managed reactively — keys are only extended when accessed.

## Dependencies & Supply Chain

| Dependency | Risk | Mitigation |
|------------|------|------------|
| `soroban-sdk` | Stellar SDK vulnerability | Pinned to stable release; contract fuzzing |
| `soroban-auth` | Auth bypass | Tested via integration test suite |
| Node.js packages | Supply chain attack | `package-lock.json`, Dependabot alerts |
| PostgreSQL extensions | Data corruption | Regular backups, read replicas |
