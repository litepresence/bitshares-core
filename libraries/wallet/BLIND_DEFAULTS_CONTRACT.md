# Blind-Defaults UI Contract (BSIP-2 §2, G1c) — browser wallet binding spec

Status: normative for the browser wallet (separate repo). The in-tree
`cli_wallet` implements the same values (see `blind_transfer_defaults` in
`libraries/wallet/include/graphene/wallet/wallet.hpp`); this document is the
shared contract so both wallets behave identically.

## 1. Defaults (exact values)

| Setting | Value | Meaning |
|---|---|---|
| `blind_by_default` | `true` | New transfers route blind unless the user opts out |
| `decoy_fetch_batch_size` | `32` | Decoy/confirmation fetches per RPC round-trip |
| `min_broadcast_delay_sec` | `3` | Wait after signing before broadcasting a blind transfer |
| `min_mix_blocks` | `0` | Optional N-block holding before spending a blind receipt (off) |

Conformance: `get_blind_defaults` MUST return these values on a fresh
wallet. Changing them is allowed but MUST be an explicit user action,
surfaced in the UI as weakening privacy (delay/batching) or strengthening
it (mix hold).

## 2. Transparent opt-out (one tap, never silent)

- Every blind-defaulted send screen shows a visible transparent opt-out
  (label guidance: "Transparent (for exchanges / compliance)").
- Blind routing REQUIRES the recipient's blind key or label. A public
  account name, a non-empty memo, or an unresolvable recipient MUST fail
  closed with an actionable error — the wallet MUST NEVER silently fall back
  to transparent. Silent fallback is a privacy bug, not UX polish.
- Exchange-deposit flows MUST pre-select the opt-out (deposits are
  transparent by necessity: asset types stay visible, market paths stay
  transparent, BSIP-2 §3).

## 3. Decoy-fetch batching (RPC hygiene, normative)

- NEVER fetch one decoy per round-trip. Collect the candidate set, then
  fetch in chunks of `decoy_fetch_batch_size` (one RPC call per chunk).
- NEVER interleave decoy fetches with spend construction in a timing-visible
  way: finish all fetches, then build the ring.
- Do not cache decoy sets across spends in a way that reuses the same
  members preferentially (reuse shrinks the effective set; the chain alarms
  on it per interval).

## 4. Minimum broadcast delay (normative)

- After signing a blind transfer, wait `min_broadcast_delay_sec` (default 3)
  before broadcasting. Rationale: propagation timing against few DPOS
  producers links broadcasts at zero crypto cost (BSIP-2 §1).
- The delay applies per broadcast, including retries (a retry is a new
  broadcast). Setting 0 is allowed only as an explicit advanced option with
  a warning.
- Enforcement point (Task 6): `wallet_api::maybe_delay_blind_broadcast`
  is the single choke point — all three blind-sending paths
  (`transfer_from_blind`, `blind_transfer_help`, `transfer_to_blind`) call
  it, and `transfer_default`'s blind branch routes through
  `transfer_to_blind`, so no blind path bypasses the delay and none delays
  twice. Hook-tested (`set_blind_sleep_hook`).
- `min_mix_blocks` (default 0, off) is ENFORCED by cli_wallet input
  selection (Task 6): a blind receipt may fund a spend only once
  `head_block - received_block >= min_mix_blocks`. Receipts recorded
  offline (or by older wallets) carry `received_block == 0` (unknown age)
  and are ineligible while any hold is configured — fail-closed. Consensus
  never enforces a hold (it cannot see wallet receipt age); the wallet is
  the only place it can live. The balance query (`get_blind_balances`)
  shows all receipts; only spend selection filters.

## 5. Ring sampler rule (normative for any wallet constructing op 104 rings)

Decoy selection is a privacy decision, not an optimization problem. Wallets
constructing stealth rings MUST sample as follows (conformance-pinned
against consensus policy in `g1_stealth_tests`):

- Candidate set: UNSPENT blinded balances of the spent asset carrying
  post-fork creation metadata (chain-visible `get_blinded_balances` +
  `get_stealth_effective_set` for depth context). Spent-flagged outputs
  cannot exist post-fork (the flag is retired and never written —
  `stealth_evaluator.cpp:837-843`; `confidential_object.hpp:54-65`); do NOT
  filter on it. Exclude grandfathered (metadata-absent) outputs and outputs
  younger than 24h. Note nullified outputs stay decoy-eligible by design
  (section 9).
- Sample UNIFORMLY at random WITHOUT replacement from the candidate set.
  Never prefer recently-created outputs, never reuse a preferred subset
  across spends (reuse shrinks the effective set; the chain alarms on it
  per interval), never stuff the ring with attacker-favorable windows.
- Size: at least 16 (TARGET floor, thin or deep — consensus rejects smaller
  rings everywhere); at most 32. Default 16; larger rings cost more verifier
  time per input (budget ~100 ring-16 worst-case per block).
- Age spread: no 100-block creation window may contribute more than 40% of
  members (deep pool, depth ≥ 64) or 25% (thin pool). Resample on violation
  (bounded retries, then surface pool-thin guidance — never silently ship
  a skewed ring).
- In-tree note: cli_wallet does NOT construct op 104 rings (no stealth
  builder in-tree); this rule binds the browser wallet and any external
  signer. The conformance test implements this rule over a seeded pool and
  asserts consensus ACCEPT for compliant rings and REJECT for
  clustered/under-age/spent-member violations.

## 6. Timing-analysis residual + dandelion (future p2p work, NOT consensus)

The broadcast delay is hygiene, not a guarantee: an observer watching few
DPOS producers can still correlate first-seen propagation with block
inclusion, and no wallet behavior fixes that — it needs network-layer
diffusion (dandelion-style stem/fluff relay, currently NOT implemented;
see the `node_impl::broadcast` comment in `libraries/net/node.cpp`).
Disposition (R7 C-03): tracked as p2p future work with honest residual
documentation, never as a consensus gate (consensus must not depend on
relay timing). What the delay buys: it removes the cheapest link (sign →
instant broadcast); what it does not buy: unlinkability against a
network-wide observer. The UI MUST NOT promise the latter.

## 7. Change and amounts

- Blinded change is the default (new transfers create blinded change, not
  transparent change).
- Amount privacy only: asset types stay visible on blind transfers (supply
  auditability is load-bearing). The UI MUST NOT promise asset hiding,
  whole-journey unlinkability, or protection at mandatory-transparent
  endpoints (DEX trade, exchange deposit) — it sells peer-to-peer leg
  privacy (BSIP-2 §2, honest scope note).

## 8. Non-goals (rejected with prejudice, BSIP-2 §3)

No mandatory blindness for any operation class; no blind order books, margin
positions, pool shares, or vault/oracle/issuance accounting; no blind asset
types or supply totals; no custodial tumbling presented as a substitute.

## 9. Availability disclosure — ring spends and the nullifier set (F-08, normative)

Wallets MUST surface this section before the first blind receive (6th
MUSE-R12 item, BSIP-2 §4):

- **Nullifier migration IS consensus at the round-9 audited tip `06dcd808`**
  (op108 `stealth_explicit_spend_operation`, same STEALTH gate as ops 104–107;
  proof verified before the nullifier lookup; whole-ring spent flag retired).
  Ring membership alone no longer marks a decoy spent: only the real input's
  nullifier is recorded. Decoy outputs stay decoy-eligible for future rings
  (this is the intended griefing elimination, not a bug).
- ANY stealth output can still be rendered unspendable by its true owner
  (or anyone who knows an opening) via an explicit spend that nullifies it —
  that is one-time spend semantics, not ring-inclusion griefing. A stranger
  who does NOT know an opening cannot nullify your output by including it as
  a decoy (nullifiers require the representation proof, verified first).
- Under the retired spent-flag regime (pre-op108), one ring-16 spend burned
  16 decoy candidates (16→2). That burn is historical. At the current tip the
  live-set cost of a spend is the anonymity-set dilution of adding decoys,
  not permanent destruction of every ring member; pool-burn economics at
  pilot scale (≤$20k book) still mean early sets are thin until volume
  arrives: the wallet MUST warn below recommended minimums and MUST NOT
  promise set sizes the chain cannot see.
- **Scale escalation — read this before the book leaves pilot size.** Thin
  anonymity sets at pilot size are a nuisance; at $5M+ book a thin set is a
  cheap denial-of-service against honest privacy. Wallets MUST NOT present
  the ≤$20k pilot economics as a general property of this protocol, and MUST
  NOT describe longer disclosure as a remedy. Activation of op108/Rule R
  remains gated on the named CLSAG/BP+ specialist audit covering those ops
  and on the activation checklist (round-9: still NO_GO).
