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
- `min_mix_blocks > 0` (user opt-in): received blind outputs younger than N
  blocks MUST NOT be selected as spend inputs. Consensus does not enforce
  this; the wallet does.

## 5. Change and amounts

- Blinded change is the default (new transfers create blinded change, not
  transparent change).
- Amount privacy only: asset types stay visible on blind transfers (supply
  auditability is load-bearing). The UI MUST NOT promise asset hiding,
  whole-journey unlinkability, or protection at mandatory-transparent
  endpoints (DEX trade, exchange deposit) — it sells peer-to-peer leg
  privacy (BSIP-2 §2, honest scope note).

## 6. Non-goals (rejected with prejudice, BSIP-2 §3)

No mandatory blindness for any operation class; no blind order books, margin
positions, pool shares, or vault/oracle/issuance accounting; no blind asset
types or supply totals; no custodial tumbling presented as a substitute.
