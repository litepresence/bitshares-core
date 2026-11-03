/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#pragma once

#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

   /// Reserve floor proposal: post-mint/post-redeem reserve ratio must stay
   /// at or above 130% (BSIP-1 section 7b). The Terra prohibition in one
   /// constant: reflexive under-collateralized mint/burn can never clear
   /// consensus, however the price moves.
   constexpr uint32_t GRAPHENE_H2_ISSUE_RMIN_BPS = 13000;
   /// Surplus target proposal: reserve ratio above 200% prices FXR against
   /// real surplus (genesis secure_ratio proposal, BSIP-1 section 7b).
   /// Deposits that lift the surplus above this target mint FXR; deposits
   /// at or below it mint stable only.
   constexpr uint32_t GRAPHENE_H2_ISSUE_TARGET_BPS = 20000;
   /// Per-block door cap proposal: $2,000 in BTS base units at the pilot
   /// basis (1e6 raw BTS per USD cent, H2a-H2d pilot: 200000 cents). Mint
   /// deposits plus redeem payouts per pair per block must not exceed this.
   /// Load-bearing (R2 audit): without it oracle profit-from-corruption is
   /// unbounded. DEX legs are NOT capped (market + slippage) -- door-only.
   constexpr uint64_t GRAPHENE_H2_ISSUE_DOOR_CAP_BTS = 200000000000ULL;
    /// Conversion fee proposal: 30bps of every door conversion stays in the
    /// reserve (griefing a mint/redeem cycle costs the fee twice while
    /// coverage rises). Mint leg: the fee slice of the deposit backs the
    /// book but buys no stable -- the requested face must be covered by the
    /// net-of-fee deposit at the bonded price (floored), while the rmin gate
    /// counts the full deposit. Redeem leg: the payout is the floored
    /// conversion minus the floored fee slice, vested 24h; the slice is
    /// never subtracted from the reserve, so fee routing needs no account.
    /// Accrues to the reserve, never to an account: junior value off-chain
    /// via the surplus ratio, no consensus price feed for FXR.
    constexpr uint32_t GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS = 30;
   /// Redeem payout vesting proposal: 24h linear (BSIP-1 section 7b).
   /// Payouts vest through the EXISTING vesting_balance_create machinery
   /// (reused, never reinvented); unvested outputs are escrow, never
   /// capitalization -- no reserve/supply credit for them.
   constexpr uint32_t GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC = 86400;
   /// FXR genesis parity: the first FXR against a surplus mints 1:1 with
   /// face units (same precision enforced between pair and FXR assets).
   /// Afterwards FXR_price = reserve_surplus / FXR_supply, floored.
   constexpr uint64_t GRAPHENE_H2_ISSUE_FXR_GENESIS_PARITY = 1;
   /// LLAMMA soft-band count proposal (BSIP-1 section 4, ISSUANCE-2): the
   /// reserve's backing is partitioned across exactly 7 bands as accounting,
   /// never custody -- band totals always sum to the reserve totals. Band
   /// edges are exact integer fractions of the bonded anchor price (bps
   /// below); no floats anywhere. All band-shift rounding floors against
   /// the mover (dust stays in the source band), favoring the protocol.
   constexpr uint32_t GRAPHENE_H2_ISSUE_N_BANDS = 7;
   /// Band tick proposal: the minimum edge spacing is 250bps (9750->10000),
   /// so the half-tick hysteresis is exactly 125bps. Consumed-price moves at
   /// or inside half a tick never rebalance (no churn); moves beyond it shift
   /// at most one band step per conversion (bounded churn). Equality with the
   /// half-tick bound is NOT a move (the bound is inclusive headroom).
   constexpr uint32_t GRAPHENE_H2_ISSUE_BAND_TICK_BPS = 250;
   /// Batch-exit fee proposal: 2% of every batched exit payout stays in the
   /// reserve. Computed as ONE truncating multiply (net = floor(gross x 9800
   /// / 10000)), so the single rounding favors the protocol; no separate fee
   /// rounding exists to argue about.
   constexpr uint32_t GRAPHENE_H2_ISSUE_EXIT_FEE_BPS = 200;
   /// Offset-pool claim vesting proposal: 7 days (604800s), strictly longer
   /// than the 24h conversion vesting. Compounding through the pool is
   /// uneconomic by construction (7-day lock plus door conversion fees plus
   /// exit haircuts on re-entry), never by provenance tracking.
   constexpr uint32_t GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC = 604800;
   /// State bound: claimants per offset pool. Refuse-or-prune choice: REFUSE
   /// (a deposit naming a 65th distinct claimant is refused; existing claims
   /// merge by owner, so honest repeat deposits never hit the bound).
   constexpr uint32_t GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS = 64;
   /// State bound: pending door-vesting records per reserve. Redeems prune
   /// matured entries first; a redeem that still overflows the list is
   /// refused fail-closed (inflow is already bounded by the door cap, so the
   /// list cannot grow without bound between prunes).
   constexpr uint32_t GRAPHENE_H2_ISSUE_PENDING_VEST_CAP = 64;
   /// Batch-exit queue bounds (both constants, either one binds): at most 8
   /// open requests per pair, and at most 1e11 BTS of queued value (~$1,000
   /// pilot-basis) at the current bonded price. New requests past either cap
   /// are refused; while EITHER cap is reached, FXR minting suspends (the
   /// mint still admits when it prices no FXR).
   constexpr uint32_t GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT = 8;
   constexpr uint64_t GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS = 100000000000ULL;
   /// Cap-function k1 proposal: the headroom leg is floor(headroom x 10000 /
   /// 10000) -- a single conversion may never exceed the STANDING headroom.
   /// Derivation (BSIP-1 section 7b memo, see h2_issue_door_admits): the
   /// fixed $2,000 ceiling keeps the shared per-block counter semantics
   /// (ISSUANCE-1 DOS bound, unchanged), while the headroom leg is a
   /// single-conversion EXTRACTION bound, never a second floor (the rmin
   /// gate already refuses below-floor posts outright). Oracle
   /// profit-from-corruption per window is bounded by the guard band (5%
   /// tripwire deviation) times the secured book; capping each conversion
   /// at the standing buffer means a corrupt price cannot vacuum the book
   /// faster than the 36h top-up/halt ladder can answer, while honest flow
   /// passes untouched: k1 = 1 is the MINIMUM consistent with live books
   /// (a half-book redeem pays ~0.71x headroom, an at-headroom top-up pays
   /// exactly 1x -- any k1 < 1 refuses healthy conversions, proven in the
   /// ISSUANCE-2 cap tests). At 200% on a $20k book headroom is $14k, so
   /// the fixed ceiling still binds in normal operation and the headroom
   /// leg binds only near the floor. Genesis creation skips the headroom
   /// leg (no standing headroom exists; the rmin gate alone guards
   /// creation). k1 UNITY is load-bearing: do not lower it without
   /// re-proving the half-book redeem and the at-headroom top-up.
   constexpr uint32_t GRAPHENE_H2_ISSUE_CAP_K1_BPS = 10000;
   /// Cap-function k2 proposal: the depth leg is floor(two-window qualified
   /// depth x 5000 / 10000) -- at most HALF the observed absorption per
   /// block. Derivation: the tripwire MIN_DEPTH floor ($10/window) keeps dust
   /// windows from pricing door flow; k2 = 1/2 keeps a single block's door
   /// flow inside the market's demonstrated two-window absorption, so door
   /// flow itself cannot push the market past the 5% guard band on a
   /// constant-product pool (impact ~= trade / depth). No tripwire state for
   /// the pair skips the depth leg (pre-pool bootstrap); a tripwire state
   /// with UNQUALIFIED windows (thin or single-pool) refuses the door
   /// outright (fail-closed: impact cannot be priced, so no flow).
   constexpr uint32_t GRAPHENE_H2_ISSUE_CAP_K2_BPS = 5000;

   /// Band edge i (i = 0..7) in bps of the anchor price. Eight edges bound
   /// seven bands: {9000,9500,9750,10000,10250,10500,11000,11500}. The anchor
   /// sits at edges[3] (= 10000, the par boundary); bands 0..2 hold discount
   /// backing, bands 4..6 premium backing. Minimum spacing 250bps.
   inline uint16_t h2_issue_band_edge_bps( uint32_t i )
   {
      switch( i )
      {
         case 0: return 9000;
         case 1: return 9500;
         case 2: return 9750;
         case 3: return 10000;
         case 4: return 10250;
         case 5: return 10500;
         case 6: return 11000;
         default: return 11500;
      }
   }

   /**
    * @brief Locks BTS into the pair reserve and receives senior stable.
    * @ingroup operations
    *
    * The minter names BOTH legs: the BTS deposit and the face stable
    * requested. The deposit must cover the request at the bonded oracle
    * price (floored conversion favors the protocol) AND the post-mint
    * reserve ratio must stay at or above rmin -- else refused. Naming the
    * request (rather than deriving it from the deposit) is load-bearing:
    * a price-derived mint on an empty book opens at ~100% backing and
    * could never clear rmin, so issuance could never start; the minter's
    * chosen over-collateralization opens every book. Deposit value above
    * the surplus target mints FXR to the minter at the pre-mint surplus
    * price (floored, exact math -- see the evaluator).
    */
    struct hybrid_mint_operation : public base_operation
    {
       // Spam math: 5 BTS matches the sibling H2 door-op fees. The fee only
       // prices mempool noise -- the load-bearing spam bound is capital, not
       // fees (R2 audit): every mint locks a real rmin-covering deposit, the
       // door cap bounds conversions per block per pair, and dust is refused
       // outright. A block-filling grief therefore costs N x 5 BTS in fees
       // PLUS N locked over-collateralized deposits for no protocol loss.
       struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type minter;       ///< Pays the fee, locks the deposit, receives stable (+FXR)
      vault_id_type   vault;        ///< Target vault: names the pair, the binding, the door
      asset           deposit;      ///< BTS locked into the reserve, > 0 (genesis: BTS-only)
      share_type      stable_amount;///< Face stable requested, > 0, covered at the bonded price
      asset_id_type   fxr_asset;    ///< Junior token: pinned at reserve creation, matched after
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return minter; }
      void            validate()const;
   };

   /**
    * @brief Burns senior stable for a 24h-vested BTS payout at the bonded price.
    * @ingroup operations
    *
    * Payouts price through the SAME bonded read as mints (primary, else the
    * single backup; dual-stale refuses). The vested payout is the floored
    * conversion MINUS the floored 30bps conversion fee (both roundings favor
    * the protocol; the slice stays in the reserve). Partial redeems must leave the
    * reserve ratio above the rmin floor -- else refused, with holders
    * exiting through wind-down claims instead. Only an exact full-book exit
    * (burning the entire outstanding) bypasses the floor: nothing remains
    * to secure. The payout never touches liquid balances: it vests 24h
    * linear in a fresh vesting object owned by the redeemer.
    */
    struct hybrid_redeem_operation : public base_operation
    {
       // Spam math: 5 BTS, same basis as the mint leg. Redeem spam additionally
       // burns stable for a haircut, fee-bearing vesting payout -- the griefer
       // pays the conversion fee twice per cycle (mint + redeem) while the
       // reserve keeps both slices.
       struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type redeemer;     ///< Pays the fee, burns stable, owns the vesting payout
      vault_id_type   vault;        ///< Target vault: names the pair, the binding, the door
      asset           burn;         ///< Face stable burned, > 0, held by the redeemer
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return redeemer; }
      void            validate()const;
   };

   /**
    * @brief Deposits BTS into the pair's offset pool (shock absorber).
    * @ingroup operations
    *
    * The deposit moves BTS from the depositor into the pool's balance and
    * merges a per-account claim {owner -> amount, available_after = head
    * time + 7 days}. Claims are non-transferable BY CONSTRUCTION: no other
    * operation names a claim, so no transfer path exists. Merges by owner
    * (one entry per account; the maturity is the LATEST deposit's, favoring
    * the protocol). A 65th distinct claimant is refused (bounded ledger).
    */
   struct offset_deposit_operation : public base_operation
   {
      // Spam math: 5 BTS, same door-op basis. The load-bearing bound is
      // capital (real BTS locked 7 days), never the fee.
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type depositor;    ///< Pays the fee, funds the pool, owns the claim
      vault_id_type   vault;        ///< Target vault: names the pair and the pool
      asset           deposit;      ///< BTS into the pool, > 0 (genesis: BTS-only)
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return depositor; }
      void            validate()const;
   };

   /**
    * @brief Pays a matured offset-pool claim in liquid BTS.
    * @ingroup operations
    *
    * Only the claim owner, only after available_after (head-block time,
    * never wall-clock), only up to the recorded amount. The payout is liquid
    * (the 7-day availability delay IS the vesting); the pool balance falls
    * with the claim so the supply audit keeps counting the remainder.
    */
   struct offset_claim_operation : public base_operation
   {
      // Spam math: 5 BTS. Claims pay real locked BTS, so griefing is
      // self-funded by construction.
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type claimant;     ///< Pays the fee, must own the claim
      vault_id_type   vault;        ///< Target vault: names the pair and the pool
      share_type      amount;       ///< BTS claimed, > 0, <= recorded claim
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return claimant; }
      void            validate()const;
   };

   /**
    * @brief Queues a batch-settled exit: burns face now, pays BTS later.
    * @ingroup operations
    *
    * The request burns the caller's face immediately (supply and outstanding
    * fall at request time, so no double-spend) and appends {requester, face,
    * block} to the reserve's bounded exit queue. Settlement happens in ONE
    * maintenance pass at ONE clearing haircut for the whole batch (no queue
    * jumping, no first-come advantage: R-06 arber residual closed by
    * construction), minus the 2% exit fee to the reserve. Request-time gates
    * mirror the redeem leg (bonded read, rmin floor on the remainder, dust
    * refusal); the exact full-book exit stays on the redeem path (exits are
    * partial by construction). Queued value counts toward NEITHER the door
    * cap (maintenance-block settlement, bounded by the queue caps instead)
    * NOR FXR dilution (face already burned; payout is BTS only).
    */
   struct issuance_exit_request_operation : public base_operation
   {
      // Spam math: 5 BTS. Each request burns real face, so queue spam
      // destroys the spammer's own senior position for a haircut payout.
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type requester;    ///< Pays the fee, burns face, queued for BTS
      vault_id_type   vault;        ///< Target vault: names the pair and the queue
      share_type      face;         ///< Face queued, > 0, held by the requester
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return requester; }
      void            validate()const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::hybrid_mint_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::hybrid_redeem_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::offset_deposit_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::offset_claim_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::issuance_exit_request_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::hybrid_mint_operation,
            (fee)(minter)(vault)(deposit)(stable_amount)(fxr_asset)(extensions) )
FC_REFLECT( graphene::protocol::hybrid_redeem_operation,
            (fee)(redeemer)(vault)(burn)(extensions) )
FC_REFLECT( graphene::protocol::offset_deposit_operation,
            (fee)(depositor)(vault)(deposit)(extensions) )
FC_REFLECT( graphene::protocol::offset_claim_operation,
            (fee)(claimant)(vault)(amount)(extensions) )
FC_REFLECT( graphene::protocol::issuance_exit_request_operation,
            (fee)(requester)(vault)(face)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::offset_deposit_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::offset_claim_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::issuance_exit_request_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::offset_deposit_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::offset_claim_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::issuance_exit_request_operation )
