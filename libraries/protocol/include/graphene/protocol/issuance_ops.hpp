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

} } // graphene::protocol

FC_REFLECT( graphene::protocol::hybrid_mint_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::hybrid_redeem_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::hybrid_mint_operation,
            (fee)(minter)(vault)(deposit)(stable_amount)(fxr_asset)(extensions) )
FC_REFLECT( graphene::protocol::hybrid_redeem_operation,
            (fee)(redeemer)(vault)(burn)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation )
