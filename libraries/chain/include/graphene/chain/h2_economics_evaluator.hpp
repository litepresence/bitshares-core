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
#include <graphene/chain/evaluator.hpp>

#include <graphene/protocol/h2_economics.hpp>

namespace graphene { namespace chain {

   class oracle_object;
   class vault_object;
   class guard_state_object;
   struct h2_promotion_record;

   class oracle_fallback_set_evaluator : public evaluator<oracle_fallback_set_evaluator>
   {
      public:
         using operation_type = oracle_fallback_set_operation;

         void_result do_evaluate( const oracle_fallback_set_operation& op );
         void_result do_apply( const oracle_fallback_set_operation& op ) const;

         const oracle_object* _oracle = nullptr;
         const oracle_object* _backup = nullptr;
   };

   /**
    * Lazily creates the reward pool + guard state shells for an oracle
    * (idempotent). Called from H2-gated paths only (producer-bond lock,
    * publish observation, fallback set, maintenance sweep), so H1 oracles
    * never grow state they do not use.
    */
   void h2_ensure_oracle_econ( database& d, oracle_id_type oracle );

   /**
    * Promotion observation (called from the oracle publish apply path after
    * aggregation): records a hardened promotion entry when the consumed value
    * advances (time or value changed), and counts it in the interval window.
    * Past GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL promotions in one window
    * the consumption hold engages (H2 reads fail closed; H1 paths untouched).
    * Oracles without econ shells are shelled first (H2-gated); pre-fork this
    * is never reached.
    */
   void h2_observe_publication( database& d, oracle_id_type oracle,
                                time_point_sec now );

   /**
    * Tripwire sampling (called from the liquidity-pool exchange apply path):
    * records the pool-side execution ratio of a direct pair<->core leg when
    * the non-core side has a live vault. Vault-less pairs (every H1 pair)
    * return before touching state: exclusion is structural. Pre-fork this is
    * never reached.
    */
   void h2_observe_pool_exchange( database& d, liquidity_pool_id_type pool,
                                  asset pool_receives, asset pool_pays );

   /**
    * Single-oracle H2 read: the consumed series value, or absent when it must
    * not be used (frozen oracle, absent/stale value, rate hold, missing or
    * mismatched promotion record, series out of range). Fail-closed in every
    * direction: absence is never an error, only a halt signal for callers.
    */
   /**
    * The liveness mode of a consumed-price read.
    *
    * LIVE is the debt-path rule: a value that outlived its lifetime is
    * refused, so a stale price can never carry new debt. AGE_EXEMPT is the
    * settlement-path rule: the age condition is dropped and NOTHING else,
    * so the bonded live set, the guard's hold, the frozen oracle and the
    * promotion proof still apply.
    */
   enum class h2_price_liveness { live, age_exempt };

   optional<protocol::oracle_value> h2_read_consumed_price(
         const database& d, oracle_id_type oracle, uint16_t series,
         time_point_sec now, h2_price_liveness liveness );

   /**
    * Pair price through the canonical binding: the bound oracle's consumed
    * read, else the single backup's consumed read, else absent (dual-stale).
    * Unbound vaults have no price leg by construction.
    */
   /**
    * The oracle's last consumed price, with the live read's liveness
    * conditions dropped (the value's age, the bonded live set, the guard's
    * consumption hold) and its promotion proof kept.
    *
    * The live read says "this price may not carry NEW DEBT"; this read says
    * "this is the price the chain last accepted under the guard". The
    * settlement path uses it so a wind-down can seat and its claims can be
    * paid when the oracle died; the debt path never calls it.
    *
    * Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 2
    */
   optional<protocol::oracle_value> h2_read_last_consumed_price(
         const database& d, oracle_id_type oracle, uint16_t series );

   /**
    * The price the settlement path may use: the live read when there is one,
    * otherwise the oracle's last consumed price (primary, then the
    * owner-controlled backup). Bounded use only: the wind-down's seat and the
    * wind-down claim's haircut leg.
    *
    * Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 3
    */
   optional<protocol::oracle_value> h2_read_settlement_price(
         const database& d, const vault_object& vault, uint16_t series );

   optional<protocol::oracle_value> h2_read_pair_price(
         const database& d, const vault_object& vault, uint16_t series,
         time_point_sec now );

   /// @return whether redemptions for @p pair are held shut by the tripwire.
   bool h2_redemptions_halted( const database& d, asset_id_type pair );

   /**
    * Converted wind-down payout (declared, rounding DOWN against claimants):
    * payout = min(haircut face converted to bond units through the bound
    * price, face × segregated / total). The pro-rata leg stays
    * face × segregated / total verbatim in 128-bit (price cancels by
    * construction, zero truncation drift); ONLY the haircut cap converts
    * pair-units to bond-units through the bound price. At a 1:1 price both
    * legs reduce exactly to the H2c same-asset formula (continuity, not
    * coincidence).
    */
   share_type h2_converted_payout_for_claim( share_type face, share_type segregated,
                                             share_type total, uint32_t haircut_bps,
                                             const protocol::oracle_value& price );

   /**
    * Maintenance sweep (H2-gated no-op pre-fork): forfeit sweep into reward
    * pools + pro-rata live-weight payouts; guard rate-window rollover;
    * Recovery scope evaluation; tripwire window rotation + ladder.
    * Runs after the H2c vault sweep in perform_chain_maintenance().
    */
   void process_h2_oracle_economics( database& d );

} } // graphene::chain
