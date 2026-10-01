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

#include <graphene/protocol/issuance_ops.hpp>

namespace graphene { namespace chain {

   class reserve_object;
   class offset_pool_object;
   class vault_object;

   class hybrid_mint_evaluator : public evaluator<hybrid_mint_evaluator>
   {
      public:
         using operation_type = hybrid_mint_operation;

         void_result do_evaluate( const hybrid_mint_operation& op );
         object_id_type do_apply( const hybrid_mint_operation& op );

         const vault_object*   _vault = nullptr;
         const reserve_object* _reserve = nullptr; ///< Null when this mint creates it
         bool                  _creates_reserve = false;
         share_type            _fxr_to_mint = share_type( 0 );
         protocol::oracle_value _price; ///< Bonded price proven in evaluate, reused in apply
   };

   class hybrid_redeem_evaluator : public evaluator<hybrid_redeem_evaluator>
   {
      public:
         using operation_type = hybrid_redeem_operation;

         void_result do_evaluate( const hybrid_redeem_operation& op );
         object_id_type do_apply( const hybrid_redeem_operation& op ) const;

         const vault_object*   _vault = nullptr;
         const reserve_object* _reserve = nullptr;
         share_type            _payout = share_type( 0 );
   };

   class offset_deposit_evaluator : public evaluator<offset_deposit_evaluator>
   {
      public:
         using operation_type = offset_deposit_operation;

         void_result do_evaluate( const offset_deposit_operation& op );
         object_id_type do_apply( const offset_deposit_operation& op );

         const vault_object*        _vault = nullptr;
         const offset_pool_object*  _pool = nullptr; ///< Null when this deposit creates it
         bool                       _creates_pool = false;
   };

   class offset_claim_evaluator : public evaluator<offset_claim_evaluator>
   {
      public:
         using operation_type = offset_claim_operation;

         void_result do_evaluate( const offset_claim_operation& op );
         object_id_type do_apply( const offset_claim_operation& op ) const;

         const vault_object*       _vault = nullptr;
         const offset_pool_object* _pool = nullptr;
   };

   class issuance_exit_request_evaluator : public evaluator<issuance_exit_request_evaluator>
   {
      public:
         using operation_type = issuance_exit_request_operation;

         void_result do_evaluate( const issuance_exit_request_operation& op );
         object_id_type do_apply( const issuance_exit_request_operation& op );

         const vault_object*   _vault = nullptr;
         const reserve_object* _reserve = nullptr;
         protocol::oracle_value _price; ///< Bonded price proven in evaluate, reused in apply
   };

   /**
    * Exact face value of @p bts_raw bond units at @p price (bond-per-pair),
    * rounding DOWN (favoring the protocol): floor(bts_raw * quote / base)
    * in 256-bit. Returns 0 on non-positive input or degenerate price.
    */
   share_type h2_issue_bts_to_face( share_type bts_raw,
                                    const protocol::oracle_value& price );

   /**
    * Exact bond payout for @p face_raw face units at @p price,
    * rounding DOWN (favoring the protocol): floor(face_raw * base / quote)
    * in 256-bit. Returns 0 on non-positive input or degenerate price.
    */
   share_type h2_issue_face_to_bts( share_type face_raw,
                                    const protocol::oracle_value& price );

   /**
    * Coverage in saturating basis points: floor(value_face * 10000 /
    * supply_face) capped at 0xFFFFFFFF, exact 128-bit division. Zero (or
    * negative) supply saturates (nothing to secure); non-positive value
    * reads 0. Deterministic on every node.
    */
   uint32_t h2_issue_coverage_bps( share_type value_face, share_type supply_face );

   /// @return the issuance reserve for @p pair, or null when none exists.
   const reserve_object* h2_find_reserve( const database& d, asset_id_type pair );

   /// @return the offset pool for @p pair, or null when none exists.
   const offset_pool_object* h2_find_offset_pool( const database& d, asset_id_type pair );

   /**
    * Half-tick move predicate (declared, exact, no floats, no division):
    * has @p now moved beyond half a band tick (125bps) from @p anchor?
    * Cross-multiplied in 256-bit: |now.base*anchor.quote -
    * anchor.base*now.quote| * 10000 > 125 * anchor.base * anchor.quote.
    * Equality is NOT a move (inclusive headroom: no churn on the boundary).
    * Degenerate inputs never count as moves (fail-closed: no anchor, or an
    * unanchored reserve, rebalances by anchoring, never by shifting).
    */
   bool h2_issue_price_moved( const protocol::oracle_value& anchor,
                              const protocol::oracle_value& now );

   /**
    * Offset absorb trigger (declared, exact, no division): is the position
    * below 100% AFTER bands? bts_raw * quote < supply_face * base in
    * 256-bit. Equality (exactly 100%) does NOT trigger. Callers guarantee
    * a non-degenerate price; degenerate prices never trigger (fail-closed).
    */
   bool h2_offset_should_absorb( share_type bts_raw, share_type supply_face,
                                 const protocol::oracle_value& price );

   /**
    * Shortfall in BTS units (declared, CEILED, exact): the BTS that would
    * restore 100% at @p price, ceil((supply*base - bts*quote) / quote) in
    * 256-bit. Ceiling favors the protocol (absorbs the full shortfall, never
    * a hair under). Zero when covered (callers check the trigger first);
    * saturates at GRAPHENE_MAX_SHARE_SUPPLY.
    */
   share_type h2_offset_shortfall_bts( share_type bts_raw, share_type supply_face,
                                       const protocol::oracle_value& price );

   /**
    * Door admission (live rule; the fixed $2,000 cap survives as the
    * ceiling). Three checks, exact integer math, every rounding favoring
    * the protocol:
    * - fixed DOS ceiling (ISSUANCE-1 semantics, unchanged): the SHARED
    *   per-block counter still bounds mint deposits plus redeem payouts at
    *   GRAPHENE_H2_ISSUE_DOOR_CAP_BTS (used + leg, 256-bit).
    * - headroom extraction bound (skipped when @p reserve is null --
    *   genesis bootstrap: no standing headroom exists; the rmin gate alone
    *   guards creation): the MARGINAL leg alone must not exceed the
    *   standing headroom, floor(max(0, bts - ceil(supply*base*rmin /
    *   (quote*10000))) * k1 / 10000) with k1 = UNITY (load-bearing: any
    *   k1 < 1 refuses healthy half-book redeems and at-headroom top-ups).
    *   The required-BTS ceiling favors the protocol (smaller headroom,
    *   tighter bound); the leg floors (tighter bound).
    * - depth flow bound (skipped when no tripwire state exists for @p pair
    *   -- pre-pool bootstrap): the marginal leg alone must not exceed
    *   floor(qualified two-window volume * k2 / 10000). When a tripwire
    *   state EXISTS but its windows are unqualified (thin or single-pool),
    *   the door refuses outright (fail-closed: impact cannot be priced).
    * k1/k2 derivation: see the constant comments (PfC bounded per window by
    * guard-band x secured book; k1 bounds single-conversion extraction at
    * the standing buffer, k2 keeps flow inside demonstrated absorption).
    */
   bool h2_issue_door_admits( const database& d,
                              const reserve_object* reserve,
                              asset_id_type pair,
                              const protocol::oracle_value& price,
                              share_type used, share_type leg );

   /**
    * Exit-queue suspension predicate: FXR minting suspends while EITHER
    * queue cap is reached (count >= MAX_COUNT or queued value >= MAX_BTS).
    * Queued value sums ceil(face*base/quote) per request (ceiling
    * over-counts, refusing sooner: favors the protocol). Null reserve reads
    * false (no queue exists to suspend on).
    */
   bool h2_issue_exit_suspended( const reserve_object* reserve,
                                 const protocol::oracle_value& price );

   /**
    * Maintenance entry (called at the end of process_h2_oracle_economics,
    * after the H2c vault sweep): settles every non-empty exit queue in ONE
    * pass at ONE clearing haircut per pair, then absorbs residual shortfalls
    * from offset pools. Legacy pairs (no reserve) cost one index walk and
    * nothing else. Dual-stale prices hold their queues fail-closed.
    */
   void h2_issue_maintenance( database& d );

   /**
    * Halt/wind-down entry (called FIRST from h2_create_winddown before the
    * outstanding snapshot, and from pair_freeze apply): runs the
    * REVERT-vs-ABSORB state machine on @p pair. No reserve: returns
    * immediately (legacy path byte-identical). Otherwise, in order:
    * 1. prune matured/missing pending vestings (STAND: settled positions are
    *    never repriced);
    * 2. REVERT every still-unvested door output (cancel escrow, BTS to the
    *    reserve, face back to owner/supply/outstanding);
    * 3. ABSORB the residual shortfall, if the trigger reads below 100% at
    *    the bonded price (offset pool first, remainder recorded as
    *    uncovered_shortfall for the rmax junior path); no bonded price
    *    holds everything fail-closed (no revert, no absorb).
    */
   void h2_issue_on_pair_halt( database& d, asset_id_type pair );

} } // graphene::chain
