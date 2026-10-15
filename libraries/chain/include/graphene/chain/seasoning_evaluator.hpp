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

#include <graphene/protocol/seasoning_ops.hpp>

namespace graphene { namespace chain {

   class seasoning_record_object;

   class seasoning_verify_evaluator : public evaluator<seasoning_verify_evaluator>
   {
      public:
         using operation_type = seasoning_verify_operation;

         void_result do_evaluate( const seasoning_verify_operation& op );
         void_result do_apply( const seasoning_verify_operation& op ) const;

         const seasoning_record_object* _record = nullptr;
   };

   /**
    * Creates the seasoning record for @p pair at @p now (genesis = window
    * start, minimums open, verifier unset, incomplete). Refuses duplicates:
    * at most one record per pair ever exists. Called from the
    * `vault_register` apply step (gateway-leg activation for the pair).
    */
   void h2_create_seasoning_record( database& d, asset_id_type pair,
                                    time_point_sec now );

   /**
    * Seasoning sweep (H2-gated no-op pre-gateway): for every record, folds
    * the current vault/oracle coverages into the full-window minimums and
    * recomputes `complete`. Any sweep with vault coverage < 2.0 or oracle
    * coverage < 1.0 marks breach: the window restarts at head-block time
    * and the minimums reopen at the current (breaching) values. Reads H2
    * bonded state only -- H1 inputs are absent by construction, so H1
    * freezes can neither pause nor extend the clock. Runs after the H2d
    * oracle sweep in perform_chain_maintenance().
    */
   void process_h2_seasoning( database& d );

    /**
     * @return whether the pair's seasoning is complete: 90 days elapsed
     * since the (re)start AND full-window minimums intact AND the
     * independent-verifier bit set.
     *
     * USD-ISSUANCE STAGING GATE (AC-08, BSIP-1 section 5): the tranched
     * issuance phase's mint evaluator calls this to refuse USD issuance on
     * unseasoned pairs (hybrid_mint_evaluator::do_evaluate). The predicate
     * is pinned here so the gate and the sweep cannot drift apart.
     */
   bool h2_seasoning_complete( const database& d, asset_id_type pair );

} } // graphene::chain
