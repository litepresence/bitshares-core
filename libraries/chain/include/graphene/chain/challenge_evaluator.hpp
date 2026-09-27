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

#include <graphene/protocol/challenge_ops.hpp>

namespace graphene { namespace chain {

   class account_object;
   class oracle_dispute_object;
   class vault_challenge_object;

   class vault_challenge_evaluator : public evaluator<vault_challenge_evaluator>
   {
      public:
         using operation_type = vault_challenge_operation;

         void_result    do_evaluate( const vault_challenge_operation& op );
         object_id_type do_apply( const vault_challenge_operation& op ) const;

         const account_object* _challenger = nullptr;
   };

   class oracle_dispute_evaluator : public evaluator<oracle_dispute_evaluator>
   {
      public:
         using operation_type = oracle_dispute_operation;

         void_result    do_evaluate( const oracle_dispute_operation& op );
         object_id_type do_apply( const oracle_dispute_operation& op ) const;

         const account_object* _challenger = nullptr;
   };

   class oracle_dispute_escalate_evaluator : public evaluator<oracle_dispute_escalate_evaluator>
   {
      public:
         using operation_type = oracle_dispute_escalate_operation;

         void_result do_evaluate( const oracle_dispute_escalate_operation& op );
         void_result do_apply( const oracle_dispute_escalate_operation& op ) const;

         const oracle_dispute_object* _dispute = nullptr;
   };

   class challenge_vote_evaluator : public evaluator<challenge_vote_evaluator>
   {
      public:
         using operation_type = challenge_vote_operation;

         void_result do_evaluate( const challenge_vote_operation& op );
         void_result do_apply( const challenge_vote_operation& op ) const;

         /// Which target the vote names (set in do_evaluate, read in do_apply).
         const vault_challenge_object* _challenge = nullptr;
         const oracle_dispute_object*  _dispute = nullptr;
   };

   /**
    * Forfeit split (BSIP-1 section 2, integer math, declared rounding): 80%
    * burns, 15% accrues to the target's forfeit pool balance (swept by the H2d
    * reward pool), and the remainder goes to the finder, capped at $83.75 in
    * USD terms at lock. The cap binds only on escalated totals; at the base
    * floor the remainder (~5%) sits well under it. Cap excess burns, so the
    * three parts always sum to @p total_raw exactly. All intermediates are
    * 128-bit; every division rounds down.
    */
   void h2_split_forfeit( share_type total_raw, uint64_t total_usd_cents,
                          share_type& burn, share_type& pool, share_type& finder );

   /**
    * Same-authority ban (H2 plan Task H2b): true when the two sides' authority
    * graphs overlap within the bounded walk (depth <= 2, width <= 15 per
    * level). The vault side roots at the vault authority, the account side at
    * the account's owner+active authorities; the oracle variant roots both
    * sides at account authorities. Iteration follows ordered flat_maps, so the
    * walk (and the width cap's first-15 cutoff) is deterministic.
    */
   bool h2_authority_graphs_overlap( database& d, account_id_type challenger,
                                     const authority& vault_auth );
   bool h2_authority_graphs_overlap( database& d, account_id_type challenger,
                                     account_id_type defender );

   /**
    * Fail-closed expiry sweep (maintenance hook, inventory OQ-19 vehicle): every
    * still-open challenge/dispute whose deadline has passed transitions to
    * expired-frozen, frees its concurrency slot, returns all escrowed bonds in
    * full (committee silence never confiscates challenger funds), and freezes
    * its target (vault mints halt; the oracle stops promoting values while
    * still aggregating transparently). Runs at maintenance granularity: expiry
    * takes effect at the first maintenance after the deadline.
    */
   void process_expired_h2_challenges( database& d );

} } // graphene::chain
