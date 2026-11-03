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

#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_ops.hpp>

namespace graphene { namespace chain {

   class producer_bond_object;
   class vesting_balance_object;

   class oracle_bond_lock_evaluator : public evaluator<oracle_bond_lock_evaluator>
   {
      public:
         using operation_type = oracle_bond_lock_operation;

         void_result    do_evaluate( const oracle_bond_lock_operation& op );
         object_id_type do_apply( const oracle_bond_lock_operation& op ) const;

         const vesting_balance_object* _vesting = nullptr;
   };

   class oracle_bond_release_evaluator : public evaluator<oracle_bond_release_evaluator>
   {
      public:
         using operation_type = oracle_bond_release_operation;

         void_result do_evaluate( const oracle_bond_release_operation& op );
         void_result do_apply( const oracle_bond_release_operation& op ) const;

         const producer_bond_object* _bond = nullptr;
   };

   /**
    * Advancing-unlock rule (H2a, inventory OQ-23 reversible minimum): each
    * successful publication pushes the publishing producer's bond unlock out by
    * GRAPHENE_H2_BOND_ADVANCE_SEC (24h), saturating instead of overflowing.
    * Called from the oracle publish apply path; a producer with no bond (every
    * H1 producer) takes no branch and sees byte-identical behavior.
    */
   void advance_producer_bond_on_publish( database& d, oracle_id_type oracle,
                                          account_id_type producer,
                                          time_point_sec now );

} } // graphene::chain
