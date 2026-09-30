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

#include <graphene/protocol/vault_lifecycle_ops.hpp>

namespace graphene { namespace chain {

   class vault_object;
   class vault_bond_object;
   class vault_challenge_object;
   class winddown_vault_object;

   class vault_rotate_evaluator : public evaluator<vault_rotate_evaluator>
   {
      public:
         using operation_type = vault_rotate_operation;

         void_result    do_evaluate( const vault_rotate_operation& op );
         object_id_type do_apply( const vault_rotate_operation& op );

         const vault_object* _vault = nullptr;
   };

   class vault_bond_release_evaluator : public evaluator<vault_bond_release_evaluator>
   {
      public:
         using operation_type = vault_bond_release_operation;

         void_result do_evaluate( const vault_bond_release_operation& op );
         void_result do_apply( const vault_bond_release_operation& op ) const;

         const vault_bond_object* _bond = nullptr;
   };

   class vault_resolve_evaluator : public evaluator<vault_resolve_evaluator>
   {
      public:
         using operation_type = vault_resolve_operation;

         void_result    do_evaluate( const vault_resolve_operation& op );
         object_id_type do_apply( const vault_resolve_operation& op );

         const vault_challenge_object* _challenge = nullptr;
   };

   class pair_freeze_evaluator : public evaluator<pair_freeze_evaluator>
   {
      public:
         using operation_type = pair_freeze_operation;

         void_result do_evaluate( const pair_freeze_operation& op );
         void_result do_apply( const pair_freeze_operation& op ) const;
   };

   class winddown_claim_evaluator : public evaluator<winddown_claim_evaluator>
   {
      public:
         using operation_type = winddown_claim_operation;

         void_result    do_evaluate( const winddown_claim_operation& op );
         object_id_type do_apply( const winddown_claim_operation& op ) const;

         const winddown_vault_object* _winddown = nullptr;
         /// Payout fixed at evaluate time so apply cannot diverge from the
         /// checked economics (same-asset H2c math or bound-oracle conversion).
         share_type _payout;
   };

    /**
     * Segregates a vault's unseized bonds into a new wind-down object: marks
     * each bond seized, debits its vesting balance (saturating at the vested
     * balance, so a partially-drawn vesting seizes only what is there), and
     * books the debited sum as segregated_bond with total_claims set to the
     * vault's outstanding at freeze. Shared by the 150% maintenance hook and
     * vault_resolve (sustained OR expired-frozen challenge execution, R5C
     * fail-closed split): one rulebook, all paths. Supply-neutral by
     * construction (every vesting debit is booked into the wind-down
     * remainder the audit counts as escrowed).
     */
   const winddown_vault_object& h2_create_winddown( database& d, const vault_object& vault );

   /**
    * Coverage predicate (declared integer math, no floats): healthy while
    * bonds * 10000 >= outstanding * 15000. Zero outstanding is vacuously
    * healthy. Only unseized bonds secure the vault.
    */
   bool h2_vault_meets_maintenance( database& d, const vault_object& vault );

   /**
    * 150% maintenance sweep (inventory OQ-19 vehicle, head-block time only):
    * healthy vaults below 150% enter the 36h top-up window (mint halt via
    * frozen); vaults still breached past the deadline wind down automatically.
    * Vaults restored to coverage inside the window return to healthy. Runs at
    * maintenance granularity like the H2b expiry sweep; pre-fork a no-op.
    */
   void process_h2_vault_maintenance( database& d );

} } // graphene::chain
