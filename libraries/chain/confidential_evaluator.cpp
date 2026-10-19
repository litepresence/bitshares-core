/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
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
#include <algorithm>
#include <graphene/chain/exceptions.hpp>
#include <graphene/protocol/confidential.hpp>
#include <graphene/chain/confidential_evaluator.hpp>
#include <graphene/chain/confidential_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/fba_accumulator_id.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/stealth_evaluator.hpp>

namespace graphene { namespace chain {

void_result transfer_to_blind_evaluator::do_evaluate( const transfer_to_blind_operation& o )
{ try {
   const auto& d = db();

   const auto& atype = o.amount.asset_id(db());
   FC_ASSERT( atype.allow_confidential() );
   FC_ASSERT( !atype.is_transfer_restricted() );
   FC_ASSERT( !(atype.options.flags & white_list) );

   for( const auto& out : o.outputs )
   {
      for( const auto& a : out.owner.account_auths )
         a.first(d); // verify all accounts exist and are valid
   }
   // G1 (STEALTH hardfork): shared blind gate (halt + per-block budget),
   // V1 sunset (no new V1 balances past sunset), and sound range proofs.
   if( HARDFORK_STEALTH_PASSED( d.head_block_time() ) )
   {
      stealth_check_blind_gate( d );
      // F-01 (R9B): one V1 range proof per output, charged at the BP+ rate
      // (conservative over-count — see stealth.hpp).
      stealth_check_blind_work_gate( d, stealth_work_for_range_proofs( (uint32_t)o.outputs.size() ) );
      stealth_check_asset_gate( d, o.amount.asset_id );
      FC_ASSERT( d.head_block_time() < stealth_v1_sunset_time( d ),
                 "No new V1 blind balances past sunset (use turnstile re-proof)" );
      stealth_require_sound_range_proofs( d, o.outputs );
      // Phase-2 A3 (spec 2026-10-11-phase2 §1): pre-floor cold-start discount.
      // Reads live depth; terminates itself at depth 11. Refusal precedes the
      // fee rule so an oversize cold deposit fails closed, never subsidized.
      const bool cold_start = stealth_pool_depth( d, o.amount.asset_id )
                              < protocol::GRAPHENE_STEALTH_BLIND_POOL_FLOOR;
      if( cold_start )
         FC_ASSERT( o.outputs.size() <= protocol::GRAPHENE_STEALTH_RING_TARGET,
                    "Pre-floor deposits carry at most one ring target of outputs" );
      const uint32_t cold_n = cold_start ? 0u : (uint32_t)o.outputs.size();
      // G1c parity float rule (BSIP-2 §2): same skip guard as the schedule
      // check — no fee paid, no subsidy consumed. Rule R: a deposit is the
      // only net source of blind-set value, so min(n, classifier) == n here.
      stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                                 o.fee.asset_id, cold_n,
                                 calculate_fee_for_operation( operation( o ) ),
                                 std::min( (uint32_t)o.outputs.size(),
                                    stealth_op39_subsidy_count( d, o.amount.asset_id, o.from, operation( o ) ) ) );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }


void_result transfer_to_blind_evaluator::do_apply( const transfer_to_blind_operation& o )
{ try {
   db().adjust_balance( o.from, -o.amount );

   const auto& add = o.amount.asset_id(db()).dynamic_asset_data_id(db());  // verify fee is a legit asset
   db().modify( add, [&]( asset_dynamic_data_object& obj ){
      obj.confidential_supply += o.amount.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   });
   stealth_shadow_add( db(), o.amount.asset_id, o.amount.amount );
   const bool post_stealth = HARDFORK_STEALTH_PASSED( db().head_block_time() );
   for( const auto& out : o.outputs )
   {
      db().create<blinded_balance_object>( [&]( blinded_balance_object& obj ){
          obj.asset_id   = o.amount.asset_id;
          obj.owner      = out.owner;
          obj.commitment = out.commitment;
          if( post_stealth )
          {
             obj.created_block = db().head_block_num() + 1;
             obj.created_time  = db().head_block_time();
          }
      });
   }
   // Phase-2 A3 (spec 2026-10-11-phase2 §1): pre-add depth — matches
   // do_evaluate's read (evaluate runs before this deposit's count-add), so
   // require/consume agree exactly and the base-only fee clears in consume.
   const uint32_t cold_n = stealth_pool_depth( db(), o.amount.asset_id )
                           < protocol::GRAPHENE_STEALTH_BLIND_POOL_FLOOR
                           ? 0u : (uint32_t)o.outputs.size();
   // Pool floor counter: post-STEALTH creates carry metadata (counted);
   // pre-fork creates are grandfathered (helper no-ops pre-fork anyway).
   stealth_pool_count_add( db(), o.amount.asset_id, (int32_t)o.outputs.size() );
   // G1c: parity subsidy settlement + skew histogram (decoy-eligible creates).
   // CI-01: consume re-derives stealth_op39_subsidy_count, which
   // reads the depositor window. It MUST see the same pre-add window that
   // do_evaluate's require saw (evaluate runs before any histogram write),
   // or a deposit that tips the depositor past the 1/16 dominance boundary
   // would be admitted at full subsidy and then consumed at the capped 1 —
   // require/consume mirror broken. Same posture as cold_n above (A3).
   stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                    o.fee.asset_id, cold_n,
                                    calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                    std::min( (uint32_t)o.outputs.size(),
                                       stealth_op39_subsidy_count( db(), o.amount.asset_id, o.from, operation( o ) ) ) );
   // Phase-1 instrumentation (spec 2026-10-11 §8): deposit-side attribution.
   // AFTER consume so the window write does not perturb the subsidy re-derivation.
   stealth_deposit_histogram_add( db(), o.amount.asset_id, o.from,
                                  (uint32_t)o.outputs.size() );
   stealth_window_count_add( db(), (uint32_t)o.outputs.size() );
   stealth_count_blind_op( db() );
   stealth_count_blind_work( db(), stealth_work_for_range_proofs( (uint32_t)o.outputs.size() ) );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void transfer_to_blind_evaluator::pay_fee()
{
   if( db().head_block_time() >= HARDFORK_563_TIME )
      pay_fba_fee( fba_accumulator_id_transfer_to_blind );
   else
      generic_evaluator::pay_fee();
}

void_result transfer_from_blind_evaluator::do_evaluate( const transfer_from_blind_operation& o )
{ try {
   const auto& d = db();
   // SUP-03: amount/fee asset confusion must fail in consensus, not only in
   // relay-side validate (proposal-embedded ops bypass validate: one block
   // producer could otherwise destroy X's blinds while crediting liquid Y).
   FC_ASSERT( o.amount.asset_id == o.fee.asset_id,
              "transfer_from_blind amount and fee must be the same asset" );
   o.fee.asset_id(d);  // verify fee is a legit asset
   const auto& bbi = d.get_index_type<blinded_balance_index>();
   const auto& cidx = bbi.indices().get<by_commitment>();
   for( const auto& in : o.inputs )
   {
      auto itr = cidx.find( in.commitment );
      FC_ASSERT( itr != cidx.end() );
      FC_ASSERT( itr->asset_id == o.fee.asset_id );
      FC_ASSERT( itr->owner == in.owner );
      // Task 3 (nullifier migration): post-fork stealth outputs spend ONLY
      // via op108, which nullifier-checks the opening. Grandfathered
      // (pre-fork, created_block == 0) balances keep using this legacy leg
      // exactly as before. Evaluator-only (no wire change: replay-safe).
      FC_ASSERT( itr->created_block == 0,
                 "Post-fork stealth output must be spent via stealth_explicit_spend" );
   }
   // G1: shared blind gate; V1 spends are spend-only-via-turnstile past sunset.
   if( HARDFORK_STEALTH_PASSED( d.head_block_time() ) )
   {
      stealth_check_blind_gate( d );
      stealth_check_asset_gate( d, o.amount.asset_id );
      FC_ASSERT( d.head_block_time() < stealth_v1_sunset_time( d ),
                 "V1 blind spends are frozen past sunset (use turnstile re-proof)" );
      // G1c parity float rule: withdrawals carry no blind outputs (n = 0).
      // Rule R (EE-1b): op41 is an EXPLICIT spend — it does consume its
      // metadata-bearing inputs (-spent_counted below) — but it carries no
      // outputs member at all, so n_out is 0 and the classifier returns 0 on
      // every shape, preserving the literal `0` verbatim.
      stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                                 o.fee.asset_id, 0,
                                 calculate_fee_for_operation( operation( o ) ),
                                 std::min( 0u, stealth_subsidy_output_count( operation( o ) ) ) );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result transfer_from_blind_evaluator::do_apply( const transfer_from_blind_operation& o )
{ try {
   db().adjust_balance( o.fee_payer(), o.fee );
   db().adjust_balance( o.to, o.amount );
   const auto& bbi = db().get_index_type<blinded_balance_index>();
   const auto& cidx = bbi.indices().get<by_commitment>();
   int32_t spent_counted = 0; // metadata-bearing balances leaving the live set
   for( const auto& in : o.inputs )
   {
      auto itr = cidx.find( in.commitment );
      FC_ASSERT( itr != cidx.end() );
      if( itr->created_block != 0 )
         ++spent_counted; // grandfathered (pre-fork) balances were never counted
      db().remove( *itr );
   }
   const auto& add = o.amount.asset_id(db()).dynamic_asset_data_id(db());  // verify fee is a legit asset
   db().modify( add, [&]( asset_dynamic_data_object& obj ){
      obj.confidential_supply -= o.amount.amount + o.fee.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   });
   stealth_shadow_add( db(), o.amount.asset_id, share_type( -( o.amount.amount + o.fee.amount ).value ) );
   stealth_pool_count_add( db(), o.amount.asset_id, -spent_counted );
   // G1c: parity subsidy settlement (withdrawals carry no new outputs).
   stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                   o.fee.asset_id, 0,
                                   calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                   std::min( 0u, stealth_subsidy_output_count( operation( o ) ) ) );
   stealth_count_blind_op( db() );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void transfer_from_blind_evaluator::pay_fee()
{
   if( db().head_block_time() >= HARDFORK_563_TIME )
      pay_fba_fee( fba_accumulator_id_transfer_from_blind );
   else
      generic_evaluator::pay_fee();
}

void_result blind_transfer_evaluator::do_evaluate( const blind_transfer_operation& o )
{ try {
   const auto& d = db();
   o.fee.asset_id(db());  // verify fee is a legit asset
   const auto& bbi = db().get_index_type<blinded_balance_index>();
   const auto& cidx = bbi.indices().get<by_commitment>();
   for( const auto& out : o.outputs )
   {
      for( const auto& a : out.owner.account_auths )
         a.first(d); // verify all accounts exist and are valid
   }
   for( const auto& in : o.inputs )
   {
      auto itr = cidx.find( in.commitment );
      GRAPHENE_ASSERT( itr != cidx.end(), blind_transfer_unknown_commitment, "", ("commitment",in.commitment) );
      FC_ASSERT( itr->asset_id == o.fee.asset_id );
      FC_ASSERT( itr->owner == in.owner );
      // Task 3 (nullifier migration): post-fork stealth outputs spend ONLY
      // via op108, which nullifier-checks the opening. Grandfathered
      // (pre-fork, created_block == 0) balances keep using this legacy leg
      // exactly as before. Evaluator-only (no wire change: replay-safe).
      FC_ASSERT( itr->created_block == 0,
                 "Post-fork stealth output must be spent via stealth_explicit_spend" );
   }
   // G1: shared blind gate (closes the live gap uniformly), V1 sunset, and
   // sound range proofs on every output (a mismatched-but-well-formed proof
   // passes header checks yet hides a negative-wrapped value; consensus must
   // verify, not just parse).
   if( HARDFORK_STEALTH_PASSED( d.head_block_time() ) )
   {
      stealth_check_blind_gate( d );
      // F-01 (R9B): one V1 range proof per output, charged at the BP+ rate
      // (conservative over-count — see stealth.hpp).
      stealth_check_blind_work_gate( d, stealth_work_for_range_proofs( (uint32_t)o.outputs.size() ) );
      stealth_check_asset_gate( d, o.fee.asset_id );
      FC_ASSERT( d.head_block_time() < stealth_v1_sunset_time( d ),
                 "V1 blind spends are frozen past sunset (use turnstile re-proof)" );
      stealth_require_sound_range_proofs( d, o.outputs );
      // G1c parity float rule (same skip guard). Rule R (EE-1b): a ring
      // spend consumes nothing from the live set, so ΔD_a is +n_out at any
      // ring size and the full per-output component is available here.
      stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                                 o.fee.asset_id, (uint32_t)o.outputs.size(),
                                 calculate_fee_for_operation( operation( o ) ),
                                 std::min( (uint32_t)o.outputs.size(),
                                    stealth_subsidy_output_count( operation( o ) ) ) );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result blind_transfer_evaluator::do_apply( const blind_transfer_operation& o )
{ try {
   db().adjust_balance( o.fee_payer(), o.fee ); // deposit the fee to the temp account
   const auto& bbi = db().get_index_type<blinded_balance_index>();
   const auto& cidx = bbi.indices().get<by_commitment>();
   int32_t spent_counted = 0;
   for( const auto& in : o.inputs )
   {
      auto itr = cidx.find( in.commitment );
      GRAPHENE_ASSERT( itr != cidx.end(), blind_transfer_unknown_commitment, "", ("commitment",in.commitment) );
      if( itr->created_block != 0 )
         ++spent_counted;
      db().remove( *itr );
   }
   const bool post_stealth = HARDFORK_STEALTH_PASSED( db().head_block_time() );
   for( const auto& out : o.outputs )
   {
      db().create<blinded_balance_object>( [&]( blinded_balance_object& obj ){
          obj.asset_id   = o.fee.asset_id;
          obj.owner      = out.owner;
          obj.commitment = out.commitment;
          if( post_stealth )
          {
             obj.created_block = db().head_block_num() + 1;
             obj.created_time  = db().head_block_time();
          }
      });
   }
   const auto& add = o.fee.asset_id(db()).dynamic_asset_data_id(db());
   db().modify( add, [&]( asset_dynamic_data_object& obj ){
      obj.confidential_supply -= o.fee.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   });
   stealth_shadow_add( db(), o.fee.asset_id, share_type( -o.fee.amount.value ) );
   stealth_pool_count_add( db(), o.fee.asset_id, -spent_counted );
   stealth_pool_count_add( db(), o.fee.asset_id, (int32_t)o.outputs.size() );
   // G1c: parity subsidy settlement + skew histogram.
   stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                   o.fee.asset_id, (uint32_t)o.outputs.size(),
                                   calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                   std::min( (uint32_t)o.outputs.size(),
                                      stealth_subsidy_output_count( operation( o ) ) ) );
   stealth_window_count_add( db(), (uint32_t)o.outputs.size() );
   stealth_count_blind_op( db() );
   stealth_count_blind_work( db(), stealth_work_for_range_proofs( (uint32_t)o.outputs.size() ) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void blind_transfer_evaluator::pay_fee()
{
   if( db().head_block_time() >= HARDFORK_563_TIME )
      pay_fba_fee( fba_accumulator_id_blind_transfer );
   else
      generic_evaluator::pay_fee();
}

} } // graphene::chain
