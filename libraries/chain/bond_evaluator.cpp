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
#include <graphene/chain/bond_evaluator.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace chain {

void_result oracle_bond_lock_evaluator::do_evaluate( const oracle_bond_lock_operation& op )
{ try {
   database& d = db();

   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( d.head_block_time() ),
              "Not allowed until the H2 bonds hardfork" );

   FC_ASSERT( nullptr != d.find( op.producer ),
              "Producer account ${a} does not exist", ("a", op.producer) );
   const oracle_object* oracle = d.find( op.oracle );
   FC_ASSERT( nullptr != oracle, "Oracle ${o} does not exist", ("o", op.oracle) );
   FC_ASSERT( oracle->options.producers.find( op.producer )
                 != oracle->options.producers.end(),
              "Producer ${a} is not in the oracle's producer set",
              ("a", op.producer) );

   // One bond per producer per oracle: a second lock is a top-up question for
   // a later task, never a silent duplicate.
   const auto& pair_idx = d.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   FC_ASSERT( pair_idx.find( boost::make_tuple( op.oracle, op.producer ) ) == pair_idx.end(),
              "Producer ${a} already has a bond on oracle ${o}",
              ("a", op.producer)("o", op.oracle) );

   _vesting = d.find( op.vesting_balance );
   FC_ASSERT( nullptr != _vesting,
              "Vesting balance ${v} does not exist", ("v", op.vesting_balance) );
   FC_ASSERT( _vesting->owner == op.producer,
              "Bond vesting balance must be owned by the producer" );
   FC_ASSERT( _vesting->policy.is_type<cdd_vesting_policy>(),
              "Bond vesting balance must use the CDD policy" );
   // BTS-first (inventory OQ-05 reversible minimum): basket assets join in a
   // later task through an explicit allow-list, never silently.
   FC_ASSERT( _vesting->balance.asset_id == asset_id_type(),
              "Producer bonds lock BTS at genesis" );
   FC_ASSERT( _vesting->balance.amount >= op.bond_amount,
              "Bond vesting balance holds insufficient funds" );

   // The USD-terms denomination is the $10,050 proposal exactly: the raw amount
   // is the basis-converted lock recorded alongside it. Live-price conversion
   // enforcement arrives with the H2d price leg.
   FC_ASSERT( op.bond_usd_cents == GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS,
              "Producer bond USD-terms record must equal the genesis min_bond basis" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type oracle_bond_lock_evaluator::do_apply( const oracle_bond_lock_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   const auto& new_bond = d.create<producer_bond_object>(
         [&op, &now]( producer_bond_object& b ) {
      b.oracle           = op.oracle;
      b.producer         = op.producer;
      b.vesting_balance  = op.vesting_balance;
      b.bond_amount      = op.bond_amount;
      b.bond_usd_cents   = op.bond_usd_cents;
      b.lock_time        = now;
      b.unlock_time      = now + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
      b.bootstrap_weight = op.bootstrap_weight;
      b.slashed          = false;
   } );
   return object_id_type( new_bond.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_bond_release_evaluator::do_evaluate( const oracle_bond_release_operation& op )
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( d.head_block_time() ),
              "Not allowed until the H2 bonds hardfork" );

   _bond = d.find( op.bond );
   FC_ASSERT( nullptr != _bond, "Producer bond ${b} does not exist", ("b", op.bond) );
   FC_ASSERT( _bond->producer == op.producer,
              "Only the bond producer may release it" );
   // The bond still secures the oracle until the unlock: early release is
   // refused, and the 7-day unbond is baked into the unlock itself. An open
   // dispute naming the producer additionally blocks release (H2b): the
   // vacuous-true H2a placeholder is now the real query over the defender
   // index. Terminal disputes (decided or expired) no longer block.
   FC_ASSERT( d.head_block_time() >= _bond->unlock_time,
              "Producer bond unlocks at ${u}; release refused before then",
              ("u", _bond->unlock_time) );
   const auto& defender_idx = d.get_index_type<oracle_dispute_index>()
                                 .indices().get<by_dispute_defender>();
   const auto range = defender_idx.equal_range( op.producer );
   for( auto itr = range.first; itr != range.second; ++itr )
      FC_ASSERT( itr->state != GRAPHENE_H2_CHALLENGE_OPEN,
                 "Producer bond is named in open dispute ${x}; release refused",
                 ("x", itr->id) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_bond_release_evaluator::do_apply( const oracle_bond_release_operation& op ) const
{ try {
   database& d = db();
   // Lifting the encumbrance only: funds stay in the vesting balance under
   // normal vesting rules, which still govern withdrawals.
   d.remove( *_bond );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void advance_producer_bond_on_publish( database& d, oracle_id_type oracle,
                                       account_id_type producer,
                                       time_point_sec now )
{
   const auto& pair_idx = d.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   const auto itr = pair_idx.find( boost::make_tuple( oracle, producer ) );
   if( itr == pair_idx.end() || itr->slashed )
      return;   // no bond (every H1 producer): nothing to do
   // Saturating advance: timestamps that cannot advance stay put rather than
   // wrapping, which would silently unlock the bond.
   time_point_sec advanced = itr->unlock_time;
   const uint64_t headroom = uint64_t( time_point_sec::maximum().sec_since_epoch() )
                           - uint64_t( advanced.sec_since_epoch() );
   if( headroom >= GRAPHENE_H2_BOND_ADVANCE_SEC )
      advanced = advanced + GRAPHENE_H2_BOND_ADVANCE_SEC;
   else
      advanced = time_point_sec::maximum();
   d.modify( *itr, [&advanced]( producer_bond_object& b ) { b.unlock_time = advanced; } );
}

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::vault_bond_object, (graphene::db::object),
                    (vault)
                    (owner)
                    (vesting_balance)
                    (bond_amount)
                    (bond_usd_cents)
                    (lock_time)
                    (unbond_delay_sec)
                    (unlock_time)
                    (seized)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::producer_bond_object, (graphene::db::object),
                    (oracle)
                    (producer)
                    (vesting_balance)
                    (bond_amount)
                    (bond_usd_cents)
                    (lock_time)
                    (unlock_time)
                    (bootstrap_weight)
                    (slashed)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::vault_bond_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::producer_bond_object )
