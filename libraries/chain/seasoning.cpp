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
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_evaluator.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/vault_object.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

#include <algorithm>
#include <limits>

namespace graphene { namespace chain {

namespace {

using boost::multiprecision::uint256_t;
using graphene::protocol::GRAPHENE_H2_SEASONING_ORACLE_MIN_BPS;
using graphene::protocol::GRAPHENE_H2_SEASONING_VAULT_MIN_BPS;
using graphene::protocol::GRAPHENE_H2_SEASONING_WINDOW_SEC;

constexpr uint32_t H2_SEASONING_BPS_SATURATE = 0xFFFFFFFF;

/// Saturating share addition for backing scope accounting: bond sums can in
/// principle exceed int64 while the comparison only needs monotonicity
/// (Recovery-scope h2_sat_add precedent in h2_economics.cpp).
share_type h2_seasoning_sat_add( share_type a, share_type b )
{
   if( a <= share_type( 0 ) )
      return b;
   if( b <= share_type( 0 ) )
      return a;
   const uint256_t sum = uint256_t( uint64_t( a.value ) )
                       + uint256_t( uint64_t( b.value ) );
   if( sum > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( sum ) ) );
}

/**
 * Coverage as saturating basis points: backing * 10000 / debt, exact
 * 128-bit division, no floats. Zero (or negative) debt counts as covered
 * (saturates): with no liabilities there is nothing to back, matching the
 * h2_vault_meets_maintenance precedent that zero outstanding meets the
 * maintenance trigger. Saturation is deterministic: every node computes
 * the same quotient and the same cap.
 */
uint32_t h2_seasoning_coverage_bps( share_type backing, share_type debt )
{
   if( debt <= share_type( 0 ) )
      return H2_SEASONING_BPS_SATURATE;
   if( backing <= share_type( 0 ) )
      return 0;
   const fc::uint128_t q = fc::uint128_t( uint64_t( backing.value ) )
                         * fc::uint128_t( 10000 )
                         / fc::uint128_t( uint64_t( debt.value ) );
   if( q >= fc::uint128_t( uint64_t( H2_SEASONING_BPS_SATURATE ) ) )
      return H2_SEASONING_BPS_SATURATE;
   return uint32_t( fc::uint128_lo64( q ) );
}

/// Unseized vault-bond backing for @p vid (same scope as
/// h2_vault_meets_maintenance: seized bonds back nothing).
share_type h2_seasoning_vault_backing( const database& d, vault_id_type vid )
{
   share_type backing( 0 );
   const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
   const auto range = bond_idx.equal_range( vid );
   for( auto itr = range.first; itr != range.second; ++itr )
      if( !itr->seized )
         backing = h2_seasoning_sat_add( backing, itr->bond_amount );
   return backing;
}

/**
 * Unslashed producer-bond backing for @p oid. A backing-SIZE sum, not the
 * bonded-live read gate (h2_oracle_has_bonded_live_set): the BSIP-H2
 * formula is oracle_bonds / secured_debt, a size ratio over locked funds,
 * so liveness, weights, and unlock posture do not filter rows -- slashed
 * bonds (dispute-loss, H2b) back nothing and are the only exclusion.
 * Unbounded by row count like the dispute-history scans (producer churn
 * can strand rows past the 32-producer set cap); stranded rows stay
 * countable because they are still locked funds.
 */
share_type h2_seasoning_oracle_backing( const database& d, oracle_id_type oid )
{
   share_type backing( 0 );
   const auto& bond_idx = d.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oid ) );
         bitr != bond_idx.end() && bitr->oracle == oid; ++bitr )
      if( !bitr->slashed )
         backing = h2_seasoning_sat_add( backing, bitr->bond_amount );
   return backing;
}

const seasoning_record_object* h2_find_seasoning( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<seasoning_record_index>()
                        .indices().get<by_seasoning_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

} // namespace

void h2_create_seasoning_record( database& d, asset_id_type pair,
                                 time_point_sec now )
{
   FC_ASSERT( h2_find_seasoning( d, pair ) == nullptr,
              "Pair ${p} already carries a seasoning record; duplicates refused",
              ("p", pair) );
   d.create<seasoning_record_object>( [&pair, &now]( seasoning_record_object& r ) {
      r.pair = pair;
      r.genesis_time = now;
      r.window_start = now;
      // No observation yet: minimums open at saturation so the first sweep's
      // fold takes the current coverages verbatim (min(saturate, cur) = cur).
      r.min_vault_bps = H2_SEASONING_BPS_SATURATE;
      r.min_oracle_bps = H2_SEASONING_BPS_SATURATE;
      r.verifier_set = false;
      r.complete = false;
      r.breach_count = 0;
   } );
}

void h2_reseed_seasoning_on_bind( database& d, asset_id_type pair )
{
   const seasoning_record_object* r = h2_find_seasoning( d, pair );
   if( r == nullptr )
      return;
   const auto now = d.head_block_time();
   d.modify( *r, [&now]( seasoning_record_object& m ) {
      m.window_start = now;
      m.min_vault_bps = H2_SEASONING_BPS_SATURATE;
      m.min_oracle_bps = H2_SEASONING_BPS_SATURATE;
      m.complete = false;
   } );
}

void process_h2_seasoning( database& d )
{
   if( !HARDFORK_H2_GATEWAY_PASSED( d.head_block_time() ) )
      return; // pre-gateway no record can exist (created at vault_register); the sweep is a no-op
   const auto now = d.head_block_time();
   const auto& pair_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   const auto& rec_idx = d.get_index_type<seasoning_record_index>().indices();
   for( auto ritr = rec_idx.begin(); ritr != rec_idx.end(); ++ritr )
   {
      // H2 bonded state only: vault bonds + outstanding + producer bonds.
      // No oracle read, no H1 state, no wall-clock -- head-block time only.
      const auto vitr = pair_idx.find( ritr->pair );
      share_type debt( 0 );
      uint32_t cur_vault_bps = 0;
      uint32_t cur_oracle_bps = 0;
      bool vault_ok = false;
      bool oracle_ok = false;
      if( vitr != pair_idx.end() )
      {
         // R11R2: an unbound pair names no bonded price series, so the
         // oracle leg cannot be measured -- and measuring it as zero would
         // poison min_oracle_bps to 0 with no recovery (covered sweeps fold
         // min(), so the poison sticks forever past binding and no
         // consensus path reaches first mint). The record is skipped
         // outright until the bind reseeds it (pair_freeze first pin): no
         // window move, no minimums touch, no breach counted. The
         // completion helper fail-closes unbound pairs, so the skip can
         // never read open.
         if( !vitr->bound_oracle.valid() )
            continue;
         debt = vitr->outstanding;
         cur_vault_bps = h2_seasoning_coverage_bps(
               h2_seasoning_vault_backing( d, vault_id_type( vitr->id ) ), debt );
         vault_ok = cur_vault_bps >= GRAPHENE_H2_SEASONING_VAULT_MIN_BPS;
         // Bound here (unbound records skipped above): measure the oracle leg
         // through the canonical binding pinned by the first pair_freeze.
         cur_oracle_bps = h2_seasoning_coverage_bps(
               h2_seasoning_oracle_backing( d, *vitr->bound_oracle ), debt );
         oracle_ok = cur_oracle_bps >= GRAPHENE_H2_SEASONING_ORACLE_MIN_BPS;
      }
      // A missing vault is unreachable (records are created with their
      // vault, which is never deleted); treated as a dual breach so the
      // clock fails closed, never open, on structural surprise.
      if( vault_ok && oracle_ok )
      {
         const uint32_t next_vault_min = std::min( ritr->min_vault_bps, cur_vault_bps );
         const uint32_t next_oracle_min = std::min( ritr->min_oracle_bps, cur_oracle_bps );
         // Recomputed, never latched: a post-complete breach resets the
         // window below and falsifies the predicate here, clearing the flag
         // in the same sweep. No block observes complete with a fresh start.
         const bool done = ( now >= ritr->window_start + GRAPHENE_H2_SEASONING_WINDOW_SEC )
                         && next_vault_min >= GRAPHENE_H2_SEASONING_VAULT_MIN_BPS
                         && next_oracle_min >= GRAPHENE_H2_SEASONING_ORACLE_MIN_BPS
                         && ritr->verifier_set;
         d.modify( *ritr, [&]( seasoning_record_object& r ) {
            r.min_vault_bps = next_vault_min;
            r.min_oracle_bps = next_oracle_min;
            r.complete = done;
         } );
      }
      else
      {
         // CONTINUOUS-HOLD, not cumulative: any breaching sweep restarts the
         // 90-day clock at head-block time and reopens the minimums at the
         // current (breaching) values. Partial-window cover cannot bank.
         // AC-15c: the breach is COUNTED, never erased -- breach_count rises
         // monotonically (saturating at uint64 max, never wrapping) and is
         // never cleared by covered sweeps, so a third party can reconstruct
         // the ungated days from (breach_count, window_start, genesis_time).
         d.modify( *ritr, [&]( seasoning_record_object& r ) {
            r.window_start = now;
            r.min_vault_bps = cur_vault_bps;
            r.min_oracle_bps = cur_oracle_bps;
            r.complete = false;
            if( r.breach_count < std::numeric_limits<uint64_t>::max() )
               ++r.breach_count;
         } );
      }
   }
}

bool h2_seasoning_complete( const database& d, asset_id_type pair )
{
   const seasoning_record_object* r = h2_find_seasoning( d, pair );
   if( r == nullptr )
      return false;
   // R11R2 fail-closed: an unbound pair names no bonded price series, so it
   // never reads complete no matter what the swept minimums say (pre-bind
   // sweeps are skipped outright, leaving the saturating genesis minimums in
   // place -- without this the skip would read open after 90 days).
   const auto& vault_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   const auto vitr = vault_idx.find( pair );
   if( vitr == vault_idx.end() || !vitr->bound_oracle.valid() )
      return false;
   const auto now = d.head_block_time();
   return ( now >= r->window_start + GRAPHENE_H2_SEASONING_WINDOW_SEC )
       && r->min_vault_bps >= GRAPHENE_H2_SEASONING_VAULT_MIN_BPS
       && r->min_oracle_bps >= GRAPHENE_H2_SEASONING_ORACLE_MIN_BPS
       && r->verifier_set;
}

void_result seasoning_verify_evaluator::do_evaluate( const seasoning_verify_operation& op )
{ try {
   database& d = db();

   // Price leg (BSIP-1 section 5): the attestation judges bonded backing,
   // so it admits at the price height. Ordering asserted inside.
   h2_require_price_leg( d.head_block_time() );

   _record = h2_find_seasoning( d, op.pair );
   FC_ASSERT( nullptr != _record,
              "Pair ${p} carries no seasoning record; only BTC ACCS-activated pairs verify",
              ("p", op.pair) );
   FC_ASSERT( !_record->verifier_set,
              "Pair ${p} is already verified by ${v}; double attestation refused",
              ("p", op.pair)("v", _record->verifier) );
    const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
    const auto mitr = member_idx.find( op.verifier );
    FC_ASSERT( mitr != member_idx.end(),
               "Verifier ${a} is not a seated committee member", ("a", op.verifier) );
    // GOV-R17-04 / ATR-R17-02 (round-17, merged at synthesis): committee_member_create
    // is permissionless (op-29, LTM only) and registry rows are never pruned, so
    // registry membership alone is a sybil door -- a pair operator could register a
    // second committee account, attest their own vault, and self-issue the AC-08
    // independence bit for the price of one registration. Mirror the elected-set
    // gate the H2 oracle_evaluator (GOV-R17-03) and pair_freeze carry: the verifier
    // must sit in the stake-elected active_committee_members set. The overlap walks
    // below are unchanged.
    const auto& elected = d.get_global_properties().active_committee_members;
    FC_ASSERT( std::find( elected.begin(), elected.end(), mitr->get_id() ) != elected.end(),
               "Verifier ${a} is not in the elected committee set", ("a", op.verifier) );

    // AC-16 (round-9): the attestation judges the pair's bonded backing, so
    // no party to the pair may issue it -- a self-attested 90-day clock is
    // worth nothing to a downstream USD-issuance gate. Both legs are walked
    // with the SAME bounded authority graph the challenge self-dealing ban
    // uses (h2_authority_graphs_overlap): the pair's ISSUER, then the VAULT's
    // registered authority. Identity is subsumed by the walk
    // (h2_collect_account_side inserts the root account); the explicit
    // message per leg keeps the refuse reason readable. Fail-closed: a
    // seasoning record exists only for a registered vault, so the lookup
    // below cannot miss; a record with no vault row is refused outright
    // rather than skipped.
    FC_ASSERT( !h2_authority_graphs_overlap( d, op.verifier,
                 authority( 1, op.pair( d ).issuer, 1 ) ),
               "Seasoning verifier ${a} shares authority with the pair's issuer",
               ("a", op.verifier) );
    const auto& vault_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
    const auto vitr = vault_idx.find( op.pair );
    FC_ASSERT( vitr != vault_idx.end(),
               "Pair ${p} carries a seasoning record but no vault; attestation refused",
               ("p", op.pair) );
    FC_ASSERT( !h2_authority_graphs_overlap( d, op.verifier, vitr->vault_authority ),
               "Seasoning verifier ${a} shares authority with the pair's vault authority",
               ("a", op.verifier) );

    return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result seasoning_verify_evaluator::do_apply( const seasoning_verify_operation& op ) const
{ try {
   database& d = db();
   // Once-only set: identity recorded, never anonymous. Completeness still
   // needs the sweep (90 days + minimums); this op sets the bit only.
   d.modify( *_record, [&op]( seasoning_record_object& r ) {
      r.verifier_set = true;
      r.verifier = op.verifier;
   } );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::seasoning_record_object, (graphene::db::object),
                    (pair)
                    (genesis_time)
                    (window_start)
                    (min_vault_bps)
                    (min_oracle_bps)
                    (verifier_set)
                    (verifier)
                    (complete)
                    (breach_count)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::seasoning_record_object )
