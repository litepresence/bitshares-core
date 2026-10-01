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
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

namespace graphene { namespace chain {

namespace {

using boost::multiprecision::uint256_t;
using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW;
using graphene::protocol::GRAPHENE_H2_ISSUE_BAND_TICK_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_CAP_K1_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_CAP_K2_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_DOOR_CAP_BTS;
using graphene::protocol::GRAPHENE_H2_ISSUE_EXIT_FEE_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS;
using graphene::protocol::GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT;
using graphene::protocol::GRAPHENE_H2_ISSUE_FXR_GENESIS_PARITY;
using graphene::protocol::GRAPHENE_H2_ISSUE_N_BANDS;
using graphene::protocol::GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS;
using graphene::protocol::GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC;
using graphene::protocol::GRAPHENE_H2_ISSUE_PENDING_VEST_CAP;
using graphene::protocol::GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC;
using graphene::protocol::GRAPHENE_H2_ISSUE_RMIN_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_TARGET_BPS;
using graphene::protocol::h2_issue_band_edge_bps;

/// Conversion-fee slice (declared, floored, exact): floor(amount * 30 /
/// 10000) in 256-bit with one truncating division. The slice never leaves
/// the reserve: on mints it backs the book while buying no stable (the
/// per-request coverage check prices the NET deposit); on redeems it is
/// withheld from the vesting payout (the payout legs below subtract it
/// before booking escrow). Rounding favors the protocol (the slice floors,
/// the minter/redeemer pays the truncation). Non-positive input yields 0.
share_type h2_issue_fee_slice( share_type amount )
{
   if( amount <= share_type( 0 ) )
      return share_type( 0 );
   const uint256_t slice = uint256_t( uint64_t( amount.value ) )
                         * uint256_t( GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS )
                         / uint256_t( 10000 );
   return share_type( int64_t( uint64_t( slice ) ) );
}

/// Saturating share addition (Recovery-scope h2_sat_add precedent):
/// pair-level totals can in principle exceed int64 while comparisons only
/// need monotonicity. Checked share math (+=) still throws on overflow at
/// the object write; this helper is for read-side sums only.
share_type h2_issue_sat_add( share_type a, share_type b )
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
 * rmin gate (declared, exact, no floats, no division): does reserve
 * @p bts_raw BTS backing @p supply_face face at @p price at or above
 * @p rmin_bps? Face value of the reserve is bts_raw * quote / base, so
 * value/supply >= rmin/10000 cross-multiplies (256-bit) to
 * bts_raw * quote * 10000 >= supply_face * base * rmin_bps.
 * Equality MEETS (the floor is inclusive headroom, tripwire-breach
 * precedent). Every factor is non-negative by construction; callers
 * guarantee supply_face > 0 and a non-degenerate price.
 */
bool h2_issue_meets_rmin( share_type bts_raw, share_type supply_face,
                          const protocol::oracle_value& price, uint32_t rmin_bps )
{
   if( bts_raw < share_type( 0 ) || supply_face <= share_type( 0 ) )
      return false;
   const uint256_t lhs = uint256_t( uint64_t( bts_raw.value ) )
                       * uint256_t( uint64_t( price.quote_amount.value ) )
                       * uint256_t( 10000 );
   const uint256_t rhs = uint256_t( uint64_t( supply_face.value ) )
                       * uint256_t( uint64_t( price.base_amount.value ) )
                       * uint256_t( rmin_bps );
   return lhs >= rhs;
}

/**
 * Target surplus (declared, floored, exact): max(0, value_face -
 * floor(target_bps * supply_face / 10000)), the face value above the
 * surplus target. 256-bit products, one truncating division: every node
 * computes the same surplus.
 */
uint256_t h2_issue_surplus_face( share_type bts_raw, share_type supply_face,
                                 const protocol::oracle_value& price,
                                 uint32_t target_bps )
{
   if( bts_raw <= share_type( 0 ) || supply_face < share_type( 0 ) )
      return uint256_t( 0 );
   // value_face = floor(bts_raw * quote / base): same truncation as the
   // bts_to_face conversion (one formula, one rounding, shared with it).
   const uint256_t value_face =
         uint256_t( uint64_t( bts_raw.value ) )
         * uint256_t( uint64_t( price.quote_amount.value ) )
         / uint256_t( uint64_t( price.base_amount.value ) );
   const uint256_t target_face =
         uint256_t( uint64_t( supply_face.value ) )
         * uint256_t( target_bps ) / uint256_t( 10000 );
   return value_face > target_face ? value_face - target_face : uint256_t( 0 );
}

/// Door accounting: the counter belongs to @p head_block iff the reserve
/// exists and stamped this block; otherwise the block opens at zero.
share_type h2_issue_door_used( const reserve_object* reserve, uint32_t head_block )
{
   if( reserve == nullptr || reserve->door_block != head_block )
      return share_type( 0 );
   return reserve->door_used_bts;
}

/// Band vector invariant: exactly N_BANDS entries (fresh zeros when absent).
/// Pre-ISSUANCE-2 reserves cannot exist on any live chain (ISSUANCE-1 never
/// activated); in-test reserves always build through the creators below, so
/// this is belt-and-suspenders, never a migration.
void h2_issue_ensure_bands( vector<share_type>& bands )
{
   if( bands.size() != GRAPHENE_H2_ISSUE_N_BANDS )
   {
      bands.clear();
      bands.reserve( GRAPHENE_H2_ISSUE_N_BANDS );
      for( uint32_t i = 0; i < GRAPHENE_H2_ISSUE_N_BANDS; ++i )
         bands.push_back( share_type( 0 ) );
   }
}

/// Spend @p amount from @p bands center-outward (order 3,4,2,5,1,6,0:
/// the active issuance band first, then alternating premium/discount).
/// Exact, deterministic, fail-closed: callers hold conservation by
/// construction (band sums equal the totals), so any remainder is a
/// consensus bug and is refused, never printed. Rounding: none -- takes
/// exact minima, no division anywhere.
void h2_issue_bands_spend( vector<share_type>& bands, share_type amount )
{
   h2_issue_ensure_bands( bands );
   static const uint32_t order[7] = { 3, 4, 2, 5, 1, 6, 0 };
   share_type remaining = amount;
   for( uint32_t k = 0; k < GRAPHENE_H2_ISSUE_N_BANDS && remaining > share_type( 0 ); ++k )
   {
      share_type& band = bands[ order[k] ];
      const share_type take = std::min( band, remaining );
      band -= take;
      remaining -= take;
   }
   FC_ASSERT( remaining == share_type( 0 ),
              "Band spend exceeds the partitioned total; conservation broken" );
}

/// Price direction at two bonded prices (bond-per-face convention): is @p now
/// strictly above @p anchor? Exact 256-bit cross-multiply, no division.
bool h2_issue_price_up( const protocol::oracle_value& anchor,
                        const protocol::oracle_value& now )
{
   return uint256_t( uint64_t( now.base_amount.value ) )
        * uint256_t( uint64_t( anchor.quote_amount.value ) )
        > uint256_t( uint64_t( anchor.base_amount.value ) )
        * uint256_t( uint64_t( now.quote_amount.value ) );
}

} // namespace

bool h2_issue_price_moved( const protocol::oracle_value& anchor,
                           const protocol::oracle_value& now )
{
   if( anchor.base_amount <= share_type( 0 ) || anchor.quote_amount <= share_type( 0 )
       || now.base_amount <= share_type( 0 ) || now.quote_amount <= share_type( 0 ) )
      return false; // degenerate inputs never count as moves (fail-closed)
   // |now - anchor| / anchor > 125/10000, cross-multiplied (256-bit):
   // |now.base*anchor.quote - anchor.base*now.quote| * 10000
   //    > 125 * anchor.base * anchor.quote.
   // Equality is NOT a move (inclusive headroom: no churn on the boundary).
   const uint256_t lhs_a = uint256_t( uint64_t( now.base_amount.value ) )
                         * uint256_t( uint64_t( anchor.quote_amount.value ) );
   const uint256_t lhs_b = uint256_t( uint64_t( anchor.base_amount.value ) )
                         * uint256_t( uint64_t( now.quote_amount.value ) );
   const uint256_t dist = lhs_a >= lhs_b ? lhs_a - lhs_b : lhs_b - lhs_a;
   const uint256_t bound = uint256_t( uint64_t( anchor.base_amount.value ) )
                         * uint256_t( uint64_t( anchor.quote_amount.value ) )
                         * uint256_t( GRAPHENE_H2_ISSUE_BAND_TICK_BPS / 2 );
   return dist * uint256_t( 10000 ) > bound;
}

bool h2_offset_should_absorb( share_type bts_raw, share_type supply_face,
                              const protocol::oracle_value& price )
{
   if( price.base_amount <= share_type( 0 ) || price.quote_amount <= share_type( 0 ) )
      return false; // degenerate prices never trigger (fail-closed)
   if( bts_raw < share_type( 0 ) || supply_face <= share_type( 0 ) )
      return false;
   // Below 100% after bands: bts*quote < supply*base (256-bit, no division).
   // Equality (exactly 100%) does NOT trigger.
   return uint256_t( uint64_t( bts_raw.value ) )
        * uint256_t( uint64_t( price.quote_amount.value ) )
        < uint256_t( uint64_t( supply_face.value ) )
        * uint256_t( uint64_t( price.base_amount.value ) );
}

share_type h2_offset_shortfall_bts( share_type bts_raw, share_type supply_face,
                                    const protocol::oracle_value& price )
{
   if( !h2_offset_should_absorb( bts_raw, supply_face, price ) )
      return share_type( 0 );
   // ceil((supply*base - bts*quote) / quote): ceiling favors the protocol
   // (absorbs the full shortfall, never a hair under). 256-bit, saturating.
   const uint256_t num = uint256_t( uint64_t( supply_face.value ) )
                       * uint256_t( uint64_t( price.base_amount.value ) )
                       - uint256_t( uint64_t( bts_raw.value ) )
                       * uint256_t( uint64_t( price.quote_amount.value ) );
   const uint256_t den = uint256_t( uint64_t( price.quote_amount.value ) );
   const uint256_t q = ( num + den - uint256_t( 1 ) ) / den;
   if( q > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( q ) ) );
}

namespace {

/// Rebalance helper: anchor when unanchored, shift one band step when the
/// consumed price moved beyond half a tick. At most one step per call
/// (bounded churn: a price gap never avalanches the partition in one
/// conversion). Shift quantum floors (dust stays in the source band,
/// favoring the protocol); the anchor still advances on dust (the price
/// basis moves once observed, the partition catches up). Totals conserved
/// exactly (equal amounts move on both legs is NOT required: each leg moves
/// its own floored quantum, and both stay within their own sums).
void h2_issue_maybe_rebalance( reserve_object& r,
                               const protocol::oracle_value& price,
                               uint32_t head_block )
{
   h2_issue_ensure_bands( r.band_bts );
   h2_issue_ensure_bands( r.band_stable );
   if( r.band_anchor.base_amount <= share_type( 0 )
       || r.band_anchor.quote_amount <= share_type( 0 ) )
   {
      r.band_anchor = price; // first anchoring: no shift, never a move
      r.band_block = head_block;
      return;
   }
   if( !h2_issue_price_moved( r.band_anchor, price ) )
      return; // inside half a tick: no churn
   const bool up = h2_issue_price_up( r.band_anchor, price );
   // Source: fullest BTS band (tie: lowest index -- deterministic).
   uint32_t src = 0;
   for( uint32_t i = 1; i < GRAPHENE_H2_ISSUE_N_BANDS; ++i )
      if( r.band_bts[i] > r.band_bts[src] )
         src = i;
   const int64_t q_bts = r.band_bts[src].value / int64_t( GRAPHENE_H2_ISSUE_N_BANDS );
   const int64_t q_face = r.band_stable[src].value / int64_t( GRAPHENE_H2_ISSUE_N_BANDS );
   uint32_t dst = src;
   if( up && src + 1 < GRAPHENE_H2_ISSUE_N_BANDS )
      dst = src + 1;
   else if( !up && src > 0 )
      dst = src - 1;
   if( dst != src && ( q_bts > 0 || q_face > 0 ) )
   {
      r.band_bts[src] -= share_type( q_bts );
      r.band_bts[dst] += share_type( q_bts );
      r.band_stable[src] -= share_type( q_face );
      r.band_stable[dst] += share_type( q_face );
   }
   r.band_anchor = price;
   r.band_block = head_block;
}

/// Queued value in BTS at @p price: sum of ceil(face*base/quote) per
/// request (256-bit, saturating at max supply for the SUM only -- callers
/// compare against the queue value cap). Ceiling over-counts, refusing
/// sooner: favors the protocol on a LIMIT (opposite direction from payout
/// floors, documented here and at the call site).
uint256_t h2_issue_queue_value_256( const reserve_object* reserve,
                                    const protocol::oracle_value& price )
{
   uint256_t total( 0 );
   if( reserve == nullptr || price.base_amount <= share_type( 0 )
       || price.quote_amount <= share_type( 0 ) )
      return total;
   for( const h2_exit_request& req : reserve->exit_queue )
   {
      if( req.face <= share_type( 0 ) )
         continue;
      const uint256_t num = uint256_t( uint64_t( req.face.value ) )
                          * uint256_t( uint64_t( price.base_amount.value ) );
      const uint256_t den = uint256_t( uint64_t( price.quote_amount.value ) );
      total += ( num + den - uint256_t( 1 ) ) / den;
   }
   return total;
}

/// Tripwire depth qualifier, same rule as the H2d sweep (h2_windows_valid
/// precedent, duplicated read-only: both windows non-empty, both at depth,
/// two distinct pools across both). No tripwire state: boost::none =
/// pre-pool bootstrap (depth leg skipped). Unqualified state: valid
/// optional holding 0 = fail-closed refuse (impact cannot be priced).
optional<uint64_t> h2_issue_qualified_depth( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<tripwire_index>().indices().get<by_tripwire_pair>();
   const auto itr = idx.find( pair );
   if( itr == idx.end() )
      return optional<uint64_t>(); // no state: bootstrap, depth leg skipped
   if( itr->win_old.samples.empty() || itr->win_new.samples.empty() )
      return optional<uint64_t>( uint64_t( 0 ) );
   if( itr->win_old.total_volume < GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW
       || itr->win_new.total_volume < GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW )
      return optional<uint64_t>( uint64_t( 0 ) );
   flat_set<liquidity_pool_id_type> pools = itr->win_old.pools;
   pools.insert( itr->win_new.pools.begin(), itr->win_new.pools.end() );
   if( pools.size() < 2 )
      return optional<uint64_t>( uint64_t( 0 ) ); // single-pool depth refused
   const uint256_t sum = uint256_t( itr->win_old.total_volume )
                       + uint256_t( itr->win_new.total_volume );
   const uint64_t cap = std::numeric_limits<uint64_t>::max();
   return optional<uint64_t>( sum > uint256_t( cap ) ? cap : uint64_t( sum ) );
}

/// Absorb pass for one pair: move min(pool, shortfall) into the reserve
/// (center band 3, the active issuance band) and record the remainder as
/// uncovered_shortfall (overwritten each computation, 0 when covered).
/// Obligations are supply PLUS queued exit face (both draw the reserve);
/// the shortfall restores 100% against their sum. No bonded price: hold
/// everything fail-closed (no absorb, no record).
void h2_issue_absorb_pair( database& d, const reserve_object& reserve,
                           const vault_object& vault,
                           const protocol::oracle_value& price )
{
   share_type obligations = reserve.stable_supply;
   for( const h2_exit_request& req : reserve.exit_queue )
      obligations = h2_issue_sat_add( obligations, req.face );
   if( !h2_offset_should_absorb( reserve.bts_balance, obligations, price ) )
   {
      if( reserve.uncovered_shortfall != share_type( 0 ) )
         d.modify( reserve, []( reserve_object& r ) { r.uncovered_shortfall = share_type( 0 ); } );
      return;
   }
   const share_type shortfall = h2_offset_shortfall_bts(
         reserve.bts_balance, obligations, price );
   const offset_pool_object* pool = h2_find_offset_pool( d, reserve.pair );
   share_type take( 0 );
   if( pool != nullptr && pool->balance > share_type( 0 ) )
      take = std::min( pool->balance, shortfall );
   if( take > share_type( 0 ) )
   {
      // Absorbers take the first loss pro-rata: the pool balance funds the
      // reserve, and every claim haircuts by the same factor (floored,
      // favoring the remaining coverage; zeroed claims prune). The
      // sum(claims) <= balance invariant holds by construction (deposits
      // enter 1:1, absorbs scale both legs, payouts reduce both equally).
      const share_type old_bal = pool->balance;
      const share_type new_bal = old_bal - take;
      d.modify( *pool, [&]( offset_pool_object& p ) {
         p.balance = new_bal;
         for( auto itr = p.claims.begin(); itr != p.claims.end(); )
         {
            const uint256_t scaled = uint256_t( uint64_t( itr->amount.value ) )
                                   * uint256_t( uint64_t( new_bal.value ) )
                                   / uint256_t( uint64_t( old_bal.value ) );
            if( scaled == uint256_t( 0 ) )
               itr = p.claims.erase( itr ); // dust haircut to zero: pruned
            else
            {
               itr->amount = share_type( int64_t( uint64_t( scaled ) ) );
               ++itr;
            }
         }
      } );
      d.modify( reserve, [&take]( reserve_object& r ) {
         h2_issue_ensure_bands( r.band_bts );
         r.bts_balance += take;
         r.band_bts[3] += take;
      } );
   }
   const share_type uncovered = shortfall - take;
   if( reserve.uncovered_shortfall != uncovered )
      d.modify( reserve, [&uncovered]( reserve_object& r ) { r.uncovered_shortfall = uncovered; } );
   (void)vault;
}

/// Count unmatured (still pending) door outputs: vesting exists, linear
/// policy, head time before begin + duration. Missing/non-linear/matured
/// entries read STOOD (pruned, never repriced).
size_t h2_issue_pending_unmatured( const database& d, const reserve_object& reserve,
                                   time_point_sec now )
{
   size_t n = 0;
   for( const h2_pending_vesting& p : reserve.pending_vestings )
   {
      const vesting_balance_object* vb = d.find( p.owner_vesting );
      if( vb == nullptr || !vb->policy.is_type<linear_vesting_policy>() )
         continue;
      const linear_vesting_policy& lin = vb->policy.get<linear_vesting_policy>();
      if( now < lin.begin_timestamp + lin.vesting_duration_seconds )
         ++n;
   }
   return n;
}

} // namespace

const reserve_object* h2_find_reserve( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<reserve_index>().indices().get<by_reserve_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

const offset_pool_object* h2_find_offset_pool( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<offset_pool_index>().indices().get<by_offset_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

bool h2_issue_door_admits( const database& d,
                             const reserve_object* reserve,
                             asset_id_type pair,
                             const protocol::oracle_value& price,
                             share_type used, share_type leg )
{
   // Fixed DOS ceiling (ISSUANCE-1 semantics, unchanged): the shared
   // per-block counter bounds all door flow through one compare.
   if( leg < share_type( 0 ) || used < share_type( 0 ) )
      return false;
   if( uint256_t( uint64_t( used.value ) ) + uint256_t( uint64_t( leg.value ) )
       > uint256_t( GRAPHENE_H2_ISSUE_DOOR_CAP_BTS ) )
      return false;
   // Headroom extraction bound on the MARGINAL leg (genesis skips: no
   // standing headroom; rmin guards creation). Required-BTS ceilings,
   // leg floors: both favor the protocol.
   if( reserve != nullptr && price.base_amount > share_type( 0 )
       && price.quote_amount > share_type( 0 ) && reserve->stable_supply > share_type( 0 ) )
   {
      const uint256_t req_num = uint256_t( uint64_t( reserve->stable_supply.value ) )
                              * uint256_t( uint64_t( price.base_amount.value ) )
                              * uint256_t( GRAPHENE_H2_ISSUE_RMIN_BPS );
      const uint256_t req_den = uint256_t( uint64_t( price.quote_amount.value ) )
                              * uint256_t( 10000 );
      const uint256_t required = ( req_num + req_den - uint256_t( 1 ) ) / req_den;
      const uint256_t have = uint256_t( uint64_t( reserve->bts_balance.value ) );
      const uint256_t headroom = have > required ? have - required : uint256_t( 0 );
      const uint256_t bound = headroom * uint256_t( GRAPHENE_H2_ISSUE_CAP_K1_BPS )
                              / uint256_t( 10000 );
      if( uint256_t( uint64_t( leg.value ) ) > bound )
         return false;
   }
   // Depth flow bound on the marginal leg (pre-pool skips: no tripwire
   // state; unqualified live state refuses outright).
   const optional<uint64_t> depth = h2_issue_qualified_depth( d, pair );
   if( depth.valid() )
   {
      if( *depth == uint64_t( 0 ) )
         return false; // thin/single-pool depth: no flow
      const uint256_t bound = uint256_t( *depth )
                              * uint256_t( GRAPHENE_H2_ISSUE_CAP_K2_BPS )
                              / uint256_t( 10000 );
      if( uint256_t( uint64_t( leg.value ) ) > bound )
         return false;
   }
   return true;
}

bool h2_issue_exit_suspended( const reserve_object* reserve,
                              const protocol::oracle_value& price )
{
   if( reserve == nullptr )
      return false;
   if( reserve->exit_queue.size() >= GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT )
      return true;
   return h2_issue_queue_value_256( reserve, price )
        >= uint256_t( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS );
}

void h2_issue_maintenance( database& d )
{
   if( !HARDFORK_H2_PRICE_PASSED( d.head_block_time() ) )
      return; // pre-leg no issuance state can exist; the sweep is a no-op
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();
   // Collect pairs first: settlement modifies reserves mid-walk.
   vector<asset_id_type> pairs;
   const auto& ridx = d.get_index_type<reserve_index>().indices();
   pairs.reserve( ridx.size() );
   for( const reserve_object& r : ridx )
      pairs.push_back( r.pair );
   const auto& vault_by_pair = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   for( const asset_id_type pair : pairs )
   {
      const reserve_object* reserve = h2_find_reserve( d, pair );
      if( reserve == nullptr )
         continue;
      const auto vitr = vault_by_pair.find( pair );
      if( vitr == vault_by_pair.end() )
         continue;
      const auto price = h2_read_pair_price( d, *vitr, 0, now );
      if( !price.valid() )
         continue; // dual-stale: hold queue + shortfall fail-closed
      // 1. Absorb residual shortfalls (offset pool first, remainder recorded
      //    for the rmax junior path). Instant on detection, every pass.
      h2_issue_absorb_pair( d, *reserve, *vitr, *price );
      // 2. Batch-settle the exit queue in ONE pass at ONE clearing haircut.
      // Obligations are supply PLUS queued face (both draw the reserve);
      // the haircut covers their sum, so a deep crash cannot overpay past
      // the reserve. Per request the payout is min(haircut-face, pro-rata
      // share) -- both legs floored against the claimant (favoring the
      // protocol); the haircut leg binds above water, the pro-rata leg is
      // declared defense-in-depth for integer edges.
      reserve = h2_find_reserve( d, pair ); // absorb may have modified it
      if( reserve == nullptr || reserve->exit_queue.empty() )
         continue;
      const share_type bts_now = reserve->bts_balance;
      share_type total_face = reserve->stable_supply;
      for( const h2_exit_request& req : reserve->exit_queue )
         total_face = h2_issue_sat_add( total_face, req.face );
      uint32_t haircut = 0;
      if( total_face > share_type( 0 ) )
      {
         const uint32_t coverage = h2_issue_coverage_bps(
               h2_issue_bts_to_face( bts_now, *price ), total_face );
         // Coverage floors, so the haircut rounds UP against claimants:
         // favors the protocol, documented.
         haircut = coverage >= 10000 ? 0 : 10000 - coverage;
      }
      const uint32_t fee = GRAPHENE_H2_ISSUE_EXIT_FEE_BPS;
      const int64_t factor = int64_t( 10000 ) - int64_t( haircut ) - int64_t( fee );
      const vector<h2_exit_request> batch = reserve->exit_queue; // copy: pay below
      for( const h2_exit_request& req : batch )
      {
         const share_type gross = h2_issue_face_to_bts( req.face, *price );
         share_type haircut_pay( 0 );
         if( gross > share_type( 0 ) && factor > 0 )
         {
            // ONE truncating multiply (declared 2% fee + batch haircut):
            // floors against the claimant, favoring the protocol. Zero or
            // negative factors pay nothing (dust-forfeit, documented).
            const uint256_t n = uint256_t( uint64_t( gross.value ) )
                              * uint256_t( uint64_t( factor ) )
                              / uint256_t( 10000 );
            if( n > uint256_t( 0 ) && n <= uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
               haircut_pay = share_type( int64_t( uint64_t( n ) ) );
         }
         // Pro-rata share of the opening reserve (floored, favoring the
         // protocol): no batch can overpay past what is there.
         const uint256_t p = uint256_t( uint64_t( req.face.value ) )
                           * uint256_t( uint64_t( bts_now.value ) )
                           / uint256_t( uint64_t( total_face.value ) );
         share_type pro_rata( 0 );
         if( p > uint256_t( 0 ) )
            pro_rata = share_type( int64_t( uint64_t( p ) ) );
         const share_type net = std::min( haircut_pay, pro_rata );
         if( net > share_type( 0 ) )
         {
            FC_ASSERT( net <= reserve->bts_balance,
                       "Batch exit payout exceeds the reserve; coverage moved inside settle" );
            d.adjust_balance( req.requester, asset( net, asset_id_type() ) );
            d.modify( *reserve, [&net]( reserve_object& r ) {
               r.bts_balance -= net;
               h2_issue_bands_spend( r.band_bts, net );
            } );
            reserve = h2_find_reserve( d, pair );
            FC_ASSERT( reserve != nullptr, "Issuance reserve vanished inside exit settle" );
         }
         // net == 0: dust-forfeit (face already burned at request; the
         // request-time dust gate makes this unreachable except under a
         // post-request price collapse -- documented, never silent: the
         // queue entry is still consumed below).
      }
      // Face was burned at request time; the queue clears unconditionally
      // (paid or dust-forfeited alike -- no bricked queue, no re-entry).
      d.modify( *reserve, [&]( reserve_object& r ) {
         r.exit_queue.clear();
         r.last_ratio_bps = h2_issue_coverage_bps(
               h2_issue_bts_to_face( r.bts_balance, *price ), r.stable_supply );
         r.snapshot_block = head_block;
      } );
   }
}

void h2_issue_on_pair_halt( database& d, asset_id_type pair )
{
   const reserve_object* reserve = h2_find_reserve( d, pair );
   if( reserve == nullptr )
      return; // legacy pair: no issuance state, halt path byte-identical
   const auto& vault_by_pair = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   const auto vitr = vault_by_pair.find( pair );
   if( vitr == vault_by_pair.end() )
      return;
   const time_point_sec now = d.head_block_time();
   const auto price = h2_read_pair_price( d, *vitr, 0, now );
   if( !price.valid() )
      return; // no bonded price: hold everything fail-closed (no revert, no absorb)
   // 1+2. Prune stood positions, REVERT unvested door outputs. Matured or
   // missing vestings STAND (never repriced); only live unvested escrows
   // revert (cancel escrow, BTS to the reserve's active band, face back to
   // owner/supply/outstanding so reverted holders can wind-down-claim).
   // Every entry is consumed here (reverted or stood): the halt leaves no
   // pending list behind.
   const vector<h2_pending_vesting> pending = reserve->pending_vestings; // copy: reverts below
   if( !pending.empty() )
   {
      for( const h2_pending_vesting& p : pending )
      {
         const vesting_balance_object* vb = d.find( p.owner_vesting );
         bool unvested = false;
         if( vb != nullptr && vb->policy.is_type<linear_vesting_policy>() )
         {
            const linear_vesting_policy& lin = vb->policy.get<linear_vesting_policy>();
            unvested = ( now < lin.begin_timestamp + lin.vesting_duration_seconds );
         }
         if( !unvested )
            continue; // stood: matured/missing/non-linear, never rebooked
         // REVERT this door output.
         const share_type escrow_bts = vb->balance.amount;
         FC_ASSERT( vb->balance.asset_id == asset_id_type(),
                    "Door escrow holds non-BTS; revert refused fail-closed" );
         const account_id_type owner = p.owner;
         const share_type face = p.face_burned;
         d.remove( *vb );
         d.adjust_balance( owner, asset( face, pair ) );
         const asset_object& pair_asset = pair( d );
         const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
         d.modify( pair_dyn, [&face]( asset_dynamic_data_object& data ) {
            data.current_supply += face;
         } );
         d.modify( *vitr, [&face]( vault_object& v ) { v.outstanding += face; } );
         reserve = h2_find_reserve( d, pair );
         FC_ASSERT( reserve != nullptr, "Issuance reserve vanished inside halt revert" );
         d.modify( *reserve, [&escrow_bts]( reserve_object& r ) {
            h2_issue_ensure_bands( r.band_bts );
            r.bts_balance += escrow_bts;
            r.band_bts[3] += escrow_bts;
         } );
         reserve = h2_find_reserve( d, pair );
         FC_ASSERT( reserve != nullptr, "Issuance reserve vanished inside halt revert" );
      }
      reserve = h2_find_reserve( d, pair );
      if( reserve != nullptr )
         d.modify( *reserve, []( reserve_object& r ) { r.pending_vestings.clear(); } );
   }
   // 3. ABSORB the residual shortfall, if below 100% after bands (offset
   // pool first, remainder recorded for the rmax junior path).
   reserve = h2_find_reserve( d, pair );
   if( reserve != nullptr )
      h2_issue_absorb_pair( d, *reserve, *vitr, *price );
}

share_type h2_issue_bts_to_face( share_type bts_raw,
                                 const protocol::oracle_value& price )
{
   if( bts_raw <= share_type( 0 ) || price.base_amount <= share_type( 0 ) || price.quote_amount <= share_type( 0 ) )
      return share_type( 0 );
   // floor(bts_raw * quote / base), 256-bit product, truncating division:
   // declared round-DOWN against the receiver (favoring the protocol).
   // Same conversion style as the H1 consumers and h2_convert_face_to_bond
   // (inverted leg), read through the same bonded gate as every H2 price.
   const uint256_t face =
         uint256_t( uint64_t( bts_raw.value ) )
         * uint256_t( uint64_t( price.quote_amount.value ) )
         / uint256_t( uint64_t( price.base_amount.value ) );
   if( face > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( face ) ) );
}

share_type h2_issue_face_to_bts( share_type face_raw,
                                 const protocol::oracle_value& price )
{
   if( face_raw <= share_type( 0 ) || price.base_amount <= share_type( 0 ) || price.quote_amount <= share_type( 0 ) )
      return share_type( 0 );
   // floor(face_raw * base / quote), 256-bit, truncating: declared
   // round-DOWN against the receiver (the redeemer: the payout floors,
   // favoring the protocol). h2_convert_face_to_bond's exact formula.
   const uint256_t bts =
         uint256_t( uint64_t( face_raw.value ) )
         * uint256_t( uint64_t( price.base_amount.value ) )
         / uint256_t( uint64_t( price.quote_amount.value ) );
   if( bts > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( bts ) ) );
}

uint32_t h2_issue_coverage_bps( share_type value_face, share_type supply_face )
{
   constexpr uint32_t saturate = 0xFFFFFFFF;
   if( supply_face <= share_type( 0 ) )
      return saturate; // nothing to secure: covered by vacuity
   if( value_face <= share_type( 0 ) )
      return 0;
   const fc::uint128_t q = fc::uint128_t( uint64_t( value_face.value ) )
                         * fc::uint128_t( 10000 )
                         / fc::uint128_t( uint64_t( supply_face.value ) );
   if( q >= fc::uint128_t( uint64_t( saturate ) ) )
      return saturate;
   return uint32_t( fc::uint128_lo64( q ) );
}

void_result hybrid_mint_evaluator::do_evaluate( const hybrid_mint_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();

   // Price leg (H2e): minting values through bonded prices, so it admits
   // at the price height. Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never mints" );
   // The door hold blocks mints (vault_object contract: while frozen, mint
   // blocked). Exits are the redeem path, never this op.
   FC_ASSERT( !_vault->frozen,
              "Vault door is held shut; mints refused until it reopens" );
   // Recovery suspends new debt (H2d rule, extended from vault_register to
   // every debt tap): a mint grows outstanding, so it is new debt. Exits
   // (redeems, wind-down claims) stay open: this gate touches entry only.
   const auto& rec_idx = d.get_index_type<recovery_state_index>().indices();
   if( !rec_idx.empty() )
      FC_ASSERT( !rec_idx.begin()->new_debt_suspended,
                 "Recovery is active: new debt suspended until scope restores" );

   // Genesis BTS-only (basket timing is a later task): the deposit, the
   // vault's bond asset, and the door unit are all core BTS.
   FC_ASSERT( op.deposit.asset_id == asset_id_type(),
              "Mint deposits are BTS-only at genesis" );
   FC_ASSERT( _vault->bond_asset == asset_id_type(),
              "Mint vaults are BTS-bonded at genesis" );
   FC_ASSERT( nullptr != d.find( op.minter ),
              "Minter account ${a} does not exist", ("a", op.minter) );
   FC_ASSERT( d.get_balance( op.minter, asset_id_type() ).amount >= op.deposit.amount,
              "Minter holds insufficient BTS for the deposit" );

   // The pair is the senior stable: a vault-backed UIA, never the bond
   // asset itself (minting the bond asset as "stable" is reflexive mint
   // and is refused here, not priced downstream).
   const asset_object* pair_asset = d.find( _vault->vault_pair );
   FC_ASSERT( nullptr != pair_asset,
              "Vault pair asset ${a} does not exist", ("a", _vault->vault_pair) );
   FC_ASSERT( !pair_asset->is_market_issued(),
              "Mint pairs are vault-backed UIAs: market-issued assets never mint here" );
   FC_ASSERT( !pair_asset->is_liquidity_pool_share_asset(),
              "Liquidity pool share assets never mint here" );
   FC_ASSERT( _vault->vault_pair != asset_id_type(),
              "The bond asset is never its own stable: reflexive mint refused" );
   FC_ASSERT( pair_asset->can_create_new_supply(), "Pair asset can create no new supply" );

   // Junior token: pinned at reserve creation (first-freeze precedent),
   // matched thereafter. Same non-reflexive shape: neither the pair nor
   // the bond asset, same precision (parity math is unit-exact).
   _reserve = h2_find_reserve( d, _vault->vault_pair );
   _creates_reserve = ( _reserve == nullptr );
   const asset_object* fxr_asset = d.find( op.fxr_asset );
   FC_ASSERT( nullptr != fxr_asset,
              "FXR asset ${a} does not exist", ("a", op.fxr_asset) );
   if( _creates_reserve )
   {
      FC_ASSERT( op.fxr_asset != _vault->vault_pair,
                 "FXR token must differ from the senior pair: reflexive junior refused" );
      FC_ASSERT( op.fxr_asset != asset_id_type(),
                 "FXR token is never the bond asset: reflexive junior refused" );
      FC_ASSERT( !fxr_asset->is_market_issued(),
                 "FXR tokens are plain UIAs: market-issued assets never back juniors" );
      FC_ASSERT( !fxr_asset->is_liquidity_pool_share_asset(),
                 "Liquidity pool share assets never back juniors" );
      FC_ASSERT( fxr_asset->precision == pair_asset->precision,
                 "FXR/pair precision must match: parity math is unit-exact" );
      FC_ASSERT( fxr_asset->can_create_new_supply(), "FXR asset can create no new supply" );
   }
   else
      FC_ASSERT( op.fxr_asset == _reserve->fxr_asset,
                 "Pair ${p} is pinned to FXR ${f}; minting ${g} refused",
                 ("p", _vault->vault_pair)("f", _reserve->fxr_asset)("g", op.fxr_asset) );

   // Bonded read (X-01 reuse, never a new price path): unbonded oracles
   // refuse mints here, so unbonded inputs can never mint bonded stable.
   // Unbound vaults have no price leg by construction (h2_read_pair_price
   // returns absent without a binding).
   const auto price = h2_read_pair_price( d, *_vault, 0, now );
   FC_ASSERT( price.valid(),
              "No bonded live price for this pair; mints halt on unbonded inputs" );
   FC_ASSERT( price->base_amount > share_type( 0 ) && price->quote_amount > share_type( 0 ),
              "Degenerate bonded price; mints refused" );
   _price = *price;

    // Deposit coverage at the bonded price (declared round-DOWN: the floor
    // favors the protocol -- the minter must over-collateralize in fact,
    // not in rounding). The conversion-fee slice (30bps, floored) stays
    // inside the deposit for the rmin book check below but buys NO stable:
    // the request must be covered by the NET deposit alone, so a full
    // mint/redeem cycle costs the fee twice while coverage rises. Both legs
    // of the comparison floor against the minter.
    const share_type fee_slice = h2_issue_fee_slice( op.deposit.amount );
    const share_type net_deposit = op.deposit.amount - fee_slice;
    const share_type net_face = h2_issue_bts_to_face( net_deposit, *price );
    FC_ASSERT( net_face >= op.stable_amount,
               "Net deposit covers ${c} face at the bonded price after the "
               "30bps conversion fee; ${m} requested",
               ("c", net_face)("m", op.stable_amount) );

    // rmin gate (the Terra prohibition): the POST-mint ratio must stay at
    // or above 13000bps. The FULL deposit counts (fee slice included: the
    // slice accrues to the reserve, so it backs the book -- it is only the
    // per-request coverage above that prices the net deposit). Naming the
    // request is load-bearing: a price-derived mint on an empty book opens
    // at ~100% backing and could never clear this gate, so issuance could
    // never start; the minter's chosen over-collateralization opens every
    // book, and this gate holds every later one. Equality meets (inclusive
    // floor).
   const share_type post_bts = h2_issue_sat_add(
         _creates_reserve ? share_type( 0 ) : _reserve->bts_balance, op.deposit.amount );
   const share_type post_supply = h2_issue_sat_add(
         _creates_reserve ? share_type( 0 ) : _reserve->stable_supply, op.stable_amount );
   FC_ASSERT( h2_issue_meets_rmin( post_bts, post_supply, *price,
                                   GRAPHENE_H2_ISSUE_RMIN_BPS ),
              "Post-mint reserve ratio breaks the rmin floor (${r}bps); "
              "over-collateralize or reduce the request",
              ("r", GRAPHENE_H2_ISSUE_RMIN_BPS) );
   // Supply headroom (asset_issue precedent): consensus never mints past max.
   {
      const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
      FC_ASSERT( ( pair_dyn.current_supply + op.stable_amount ) <= pair_asset->options.max_supply,
                 "Mint exceeds the pair asset's maximum supply" );
   }

   // Effective door cap (ISSUANCE-2 live rule; the fixed $2,000 cap survives
   // as the ceiling inside it): the shared per-block counter still bounds
   // ALL door flow (ISSUANCE-1 DOS semantics, unchanged), while the
   // headroom/depth legs bound the marginal conversion (extraction/flow
   // bounds). Head-block-number-keyed reset: a reserve stamped for an older
   // block opens at zero. Genesis creation skips the headroom leg (no
   // standing headroom; rmin guards creation); pre-pool pairs skip the
   // depth leg (no tripwire state); unqualified depth with live state
   // refuses here. 256-bit compares, no floats.
   FC_ASSERT( h2_issue_door_admits( d, _reserve, _vault->vault_pair, *price,
                                    h2_issue_door_used( _reserve, head_block ),
                                    op.deposit.amount ),
              "Per-block door conversion cap exceeded for this pair; "
              "retry next block" );

   // FXR junior mint (minimal shippable): only the deposit's surplus
   // contribution above the target prices junior coin. contrib is the rise
   // in above-target surplus this deposit creates (pre-existing surplus
   // never mints to newcomers: its holders already own it). At-par mints
   // weakly REDUCE surplus (adding ~1:1 value-to-face against a >100%
   // target), so they mint no FXR; over-collateralized deposits (and the
   // fee slice inside every deposit) lift it and mint. FXR_price is the
   // pre-mint surplus per FXR (floored; genesis parity 1:1); a floored-0
   // price mints nothing (fail-closed, never divide-by-zero). Cap: the
   // fee slice already sits inside the door-counted deposit, so the FXR
   // leg rides the same door cap by construction.
   _fxr_to_mint = share_type( 0 );
   {
      const share_type r_before = _creates_reserve ? share_type( 0 ) : _reserve->bts_balance;
      const share_type s_before = _creates_reserve ? share_type( 0 ) : _reserve->stable_supply;
      const share_type fxr_supply_before =
            _creates_reserve ? share_type( 0 ) : _reserve->fxr_supply;
      const uint256_t surplus_pre = h2_issue_surplus_face(
            r_before, s_before, *price, GRAPHENE_H2_ISSUE_TARGET_BPS );
      const uint256_t surplus_new = h2_issue_surplus_face(
            post_bts, post_supply, *price, GRAPHENE_H2_ISSUE_TARGET_BPS );
      if( surplus_new > surplus_pre )
      {
         const uint256_t contrib = surplus_new - surplus_pre;
         uint256_t fxr_price = uint256_t( GRAPHENE_H2_ISSUE_FXR_GENESIS_PARITY );
         if( fxr_supply_before > share_type( 0 ) )
            fxr_price = surplus_pre / uint256_t( uint64_t( fxr_supply_before.value ) );
         if( fxr_price > uint256_t( 0 ) )
         {
            const uint256_t fxr = contrib / fxr_price;
            if( fxr > uint256_t( 0 ) )
            {
               FC_ASSERT( fxr <= uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ),
                          "FXR mint exceeds maximum share supply" );
               const share_type fxr_mint = share_type( int64_t( uint64_t( fxr ) ) );
               const auto& fxr_dyn = fxr_asset->dynamic_asset_data_id( d );
               FC_ASSERT( ( fxr_dyn.current_supply + fxr_mint ) <= fxr_asset->options.max_supply,
                          "FXR mint exceeds the junior asset's maximum supply" );
               _fxr_to_mint = fxr_mint;
            }
         }
      }
   }

   // FXR suspension (ISSUANCE-2): while the batch-exit queue sits at either
   // cap, no new junior mints. Mints that price no FXR still admit (the door
   // stays open for senior flow); only the junior leg suspends.
   if( _fxr_to_mint > share_type( 0 )
       && h2_issue_exit_suspended( _reserve, *price ) )
      FC_ASSERT( false,
                 "FXR minting suspended while the exit queue exceeds threshold; "
                 "retry after the maintenance batch settles" );

   // No reflexive mint between legs: this evaluator issues stable/FXR
   // balances only (never a nested redeem, never a nested mint); the
   // redeem evaluator burns stable only (never mints). The only shared
   // path is the bonded read above. Structural, asserted here in prose
   // and pinned by the round-trip accounting test.
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type hybrid_mint_evaluator::do_apply( const hybrid_mint_operation& op )
{ try {
   database& d = db();
   const uint32_t head_block = d.head_block_num();
   const asset_id_type core = asset_id_type();

   d.adjust_balance( op.minter, -asset( op.deposit.amount, core ) );

   const share_type fxr = _fxr_to_mint;
   const protocol::oracle_value snap_price = _price;
   const reserve_object* reserve = nullptr;
   if( _creates_reserve )
   {
      const auto& created = d.create<reserve_object>(
            [&]( reserve_object& r ) {
         r.pair          = _vault->vault_pair;
         r.fxr_asset     = op.fxr_asset;
         r.bts_balance   = op.deposit.amount;
         r.stable_supply = op.stable_amount;
         r.fxr_supply    = fxr;
         r.door_used_bts = op.deposit.amount;
         r.door_block    = head_block;
         // Genesis band partition: the whole book opens in the active
         // issuance band 3, anchored at the proving bonded price.
         h2_issue_ensure_bands( r.band_bts );
         h2_issue_ensure_bands( r.band_stable );
         r.band_bts[3] = op.deposit.amount;
         r.band_stable[3] = op.stable_amount;
         r.band_anchor = snap_price;
         r.band_block = head_block;
      } );
      reserve = &created;
   }
   else
   {
      d.modify( *_reserve, [&]( reserve_object& r ) {
         r.bts_balance += op.deposit.amount;
         r.stable_supply += op.stable_amount;
         r.fxr_supply += fxr;
         // New backing enters at the anchor (active issuance band 3).
         h2_issue_ensure_bands( r.band_bts );
         h2_issue_ensure_bands( r.band_stable );
         r.band_bts[3] += op.deposit.amount;
         r.band_stable[3] += op.stable_amount;
         if( r.door_block != head_block )
         {
            r.door_block = head_block;
            r.door_used_bts = op.deposit.amount;
         }
         else
            r.door_used_bts += op.deposit.amount;
      } );
      reserve = _reserve;
   }
   // Soft-band rebalance on the consumed-price move (half-tick hysteresis,
   // at most one step per conversion). Totals conserved by construction.
   d.modify( *reserve, [&]( reserve_object& r ) {
      h2_issue_maybe_rebalance( r, snap_price, head_block );
   } );
   reserve = h2_find_reserve( d, _vault->vault_pair );
   // Coverage snapshot (face terms, saturating bps): every door conversion
   // re-stamps what the rmin gate just proved, so explorers read backing
   // without replaying conversions.
   d.modify( *reserve, [&]( reserve_object& r ) {
      r.last_ratio_bps = h2_issue_coverage_bps(
            h2_issue_bts_to_face( r.bts_balance, snap_price ), r.stable_supply );
      r.snapshot_block = head_block;
   } );

   d.adjust_balance( op.minter, asset( op.stable_amount, _vault->vault_pair ) );
   {
      const asset_object& pair_asset = _vault->vault_pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         data.current_supply += op.stable_amount;
      } );
   }
   if( fxr > share_type( 0 ) )
   {
      d.adjust_balance( op.minter, asset( fxr, op.fxr_asset ) );
      const asset_object& fxr_asset = op.fxr_asset( d );
      const auto& fxr_dyn = fxr_asset.dynamic_asset_data_id( d );
      d.modify( fxr_dyn, [&fxr]( asset_dynamic_data_object& data ) {
         data.current_supply += fxr;
      } );
   }
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding += op.stable_amount;
   } );
   return object_id_type( reserve->id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result hybrid_redeem_evaluator::do_evaluate( const hybrid_redeem_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();

   // Price leg (H2e): the payout values through bonded prices, symmetric
   // with mint. Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never redeems" );
   // Exits continue through a held door (H2c top-up precedent: frozen
   // blocks mints, redemptions continue pro-rata). Only the tripwire's
   // stage-3 redemptions latch and terminal wind-down shut this path.
   FC_ASSERT( !h2_redemptions_halted( d, _vault->vault_pair ),
              "Redemptions for this pair are held shut by the tripwire" );
   _reserve = h2_find_reserve( d, _vault->vault_pair );
   FC_ASSERT( nullptr != _reserve,
              "Pair carries no issuance reserve; nothing to redeem" );

   FC_ASSERT( op.burn.asset_id == _vault->vault_pair,
              "Redeem burns the vault's senior stable, never another asset" );
   FC_ASSERT( op.burn.amount <= _reserve->stable_supply,
              "Redeem burns more stable than the reserve issued" );
   FC_ASSERT( op.burn.amount <= _vault->outstanding,
              "Redeem burns more stable than the vault's outstanding" );
   FC_ASSERT( nullptr != d.find( op.redeemer ),
              "Redeemer account ${a} does not exist", ("a", op.redeemer) );
   FC_ASSERT( d.get_balance( op.redeemer, _vault->vault_pair ).amount >= op.burn.amount,
              "Redeemer holds insufficient stable for the burn" );

   // Same bonded read as mint (X-01 reuse): dual-stale refuses conversion-
   // dependent exits rather than paying on a dead price (wind-down-claim
   // precedent).
   const auto price = h2_read_pair_price( d, *_vault, 0, now );
   FC_ASSERT( price.valid(),
              "No bonded live price for this pair; conversion exits halt" );
   FC_ASSERT( price->base_amount > share_type( 0 ) && price->quote_amount > share_type( 0 ),
              "Degenerate bonded price; redeems refused" );

    // Payout (declared round-DOWN against the redeemer twice over: the
    // conversion floors, then the 30bps conversion fee withholds -- both
    // favor the protocol, and a full mint/redeem cycle costs the fee on
    // both legs while coverage rises). The withheld slice never leaves the
    // reserve: it is simply not subtracted below, so fee routing needs no
    // account and no map. Dust that pays nothing -- including a gross the
    // fee eats whole -- is refused, never vested.
    const share_type gross = h2_issue_face_to_bts( op.burn.amount, *price );
    _payout = gross - h2_issue_fee_slice( gross );
    FC_ASSERT( _payout > share_type( 0 ),
               "Dust redeems that pay nothing are refused" );
    FC_ASSERT( _payout <= _reserve->bts_balance,
               "Reserve cannot cover the payout; shortfall exits go through wind-down" );

    // rmin floor on the remainder (same constant as mint: one floor, both
    // doors). The retained fee slice stays in the remainder, strengthening
    // it. Partial redeems must leave the book above the floor; an exact
    // full-book exit (burning the entire outstanding, which mirrors the
    // reserve supply across every door conversion) bypasses it -- nothing
    // remains to secure, and any FXR surplus stays for juniors. A burn that
    // equals the supply while the mirrors drift is refused fail-closed
    // (unreachable through the door ops, which move both together).
    if( op.burn.amount < _reserve->stable_supply )
       FC_ASSERT( h2_issue_meets_rmin( _reserve->bts_balance - _payout,
                                       _reserve->stable_supply - op.burn.amount,
                                       *price, GRAPHENE_H2_ISSUE_RMIN_BPS ),
                  "Post-redeem reserve ratio breaks the rmin floor (${r}bps); "
                  "exit the remainder through wind-down",
                  ("r", GRAPHENE_H2_ISSUE_RMIN_BPS) );
    else
       FC_ASSERT( _reserve->stable_supply == _vault->outstanding,
                  "Full-book exits burn the entire outstanding; mirror drift refused" );

    // Effective door cap, same shared counter as mint (ISSUANCE-1 DOS
    // semantics, unchanged). The redeem leg counts the NET payout -- the
    // BTS that actually leaves the reserve; the withheld fee never moves,
    // so it consumes no door. Exact full-book exits bypass the whole
    // predicate with the rmin floor (nothing remains to secure; holding
    // the last payout hostage is theft, and the face already burned).
    if( op.burn.amount < _reserve->stable_supply )
       FC_ASSERT( h2_issue_door_admits( d, _reserve, _vault->vault_pair, *price,
                                        h2_issue_door_used( _reserve, head_block ),
                                        _payout ),
                  "Per-block door conversion cap exceeded for this pair; "
                  "retry next block" );
    // Pending-vesting bound (ISSUANCE-2 REVERT-vs-ABSORB): the redeem below
    // records its escrow on the reserve; matured entries prune first, and a
    // redeem that still overflows the bounded list is refused here (read-only
    // count: apply prunes and appends without failing).
    FC_ASSERT( h2_issue_pending_unmatured( d, *_reserve, now )
               < GRAPHENE_H2_ISSUE_PENDING_VEST_CAP,
               "Too many unvested door outputs; retry after some vest" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type hybrid_redeem_evaluator::do_apply( const hybrid_redeem_operation& op ) const
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();
   const asset_id_type core = asset_id_type();

   // Burn the senior: supply and outstanding fall together (the mirror
   // invariant the round-trip test pins: stable_supply == outstanding
   // across every door conversion).
   d.adjust_balance( op.redeemer, -asset( op.burn.amount, _vault->vault_pair ) );
   {
      const asset_object& pair_asset = _vault->vault_pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         data.current_supply -= op.burn.amount;
      } );
   }
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding -= op.burn.amount;
   } );

   // Reserve pays into vesting escrow: BTS leaves the reserve the same
   // block the liability burns. Unvested outputs are escrow, never
   // capitalization -- no supply credit anywhere for them (BTS supply is
   // unchanged: still-counted funds move reserve -> escrow, wind-down
   // seizure precedent). The escrow ID is recorded on the reserve's bounded
   // pending list above: on halt/wind-down entry h2_issue_on_pair_halt
   // REVERTs unvested outputs (cancel escrow, face back for claiming) while
   // matured outputs STAND (pruned, never repriced).
   d.modify( *_reserve, [&]( reserve_object& r ) {
      r.bts_balance -= _payout;
      r.stable_supply -= op.burn.amount;
      // Band partition follows the totals (center-outward spend, exact).
      h2_issue_bands_spend( r.band_bts, _payout );
      h2_issue_bands_spend( r.band_stable, op.burn.amount );
      if( r.door_block != head_block )
      {
         r.door_block = head_block;
         r.door_used_bts = _payout;
      }
      else
         r.door_used_bts += _payout;
   } );
   const auto& escrow = d.create<vesting_balance_object>(
         [&]( vesting_balance_object& o ) {
      o.owner = op.redeemer;
      o.balance = asset( _payout, core );
      linear_vesting_policy policy;
      policy.begin_timestamp = now;
      policy.vesting_cliff_seconds = 0;
      policy.vesting_duration_seconds = GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC;
      policy.begin_balance = _payout;
      o.policy = policy;
   } );
   // Pending-vesting record (ISSUANCE-2 REVERT-vs-ABSORB): prune matured
   // entries (read-only walk outside the modify), then append this escrow.
   // The evaluate-side bound guarantees room, so apply never fails here.
   {
      vector<h2_pending_vesting> survivors;
      survivors.reserve( _reserve->pending_vestings.size() + 1 );
      for( const h2_pending_vesting& p : _reserve->pending_vestings )
      {
         const vesting_balance_object* vb = d.find( p.owner_vesting );
         if( vb != nullptr && vb->policy.is_type<linear_vesting_policy>() )
         {
            const linear_vesting_policy& lin = vb->policy.get<linear_vesting_policy>();
            if( now < lin.begin_timestamp + lin.vesting_duration_seconds )
               survivors.push_back( p );
         }
         // Matured/missing/non-linear: stood, pruned (never rebooked).
      }
      h2_pending_vesting entry;
      entry.owner_vesting = vesting_balance_id_type( escrow.id );
      entry.owner = op.redeemer;
      entry.face_burned = op.burn.amount;
      entry.validate();
      survivors.push_back( entry );
      FC_ASSERT( survivors.size() <= GRAPHENE_H2_ISSUE_PENDING_VEST_CAP,
                 "Pending door-output list overflow inside redeem apply" );
      d.modify( *_reserve, [&survivors]( reserve_object& r ) {
         r.pending_vestings = survivors;
      } );
   }
   // Re-stamp the snapshot the gate just proved (post-payout book).
   {
      const auto price = h2_read_pair_price( d, *_vault, 0, now );
      FC_ASSERT( price.valid(), "Bonded price leg vanished inside redeem apply" );
      d.modify( *_reserve, [&]( reserve_object& r ) {
         h2_issue_maybe_rebalance( r, *price, head_block );
         r.last_ratio_bps = h2_issue_coverage_bps(
               h2_issue_bts_to_face( r.bts_balance, *price ), r.stable_supply );
         r.snapshot_block = head_block;
      } );
   }
   return object_id_type( escrow.id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain

// ---- ISSUANCE-2 evaluators (offset pool + batch exits, tags 101-103) ----

namespace graphene { namespace chain {

void_result offset_deposit_evaluator::do_evaluate( const offset_deposit_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   (void)now;

   // Price leg (H2e): uniform for every new op -- dual + fee-vote gates.
   // Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; pool funding post-mortem is refused" );
   // Pool funding stays open through a held door (stress is when the
   // absorber must grow); only terminal wind-down shuts it.
   FC_ASSERT( op.deposit.asset_id == asset_id_type(),
              "Offset deposits are BTS-only at genesis" );
   FC_ASSERT( nullptr != d.find( op.depositor ),
              "Depositor account ${a} does not exist", ("a", op.depositor) );
   FC_ASSERT( d.get_balance( op.depositor, asset_id_type() ).amount >= op.deposit.amount,
              "Depositor holds insufficient BTS for the pool deposit" );

   // The pool belongs to the vault's pair (vault-backed UIA, never core).
   const asset_object* pair_asset = d.find( _vault->vault_pair );
   FC_ASSERT( nullptr != pair_asset,
              "Vault pair asset ${a} does not exist", ("a", _vault->vault_pair) );
   FC_ASSERT( _vault->vault_pair != asset_id_type(),
              "The bond asset never owns an offset pool" );

   // Bounded ledger (refuse past the cap; merges by owner never hit it).
   _pool = h2_find_offset_pool( d, _vault->vault_pair );
   _creates_pool = ( _pool == nullptr );
   if( !_creates_pool )
   {
      bool known = false;
      for( const h2_offset_claim& c : _pool->claims )
         if( c.owner == op.depositor )
         {
            known = true;
            break;
         }
      if( !known )
         FC_ASSERT( _pool->claims.size() < GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS,
                    "Offset claim ledger is full for this pair; "
                    "retry after claims settle" );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type offset_deposit_evaluator::do_apply( const offset_deposit_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const asset_id_type core = asset_id_type();
   const time_point_sec matures = now + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC;

   d.adjust_balance( op.depositor, -asset( op.deposit.amount, core ) );

   const offset_pool_object* pool = nullptr;
   if( _creates_pool )
   {
      const auto& created = d.create<offset_pool_object>(
            [&]( offset_pool_object& p ) {
         p.pair = _vault->vault_pair;
         p.balance = op.deposit.amount;
         h2_offset_claim c;
         c.owner = op.depositor;
         c.amount = op.deposit.amount;
         c.available_after = matures;
         c.validate();
         p.claims.push_back( c );
      } );
      pool = &created;
   }
   else
   {
      d.modify( *_pool, [&]( offset_pool_object& p ) {
         p.balance += op.deposit.amount;
         bool merged = false;
         for( h2_offset_claim& c : p.claims )
            if( c.owner == op.depositor )
            {
               c.amount += op.deposit.amount;
               // The LATEST deposit sets the merged maturity (favoring the
               // protocol: new money cannot shorten the old lock).
               if( matures > c.available_after )
                  c.available_after = matures;
               merged = true;
               break;
            }
         if( !merged )
         {
            FC_ASSERT( p.claims.size() < GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS,
                       "Offset claim ledger overflow inside deposit apply" );
            h2_offset_claim c;
            c.owner = op.depositor;
            c.amount = op.deposit.amount;
            c.available_after = matures;
            c.validate();
            p.claims.push_back( c );
         }
      } );
      pool = _pool;
   }
   return object_id_type( pool->id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result offset_claim_evaluator::do_evaluate( const offset_claim_operation& op )
{ try {
   const database& d = db();
   const time_point_sec now = d.head_block_time();

   // Price leg (H2e): uniform for every new op. Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   // Claims survive every vault state (funded absorber pays out even in
   // wind-down: the pool is holder backstop, never vault property).
   _pool = h2_find_offset_pool( d, _vault->vault_pair );
   FC_ASSERT( nullptr != _pool,
              "Pair carries no offset pool; nothing to claim" );
   const h2_offset_claim* found = nullptr;
   for( const h2_offset_claim& c : _pool->claims )
      if( c.owner == op.claimant )
      {
         found = &c;
         break;
      }
   FC_ASSERT( nullptr != found,
              "Claimant holds no offset claim on this pair" );
   FC_ASSERT( now >= found->available_after,
              "Offset claim vests at ${t}; early exits refused",
              ("t", found->available_after) );
   FC_ASSERT( op.amount <= found->amount,
              "Claim exceeds the recorded amount" );
   FC_ASSERT( op.amount <= _pool->balance,
              "Pool cannot cover the claim; shortfall absorbs first" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type offset_claim_evaluator::do_apply( const offset_claim_operation& op ) const
{ try {
   database& d = db();
   const asset_id_type core = asset_id_type();

   d.modify( *_pool, [&op]( offset_pool_object& p ) {
      p.balance -= op.amount;
      for( auto itr = p.claims.begin(); itr != p.claims.end(); ++itr )
         if( itr->owner == op.claimant )
         {
            itr->amount -= op.amount;
            if( itr->amount == share_type( 0 ) )
               p.claims.erase( itr );
            break;
         }
   } );
   d.adjust_balance( op.claimant, asset( op.amount, core ) );
   return object_id_type( _pool->id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result issuance_exit_request_evaluator::do_evaluate( const issuance_exit_request_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();

   // Price leg (H2e): exits value through bonded prices. Ordering inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never the queue" );
   // Tripwire redemptions latch covers the queue too (redeem precedent):
   // held-shut pairs exit only through the reopen rule, never a side door.
   FC_ASSERT( !h2_redemptions_halted( d, _vault->vault_pair ),
              "Redemptions for this pair are held shut by the tripwire" );
   _reserve = h2_find_reserve( d, _vault->vault_pair );
   FC_ASSERT( nullptr != _reserve,
              "Pair carries no issuance reserve; nothing to exit" );

   FC_ASSERT( nullptr != d.find( op.requester ),
              "Requester account ${a} does not exist", ("a", op.requester) );
   FC_ASSERT( d.get_balance( op.requester, _vault->vault_pair ).amount >= op.face,
              "Requester holds insufficient stable for the exit" );
   FC_ASSERT( op.face <= _reserve->stable_supply,
              "Exit queues more face than the reserve issued" );
   FC_ASSERT( op.face <= _vault->outstanding,
              "Exit queues more face than the vault's outstanding" );

   // Same bonded read as the door (X-01 reuse): dual-stale refuses rather
   // than queueing at a dead price.
   const auto price = h2_read_pair_price( d, *_vault, 0, now );
   FC_ASSERT( price.valid(),
              "No bonded live price for this pair; queued exits halt" );
   FC_ASSERT( price->base_amount > share_type( 0 ) && price->quote_amount > share_type( 0 ),
              "Degenerate bonded price; queued exits refused" );
   _price = *price;

   // rmin floor on the remainder (same constant as the door: one floor).
   // Exits are partial by construction: the exact full-book exit stays on
   // the redeem path (which bypasses for terminal books); queueing the last
   // face would strand the batch with no book to price it.
   FC_ASSERT( op.face < _reserve->stable_supply,
              "Full-book exits use the redeem path, never the queue" );
   FC_ASSERT( h2_issue_meets_rmin( _reserve->bts_balance,
                                   _reserve->stable_supply - op.face,
                                   *price, GRAPHENE_H2_ISSUE_RMIN_BPS ),
              "Post-exit reserve ratio breaks the rmin floor (${r}bps); "
              "exit the remainder through wind-down",
              ("r", GRAPHENE_H2_ISSUE_RMIN_BPS) );

   // Dust refusal at the declared net (single truncating 2% fee, floored
   // against the requester, favoring the protocol).
   const share_type gross = h2_issue_face_to_bts( op.face, *price );
   FC_ASSERT( gross > share_type( 0 ), "Dust exits that pay nothing are refused" );
   const share_type net_est = share_type(
         int64_t( uint64_t( uint256_t( uint64_t( gross.value ) )
                            * uint256_t( 10000 - GRAPHENE_H2_ISSUE_EXIT_FEE_BPS )
                            / uint256_t( 10000 ) ) ) );
   FC_ASSERT( net_est > share_type( 0 ),
              "Dust exits that pay nothing after the exit fee are refused" );

   // Bounded queue (both caps refuse; counts and ceiling-valued sums).
   FC_ASSERT( _reserve->exit_queue.size() < GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT,
              "Exit queue is full for this pair; retry after the batch settles" );
   {
      const uint256_t leg_num = uint256_t( uint64_t( op.face.value ) )
                              * uint256_t( uint64_t( price->base_amount.value ) );
      const uint256_t leg_den = uint256_t( uint64_t( price->quote_amount.value ) );
      const uint256_t leg = ( leg_num + leg_den - uint256_t( 1 ) ) / leg_den; // ceil: refuse sooner
      FC_ASSERT( h2_issue_queue_value_256( _reserve, *price ) + leg
                 <= uint256_t( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS ),
                 "Exit queue value cap exceeded for this pair; "
                 "retry after the batch settles" );
   }
   (void)head_block;
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type issuance_exit_request_evaluator::do_apply( const issuance_exit_request_operation& op )
{ try {
   database& d = db();
   const uint32_t head_block = d.head_block_num();

   // Burn the face now (supply and outstanding fall at request time: no
   // double-spend, no re-entry); the BTS pays at the maintenance batch.
   d.adjust_balance( op.requester, -asset( op.face, _vault->vault_pair ) );
   {
      const asset_object& pair_asset = _vault->vault_pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         data.current_supply -= op.face;
      } );
   }
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding -= op.face;
   } );
   // Face leaves the band partition with the totals (center-outward, exact).
   d.modify( *_reserve, [&]( reserve_object& r ) {
      r.stable_supply -= op.face;
      h2_issue_bands_spend( r.band_stable, op.face );
   } );
   const reserve_object* reserve = _reserve;
   d.modify( *reserve, [&]( reserve_object& r ) {
      FC_ASSERT( r.exit_queue.size() < GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT,
                 "Exit queue overflow inside request apply" );
      h2_exit_request req;
      req.requester = op.requester;
      req.face = op.face;
      req.block = head_block;
      req.validate();
      r.exit_queue.push_back( req );
   } );
   return object_id_type( reserve->id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain

FC_REFLECT( graphene::chain::h2_pending_vesting,
            (owner_vesting)
            (owner)
            (face_burned)
          )

FC_REFLECT( graphene::chain::h2_exit_request,
            (requester)
            (face)
            (block)
          )

FC_REFLECT( graphene::chain::h2_offset_claim,
            (owner)
            (amount)
            (available_after)
          )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::reserve_object, (graphene::db::object),
                    (pair)
                    (fxr_asset)
                    (bts_balance)
                    (stable_supply)
                    (fxr_supply)
                    (last_ratio_bps)
                    (snapshot_block)
                    (door_used_bts)
                    (door_block)
                    (band_bts)
                    (band_stable)
                    (band_anchor)
                    (band_block)
                    (pending_vestings)
                    (exit_queue)
                    (uncovered_shortfall)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::offset_pool_object, (graphene::db::object),
                    (pair)
                    (balance)
                    (claims)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reserve_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::offset_pool_object )
