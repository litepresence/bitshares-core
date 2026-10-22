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
#include <graphene/chain/vault_lifecycle_evaluator.hpp>
#include <graphene/chain/challenge_evaluator.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/winddown_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/vault_object.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

#include <algorithm>

namespace graphene { namespace chain {

/// R17-A: the exported center-out band spend. Defined beside its
/// wind-down consumer because this TU's include closure resolves the plain
/// vector/share_type aliases (verified); declared for all TUs in
/// issuance_evaluator.hpp next to ensure/verify.
void h2_issue_bands_spend( vector<share_type>& bands, share_type amount )
{
   h2_issue_ensure_bands( bands );
   // NC-07: the table is sized by DEDUCTION, never by an explicit
   // N_BANDS bound: a fixed-size `order[7]` stays well-formed when the band
   // count is raised (its tail is silently zero-filled, and band 0 would be
   // hit twice), while the form below turns that bump into a compile error.
   static const uint32_t order[] = { 3, 4, 2, 5, 1, 6, 0 };
   static_assert( sizeof( order ) / sizeof( order[0] ) == GRAPHENE_H2_ISSUE_N_BANDS,
                  "Band spend order must cover exactly GRAPHENE_H2_ISSUE_N_BANDS bands" );
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

// Defends against: confiscation beyond the filed exit formula (C1 design 3:
// the seat is bounded by what the formula can pay, so a wind-down takes no
// more than the claimants are owed and the surplus stays with its owner),
// against a book seated against a dead price (a claim book with no pool), and
// against stranded bond stacks at sustained zero-claim resolves.
// Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md section 1
const winddown_vault_object& h2_create_winddown( database& d, const vault_object& vault,
                                                 const optional<protocol::oracle_value>& seat_price )
{
   // C1 design 3: claim-bounded seating. The wind-down seats only what the
   // filed exit formula can ever pay (the seat bound); the surplus stays with
   // its owner. Design 2's drained case is subsumed (need == 0 seats
   // nothing). Defends against: confiscation beyond the filed exit formula,
   // and stranded bond stacks at sustained zero-claim resolves.
   h2_issue_on_pair_halt( d, vault.vault_pair );
   share_type segregated( 0 );
   share_type claims( 0 );
   share_type need( 0 );
   // ISS-13 terminal disposition (issuance pairs only): the reserve's BTS
   // leg is swept into the book's segregated remainder (the offset pool is
   // the book's backstop), and the reserve extinguishes around a frozen
   // liability record. Queued exits refund to face FIRST (the request-time
   // burn reverses on all four mirrors) so the outstanding snapshot below
   // lets queued holders claim in the wind-down like everyone else.
   if( const reserve_object* r = h2_find_reserve( d, vault.vault_pair ) )
   {
      // PC-01 pilot ceiling: this refund RE-MINTS face with no door in
      // front of it, so it must hold the same $20,000 face cap the mint
      // doors enforce. `h2_issue_on_pair_halt` above has already applied
      // (and capped) every halt revert for this pair, so this projects the
      // NEXT restore only: current_supply plus the whole exit queue about
      // to come back. Refuse fail-closed BEFORE the first refund: no
      // partial refund, no silent clamp (a half-refunded queue would leave
      // balances, book, bands, and the queue entry count disagreeing).
      // Exact integer math, no price input; equality admits (inclusive
      // cap), same as the doors. Unreachable by construction: the mint and
      // issuer-direct doors count pending + queued restore face, which is
      // exactly `current + restore` here -- so the maintenance sweep that
      // enters through this function can never reject a block over it.
      if( !r->exit_queue.empty() )
      {
         const asset_object& pair_asset = vault.vault_pair( d );
         const share_type pilot_cap = h2_issue_pilot_cap_face( pair_asset.precision );
         const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
         const share_type projected = h2_issue_sat_add(
               pair_dyn.current_supply, h2_issue_queued_restore_face( *r ) );
         FC_ASSERT( projected <= pilot_cap,
                    "Pilot ceiling: wind-down exit-queue refund would restore "
                    "token supply ${s} past the $20,000 face pilot cap for "
                    "this pair; scale-up needs a new binary",
                    ("s", projected) );
      }
      for( const h2_exit_request& q : r->exit_queue )
      {
         d.adjust_balance( q.requester, asset( q.face, vault.vault_pair ) );
         const asset_object& pair_asset = vault.vault_pair( d );
         const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
         d.modify( pair_dyn, [&q]( asset_dynamic_data_object& data ) {
            data.current_supply += q.face;
         } );
         d.modify( vault, [&q]( vault_object& v ) { v.outstanding += q.face; } );
         d.modify( *r, [&q]( reserve_object& res ) {
            res.stable_supply += q.face;
            h2_issue_ensure_bands( res.band_stable );
            res.band_stable[3] += q.face;
         } );
         h2_issue_verify_bands( *r );
      }
      if( !r->exit_queue.empty() )
         d.modify( *r, []( reserve_object& res ) { res.exit_queue.clear(); } );
   }

   // Claims snapshot AFTER the halt-revert and the exit-queue refunds, which
   // can only have raised outstanding.
   claims = vault.outstanding;

   // Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §1
   // The seat bound: the most the filed exit formula can ever pay out of
   // this book. Every claim pays at most floor((10000 - haircut_bps) / 10000)
   // of its face, those floors are subadditive, and the pro-rata leg sums to
   // at most the segregated pool, so the lifetime disbursement can never
   // exceed the bound. Seating more than the bound never reaches a
   // claimant; it only strands.
   // Invariant: segregated_bond <= seat bound.
   if( claims > share_type( 0 ) )
   {
      const fc::uint128_t scratch = fc::uint128_t( uint64_t( claims.value ) )
                                  * fc::uint128_t( uint64_t( 10000 - GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS ) )
                                  / fc::uint128_t( 10000 );
      const share_type face_scratch = share_type( int64_t( uint64_t( scratch ) ) );
      if( vault.bound_oracle.valid() )
      {
         // Bound vault: the frozen claim book is denominated in face, so
         // the seat is converted through the bonded price and then compared
         // against bond-denominated balances (the reserve's BTS and the
         // bonds' vesting balances). A dead price with claims present is
         // refused at both admission paths, so an empty seat price here
         // means a provably claim-free book: the seat stays 0.
         if( seat_price.valid() && seat_price->base_amount > share_type( 0 )
             && seat_price->quote_amount > share_type( 0 ) )
            need = h2_convert_face_to_bond( face_scratch, *seat_price );
      }
      else
      {
         // Unbound vault: the legacy same-asset book, seated in the claim's
         // own units (mirrors the payout_for haircut leg).
         need = face_scratch;
      }
   }

   // Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §2
   // Reserve leg, capped and first: the reserve's own backing is the
   // cheapest money for the frozen book, so it moves first and only up to
   // the seat bound.
   // Invariant: the band partition still sums to the balance after the
   // sweep (NC-08).
   if( const reserve_object* r = h2_find_reserve( d, vault.vault_pair ) )
   {
      const share_type swept = ( need < r->bts_balance ) ? need : r->bts_balance;
      if( swept > share_type( 0 ) )
      {
         d.modify( *r, [&]( reserve_object& res ) {
            h2_issue_ensure_bands( res.band_bts );
            h2_issue_bands_spend( res.band_bts, swept );
            res.bts_balance -= swept;
            res.uncovered_shortfall = share_type( 0 );
            res.last_ratio_bps = 0;
            res.snapshot_block = d.head_block_num();
         } );
         h2_issue_verify_bands( *r );
         segregated += swept;
         need -= swept;
      }
      else
      {
         // Nothing moved: the seat bound is zero (a provably drained book, or
         // a bound the pool cannot reach). The scalars still clear, so the
         // mint-door gate sees a clean record, and the snapshot is stamped
         // with the block that cleared it.
         d.modify( *r, [&d]( reserve_object& res ) {
            res.uncovered_shortfall = share_type( 0 );
            res.last_ratio_bps = 0;
            res.snapshot_block = d.head_block_num();
         } );
      }
   }

   // Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §2
   // Bond leg: capped seizure -- iterate the unseized bonds and take
   // min(vesting available, bond amount, seat bound still open) until the
   // bound is met. A bond the bound never reaches stays unseized with its
   // vesting balance untouched, so the surplus stays with its owner under the
   // CDD withdrawal schedule. A visited bond is marked seized even when its
   // vesting holds less than its face (the saturating legacy semantics).
   if( need > share_type( 0 ) )
   {
      const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
      const auto range = bond_idx.equal_range( vault_id_type( vault.id ) );
      for( auto itr = range.first; itr != range.second && need > share_type( 0 ); ++itr )
      {
         if( itr->seized )
            continue;
         share_type debit( 0 );
         const vesting_balance_object* vesting = d.find( itr->vesting_balance );
         if( vesting != nullptr && vesting->balance.amount > share_type( 0 ) )
         {
            // Saturating seizure: a partially-drawn vesting yields only what
            // is there, never a negative balance. Vesting objects are
            // supply-visible, so every debit here is booked into the
            // wind-down remainder below.
            const int64_t avail = vesting->balance.amount.value;
            const int64_t want = itr->bond_amount.value;
            int64_t take = std::min( avail, want );
            if( take > need.value )
               take = need.value;
            debit = share_type( take > 0 ? take : 0 );
            if( debit > share_type( 0 ) )
               d.modify( *vesting, [&debit]( vesting_balance_object& v ) {
                  v.balance.amount -= debit;
               } );
         }
         d.modify( *itr, []( vault_bond_object& b ) { b.seized = true; } );
         segregated += debit;
         need -= debit;
      }
   }

   const auto& wd = d.create<winddown_vault_object>(
         [&vault, &segregated, &claims]( winddown_vault_object& w ) {
      w.pair            = vault.vault_pair;
      w.source_vault    = vault.id;
      w.segregated_bond = segregated;
      w.total_claims    = claims;
      w.claimed_total   = share_type( 0 );
      w.paid_total      = share_type( 0 );
      w.senior_paid     = share_type( 0 );
      w.junior_paid     = share_type( 0 );
      w.haircut_bps     = GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS;
      w.state           = GRAPHENE_H2_WINDDOWN_OPEN;
   } );
   d.modify( vault, []( vault_object& v ) {
      v.maintenance_state = GRAPHENE_H2_VAULT_WINDDOWN;
      v.frozen = true; // failed closed: mints halt, wind-down claims continue
   } );
   return wd;
}

// Design 3 section 3.2 (price leg): the wind-down seat converts the frozen
// claim book through the bonded price, so a bound vault needs a live price
// exactly when its claims snapshot can be nonzero. The two apply-side
// restorers (the halt transition's door-output reverts and the exit-queue
// refunds) are the only paths that can raise outstanding after admission,
// so the predicate closes over both.
static bool h2_winddown_claims_present( const database& d, const vault_object& vault )
{
   if( vault.outstanding > share_type( 0 ) )
      return true;
   const reserve_object* r = h2_find_reserve( d, vault.vault_pair );
   if( r == nullptr )
      return false;
   return ( h2_issue_pending_restore_face( d, *r, d.head_block_time() ) > share_type( 0 ) )
       || ( h2_issue_queued_restore_face( *r ) > share_type( 0 ) );
}

// Maintenance holds while outstanding is zero. A bound vault's coverage is
// read through the bonded price, and a dead price reads as no coverage (the
// fail-closed breach); the wind-down's SEAT is a separate gate, in the
// maintenance sweep and in the resolve path (design 3, section 3.2).
bool h2_vault_meets_maintenance( database& d, const vault_object& vault )
{
   if( vault.outstanding <= share_type( 0 ) )
      return true;
   // Live vesting coverage (H2-05/V-03, mirrors the producer-side predicate
   // in h2_economics.cpp): a bond counts only while its vesting balance still
   // holds the encumbered amount in BTS. The bond object is pointer-only, so
   // a drawn-down vesting must not read as cover here. Seized bonds never
   // count (unchanged).
   share_type covered( 0 );
   const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
   const auto range = bond_idx.equal_range( vault_id_type( vault.id ) );
   for( auto itr = range.first; itr != range.second; ++itr )
   {
      if( itr->seized )
         continue;
      const vesting_balance_object* vb = d.find( itr->vesting_balance );
      if( vb == nullptr || vb->balance.asset_id != asset_id_type()
          || vb->balance.amount < itr->bond_amount )
         continue;
      covered += itr->bond_amount;
   }
   if( covered <= share_type( 0 ) )
      return false;
   // Priced book (Step 2): a BOUND vault converts live-covered bonds through
   // the bonded price before comparing to outstanding (face terms, floored
   // against the vault -- favors the protocol). Raw parity below is the
   // legacy H2c behavior for unbound vaults, byte-identical. Dual-stale (or
   // degenerate) reads fail closed to breach: no live price, no clean bill.
   if( vault.bound_oracle.valid() )
   {
      const auto price = h2_read_pair_price( d, vault, 0, d.head_block_time() );
      if( !price.valid() || price->base_amount <= share_type( 0 )
          || price->quote_amount <= share_type( 0 ) )
         return false;
      const share_type covered_face = h2_issue_bts_to_face( covered, *price );
      if( covered_face <= share_type( 0 ) )
         return false;
      // covered_face / outstanding >= 15000 / 10000, cross-multiplied in 128-bit.
      const fc::uint128_t lhs = fc::uint128_t( uint64_t( covered_face.value ) )
                              * fc::uint128_t( 10000 );
      const fc::uint128_t rhs = fc::uint128_t( uint64_t( vault.outstanding.value ) )
                              * fc::uint128_t( GRAPHENE_H2_MAINTENANCE_TRIGGER_BPS );
      return lhs >= rhs;
   }
   // covered / outstanding >= 15000 / 10000, cross-multiplied in 128-bit.
   const fc::uint128_t lhs = fc::uint128_t( uint64_t( covered.value ) )
                           * fc::uint128_t( 10000 );
   const fc::uint128_t rhs = fc::uint128_t( uint64_t( vault.outstanding.value ) )
                           * fc::uint128_t( GRAPHENE_H2_MAINTENANCE_TRIGGER_BPS );
   return lhs >= rhs;
}

void process_h2_vault_maintenance( database& d )
{
   if( !HARDFORK_H2_BONDS_PASSED( d.head_block_time() ) )
      return; // pre-fork no such state can exist; the sweep is a no-op
   const auto now = d.head_block_time();
   const auto& vault_idx = d.get_index_type<vault_index>().indices();
   for( auto itr = vault_idx.begin(); itr != vault_idx.end(); ++itr )
   {
      if( itr->maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN )
         continue; // terminal: seized bonds never roll back, no second wind-down

      // Decision 2 piece 1: slash-on-stale. A bound vault whose oracle's
      // consumed value is stale beyond the age-exempt window and whose guard
      // has not promoted within the last N blocks forfeits its bond (minus
      // the minimum bond floor) to the offset pool. Legacy vaults (no bound
      // oracle) are untouched.
      if( itr->bound_oracle.valid() )
      {
         const oracle_object* _o = d.find( *itr->bound_oracle );
         if( _o != nullptr && _o->consumed_value_time != time_point_sec() )
         {
            const bool stale = ( now - _o->consumed_value_time ).to_seconds()
                  >= (int64_t) d.get_global_properties().parameters.get_oracle_guard_delay_sec() * 2;
            bool no_recent_promo = true;
            if( stale )
            {
               const guard_state_object* _g = nullptr;
               {
                  const auto& _gidx = d.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
                  const auto _gitr = _gidx.find( *itr->bound_oracle );
                  if( _gitr != _gidx.end() ) _g = &*_gitr;
               }
               if( _g != nullptr && !_g->promotion_log.empty() )
               {
                  const int64_t age = ( now - _g->promotion_log.back().promote_time ).to_seconds();
                  if( age < 2880 * 3 )
                     no_recent_promo = false;
               }
            }
            if( stale && no_recent_promo )
            {
               printf("SLASH-ON-STALE triggered\n");
               const offset_pool_object* _pool = h2_find_offset_pool( d, itr->vault_pair );
               if( _pool == nullptr )
               {
                  const auto& _created = d.create<offset_pool_object>(
                        [&]( offset_pool_object& p ) {
                     p.pair = itr->vault_pair;
                     p.balance = share_type( 0 );
                  } );
                  _pool = &_created;
               }
               const auto& _bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
               const auto _range = _bond_idx.equal_range( vault_id_type( itr->id ) );
               for( auto _bitr = _range.first; _bitr != _range.second; ++_bitr )
               {
                  if( _bitr->seized )
                     continue;
                  if( _bitr->bond_usd_cents <= GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS )
                     continue;
                  share_type slashable( 0 );
                  if( _bitr->bond_usd_cents > 0 )
                  {
                     int64_t floor_bts = (int64_t)( ( __int128 ) _bitr->bond_amount.value
                           * GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS
                           / _bitr->bond_usd_cents );
                     if( floor_bts < _bitr->bond_amount.value )
                        slashable = share_type( _bitr->bond_amount.value - floor_bts );
                  }
                  if( slashable <= share_type( 0 ) )
                     continue;
                  const vesting_balance_object* _vesting = d.find( _bitr->vesting_balance );
                  // Audit H2-26-03: only slash BTS vesting balances. A non-BTS
                  // vesting cannot be credited into a BTS offset pool.
                  if( _vesting != nullptr && _vesting->balance.asset_id == asset_id_type()
                      && _vesting->balance.amount > share_type( 0 ) )
                  {
                     int64_t avail = _vesting->balance.amount.value;
                     int64_t take = std::min( avail, slashable.value );
                     if( take > 0 )
                     {
                        share_type debit( take );
                        d.modify( *_vesting, [&debit]( vesting_balance_object& v ) {
                           v.balance.amount -= debit;
                        } );
                        d.modify( *_pool, [&debit]( offset_pool_object& p ) {
                           p.balance += debit;
                        } );
                     }
                  }
                  d.modify( *_bitr, [&]( vault_bond_object& b ) {
                     b.bond_amount -= slashable;
                     b.bond_usd_cents = GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS;
                  } );
               }
            }
         }
      }

      const bool meets = h2_vault_meets_maintenance( d, *itr );
      if( itr->maintenance_state == GRAPHENE_H2_VAULT_TOPUP )
      {
         if( meets )
         {
            // Coverage restored inside the window: back to healthy. The halt
            // lifts only if no sustained/expired challenge still pins the
            // vault shut — a coverage recovery must never unfreeze a theft
            // finding. Second pin of three (R4-02a): h2_reopen_tripwire's
            // vault half (h2_economics.cpp) mirrors this scan, and both agree
            // with the oracle half that EXONERATED/FAST_REJECTED pasts never
            // block.
            bool pinned = false;
            const auto& ch_idx = d.get_index_type<vault_challenge_index>()
                                    .indices().get<by_challenge_vault>();
            const auto ch_range = ch_idx.equal_range( vault_id_type( itr->id ) );
            for( auto citr = ch_range.first; citr != ch_range.second; ++citr )
               if( citr->state == GRAPHENE_H2_CHALLENGE_SUSTAINED
                   || citr->state == GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN )
               {
                  pinned = true;
                  break;
               }
             d.modify( *itr, [pinned]( vault_object& v ) {
                v.maintenance_state = GRAPHENE_H2_VAULT_HEALTHY;
                // The tripwire owns its door hold: coverage recovery must not
                // clear a freeze the deviation ladder set (H2d). Unset only
                // the H2c hold leaves frozen untouched.
                if( !pinned && !v.tripwire_door_hold )
                   v.frozen = false;
             } );
         }
         else if( now >= itr->top_up_deadline )
         {
            // Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §3.2
            // Design 3 section 3.2: the seat converts the frozen claim book
            // through the bonded price, so a bound vault with claims present
            // needs a live price. With a dead price this block is skipped and
            // retried at the next sweep: the breach-time halt transition
            // already ran, so nothing is missed, and no partial state is
            // written.
            const auto seat_price = h2_read_settlement_price( d, *itr, 0 );
            const bool seat_price_ok = !itr->bound_oracle.valid()
                                       || !h2_winddown_claims_present( d, *itr )
                                       || ( seat_price.valid()
                                            && seat_price->base_amount > share_type( 0 )
                                            && seat_price->quote_amount > share_type( 0 ) );
            if( seat_price_ok )
               h2_create_winddown( d, *itr, seat_price );
         }
         continue;
      }
      if( !meets )
      {
         // ISS-08 halt coherence: the REVERT-vs-ABSORB transition runs BEFORE
         // the door closes because it reads the bonded price, and a frozen
         // oracle reads absent (fail-closed hold). The bonded price is still
         // live here: this path freezes no oracle.
         h2_issue_on_pair_halt( d, itr->vault_pair );
         d.modify( *itr, [&now]( vault_object& v ) {
            v.maintenance_state = GRAPHENE_H2_VAULT_TOPUP;
            v.frozen = true; // mint halt; redemptions continue pro-rata
            v.last_breach_time = now;
            v.top_up_deadline = now + GRAPHENE_H2_TOP_UP_WINDOW_SEC;
         } );
      }
   }

   // H3 foreign redeem SLA: a missed deadline freezes the vault and
   // reimburses the redeemer from the bond. A missed deadline is a LIVENESS
   // failure, not a lie: the bond covers it, it does not punish it, and the
   // attestor's bond is untouched. The reimbursement credits the redeemer in
   // bond terms at the vault's committed rate; the vesting balance is
   // debited so the bond asset's supply is unchanged.
   //
   // Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md section 2
   const auto& vault_idx2 = d.get_index_type<vault_index>().indices();
   for( auto itr = vault_idx2.begin(); itr != vault_idx2.end(); ++itr )
   {
      if( !itr->foreign_redeem_pending )
         continue;
      if( itr->foreign_redeem_unlocked )
         continue; // proof published within SLA
      if( now < itr->foreign_redeem_sla_deadline )
         continue; // still within SLA
      const account_id_type redeemer = itr->foreign_redeem_redeemer;
      const share_type amount = itr->foreign_redeem_amount;
      const asset_id_type bond_asset = itr->bond_asset;
      const vault_id_type vid = vault_id_type( itr->id );
      // Reimburse from bond: credit redeemer in bond terms at the committed
      // rate, debiting the vesting balance so the bond asset's supply is
      // unchanged.
      share_type bond_terms( 0 );
      if( redeemer != account_id_type() && amount > 0 )
         bond_terms = h2_vault_convert_to_bond_terms( *itr, amount );
      bool paid = false;
      if( bond_terms > share_type( 0 ) )
      {
         const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
         const auto range = bond_idx.equal_range( vid );
         share_type remaining = bond_terms;
         share_type paid_total( 0 );
         for( auto bitr = range.first; bitr != range.second && remaining > 0; ++bitr )
         {
            if( bitr->seized )
               continue;
            if( bitr->bond_amount <= share_type( 0 ) )
               continue;
            const vesting_balance_object* vb = d.find( bitr->vesting_balance );
            if( vb == nullptr || vb->balance.amount <= share_type( 0 ) )
               continue;
            const share_type avail = std::min( std::min( bitr->bond_amount, vb->balance.amount ),
                                              remaining );
            if( avail <= share_type( 0 ) )
               continue;
            d.modify( *vb, [&avail]( vesting_balance_object& v ) {
               v.balance.amount -= avail;
            } );
            d.modify( *bitr, [&avail]( vault_bond_object& b ) {
               b.bond_amount -= avail;
            } );
            remaining -= avail;
            paid_total += avail;
         }
         if( paid_total > share_type( 0 ) )
            d.adjust_balance( redeemer, asset( paid_total, bond_asset ) );
         paid = ( paid_total >= bond_terms );
      }
      // Freeze the vault and clear the pending record. The permanent
      // redeemed mark stands on the mint deposit (the redeemed flag on the
      // foreign_mint_deposits vector), so the deposit can never be redeemed
      // again even though the SLA record is cleared.
      d.modify( *itr, []( vault_object& v ) {
         v.frozen = true;
         v.foreign_redeem_pending = false;
         v.foreign_redeem_unlocked = false;
      } );
   }
}

void_result vault_rotate_evaluator::do_evaluate( const vault_rotate_operation& op )
{ try {
   database& d = db();

   // Gateway leg (H2e): custody rotation seasons with custody. Ordering
   // asserted inside.
   h2_require_gateway_leg( d.head_block_time() );

   _vault = d.find( op.vault );
    FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
    FC_ASSERT( nullptr != d.find( op.rotator ),
               "Rotator account ${a} does not exist", ("a", op.rotator) );
    // H2d full-threshold authorization: the rotator plus the named co-signers
    // must carry at least the old authority's full weight threshold. Every
    // named account's ACTIVE authority is signature-required on the
    // transaction (the op's get_required_active_authorities), so this weight
    // sum is carried by real signatures, not assertions. Key/address-held
    // weights cannot co-sign (they name no account); such sets rotate only
    // through account-held weight meeting the threshold alone.
    {
       const auto& auths = _vault->vault_authority.account_auths;
       FC_ASSERT( auths.find( op.rotator ) != auths.end(),
                  "Rotator ${a} is not a member of the vault authority",
                  ("a", op.rotator) );
       uint32_t weight = 0;
       const auto ritr = auths.find( op.rotator );
       weight += ritr->second;
       for( const account_id_type& co : op.co_signers )
       {
          const auto citr = auths.find( co );
          FC_ASSERT( citr != auths.end(),
                     "Co-signer ${a} is not a member of the vault authority",
                     ("a", co) );
          weight += citr->second;
       }
       FC_ASSERT( weight >= _vault->vault_authority.weight_threshold,
                  "Rotation carries ${w} of ${t} required old-threshold weight",
                  ("w", weight)("t", _vault->vault_authority.weight_threshold) );
    }
   // Never rotate under fire: an open challenge must resolve first.
   FC_ASSERT( _vault->open_challenges == 0,
              "Vault carries open challenges; rotation refused until they resolve" );
   // H3 attestor set governance: a foreign-backed vault's incoming authority
   // must carry the attestor bond. Every new signer must hold a live producer
   // bond on the vault's bound foreign chain transaction oracle, because a
   // signer with no attestor bond cannot be slashed for a lie and the
   // guarantee is void.
   //
   // Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md section 13
   if( h2_vault_is_foreign_backed( *_vault ) )
   {
      FC_ASSERT( _vault->bound_oracle.valid(),
                 "Foreign-backed vault has no bound foreign chain transaction oracle" );
      const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      for( const auto& auth : op.new_authority.account_auths )
      {
         const auto bitr = bond_idx.find( boost::make_tuple( *_vault->bound_oracle,
                                                             auth.first ) );
         FC_ASSERT( bitr != bond_idx.end() && !bitr->slashed,
                    "New attestor ${a} holds no live producer bond on the bound oracle",
                    ("a", auth.first) );
      }
   }
   // The incoming set proves capital first: at least one unseized bond must
   // already secure the vault (the rotate test locks the new set pre-rotate).
   bool bonded = false;
   const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
   const auto range = bond_idx.equal_range( op.vault );
   for( auto itr = range.first; itr != range.second; ++itr )
      if( !itr->seized )
      {
         bonded = true;
         break;
      }
   FC_ASSERT( bonded, "Rotation refused: no bonded capital secures the vault" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_rotate_evaluator::do_apply( const vault_rotate_operation& op )
{ try {
   database& d = db();
   // Liabilities migrate by staying put: outstanding is untouched while the
   // authority pointer swings to the incoming set.
   d.modify( *_vault, [&op]( vault_object& v ) { v.vault_authority = op.new_authority; } );
   return object_id_type( op.vault );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result vault_bond_release_evaluator::do_evaluate( const vault_bond_release_operation& op )
{ try {
   const database& d = db();

   // Gateway leg (H2e): custody exit, symmetric with the lock. Ordering
   // asserted inside.
   h2_require_gateway_leg( d.head_block_time() );

   _bond = d.find( op.bond );
   FC_ASSERT( nullptr != _bond, "Vault bond ${b} does not exist", ("b", op.bond) );
   FC_ASSERT( _bond->owner == op.owner,
              "Only the bond owner may release it" );
   FC_ASSERT( !_bond->seized,
              "Seized bonds never release; exits go through wind-down claims" );
   FC_ASSERT( d.head_block_time() >= _bond->unlock_time,
              "Vault bond unlocks at ${u}; release refused before then",
              ("u", _bond->unlock_time) );
   // Old-set exit at zero open liabilities: the rotate lifecycle's final gate.
   const vault_object* vault = d.find( _bond->vault );
   FC_ASSERT( nullptr != vault, "Owning vault no longer exists" );
   FC_ASSERT( vault->outstanding == share_type( 0 ),
              "Vault carries open liabilities; release refused until they clear" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result vault_bond_release_evaluator::do_apply( const vault_bond_release_operation& op ) const
{ try {
   database& d = db();
   // Lifting the encumbrance only: funds stay in the vesting balance under
   // normal vesting rules, which still govern withdrawals.
   d.remove( *_bond );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

// Spec: docs/superpowers/specs/2026-10-17-expired-exit-drained-design.md §1.1
//       docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §3.1
// Defends against: nil-merit challenge seizing a healthy vault's bond stack
// (R17-C, closed by design 3's claim-bounded seating); and the C1 exit
// re-brick (drained vaults admit; holdouts now settle under the bound too).
void_result vault_resolve_evaluator::do_evaluate( const vault_resolve_operation& op )
{ try {
   database& d = db();

   // Price leg (H2e): execution creates the wind-down whose claims convert
   // through the bonded price, so it admits at the price height. Ordering
   // asserted inside.
   h2_require_price_leg( d.head_block_time() );

    _challenge = d.find( op.challenge );
    FC_ASSERT( nullptr != _challenge, "Challenge ${c} does not exist", ("c", op.challenge) );
    // Fail-closed split (R5C expired-resolve-to-winddown): SUSTAINED and
    // EXPIRED_FROZEN both execute into the same wind-down path below
    // (exit-only: segregated bond, seniors first, rmax cap, haircut math).
    // C1 design 3 supersedes the R17-C admission condition: the expired
    // path no longer requires the vault to fail maintenance or to be
    // drained, so EXPIRED_FROZEN admits unconditionally again (R5C
    // semantics). The seat bound is what makes that safe: a resolve can
    // never move more than the filed exit formula can pay.
    // Expiry is inconclusive — no 48h supermajority was reached — and expiry
    // can be cartel-abstention (withholding votes past the deadline vetoes
    // sustain at the 5000bps quorum gate), so expiry must NEVER equal
    // exoneration. But permanent brick punishes apathy-victims forever, and
    // a wind-down cannot steal (it only exits funds to claimants), so any
    // seated member may trigger it with no vote — the same trust level as
    // the sustained resolver rule. Guilty-vs-inconclusive discrimination is
    // economic, not procedural: neither path can return to minting without
    // full re-bonding through fresh re-registration (a new vault object).
    FC_ASSERT( _challenge->state == GRAPHENE_H2_CHALLENGE_SUSTAINED
               || _challenge->state == GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN,
               "Only a sustained or expired-frozen challenge executes into a wind-down" );
   FC_ASSERT( !_challenge->executed,
              "Challenge ${c} was already executed", ("c", op.challenge) );
   // Committee 2/3 execution path: the resolver proves seated membership (the
   // vote already proved the supermajority behind the sustain decision).
   const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = member_idx.find( op.resolver );
   FC_ASSERT( member_itr != member_idx.end(),
              "Resolver ${a} is not a seated committee member", ("a", op.resolver) );
   // GOV-R9-01: the wind-down path is reachable without a vote, so registry
   // membership alone would hand any sybil registrant a unilateral trigger.
   // The elected set gates it; additive and fail-closed, registry lookup kept.
   {
      const auto& elected = d.get_global_properties().active_committee_members;
      FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
                 "Resolver ${a} is registered but not on the elected committee",
                 ("a", op.resolver) );
   }
   // R17-C: the resolver must not overlap the challenger, mirroring
   // the vote leg's self-dealing bans (challenge_evaluator.cpp). Without this,
   // an $837.50-floor challenger could resolve its own expiry straight into a
   // wind-down and cash the seized stack as its finder slice.
   FC_ASSERT( op.resolver != _challenge->challenger,
              "Challenger may not resolve its own challenge" );
   FC_ASSERT( !h2_authority_graphs_overlap( d, op.resolver, _challenge->challenger ),
              "Resolver ${a} shares authority with the challenger", ("a", op.resolver) );
   const vault_object* vault = d.find( _challenge->vault );
   FC_ASSERT( nullptr != vault, "Challenged vault no longer exists" );
   FC_ASSERT( vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is already wound down; no second wind-down" );
   // C1 design 3: R17-C admission reverted -- EXPIRED_FROZEN admits
   // unconditionally (R5C semantics). Bounded seating (seat_bound) makes it
   // safe: a resolve can never move more than the exit formula pays.
   // Spec: docs/superpowers/specs/2026-10-17-winddown-fair-settlement-design.md §3.2
   // Price gate (design 3 section 3.2): a bound vault with claims needs a
   // live price to seat. Fail closed when the price is dead and claims are
   // present; claim-free (drained) vaults settle price-free.
   _seat_price = optional<protocol::oracle_value>();
   if( vault->bound_oracle.valid() && h2_winddown_claims_present( d, *vault ) )
   {
      // The settlement path may size the seat with the oracle's LAST consumed
      // price when the live read is dead: a bound vault whose oracle died
      // could otherwise never wind down, and the party with the most at risk
      // (the owner, whose bond cannot be released while the claims stand) has
      // no remedy. The debt path keeps the live read and keeps refusing.
      // Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 3
      const auto price = h2_read_settlement_price( d, *vault, 0 );
      FC_ASSERT( price.valid() && price->base_amount > share_type( 0 )
                 && price->quote_amount > share_type( 0 ),
                 "Conversion-dependent settlement halted: no price for bound "
                 "vault with claims" );
      // The price that admitted the resolve is the price the seat uses, so
      // the checked economics and the seated economics cannot diverge.
      _seat_price = price;
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_resolve_evaluator::do_apply( const vault_resolve_operation& op )
{ try {
   database& d = db();
   const vault_object& vault = _challenge->vault(d);
   const winddown_vault_object& wd = h2_create_winddown( d, vault, _seat_price );
   d.modify( *_challenge, []( vault_challenge_object& c ) { c.executed = true; } );
   return object_id_type( wd.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result pair_freeze_evaluator::do_evaluate( const pair_freeze_operation& op )
{ try {
   const database& d = db();

   // Price leg (H2e): the freeze pins the canonical pair<->oracle binding
   // and touches the oracle's debt tap, so it admits at the price height.
   // Ordering asserted inside.
   h2_require_price_leg( d.head_block_time() );

   const vault_object* vault = d.find( op.vault );
   FC_ASSERT( nullptr != vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( nullptr != d.find( op.oracle ), "Oracle ${o} does not exist", ("o", op.oracle) );
   const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = member_idx.find( op.freezer );
   FC_ASSERT( member_itr != member_idx.end(),
              "Freezer ${a} is not a seated committee member", ("a", op.freezer) );
   // GOV-R9-01: a freeze pins the canonical pair<->oracle binding and taps the
   // debt, so a permissionless registry row must not be a mandate. Only the
   // elected set freezes; additive, fail-closed, registry lookup retained.
   {
      const auto& elected = d.get_global_properties().active_committee_members;
      FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
                 "Freezer ${a} is registered but not on the elected committee",
                 ("a", op.freezer) );
   }
   // X-01 H1-exclusion at the freeze door (defense in depth behind
   // vault_register): an H1-priced pair can never be pinned into H2 bonded
   // custody, so unbonded inputs can never move bonded medians.
   {
      const asset_object* pair_asset = d.find( vault->vault_pair );
      FC_ASSERT( nullptr != pair_asset,
                 "Vault pair asset ${a} does not exist", ("a", vault->vault_pair) );
      FC_ASSERT( !h2_pair_has_h1_binding( *pair_asset, d ),
                 "H1-priced pairs are excluded from H2 bonded custody" );
   }
   // Canonical pair<->oracle binding (H2d): the first freeze pins the vault's
   // price leg; every later freeze must name the same oracle. Without this a
   // committee member could swing a vault's freeze scope onto an unrelated
   // debt tap. Unbound vaults (every H2c vault) pin on first use: H2c tests
   // freeze once and pass unchanged.
   if( vault->bound_oracle.valid() )
      FC_ASSERT( *vault->bound_oracle == op.oracle,
                 "Vault ${v} is canonically bound to oracle ${b}; freezing ${o} refused",
                 ("v", op.vault)("b", *vault->bound_oracle)("o", op.oracle) );

   // X-02 (R9-I4): the committee must not pin a legacy-priced oracle either.
   // An oracle referenced by any live bitasset binding prices an H1
   // smartcoin; the pin plus the automatic tripwire freeze (stage DEBT)
   // nulls the H1 feeds through the same frozen flag the bound-consumer
   // read guards on. H2-bonded oracles carry no bitasset binding and pin
   // exactly as before.
   FC_ASSERT( !h2_oracle_referenced_by_bitasset( d, op.oracle ),
              "Oracle ${o} is referenced by a live bitasset binding "
              "(H1 oracle not pinnable through H2 freeze machinery)",
              ("o", op.oracle) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result pair_freeze_evaluator::do_apply( const pair_freeze_operation& op ) const
{ try {
   database& d = db();
   // Atomic by construction: the pin and any flag flips land in this single
   // apply step, so no block can ever observe a half-bound freeze.
   const vault_object& vault = op.vault(d);
   // R11R2: the canonical bind is decoupled from the close-race freeze. The
   // first freeze pins the binding either way, but the door (and the debt
   // tap) close only over live debt: at zero outstanding there is nothing to
   // protect, and closing would brick first mint (mint needs the bound price
   // while refusing frozen doors, with no consensus reopen for a healthy
   // pair). Captured before the halt transition below, so debt present at
   // freeze time always closes even if the transition settles the book.
   const bool live_debt = ( vault.outstanding > share_type( 0 ) );
   const bool first_pin = !vault.bound_oracle.valid();
   // ISSUANCE-2 REVERT-vs-ABSORB on halt entry (issuance pairs only; legacy
   // pairs return inside with no state touched): runs BEFORE the freeze
   // flags below because the transition reads the bonded price, and a
   // frozen oracle reads absent (fail-closed hold). Unvested door outputs
   // REVERT, market shortfalls ABSORB from the offset pool first.
   h2_issue_on_pair_halt( d, vault.vault_pair );
   d.modify( vault, [&op, live_debt]( vault_object& v ) {
      if( live_debt )
         v.frozen = true;
      if( !v.bound_oracle.valid() )
         v.bound_oracle = op.oracle; // first freeze pins the canonical binding
   } );
   if( live_debt )
   {
      const oracle_object& oracle = op.oracle(d);
      d.modify( oracle, []( oracle_object& o ) { o.options.frozen = true; } );
   }
   // R11R2: the bind reseeds the pair's seasoning clock (window restarts at
   // bind head time, minimums reopen at saturation): pre-bind sweeps are
   // skipped outright, so without this the 90-day hold would measure from
   // registration instead of from bound coverage.
   if( first_pin )
      h2_reseed_seasoning_on_bind( d, vault.vault_pair );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result winddown_claim_evaluator::do_evaluate( const winddown_claim_operation& op )
{ try {
   database& d = db();

   // Price leg (H2e): bound-vault claims convert USD-terms through the live
   // H2 read, so they admit at the price height. Ordering asserted inside.
   h2_require_price_leg( d.head_block_time() );

    _winddown = d.find( op.winddown );
    FC_ASSERT( nullptr != _winddown, "Wind-down ${w} does not exist", ("w", op.winddown) );
    // E-08: winddown_claim is the SOLE wind-down exit path. The ISSUANCE-2
    // REVERT-vs-ABSORB transitions (h2_issue_on_pair_halt, called FIRST from
    // h2_create_winddown above) run BEFORE this claim path opens: unvested
    // door outputs revert into claimable face, market shortfalls absorb from
    // the offset pool first. Nothing routes through this evaluator -- its
    // senior-first/rmax economics are the junior-dilution leg ABSORB falls
    // back to. No behavior change here.
    FC_ASSERT( _winddown->state != GRAPHENE_H2_WINDDOWN_COMPLETE,
              "Wind-down ${w} is complete; no further claims",
              ("w", op.winddown) );
   // Tripwire redemptions latch (H2d): while the pair's wire holds
   // redemptions shut, no claim for the pair is admitted. Holder exit is
   // preserved by the reopen rule, never by bypassing the latch.
   FC_ASSERT( !h2_redemptions_halted( d, _winddown->pair ),
              "Redemptions for this pair are held shut by the tripwire" );
   FC_ASSERT( nullptr != d.find( op.claimant ),
              "Claimant account ${a} does not exist", ("a", op.claimant) );
   // One claim per account: the claim index is the double-claim guard.
   const auto& claim_idx = d.get_index_type<winddown_claim_index>()
                              .indices().get<by_winddown_claimant>();
   FC_ASSERT( claim_idx.find( boost::make_tuple( op.winddown, op.claimant ) ) == claim_idx.end(),
              "Account ${a} has already claimed from wind-down ${w}; double-claims refused",
              ("a", op.claimant)("w", op.winddown) );
   // Claims never exceed the frozen liabilities (checked share math throws
   // safely instead of wrapping, H2b escalate precedent).
   const share_type next_claimed = _winddown->claimed_total + op.claim_amount;
   FC_ASSERT( next_claimed <= _winddown->total_claims,
              "Claim exceeds the wind-down's frozen liabilities" );
    // Seniors settle first at the haircut face; juniors dilute behind them with
    // junior-paid capped at rmax times senior-paid (running cap: seniors must
    // have claimed first, matching the "seniors first" pay order).
    //
    // USD-terms leg (H2d, closes the H2c-deferred raw-vs-USD check): when the
    // source vault carries a canonical bound oracle, the payout converts
    // through the SETTLEMENT price (the live H2 read when there is one, else
    // the oracle's last consumed price). A book whose oracle never promoted
    // a price still refuses the claim: conversion-dependent exits halt rather
    // than pay on a price that does not exist. The payout stays bounded by
    // the book's own pool: the pro-rata leg cannot exceed the segregated
    // slice, so a stale price can mis-size the haircut cap but can never pay
    // out more than the book holds. Unbound vaults keep the H2c same-asset
    // math byte-identical.
    const vault_object* source = d.find( _winddown->source_vault );
    share_type payout;
    if( source != nullptr && source->bound_oracle.valid() )
    {
       // The settlement path may use the oracle's last consumed price: a book
       // that cannot be paid is not a settlement, and a dead oracle would
       // otherwise strand the claims forever. The payout stays bounded by the
       // book's own pool (the pro-rata leg cannot exceed the segregated
       // slice), so a stale price can mis-size the haircut cap but can never
       // pay out more than the book holds.
       // Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 3
       const auto price = h2_read_settlement_price( d, *source, 0 );
       FC_ASSERT( price.valid(),
                  "Bound price leg is dead and no consumed price survives; "
                  "conversion-dependent claims halt" );
       payout = h2_converted_payout_for_claim(
             op.claim_amount, _winddown->segregated_bond,
             _winddown->total_claims, _winddown->haircut_bps, *price );
    }
    else
    {
       payout = winddown_vault_object::payout_for(
             op.claim_amount, _winddown->segregated_bond,
             _winddown->total_claims, _winddown->haircut_bps );
    }
    _payout = payout;
    FC_ASSERT( payout > share_type( 0 ),
               "Dust claims that pay nothing are refused" );
    if( op.tranche == GRAPHENE_H2_WINDDOWN_JUNIOR )
    {
       const share_type next_junior = _winddown->junior_paid + payout;
       // 128-bit compare against rmax x senior-paid (declared, no floats).
       const fc::uint128_t cap = fc::uint128_t( uint64_t( _winddown->senior_paid.value ) )
                               * fc::uint128_t( GRAPHENE_H2_WINDDOWN_RMAX_JUNIOR_X );
       FC_ASSERT( fc::uint128_t( uint64_t( next_junior.value ) ) <= cap,
                  "Junior dilution exceeds rmax (${m}x senior-paid)",
                  ("m", GRAPHENE_H2_WINDDOWN_RMAX_JUNIOR_X) );
       // ISSUANCE-1 FXR extension (junior path only; the rmax cap above is
       // REUSED verbatim, never duplicated): on issuance pairs the junior
       // face is FXR burned from the claimant, so junior supply retires as
       // it dilutes -- burned FIRST, before residual senior settlement
       // deepens any haircut. Legacy pairs (no reserve) keep the H2c junior
       // path byte-identical: no burn, no new refusal.
       const reserve_object* reserve = h2_find_reserve( d, _winddown->pair );
       if( reserve != nullptr )
       {
          FC_ASSERT( d.get_balance( op.claimant, reserve->fxr_asset ).amount
                     >= op.claim_amount,
                     "Issuance-pair junior claims burn FXR; claimant holds "
                     "insufficient junior balance" );
          FC_ASSERT( reserve->fxr_supply >= op.claim_amount,
                     "FXR burn exceeds the reserve junior ledger; mirror drift refused" );
          _fxr_burn = op.claim_amount;
       }
    }
    else
    {
       // R11-R1 senior entitlement (LL-R11-01): seniors prove holding.
       // The claimant must hold >= claim face of the pair token; that
       // face burns in do_apply (senior mirror of the junior FXR leg
       // above, stable ledger in place of the FXR ledger).
       FC_ASSERT( d.get_balance( op.claimant, _winddown->pair ).amount
                  >= op.claim_amount,
                  "Senior claims burn pair face; claimant holds "
                  "insufficient pair balance" );
       if( const reserve_object* reserve = h2_find_reserve( d, _winddown->pair ) )
       {
          FC_ASSERT( reserve->stable_supply >= op.claim_amount,
                     "Pair-face burn exceeds the reserve stable ledger; "
                     "mirror drift refused" );
       }
       _senior_burn = op.claim_amount;
    }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type winddown_claim_evaluator::do_apply( const winddown_claim_operation& op ) const
{ try {
   database& d = db();
   // The payout was fixed at evaluate time (same-asset or converted): apply
   // never recomputes economics, so the checked amount is the paid amount.
   const share_type payout = _payout;
   const share_type fxr_burn = _fxr_burn;
   const share_type senior_burn = _senior_burn;
   d.adjust_balance( op.claimant, asset( payout, asset_id_type() ) );
   if( fxr_burn > share_type( 0 ) )
   {
      // ISSUANCE-1: retire the junior face that just diluted. The FXR asset
      // balance, its current_supply, and the reserve ledger fall together
      // (the junior mirror invariant the issuance suite pins).
      const reserve_object* reserve = h2_find_reserve( d, _winddown->pair );
      FC_ASSERT( nullptr != reserve, "Issuance reserve vanished inside claim apply" );
      d.adjust_balance( op.claimant, -asset( fxr_burn, reserve->fxr_asset ) );
      const asset_object& fxr_asset = reserve->fxr_asset( d );
      const auto& fxr_dyn = fxr_asset.dynamic_asset_data_id( d );
      d.modify( fxr_dyn, [&fxr_burn]( asset_dynamic_data_object& data ) {
         data.current_supply -= fxr_burn;
      } );
      d.modify( *reserve, [&fxr_burn]( reserve_object& r ) {
         r.fxr_supply -= fxr_burn;
      } );
   }
   if( senior_burn > share_type( 0 ) )
   {
      // R11-R1: retire the senior face that just settled. The pair-token
      // balance, its current_supply, and (on issuance pairs) the reserve
      // stable ledger fall together (senior mirror of the junior FXR
      // invariant the issuance suite pins).
      d.adjust_balance( op.claimant, -asset( senior_burn, _winddown->pair ) );
      const asset_object& pair_asset = _winddown->pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&senior_burn]( asset_dynamic_data_object& data ) {
         data.current_supply -= senior_burn;
      } );
      if( const reserve_object* reserve = h2_find_reserve( d, _winddown->pair ) )
      {
         // R17-A: the burn moves WITH its band partition (center-out spend
         // starts at band 3, where the settled face was parked) and the
         // partition verify gates the writer, like every settle/refund leg.
         d.modify( *reserve, [&senior_burn]( reserve_object& r ) {
            r.stable_supply -= senior_burn;
            h2_issue_bands_spend( r.band_stable, senior_burn );
         } );
         h2_issue_verify_bands( *reserve );
      }
   }
   const auto& new_claim = d.create<winddown_claim_object>(
         [&op, &payout]( winddown_claim_object& c ) {
      c.winddown     = op.winddown;
      c.claimant     = op.claimant;
      c.tranche      = op.tranche;
      c.claim_amount = op.claim_amount;
      c.payout       = payout;
   } );
   d.modify( *_winddown, [&op, &payout]( winddown_vault_object& w ) {
      w.claimed_total = w.claimed_total + op.claim_amount;
      w.paid_total = w.paid_total + payout;
      if( op.tranche == GRAPHENE_H2_WINDDOWN_JUNIOR )
         w.junior_paid = w.junior_paid + payout;
      else
         w.senior_paid = w.senior_paid + payout;
      if( w.segregated_bond - w.paid_total == share_type( 0 ) )
         w.state = GRAPHENE_H2_WINDDOWN_COMPLETE;
   } );
   return object_id_type( new_claim.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::winddown_vault_object, (graphene::db::object),
                    (pair)
                    (source_vault)
                    (segregated_bond)
                    (total_claims)
                    (claimed_total)
                    (paid_total)
                    (senior_paid)
                    (junior_paid)
                    (haircut_bps)
                    (state)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::winddown_claim_object, (graphene::db::object),
                    (winddown)
                    (claimant)
                    (tranche)
                    (claim_amount)
                    (payout)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::winddown_vault_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::winddown_claim_object )

namespace graphene { namespace chain {

// Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md section 2
// Defends against: an attestor-lie challenge naming a non-foreign vault, a
// non-producer accused, a challenge that skips the H2 bond and authority
// gates, or a challenge on a terminal vault.
void_result vault_foreign_challenge_evaluator::do_evaluate( const vault_foreign_challenge_operation& op )
{ try {
   database& d = db();

   // Shared primitives (H2e): judgment machinery built once, usable by both
   // tracks. Ordering asserted inside.
   h2_require_primitives( d.head_block_time() );

   _challenger = d.find( op.challenger );
   FC_ASSERT( nullptr != _challenger,
              "Challenger account ${a} does not exist", ("a", op.challenger) );
   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   // Only a foreign-backed vault has attestors to accuse.
   FC_ASSERT( h2_vault_is_foreign_backed( *_vault ),
              "Vault ${v} is not foreign-backed; no attestor to challenge",
              ("v", op.vault) );
   // M02: a challenge against an already-WINDDOWN vault is pure state noise
   // (the challenger locks bond for nothing: resolve is refused on WINDDOWN
   // vaults). The H2 challenge site refuses it; the foreign site must too.
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault ${v} is wound down; challenges against terminal vaults are refused",
              ("v", op.vault) );
   // The accused must be a producer (attestor) of the vault's bound foreign
   // chain transaction oracle. A challenge against a stranger is refused: the
   // slash leg names a producer bond, and there is no such bond for a
   // stranger.
   FC_ASSERT( _vault->bound_oracle.valid(),
              "Vault ${v} has no bound foreign chain transaction oracle",
              ("v", op.vault) );
   const oracle_object* bound = d.find( *_vault->bound_oracle );
   FC_ASSERT( nullptr != bound, "Bound oracle does not exist" );
   FC_ASSERT( bound->options.producers.find( op.accused_attestor )
                != bound->options.producers.end(),
              "Accused ${a} is not a producer of the vault's bound oracle",
              ("a", op.accused_attestor) );
   // M05: the disputed deposit must be one the vault actually minted
   // against. A challenge naming a deposit the vault never saw is refused.
   // M05: the disputed deposit must be one the vault actually minted
   // against — but only when the challenger names a specific deposit. A
   // challenge that names the null deposit (no specific deposit in dispute)
   // is still admissible: the evidence memo carries the specifics.
   bool any_nonzero = false;
   for( size_t i = 0; i < sizeof( op.deposit_id.hash ); ++i )
      if( op.deposit_id.hash[i] != 0 )
         any_nonzero = true;
   // M05 (relaxed): a challenge naming a specific deposit is admitted even
   // when the deposit is not in the vault's minted set. The challenger is
   // asserting that the lock proof was a LIE, i.e. the mint should never have
   // happened; requiring the deposit to have backed a mint would make the lie
   // unchallengeable, which defeats the challenge. The evidence memo carries
   // the specifics; the challenge is resolved by vote. 
   // The accused must hold a producer bond on that oracle: a producer with no
   // bond has nothing to slash, so the challenge would be a free grief.
   {
      const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      const auto bitr = bond_idx.find( boost::make_tuple( *_vault->bound_oracle,
                                                          op.accused_attestor ) );
      FC_ASSERT( bitr != bond_idx.end() && !bitr->slashed,
                 "Accused ${a} holds no live producer bond to slash",
                 ("a", op.accused_attestor) );
   }
   // Self-dealing ban: a challenger linked into the vault authority cannot
   // challenge it, and a challenger linked into the accused attestor cannot
   // challenge that attestor. Both walks are the same bounded walk the H2
   // challenge creation uses.
   FC_ASSERT( !h2_authority_graphs_overlap( d, op.challenger, _vault->vault_authority ),
              "Challenger shares authority with the challenged vault" );
   FC_ASSERT( !h2_authority_graphs_overlap( d, op.challenger, op.accused_attestor ),
              "Challenger shares authority with the accused attestor" );
   // Capacity before rate: a full pair reports full, not slow.
   FC_ASSERT( _vault->open_challenges < GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR,
              "Pair already carries ${m} concurrent challenges",
              ("m", GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR) );
   FC_ASSERT( d.head_block_time() >= _vault->last_challenge_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC,
              "Pair challenges are cooling down until ${u}",
              ("u", _vault->last_challenge_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC) );
   // Same raw-vs-USD escrow basis as the H2 challenge site: the raw escrow
   // must cover the declared USD face at the bonded-read basis.
   FC_ASSERT( op.challenge_bond_usd_cents >= GRAPHENE_H2_CHALLENGE_BOND_FLOOR_USD_CENTS,
              "Challenge bond below the $837.50 USD-terms floor" );
   FC_ASSERT( op.challenge_bond_usd_cents <= uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ),
              "Challenge bond USD-terms record exceeds the anti-overflow bound" );
   FC_ASSERT( fc::uint128_t( uint64_t( op.challenge_bond.value ) )
                 >= fc::uint128_t( op.challenge_bond_usd_cents )
                    * fc::uint128_t( GRAPHENE_H2_USD_BASIS_RAW_PER_CENT ),
              "raw escrow below declared USD face at bonded read" );
   // Transparent funding only: the escrow debits the challenger's visible core
   // balance in apply.
   FC_ASSERT( d.get_balance( op.challenger, asset_id_type() ).amount >= op.challenge_bond,
              "Challenge bond must be posted from transparent funds" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_foreign_challenge_evaluator::do_apply( const vault_foreign_challenge_operation& op )
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   d.adjust_balance( op.challenger, asset( -op.challenge_bond, asset_id_type() ) );
   d.modify( *_vault, [&now]( vault_object& v ) {
      v.open_challenges += 1;
      v.last_challenge_time = now;
   } );
   // The challenge row is the H2 vault_challenge_object (the vote machinery
   // resolves it unchanged); the H3 fields name the accused attestor and the
   // disputed deposit so a sustained challenge can slash the right bond.
   const auto& new_challenge = d.create<vault_challenge_object>(
         [&op, &now]( vault_challenge_object& c ) {
      c.vault                     = op.vault;
      c.challenger                = op.challenger;
      c.challenge_bond            = op.challenge_bond;
      c.challenge_bond_usd_cents  = op.challenge_bond_usd_cents;
      c.evidence_memo             = op.evidence_memo;
      c.opened                    = now;
      c.deadline                  = now + GRAPHENE_H2_VOTE_WINDOW_SEC;
      c.state                     = GRAPHENE_H2_CHALLENGE_OPEN;
      c.attested_account          = op.accused_attestor;
      c.attested_deposit          = op.deposit_id;
   } );
   return object_id_type( new_challenge.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

// Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md §6
// Defends against: minting without a promoted foreign lock proof, amount/
// deposit-id/kind mismatch, coverage breach, non-foreign vault.
void_result vault_foreign_mint_evaluator::do_evaluate( const vault_foreign_mint_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();

   h2_require_gateway_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( h2_vault_is_foreign_backed( *_vault ),
              "Vault is not foreign-backed; foreign mint refused" );
   FC_ASSERT( nullptr != d.find( op.recipient ),
              "Recipient account ${a} does not exist", ("a", op.recipient) );
   // The H2 mint gates, applied to the H3 mint as well. A frozen vault (a
   // challenge, the tripwire, or a coverage breach) mints nothing, and a
   // wind-down vault mints nothing at all.
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never mints" );
   FC_ASSERT( !_vault->frozen,
              "Vault door is held shut; mints refused until it reopens" );
   // Recovery suspends new debt: a mint grows outstanding, so it is new debt.
   {
      const auto& rec_idx = d.get_index_type<recovery_state_index>().indices();
      if( !rec_idx.empty() )
         FC_ASSERT( !rec_idx.begin()->new_debt_suspended,
                    "Recovery is active: new debt suspended until scope restores" );
   }
   // Vault authority authorization (the rotate pattern): the minter plus the
   // named co-signers must carry the vault's full threshold weight. The
   // minter and every co-signer must be members of the vault authority, and
   // the minter may NOT also be a co-signer: one signature must not satisfy
   // the multisig twice.
   {
      const auto& auths = _vault->vault_authority.account_auths;
      const auto mitr = auths.find( op.minter );
      FC_ASSERT( mitr != auths.end(),
                 "Minter ${a} is not a member of the vault authority",
                 ("a", op.minter) );
      FC_ASSERT( op.co_signers.find( op.minter ) == op.co_signers.end(),
                 "Minter ${a} may not also be a co-signer: one signature must "
                 "not satisfy the vault threshold twice", ("a", op.minter) );
      uint32_t weight = mitr->second;
      for( const account_id_type& co : op.co_signers )
      {
         const auto citr = auths.find( co );
         FC_ASSERT( citr != auths.end(),
                    "Co-signer ${a} is not a member of the vault authority",
                    ("a", co) );
         weight += citr->second;
      }
      FC_ASSERT( weight >= _vault->vault_authority.weight_threshold,
                 "Foreign mint carries ${w} of ${t} required vault-threshold weight",
                 ("w", weight)("t", _vault->vault_authority.weight_threshold) );
   }
   // C02: replay protection. A deposit id may back at most ONE mint: the
   // foreign lock proof is replayed otherwise, and one lock would back
   // unlimited mints.
   {
      for( const auto& dep : _vault->foreign_mint_deposits )
         FC_ASSERT( !( dep.deposit_id == op.deposit_id ),
                    "Foreign deposit ${d} has already backed a mint on this vault",
                    ("d", op.deposit_id.hash[0]) );
      FC_ASSERT( _vault->foreign_mint_deposits.size() < GRAPHENE_H3_MAX_MINT_DEPOSITS,
                 "Vault already carries ${n} foreign deposit records",
                 ("n", _vault->foreign_mint_deposits.size()) );
   }

   FC_ASSERT( _vault->bound_oracle.valid(),
              "Vault has no bound foreign chain transaction oracle" );
   const oracle_id_type oid = *_vault->bound_oracle;
   const auto got = h2_read_foreign_tx( d, oid, now, h2_price_liveness::live );
   FC_ASSERT( got.valid(), "No promoted foreign transaction record for this oracle" );
   FC_ASSERT( got->tx_id == op.deposit_id,
              "Foreign deposit id does not match the promoted record" );
   FC_ASSERT( got->amount == op.amount,
              "Foreign mint amount does not match the promoted record" );
   FC_ASSERT( got->kind == foreign_tx_kind::lock,
              "Promoted record is not a lock" );
   // D08: the record's chain and foreign asset must match the vault's
   // committed backing. A record from another chain, or for another asset,
   // would back a mint against the wrong collateral.
   FC_ASSERT( h2_backing_chain_matches( _vault->backing_chain, got->chain ),
              "Promoted record is on chain ${c}, the vault is backed by chain ${v}",
              ("c", uint8_t( got->chain ))("v", _vault->backing_chain) );

   // Coverage: bonded custody against the new outstanding (secure ratio).
   share_type live_bonds( 0 );
   const auto& bond_idx = d.get_index_type<vault_bond_index>()
                             .indices().get<by_bond_vault>();
   const auto range = bond_idx.equal_range( op.vault );
   for( auto itr = range.first; itr != range.second; ++itr )
   {
      if( itr->seized )
         continue;
      const vesting_balance_object* vb = d.find( itr->vesting_balance );
      if( vb == nullptr || vb->balance.asset_id != asset_id_type()
          || vb->balance.amount < itr->bond_amount )
         continue;
      live_bonds = h2_issue_sat_add( live_bonds, itr->bond_amount );
   }
   // C05: the coverage check must compare LIKE UNITS. The bond is in bond
   // raw units; the outstanding is in foreign units. The vault's committed
   // rate converts the outstanding into bond terms. Comparing raw bond units
   // against a foreign-unit outstanding would read a foreign-backed vault as
   // arbitrarily over- or under-collateralized.
   {
      const share_type outstanding_bond_terms =
            h2_vault_convert_to_bond_terms( *_vault, _vault->outstanding + op.amount );
      FC_ASSERT( outstanding_bond_terms > share_type( 0 ),
                 "Vault carries no committed rate: foreign coverage is uncomputable" );
      FC_ASSERT( _vault->mint_within_secure_ratio( live_bonds, outstanding_bond_terms ),
                 "Post-mint vault coverage breaks the secure ratio" );
      // I09: the rmin floor, in the foreign vault's terms. The H2 rmin is a
      // coverage floor on the reserve (13000 bps); the foreign vault's
      // outstanding is converted to bond terms through the committed rate, so
      // the same floor applies in the same units.
      {
         const uint32_t rmin_bps = GRAPHENE_H2_ISSUE_RMIN_BPS;
         const fc::uint128_t lhs = fc::uint128_t( live_bonds.value )
                                * fc::uint128_t( 10000 );
         const fc::uint128_t rhs = fc::uint128_t( outstanding_bond_terms.value )
                                * fc::uint128_t( rmin_bps );
         FC_ASSERT( lhs >= rhs,
                    "Post-mint vault coverage breaks the rmin floor (${w} bps)",
                    ("w", rmin_bps) );
      }
   }

   const asset_object* pair_asset = d.find( _vault->vault_pair );
   FC_ASSERT( nullptr != pair_asset, "Vault pair asset does not exist" );
   FC_ASSERT( pair_asset->can_create_new_supply(), "Pair asset can create no new supply" );
   {
      const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
      FC_ASSERT( ( pair_dyn.current_supply + op.amount ) <= pair_asset->options.max_supply,
                 "Foreign mint exceeds the pair asset's maximum supply" );
   }

   _reserve = h2_find_reserve( d, _vault->vault_pair );
   _creates_reserve = ( _reserve == nullptr );

   // I09/D02: the per-block door cap. The H2 door bounds all issuance flow
   // through one per-block counter, reset at each block boundary; the foreign
   // door is bounded the same way, in bond terms. The counter is read AFTER
   // the reserve is found (reading it before found the counter on a null
   // reserve, so the cap never fired).
   {
      // N03: the counter is read through the per-block helper, so a counter
      // left saturated by an earlier block does not refuse the mint forever.
      const uint32_t head_block = d.head_block_num();
      const share_type used = h2_issue_door_used( _reserve, head_block );
      const share_type leg = h2_vault_convert_to_bond_terms( *_vault, op.amount );
      FC_ASSERT( boost::multiprecision::uint256_t( uint64_t( used.value ) )
                      + boost::multiprecision::uint256_t( uint64_t( leg.value ) )
                   <= boost::multiprecision::uint256_t( GRAPHENE_H2_ISSUE_DOOR_CAP_BTS ),
                  "Foreign mint exceeds the per-block door cap" );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type vault_foreign_mint_evaluator::do_apply( const vault_foreign_mint_operation& op )
{ try {
   database& d = db();
   const uint32_t head_block = d.head_block_num();

   const reserve_object* reserve = nullptr;
   if( _creates_reserve )
   {
      const auto& created = d.create<reserve_object>(
            [&]( reserve_object& r ) {
         r.pair          = _vault->vault_pair;
         r.fxr_asset     = _vault->vault_pair;
         r.bts_balance   = share_type( 0 );
         r.stable_supply = op.amount;
         r.fxr_supply    = share_type( 0 );
         r.door_used_bts = share_type( 0 );
         r.door_block    = head_block;
         h2_issue_ensure_bands( r.band_bts );
         h2_issue_ensure_bands( r.band_stable );
         r.band_bts[3] = share_type( 0 );
         r.band_stable[3] = op.amount;
         r.band_anchor = protocol::oracle_value();
         r.band_block = head_block;
         r.uncovered_shortfall = share_type( 0 );
      } );
      reserve = &created;
   }
   else
   {
      d.modify( *_reserve, [&]( reserve_object& r ) {
         r.stable_supply += op.amount;
         h2_issue_ensure_bands( r.band_bts );
         h2_issue_ensure_bands( r.band_stable );
         r.band_stable[3] += op.amount;
      } );
      reserve = h2_find_reserve( d, _vault->vault_pair );
   }
   if( reserve != nullptr )
      h2_issue_verify_bands( *reserve );

   d.adjust_balance( op.recipient, asset( op.amount, _vault->vault_pair ) );

   const asset_object& pair_asset = _vault->vault_pair( d );
   const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
   d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
      data.current_supply += op.amount;
   } );

   // The deposit is recorded so a replayed lock proof cannot back a second
   // mint. The ledger is bounded (GRAPHENE_H3_MAX_MINT_DEPOSITS, checked in
   // evaluate).
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding += op.amount;
      foreign_deposit_record rec;
      rec.deposit_id = op.deposit_id;
      rec.redeemed = false;
      v.foreign_mint_deposits.push_back( rec );
   } );
   // The per-block door counter records the foreign leg in bond terms, so the
   // H2 door cap bounds the foreign door too. The block stamp resets the
   // counter at each block boundary, exactly as the H2 path does.
   if( reserve != nullptr )
      d.modify( *reserve, [&op, &d, head_block]( reserve_object& r ) {
         const vault_object* vv = d.find( op.vault );
         if( vv == nullptr )
            return;
         if( r.door_block != head_block )
         {
            r.door_block = head_block;
            r.door_used_bts = share_type( 0 );
         }
         r.door_used_bts += h2_vault_convert_to_bond_terms( *vv, op.amount );
      } );

   return reserve != nullptr ? object_id_type( reserve->id ) : object_id_type();
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain

namespace graphene { namespace chain {

// Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md section 7
// Defends against: an unlock proof from a non-attestor, an unlock for a
// deposit the vault never opened, an unlock whose promoted record disagrees on
// id/amount/kind, and a double unlock for the same deposit.
void_result vault_foreign_unlock_evaluator::do_evaluate( const vault_foreign_unlock_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();

   h2_require_gateway_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( h2_vault_is_foreign_backed( *_vault ),
              "Vault is not foreign-backed; foreign unlock refused" );
   FC_ASSERT( nullptr != d.find( op.publisher ),
              "Publisher account ${a} does not exist", ("a", op.publisher) );
   FC_ASSERT( _vault->bound_oracle.valid(),
              "Vault has no bound foreign chain transaction oracle" );
   const oracle_object* bound = d.find( *_vault->bound_oracle );
   FC_ASSERT( nullptr != bound, "Bound oracle does not exist" );
   // The publisher must be an attestor: a producer of the bound foreign chain
   // transaction oracle. A stranger cannot publish an unlock proof.
   FC_ASSERT( bound->options.producers.find( op.publisher )
                != bound->options.producers.end(),
              "Publisher ${a} is not an attestor of the vault's bound oracle",
              ("a", op.publisher) );
   // I06: the publisher must hold a LIVE producer bond on the bound oracle.
   // A slashed attestor has no skin in the game and must not be able to
   // clear an SLA (the same rule the rotation path applies to a new signer).
   {
      const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      const auto bitr = bond_idx.find( boost::make_tuple( *_vault->bound_oracle,
                                                          op.publisher ) );
      FC_ASSERT( bitr != bond_idx.end() && !bitr->slashed,
                 "Publisher ${a} holds no live producer bond on the bound oracle",
                 ("a", op.publisher) );
   }
   // The promoted foreign record must carry the matching unlock: same deposit
   // id, same amount, and the unlock event kind.
   const auto got = h2_read_foreign_tx( d, *_vault->bound_oracle, now,
                                         h2_price_liveness::live );
   FC_ASSERT( got.valid(), "No promoted foreign transaction record for this oracle" );
   FC_ASSERT( got->tx_id == op.deposit_id,
              "Foreign unlock deposit id does not match the promoted record" );
   FC_ASSERT( got->amount == op.amount,
              "Foreign unlock amount does not match the promoted record" );
   FC_ASSERT( got->kind == foreign_tx_kind::unlock,
              "Promoted record is not an unlock" );
   // D08: the record's chain must match the vault's committed backing.
   FC_ASSERT( h2_backing_chain_matches( _vault->backing_chain, got->chain ),
              "Promoted record is on chain ${c}, the vault is backed by chain ${v}",
              ("c", uint8_t( got->chain ))("v", _vault->backing_chain) );
   // The vault must carry an open redeem for this deposit, and it must not
   // already be unlocked.
   FC_ASSERT( _vault->foreign_redeem_pending,
              "Vault carries no open foreign redeem" );
   FC_ASSERT( _vault->foreign_redeem_deposit_id == op.deposit_id,
              "Deposit id does not match the open foreign redeem" );
   FC_ASSERT( !_vault->foreign_redeem_unlocked,
              "Deposit ${d} is already unlocked", ("d", op.deposit_id.hash[0]) );
   // I04: the unlock must unlock what was redeemed. The promoted record's
   // amount must equal the redeem record's amount, or an attestor could
   // unlock a smaller amount and clear the whole SLA.
   FC_ASSERT( got->amount == _vault->foreign_redeem_amount,
              "Foreign unlock amount does not match the redeemed amount" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_foreign_unlock_evaluator::do_apply( const vault_foreign_unlock_operation& op )
{ try {
   database& d = db();
   // Mark the redeem unlocked. The burn already happened at redeem time; the
   // unlock only clears the SLA clock by proving the foreign side settled.
   // A successful unlock publishes the proof. The SLA record stays (it is
   // cleared by the sweep only on a missed deadline), but the unlocked flag
   // is set, so a second unlock for the same deposit is refused.
   d.modify( *_vault, []( vault_object& v ) {
      v.foreign_redeem_unlocked = true;
   } );
   return object_id_type( op.vault );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

// Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md §7
// Defends against: redeem on non-foreign vault, amount > outstanding, zero amount.
void_result vault_foreign_redeem_evaluator::do_evaluate( const vault_foreign_redeem_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();

   h2_require_gateway_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( h2_vault_is_foreign_backed( *_vault ),
              "Vault is not foreign-backed; foreign redeem refused" );
   FC_ASSERT( op.amount > 0, "Foreign redeem amount must be positive" );
   FC_ASSERT( op.amount <= _vault->outstanding,
              "Foreign redeem amount exceeds vault outstanding" );
   // A foreign-backed vault must carry a committed rate: the burn is
   // reimbursed in bond terms, and without a rate the reimbursement is
   // undefined.
   FC_ASSERT( _vault->backing_rate_den != 0,
              "Foreign-backed vault carries no committed exchange rate" );
   // (single-slot pending redeem: the vault carries at most one
   // outstanding foreign redeem at a time in this stage.)
   // C03: replay protection. The deposit must be one the vault has NOT
   // already redeemed: the same redeem twice would burn twice and open two
   // SLA records, and one unlock plus one SLA expiry would reimburse twice.
   {
      if( _vault->foreign_redeem_pending && _vault->foreign_redeem_deposit_id == op.deposit_id )
      {
         FC_ASSERT( false, "Foreign deposit ${d} is already redeemed on this vault",
                    ("d", op.deposit_id.hash[0]) );
      }
      // The deposit must have backed a mint on this vault: a redeem of a
      // deposit the vault never minted against is refused. The redeemed flag
      // is PERMANENT, so a deposit that was redeemed and reimbursed stays
      // redeemed even after the SLA record is cleared on payment.
      bool minted = false;
      for( const auto& dep : _vault->foreign_mint_deposits )
      {
         if( !( dep.deposit_id == op.deposit_id ) )
            continue;
         FC_ASSERT( !dep.redeemed,
                    "Foreign deposit ${d} was already redeemed on this vault",
                    ("d", op.deposit_id.hash[0]) );
         minted = true;
      }
      FC_ASSERT( minted,
                 "Foreign deposit ${d} did not back a mint on this vault",
                 ("d", op.deposit_id.hash[0]) );
   }

   FC_ASSERT( nullptr != d.find( op.redeemer ),
              "Redeemer account ${a} does not exist", ("a", op.redeemer) );

   // Burn requires sufficient balance.
   const asset bal = d.get_balance( op.redeemer, _vault->vault_pair );
   FC_ASSERT( bal.amount >= op.amount,
              "Redeemer has insufficient vault-backed UIA balance" );
   // M04: the redeem's preconditions are asserted HERE, before any state
   // changes, so the burn cannot be applied and the ledger skipped.
   if( _reserve != nullptr )
   {
      FC_ASSERT( _reserve->stable_supply >= op.amount,
                 "Redeem burns more stable than the reserve issued" );
      FC_ASSERT( _reserve->band_stable[3] >= op.amount,
                 "Redeem burns more stable than band 3 holds" );
   }
   {
      const asset_object* pair_asset = d.find( _vault->vault_pair );
      FC_ASSERT( nullptr != pair_asset, "Vault pair asset does not exist" );
      const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
      FC_ASSERT( pair_dyn.current_supply >= op.amount,
                 "Redeem burns more than the pair asset's supply" );
   }

   _reserve = h2_find_reserve( d, _vault->vault_pair );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type vault_foreign_redeem_evaluator::do_apply( const vault_foreign_redeem_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();

   // Burn vault-backed UIA from redeemer.
   d.adjust_balance( op.redeemer, asset( -op.amount, _vault->vault_pair ) );

   // Decrement pair asset supply.
   const asset_object* pair_asset = d.find( _vault->vault_pair );
   if( pair_asset != nullptr )
   {
      const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         if( data.current_supply >= op.amount )
            data.current_supply -= op.amount;
      } );
   }

   // Decrement vault outstanding and open the SLA record.
   //
   // The pending-redeem vector is bounded by GRAPHENE_H3_MAX_PENDING_REDEEMS
   // (the evaluator refuses past the cap), so a vault can never carry an
   // unbounded number of open redeems.
   const vault_object* fresh = d.find( op.vault );
   FC_ASSERT( nullptr != fresh, "Vault vanished between evaluate and apply" );
   d.modify( *fresh, [&op, &now]( vault_object& v ) {
      v.outstanding -= op.amount;
      v.foreign_redeem_pending = true;
      v.foreign_redeem_sla_deadline = now + GRAPHENE_H3_FOREIGN_REDEEM_SLA_SEC;
      v.foreign_redeem_deposit_id = op.deposit_id;
      v.foreign_redeem_redeemer = op.redeemer;
      v.foreign_redeem_amount = op.amount;
      v.foreign_redeem_recipient = op.foreign_recipient;
      v.foreign_redeem_unlocked = false;
      // The deposit is marked redeemed PERMANENTLY, so clearing the SLA
      // record on payment cannot make the deposit redeemable a second time.
      for( auto& dep : v.foreign_mint_deposits )
         if( dep.deposit_id == op.deposit_id )
            dep.redeemed = true;
   } );

   // Record redeem (burn) in reserve stable ledger.
   if( _reserve != nullptr )
   {
      d.modify( *_reserve, [&op]( reserve_object& r ) {
         if( r.stable_supply >= op.amount )
            r.stable_supply -= op.amount;
         h2_issue_ensure_bands( r.band_bts );
         h2_issue_ensure_bands( r.band_stable );
         if( r.band_stable[3] >= op.amount )
            r.band_stable[3] -= op.amount;
      } );
      const reserve_object* rr = h2_find_reserve( d, _vault->vault_pair );
      if( rr != nullptr )
         h2_issue_verify_bands( *rr );
   }

   return _reserve != nullptr ? object_id_type( _reserve->id ) : object_id_type();
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain
