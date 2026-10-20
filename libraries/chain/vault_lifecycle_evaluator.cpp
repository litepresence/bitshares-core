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
                  if( _vesting != nullptr && _vesting->balance.amount > share_type( 0 ) )
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
