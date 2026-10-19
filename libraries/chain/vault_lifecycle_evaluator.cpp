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

// Defends against: confiscation beyond the filed exit formula at zero-claims resolutions
// (C1 design 2: a provably drained vault seats nothing - empty book, no reserve sweep,
// no bond seizure), and against stranded bond stacks at sustained zero-claim resolves.
const winddown_vault_object& h2_create_winddown( database& d, const vault_object& vault )
{
   // ISSUANCE-2 REVERT-vs-ABSORB (issuance pairs only; legacy pairs return
   // inside with no state touched): unvested door outputs REVERT first so
   // the outstanding snapshot below includes reverted face (reverted holders
   // claim here), then the offset pool absorbs what it can of any residual
   // shortfall. Runs before segregation: reverted face is holder property,
   // never segregated bond.
   h2_issue_on_pair_halt( d, vault.vault_pair );
   share_type segregated( 0 );
   // ISS-13 terminal disposition (issuance pairs only): the reserve's BTS
   // backing follows the liability into the segregated remainder (holders'
   // backstop), and the reserve extinguishes around a frozen liability
   // record. Queued exits refund to face FIRST (the request-time burn
   // reverses on all four mirrors) so the outstanding snapshot below lets
   // queued holders claim in the wind-down like everyone else; without this
   // their face would stay burned and unpaid (the post-wind-down maintenance
   // sweep never settles). Offset pools are NOT swept: funded claims pay
   // liquid even in wind-down.
    if( const reserve_object* r = h2_find_reserve( d, vault.vault_pair ) )
    {
       // PC-01 pilot ceiling: this refund RE-MINTS face with
       // no door in front of it, so it must hold the same $20,000 face cap
       // the mint doors enforce. `h2_issue_on_pair_halt` above has already
       // applied (and capped) every halt revert for this pair, so this
       // projects the NEXT restore only: current_supply plus the whole exit
       // queue about to come back. Refuse fail-closed BEFORE the first
       // refund: no partial refund, no silent clamp (a half-refunded queue
       // would leave balances, book, bands, and the queue entry count
       // disagreeing). Exact integer math, no price input; equality admits
       // (inclusive cap), same as the doors. Unreachable by construction:
       // the mint and issuer-direct doors count pending + queued restore
       // face, which is exactly `current + restore` here -- so the
       // maintenance sweep that enters through this function can never
       // reject a block over it.
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
         // NC-08: the refund restored a total with its band; assert both.
         h2_issue_verify_bands( *r );
      }
      if( !r->exit_queue.empty() )
         d.modify( *r, []( reserve_object& res ) { res.exit_queue.clear(); } );
      // C1 design 2: at zero outstanding (provably drained) the
      // reserve is NOT extinguished -- no bts_balance move, no band zeroing --
      // so the empty book seats nothing and no funds move. Only the scalar
      // housekeeping fields clear, as in every wind-down (a nonzero
      // uncovered_shortfall would halt the next book's mint door). The exit
      // queue refunds above already ran and can only have raised outstanding.
      if( vault.outstanding > share_type( 0 ) )
      {
         const share_type swept = r->bts_balance;
         d.modify( *r, [&]( reserve_object& res ) {
            h2_issue_ensure_bands( res.band_bts );
            std::fill( res.band_bts.begin(), res.band_bts.end(), share_type( 0 ) );
            res.bts_balance = share_type( 0 );
            res.uncovered_shortfall = share_type( 0 );
            res.last_ratio_bps = 0;
            res.snapshot_block = d.head_block_num();
         } );
         // NC-08: extinction zeroes one leg of the partition; the other leg
         // stays (frozen liability record), so both sums must still equal their
         // totals after the sweep.
         h2_issue_verify_bands( *r );
         segregated += swept;
      }
      else
      {
         d.modify( *r, [&]( reserve_object& res ) {
            res.uncovered_shortfall = share_type( 0 );
            res.last_ratio_bps = 0;
            res.snapshot_block = d.head_block_num();
         } );
      }
   }
   // C1 design 2: at zero claims (provably drained) no bond is
   // seized -- the stack stays unseized and releasable, and the book is
   // created empty. Only claims > 0 runs the seizure loop. The claims snapshot
   // is taken AFTER the halt-revert and exit-queue refunds above, which can
   // only have raised outstanding, so a zero here is stable.
   if( vault.outstanding > share_type( 0 ) )
   {
      const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
      const auto range = bond_idx.equal_range( vault_id_type( vault.id ) );
      for( auto itr = range.first; itr != range.second; ++itr )
      {
         if( itr->seized )
            continue;
         share_type debit( 0 );
         const vesting_balance_object* vesting = d.find( itr->vesting_balance );
         if( vesting != nullptr && vesting->balance.amount > share_type( 0 ) )
         {
            // Saturating seizure: a partially-drawn vesting yields only what is
            // there, never a negative balance. Vesting objects are supply-visible,
            // so every debit here is booked into the wind-down remainder below.
            const int64_t avail = vesting->balance.amount.value;
            const int64_t want = itr->bond_amount.value;
            debit = share_type( std::min( avail, want ) );
            if( debit > share_type( 0 ) )
               d.modify( *vesting, [&debit]( vesting_balance_object& v ) {
                  v.balance.amount -= debit;
               } );
         }
         d.modify( *itr, []( vault_bond_object& b ) { b.seized = true; } );
         segregated += debit;
      }
   }
   const share_type claims = vault.outstanding;
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

// Maintenance holds while outstanding is zero; a dual-stale price leg refuses resolution when claims are present (fail-closed).
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
            h2_create_winddown( d, *itr );
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
// (R17-C); and the C1 exit re-brick (drained vaults admit; holdouts refused
// until design 3).
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
    // (exit-only: segregated bond, seniors first, rmax cap, haircut math);
    // the expired path additionally requires the vault to fail maintenance
    // or be provably drained at resolve time (R17-C + C1 design 2, gated
    // below — a healthy vault with live claims stays frozen).
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
   // R17-C + C1 design 2: expiry is INCONCLUSIVE, not
   // guilty. An EXPIRED_FROZEN wind-down runs only when the vault genuinely
   // fails maintenance at resolve time, OR when it is provably drained (no
   // outstanding face and no restorable face from the halt-revert or
   // exit-queue paths): then there is nothing left to protect and the pair
   // must be recoverable. Sustained challenges keep the seizure (the vote is
   // the merit finding there).
   if( _challenge->state == GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN )
   {
      const reserve_object* r = h2_find_reserve( d, vault->vault_pair );
      const share_type restorable = ( r == nullptr ) ? share_type( 0 )
         : h2_issue_sat_add(
              h2_issue_pending_restore_face( d, *r, d.head_block_time() ),
              h2_issue_queued_restore_face( *r ) );
      const bool provably_drained =
         vault->outstanding <= share_type( 0 ) && restorable == share_type( 0 );
      if( !provably_drained )
         FC_ASSERT( !h2_vault_meets_maintenance( d, *vault ),
                    "Expired challenge cannot wind down a vault that still "
                    "meets maintenance; resolve refused without coverage breach" );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_resolve_evaluator::do_apply( const vault_resolve_operation& op )
{ try {
   database& d = db();
   const vault_object& vault = _challenge->vault(d);
   const winddown_vault_object& wd = h2_create_winddown( d, vault );
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
    // through the live H2 price read (primary, else the single backup). A
    // dual-stale read refuses the claim: conversion-dependent exits halt
    // rather than pay on a dead price. Unbound vaults keep the H2c same-asset
    // math byte-identical.
    const vault_object* source = d.find( _winddown->source_vault );
    share_type payout;
    if( source != nullptr && source->bound_oracle.valid() )
    {
       const auto price = h2_read_pair_price( d, *source, 0, d.head_block_time() );
       FC_ASSERT( price.valid(),
                  "Bound price leg is dual-stale; conversion-dependent claims halt" );
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
