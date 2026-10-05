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
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

#include <algorithm>

namespace graphene { namespace chain {

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
      }
      if( !r->exit_queue.empty() )
         d.modify( *r, []( reserve_object& res ) { res.exit_queue.clear(); } );
      const share_type swept = r->bts_balance;
      d.modify( *r, [&]( reserve_object& res ) {
         h2_issue_ensure_bands( res.band_bts );
         std::fill( res.band_bts.begin(), res.band_bts.end(), share_type( 0 ) );
         res.bts_balance = share_type( 0 );
         res.uncovered_shortfall = share_type( 0 );
         res.last_ratio_bps = 0;
         res.snapshot_block = d.head_block_num();
      } );
      segregated += swept;
   }
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
    // EXPIRED_FROZEN both execute into the IDENTICAL wind-down path below
    // (exit-only: segregated bond, seniors first, rmax cap, haircut math).
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
   FC_ASSERT( member_idx.find( op.resolver ) != member_idx.end(),
              "Resolver ${a} is not a seated committee member", ("a", op.resolver) );
   const vault_object* vault = d.find( _challenge->vault );
   FC_ASSERT( nullptr != vault, "Challenged vault no longer exists" );
   FC_ASSERT( vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is already wound down; no second wind-down" );

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
   FC_ASSERT( member_idx.find( op.freezer ) != member_idx.end(),
              "Freezer ${a} is not a seated committee member", ("a", op.freezer) );
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

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result pair_freeze_evaluator::do_apply( const pair_freeze_operation& op ) const
{ try {
   database& d = db();
   // Atomic by construction: both flags flip in this single apply step, so no
   // block can ever observe the door closed with debt still open.
   const vault_object& vault = op.vault(d);
   // ISSUANCE-2 REVERT-vs-ABSORB on halt entry (issuance pairs only; legacy
   // pairs return inside with no state touched): runs BEFORE the freeze
   // flags below because the transition reads the bonded price, and a
   // frozen oracle reads absent (fail-closed hold). Unvested door outputs
   // REVERT, market shortfalls ABSORB from the offset pool first.
   h2_issue_on_pair_halt( d, vault.vault_pair );
   d.modify( vault, [&op]( vault_object& v ) {
      v.frozen = true;
      if( !v.bound_oracle.valid() )
         v.bound_oracle = op.oracle; // first freeze pins the canonical binding
   } );
   const oracle_object& oracle = op.oracle(d);
   d.modify( oracle, []( oracle_object& o ) { o.options.frozen = true; } );
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

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type winddown_claim_evaluator::do_apply( const winddown_claim_operation& op ) const
{ try {
   database& d = db();
   // The payout was fixed at evaluate time (same-asset or converted): apply
   // never recomputes economics, so the checked amount is the paid amount.
   const share_type payout = _payout;
   const share_type fxr_burn = _fxr_burn;
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
