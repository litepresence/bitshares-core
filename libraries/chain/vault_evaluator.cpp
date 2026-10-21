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
#include <graphene/chain/vault_evaluator.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>

#include <fc/uint128.hpp>

namespace graphene { namespace chain {

namespace {

/// R9-I9 (H2-09): whether @p vault's wind-down book is settled — every unit
/// of the frozen-liability book has been claimed. Two equivalent readings,
/// both admission-grade: the wind-down reached COMPLETE (segregated bond
/// exhausted exactly; fires when the full claim face pays out the whole
/// seized slice), or claimed_total caught total_claims. A same-asset book
/// exhausts its slice exactly, modulo the truncation dust on the payout
/// floor; a bound book may retain drift, because the seat holds only what
/// the filed exit formula can pay and the haircut remainder is
/// protocol-retained. COMPLETE alone would re-bar those pairs forever, so
/// the claim-side reading carries them.
/// A vault in wind-down always has exactly one winddown_vault_object (no
/// second wind-down: resolve and the maintenance sweep both refuse).
bool h2_winddown_book_settled( const database& d, vault_id_type vault )
{
   const auto& wd_idx = d.get_index_type<winddown_vault_index>()
                          .indices().get<by_winddown_vault>();
   const auto range = wd_idx.equal_range( vault );
   for( auto itr = range.first; itr != range.second; ++itr )
      if( itr->state == GRAPHENE_H2_WINDDOWN_COMPLETE
          || itr->claimed_total == itr->total_claims )
         return true;
   return false; // no wind-down row: fail closed, never settled
}

} // namespace

void_result vault_register_evaluator::do_evaluate( const vault_register_operation& op ) const
{ try {
   const database& d = db();

   // Gateway leg (H2e): bonded custody admits at the gateway height, ahead
   // of price judgment. Also asserts the gateway-before-price ordering, so
   // an inverted schedule refuses here, never silently stages.
   h2_require_gateway_leg( d.head_block_time() );

   FC_ASSERT( nullptr != d.find( op.registrar ),
               "Registrar account ${a} does not exist", ("a", op.registrar) );
   const asset_object* pair_asset = d.find( op.pair );
   FC_ASSERT( nullptr != pair_asset,
               "Vault pair asset ${a} does not exist", ("a", op.pair) );
   FC_ASSERT( nullptr != d.find( op.bond_asset ),
              "Bond asset ${a} does not exist", ("a", op.bond_asset) );
   // H1-exclusion is consensus-reject (BSIP-1 section 6): bonded custody
   // is for vault-backed UIAs only. An H1-priced pair (explicit oracle
   // binding on its bitasset options) can never migrate into H2 coverage,
   // and neither can any other market-issued asset (the H1/legacy track):
   // unbonded inputs must not move bonded medians, so they are refused at
   // the custody door, not filtered downstream.
   FC_ASSERT( !h2_pair_has_h1_binding( *pair_asset, d ),
              "H1-priced pairs are excluded from H2 bonded custody" );
    FC_ASSERT( !pair_asset->is_market_issued(),
               "Vault pairs must be vault-backed UIAs: market-issued (H1-track) "
               "assets are excluded from bonded custody" );
    // LEG-R11-01 legacy attach gate (BSIP-1 coexistence: no caps, no changes
    // on legacy assets, permanently): the registrar must be the pair's
    // issuer. Without this any account could bind an H2 vault to somebody
    // else's UIA under the pilot cap, after which the pilot ceiling clamps
    // the legacy issuer's own issuance with no unregister path. Issuer
    // consent is proven by the registrar match (the registrar signs the
    // transaction as fee payer).
    FC_ASSERT( pair_asset->issuer == op.registrar,
               "Vault pair ${a} is issued by ${i}; vault registration requires "
               "the pair issuer as registrar (third-party legacy attach refused)",
               ("a", op.pair)("i", pair_asset->issuer) );
    // Pilot ceiling (AC-02, consensus-enforced): the pair's standing token
    // supply must already sit at or under the $20,000 face cap when the
    // vault binds it. Without this, pre-bind issuer-direct flow (inert
    // with no vault row to match) could print past the cap, then register
    // and leave over-cap supply standing while every future mint refuses.
    // Exact integer compare, no price/time input; equality admits
    // (inclusive cap). PC-01: pending + queued restore face counts here too
    // (all other doors do), so a bind can never accept a pair whose
    // restore paths would later cross the cap. A fresh bind has no reserve
    // yet -- the reserve is created at the first mint -- so today this term
    // is exactly zero and the check is byte-equivalent to the standing one;
    // it holds the invariant on its own should a re-bind ever follow a
    // reserve that still carries parked restore face.
    {
       const share_type pilot_cap = h2_issue_pilot_cap_face( pair_asset->precision );
       const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
       share_type restore_face( 0 );
       if( const reserve_object* reserve = h2_find_reserve( d, op.pair ) )
          restore_face = h2_issue_sat_add(
                h2_issue_pending_restore_face( d, *reserve, d.head_block_time() ),
                h2_issue_queued_restore_face( *reserve ) );
       const share_type projected =
             h2_issue_sat_add( pair_dyn.current_supply, restore_face );
       FC_ASSERT( projected <= pilot_cap,
                  "Pilot ceiling: pair current supply ${s} exceeds the "
                  "$20,000 face pilot cap for this pair; vault registration "
                  "refused while over-cap",
                  ("s", projected) );
    }
   // Allow-list enforced at registration (H2a review direction): locks check
   // per-type, so registration must not accept anything else. BTS-only at
   // genesis; basket assets join through an explicit later rule.
   FC_ASSERT( op.bond_asset == asset_id_type(),
              "Vault bond asset is BTS-only at genesis" );

   // Threshold custody must be satisfiable: an impossible threshold would lock
   // the vault on day one. Member count is bounded so the authority stays
   // serializable and signable (inventory OQ-04 proposal: 15).
   FC_ASSERT( !op.vault_authority.is_impossible(),
              "Vault authority threshold exceeds the sum of member weights" );
   FC_ASSERT( op.vault_authority.num_auths() <= GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS,
              "Vault authority exceeds ${m} members",
              ("m", GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS) );

   // One live vault set per pair (inventory OQ-03 reversible minimum): parallel
   // sets per pair are a later task's multi-set rule, never a silent duplicate.
   // R9-I9 (H2-09): a TERMINAL vault does not occupy the pair forever. The
   // documented recovery path after wind-down is fresh re-registration, so a
   // pair whose existing vault sits in wind-down with every claim settled may
   // register again (do_apply then removes the terminal object — the only
   // vault_object removal in consensus). Until settlement the refusal stands:
   // open claims must never lose their segregated source. Every other state
   // (HEALTHY, TOPUP, missing wind-down book) keeps the original live-set
   // refusal byte-for-byte.
   {
      const auto& pair_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
      const auto existing = pair_idx.find( op.pair );
      if( existing != pair_idx.end() )
      {
         FC_ASSERT( existing->maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN,
                    "Pair ${a} already has a live vault set", ("a", op.pair) );
         FC_ASSERT( h2_winddown_book_settled( d, vault_id_type( existing->id ) ),
                    "Pair ${a} carries a wound-down vault whose claims are not "
                    "settled; re-registration refused until the wind-down "
                    "completes", ("a", op.pair) );
         // R17-E: never remove a vault that still carries an OPEN
         // challenge. The removal strands the challenge row behind a dangling
         // vault id and the next expiry sweep (process_expired_h2_challenges)
         // dereferences it and halts the chain. vault_rotate carries the same
         // gate; re-registration reaches the same removal, so it needs the
         // same stop.
         FC_ASSERT( existing->open_challenges == 0,
                    "Pair ${a} carries ${c} open challenges; re-registration "
                    "refused until they resolve",
                    ("a", op.pair)("c", existing->open_challenges) );
      }
   }

   // Recovery suspends new debt (H2d): while the system scope sits below
   // 150%, registering a new vault (new debt capacity) is refused. Exits
   // (wind-down claims) stay open: this gate touches entry only.
   const auto& rec_idx = d.get_index_type<recovery_state_index>().indices();
   if( !rec_idx.empty() )
      FC_ASSERT( !rec_idx.begin()->new_debt_suspended,
                 "Recovery is active: new debt suspended until scope restores" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_register_evaluator::do_apply( const vault_register_operation& op ) const
{ try {
   database& d = db();
   // R9-I9: clear a settled terminal vault off the pair index BEFORE the new
   // row lands (by_vault_pair is ordered_unique on pair). do_evaluate admits
   // only settled wind-down books; the maintenance-state re-assert below is
   // fail-closed defense in depth — apply must never remove a live book, so
   // a drifted evaluate gate can never cascade into a live-vault removal.
   // Post-removal dangling references are all pre-tolerated: winddown_claim
   // falls back to same-asset math on a missing source vault (and a settled
   // book refuses further claims at the liability ceiling anyway),
   // vault_bond_release refuses on a missing owner vault, and the maintenance
   // / recovery / seasoning sweeps iterate live vaults only.
   share_type carried_forfeit( 0 );
   {
      const auto& pair_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
      const auto existing = pair_idx.find( op.pair );
      if( existing != pair_idx.end() )
      {
         FC_ASSERT( existing->maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN,
                    "Refusing to remove a non-winddown vault at re-registration" );
         // R17-E mirror gate (defense in depth; see do_evaluate): a drifted
         // evaluate gate can never cascade into removing a live challenge
         // tracker with the chain's expiry sweep standing behind it.
         FC_ASSERT( existing->open_challenges == 0,
                    "Refusing to remove a winddown vault that carries "
                    "${c} open challenges",
                    ("c", existing->open_challenges) );
         // The terminal vault's forfeit pool (the 15% slice of expired
         // challenge bonds) is supply-visible escrow with no other home: the
         // H2d sweep only drains BOUND vaults through their oracle's reward
         // pool, and a terminal vault's binding never advances. Carrying the
         // shell onto the pair's fresh vault keeps it counted and sweepable
         // (never crosses pairs, never burns, no invented recipient); removal
         // alone would silently destroy the escrow and unbalance supply.
         carried_forfeit = existing->forfeit_pool_balance;
         d.remove( *existing );
      }
   }
   const auto& new_vault = d.create<vault_object>( [&op, &carried_forfeit]( vault_object& v ) {
      v.vault_pair           = op.pair;
      v.vault_authority      = op.vault_authority;
      v.min_bond             = op.min_bond;
      v.min_bond_usd_cents   = op.min_bond_usd_cents;
      v.bond_asset           = op.bond_asset;
      v.secure_ratio_bps     = op.secure_ratio_bps;
      v.challenge_window_sec = op.challenge_window_sec;
      v.backing_chain        = op.backing_chain;
      v.backing_asset        = op.backing_asset;
      v.outstanding          = share_type( 0 );
      v.frozen               = false;
      v.forfeit_pool_balance = carried_forfeit;
   } );
   // Gateway-leg activation for the pair starts its 90-day BTC seasoning
   // clock (BSIP-1 section 5) in the same atomic step: no vault without a
   // clock, no clock without a vault. R9-I9: the clock is PAIR-level — a
   // re-registered pair inherits its standing record (it already seasoned
   // under the old vault; restarting the window on recovery would re-brick
   // the pair for 90 days with no adversary required), so only a first-time
   // pair opens the window here. The create helper re-asserts uniqueness.
   const auto& season_idx = d.get_index_type<seasoning_record_index>()
                              .indices().get<by_seasoning_pair>();
   if( season_idx.find( op.pair ) == season_idx.end() )
      h2_create_seasoning_record( d, op.pair, d.head_block_time() );
   return object_id_type( new_vault.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result vault_bond_lock_evaluator::do_evaluate( const vault_bond_lock_operation& op ) const
{ try {
   const database& d = db();

   // Gateway leg (H2e): vault funding seasons with custody, ahead of price
   // judgment. Ordering asserted inside.
   h2_require_gateway_leg( d.head_block_time() );

   const vault_object* vault = d.find( op.vault );
   FC_ASSERT( nullptr != vault, "Vault ${v} does not exist", ("v", op.vault) );

   const vesting_balance_object* vesting = d.find( op.vesting_balance );
   FC_ASSERT( nullptr != vesting,
              "Vesting balance ${v} does not exist", ("v", op.vesting_balance) );
   FC_ASSERT( vesting->owner == op.owner,
              "Bond vesting balance must be owned by the bond owner" );
   // H2a vesting policy is CDD: coin-days accrue but nothing vests early, so a
   // bonded member cannot quietly withdraw under the lock.
   FC_ASSERT( vesting->policy.is_type<cdd_vesting_policy>(),
              "Bond vesting balance must use the CDD policy" );
   FC_ASSERT( vesting->balance.asset_id == vault->bond_asset,
              "Bond vesting balance must be denominated in the vault bond asset" );
   FC_ASSERT( vesting->balance.amount >= op.bond_amount,
              "Bond vesting balance holds insufficient funds" );

   // The lock must equal the registered min_bond exactly, in both the raw and
   // the USD-terms records: a BTS-price move cannot silently re-size the lock.
   // The raw leg must additionally cover the USD face at the bonded-read
   // basis (H2-03): equality with a short vault record is refused, never
   // locked.
   FC_ASSERT( op.bond_amount == vault->min_bond,
              "Bond amount must equal the vault min_bond" );
   FC_ASSERT( op.bond_usd_cents == vault->min_bond_usd_cents,
              "Bond USD-terms record must match the vault min_bond basis" );
   FC_ASSERT( fc::uint128_t( uint64_t( op.bond_amount.value ) )
                 >= fc::uint128_t( op.bond_usd_cents )
                    * fc::uint128_t( GRAPHENE_H2_USD_BASIS_RAW_PER_CENT ),
              "raw escrow below declared USD face at bonded read" );

   // CDD forward-lock bounds (H2-06/SUP-05): same rule as the producer lock —
   // the encumbered vesting must be locked 7d+ into the future.
   const auto& cdd = vesting->policy.get<cdd_vesting_policy>();
   FC_ASSERT( cdd.vesting_seconds >= GRAPHENE_H2_BOND_UNBOND_DELAY_SEC
              && cdd.start_claim >= d.head_block_time(),
              "CDD must be forward-locked 7d+" );

   // Sub-vault bound (inventory OQ-10 proposal: 64): per-deposit sub-vaults
   // stay countable on-chain; the 65th lock is refused while the first 64
   // stand. Counted over live bond objects, seized bonds included (a seized
   // bond still occupies its deposit slot; wind-downs never free it).
   const auto& bond_idx = d.get_index_type<vault_bond_index>().indices().get<by_bond_vault>();
   const auto bond_range = bond_idx.equal_range( op.vault );
   uint32_t bond_count = 0;
   for( auto bitr = bond_range.first; bitr != bond_range.second; ++bitr )
      ++bond_count;
   FC_ASSERT( bond_count < GRAPHENE_H2_SUBVAULT_CAP,
              "Vault already carries ${m} bonded sub-vaults",
              ("m", GRAPHENE_H2_SUBVAULT_CAP) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_bond_lock_evaluator::do_apply( const vault_bond_lock_operation& op ) const
{ try {
   database& d = db();
   const vault_object& vault = op.vault(d);
   // Vault unbond is the challenge window plus a 7-day floor: the old bond must
   // still secure the vault until a challenger could no longer act (inventory
   // section 1.3). Zero-liability release gating arrives with wind-downs (H2c).
   const uint32_t unbond_sec = std::max( vault.challenge_window_sec,
                                         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   const auto now = d.head_block_time();
   const auto& new_bond = d.create<vault_bond_object>( [&op, &now, unbond_sec]( vault_bond_object& b ) {
      b.vault            = op.vault;
      b.owner            = op.owner;
      b.vesting_balance  = op.vesting_balance;
      b.bond_amount      = op.bond_amount;
      b.bond_usd_cents   = op.bond_usd_cents;
      b.lock_time        = now;
      b.unbond_delay_sec = unbond_sec;
      b.unlock_time      = now + unbond_sec;
      b.seized           = false;
   } );
   return object_id_type( new_bond.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

} } // graphene::chain
