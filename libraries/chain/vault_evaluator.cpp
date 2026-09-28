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
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

namespace graphene { namespace chain {

void_result vault_register_evaluator::do_evaluate( const vault_register_operation& op ) const
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( d.head_block_time() ),
              "Not allowed until the H2 bonds hardfork" );

   FC_ASSERT( nullptr != d.find( op.registrar ),
              "Registrar account ${a} does not exist", ("a", op.registrar) );
   FC_ASSERT( nullptr != d.find( op.pair ),
              "Vault pair asset ${a} does not exist", ("a", op.pair) );
   FC_ASSERT( nullptr != d.find( op.bond_asset ),
              "Bond asset ${a} does not exist", ("a", op.bond_asset) );
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
   const auto& pair_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   FC_ASSERT( pair_idx.find( op.pair ) == pair_idx.end(),
              "Pair ${a} already has a live vault set", ("a", op.pair) );

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
   const auto& new_vault = db().create<vault_object>( [&op]( vault_object& v ) {
      v.vault_pair           = op.pair;
      v.vault_authority      = op.vault_authority;
      v.min_bond             = op.min_bond;
      v.min_bond_usd_cents   = op.min_bond_usd_cents;
      v.bond_asset           = op.bond_asset;
      v.secure_ratio_bps     = op.secure_ratio_bps;
      v.challenge_window_sec = op.challenge_window_sec;
      v.outstanding          = share_type( 0 );
      v.frozen               = false;
   } );
   return object_id_type( new_vault.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result vault_bond_lock_evaluator::do_evaluate( const vault_bond_lock_operation& op ) const
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( d.head_block_time() ),
              "Not allowed until the H2 bonds hardfork" );

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
   FC_ASSERT( op.bond_amount == vault->min_bond,
              "Bond amount must equal the vault min_bond" );
   FC_ASSERT( op.bond_usd_cents == vault->min_bond_usd_cents,
              "Bond USD-terms record must match the vault min_bond basis" );

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
