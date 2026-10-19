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
#include <graphene/chain/challenge_evaluator.hpp>
#include <graphene/chain/challenge_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

#include <algorithm>

namespace graphene { namespace chain {

namespace {

/// Collects one side's authority graph: the root authority's members (1 hop),
/// then members-of-members (2 hops). The width cap takes the first 15 entries
/// of each ordered authority map, so the cutoff is deterministic. Cycles
/// terminate through the insert check: a revisited account is never expanded.
void h2_collect_authority( database& d, const authority& auth, uint32_t depth,
                           flat_set<account_id_type>& accts, flat_set<public_key_type>& keys )
{
   if( depth > GRAPHENE_H2_AUTHORITY_GRAPH_MAX_DEPTH )
      return;
   uint32_t width = 0;
   for( const auto& item : auth.account_auths )
   {
      if( width++ >= GRAPHENE_H2_AUTHORITY_GRAPH_MAX_WIDTH )
         break;
      if( !accts.insert( item.first ).second )
         continue; // already walked: cycle-safe
      if( depth + 1 >= GRAPHENE_H2_AUTHORITY_GRAPH_MAX_DEPTH )
         continue;
      const account_object* acct = d.find( item.first );
      if( acct == nullptr )
         continue;
      h2_collect_authority( d, acct->owner, depth + 1, accts, keys );
      h2_collect_authority( d, acct->active, depth + 1, accts, keys );
   }
   width = 0;
   for( const auto& item : auth.key_auths )
   {
      if( width++ >= GRAPHENE_H2_AUTHORITY_GRAPH_MAX_WIDTH )
         break;
      keys.insert( item.first );
   }
}

void h2_collect_account_side( database& d, account_id_type root,
                              flat_set<account_id_type>& accts,
                              flat_set<public_key_type>& keys )
{
   accts.insert( root ); // the root itself: self-pairings overlap by construction
   const account_object* acct = d.find( root );
   if( acct == nullptr )
      return;
   h2_collect_authority( d, acct->owner, 0, accts, keys );
   h2_collect_authority( d, acct->active, 0, accts, keys );
}

bool h2_sets_overlap( const flat_set<account_id_type>& a_accts,
                      const flat_set<public_key_type>& a_keys,
                      const flat_set<account_id_type>& b_accts,
                      const flat_set<public_key_type>& b_keys )
{
   for( const account_id_type& id : a_accts )
      if( b_accts.find( id ) != b_accts.end() )
         return true;
   for( const public_key_type& key : a_keys )
      if( b_keys.find( key ) != b_keys.end() )
         return true;
   return false;
}

/// 2/3-supermajority threshold over N seated members, from the published
/// GRAPHENE_H2_SUPERMAJORITY_BPS constant (H2c cleanup: was an inline
/// ceil(2N/3); the BPS form is authoritative. It coincides with ceil(2N/3)
/// except where 6667bps strictly exceeds two-thirds (N a multiple of 3),
/// where it requires one more vote — the conservative side).
uint64_t h2_supermajority_of( uint64_t n )
{
   return ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
}

bool h2_quorum_met( uint64_t votes_cast, uint64_t n )
{
   // Published quorum GRAPHENE_H2_QUORUM_BPS participation (H2c cleanup: now
   // computed from the constant; arithmetically identical to 2*votes >= n).
   return votes_cast * 10000 >= n * GRAPHENE_H2_QUORUM_BPS;
}

} // namespace

void h2_split_forfeit( share_type total_raw, uint64_t total_usd_cents,
                       share_type& burn, share_type& pool, share_type& finder )
{
   if( total_raw <= 0 )
   {
      burn = pool = finder = share_type( 0 );
      return;
   }
   const fc::uint128_t total = fc::uint128_t( uint64_t( total_raw.value ) );
   const uint64_t burn_raw = uint64_t( total * GRAPHENE_H2_FORFEIT_BURN_BPS / 10000 );
   const uint64_t pool_raw = uint64_t( total * GRAPHENE_H2_FORFEIT_POOL_BPS / 10000 );
   uint64_t finder_raw = uint64_t( total_raw.value ) - burn_raw - pool_raw;
   // The finder remainder (~5% plus dust) is capped at $83.75 in USD terms at
   // lock. The cap binds only on escalated totals; cap excess burns so the
   // three parts always sum to the total exactly.
   uint64_t burn_final = burn_raw;
   if( finder_raw > 0 )
   {
      const fc::uint128_t finder_usd =
            fc::uint128_t( total_usd_cents ) * fc::uint128_t( finder_raw )
            / fc::uint128_t( uint64_t( total_raw.value ) );
      if( finder_usd > GRAPHENE_H2_FINDER_CAP_USD_CENTS )
      {
         finder_raw = uint64_t( fc::uint128_t( finder_raw )
                        * fc::uint128_t( GRAPHENE_H2_FINDER_CAP_USD_CENTS )
                        / finder_usd );
         burn_final = uint64_t( total_raw.value ) - pool_raw - finder_raw;
      }
   }
   burn = share_type( int64_t( burn_final ) );
   pool = share_type( int64_t( pool_raw ) );
   finder = share_type( int64_t( finder_raw ) );
}

bool h2_authority_graphs_overlap( database& d, account_id_type challenger,
                                  const authority& vault_auth )
{
   flat_set<account_id_type> c_accts, v_accts;
   flat_set<public_key_type> c_keys, v_keys;
   h2_collect_account_side( d, challenger, c_accts, c_keys );
   h2_collect_authority( d, vault_auth, 0, v_accts, v_keys );
   return h2_sets_overlap( c_accts, c_keys, v_accts, v_keys );
}

bool h2_authority_graphs_overlap( database& d, account_id_type challenger,
                                  account_id_type defender )
{
   flat_set<account_id_type> c_accts, d_accts;
   flat_set<public_key_type> c_keys, d_keys;
   h2_collect_account_side( d, challenger, c_accts, c_keys );
   h2_collect_account_side( d, defender, d_accts, d_keys );
   return h2_sets_overlap( c_accts, c_keys, d_accts, d_keys );
}

void_result vault_challenge_evaluator::do_evaluate( const vault_challenge_operation& op )
{ try {
   database& d = db();

   // Shared primitives (H2e): judgment machinery built once, usable by both
   // tracks. Ordering asserted inside.
   h2_require_primitives( d.head_block_time() );

   _challenger = d.find( op.challenger );
   FC_ASSERT( nullptr != _challenger,
              "Challenger account ${a} does not exist", ("a", op.challenger) );
    const vault_object* vault = d.find( op.vault );
    FC_ASSERT( nullptr != vault, "Vault ${v} does not exist", ("v", op.vault) );
    // R6C fail-closed: challenges against an already-WINDDOWN vault are pure
    // state noise (the challenger locks bond for nothing: resolve is refused
    // on WINDDOWN vaults). Refuse creation here, before the capacity/cooldown
    // branches, so the refusal pins to the terminal state and never to a
    // cooldown. Fail-closed direction only (rejects more, never less).
    FC_ASSERT( vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
               "Vault ${v} is wound down; challenges against terminal vaults are refused",
               ("v", op.vault) );

   // Self-dealing ban: a challenger linked into the vault authority within the
   // bounded walk cannot challenge it.
   FC_ASSERT( !h2_authority_graphs_overlap( d, op.challenger, vault->vault_authority ),
              "Challenger shares authority with the challenged vault" );

   // Capacity before rate: a full pair reports full, not slow.
   FC_ASSERT( vault->open_challenges < GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR,
              "Pair already carries ${m} concurrent challenges",
              ("m", GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR) );
   FC_ASSERT( d.head_block_time() >= vault->last_challenge_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC,
              "Pair challenges are cooling down until ${u}",
              ("u", vault->last_challenge_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC) );

   // Raw-vs-USD escrow basis (H2-03): the raw escrow must cover the declared
   // USD face at GRAPHENE_H2_USD_BASIS_RAW_PER_CENT (128-bit, overflow-safe).
   // The old H2d-deferral let a 1-satoshi escrow claim the full $837.50 face;
   // the floor below kills that today, with no consensus price needed.
   FC_ASSERT( op.challenge_bond_usd_cents >= GRAPHENE_H2_CHALLENGE_BOND_FLOOR_USD_CENTS,
              "Challenge bond below the $837.50 USD-terms floor" );
   FC_ASSERT( op.challenge_bond_usd_cents <= uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ),
              "Challenge bond USD-terms record exceeds the anti-overflow bound" );
   FC_ASSERT( fc::uint128_t( uint64_t( op.challenge_bond.value ) )
                 >= fc::uint128_t( op.challenge_bond_usd_cents )
                    * fc::uint128_t( GRAPHENE_H2_USD_BASIS_RAW_PER_CENT ),
              "raw escrow below declared USD face at bonded read" );

   // Transparent funding only: the escrow debits the challenger's visible core
   // balance in apply. Confidential balances are never consulted, so blind
   // money cannot fund a challenge; an account holding only blind funds fails
   // here.
   FC_ASSERT( d.get_balance( op.challenger, asset_id_type() ).amount >= op.challenge_bond,
              "Challenge bond must be posted from transparent funds" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type vault_challenge_evaluator::do_apply( const vault_challenge_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   d.adjust_balance( op.challenger, asset( -op.challenge_bond, asset_id_type() ) );
   const vault_object& vault = op.vault(d);
   d.modify( vault, [&now]( vault_object& v ) {
      v.open_challenges += 1;
      v.last_challenge_time = now;
   } );
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
   } );
   return object_id_type( new_challenge.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_dispute_evaluator::do_evaluate( const oracle_dispute_operation& op )
{ try {
   database& d = db();

   // Shared primitives (H2e): judgment machinery built once, usable by both
   // tracks. Ordering asserted inside.
   h2_require_primitives( d.head_block_time() );

   _challenger = d.find( op.challenger );
   FC_ASSERT( nullptr != _challenger,
              "Challenger account ${a} does not exist", ("a", op.challenger) );
   const oracle_object* oracle = d.find( op.oracle );
   FC_ASSERT( nullptr != oracle, "Oracle ${o} does not exist", ("o", op.oracle) );
   FC_ASSERT( oracle->options.producers.find( op.defender ) != oracle->options.producers.end(),
              "Defender ${a} is not a producer of oracle ${o}",
              ("a", op.defender)("o", op.oracle) );

   FC_ASSERT( !h2_authority_graphs_overlap( d, op.challenger, op.defender ),
              "Challenger shares authority with the accused producer" );

   FC_ASSERT( oracle->open_disputes < GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR,
              "Oracle already carries ${m} concurrent disputes",
              ("m", GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR) );
   FC_ASSERT( d.head_block_time() >= oracle->last_dispute_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC,
              "Oracle disputes are cooling down until ${u}",
              ("u", oracle->last_dispute_time + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC) );

   // Disputes name a retained aggregate (inventory OQ-28 reversible minimum:
   // history timestamp plus series index), never a live submission.
   bool accused_found = false;
   for( const auto& entry : oracle->history )
   {
      if( entry.first != op.accused_time )
         continue;
      FC_ASSERT( op.accused_series < entry.second.size(),
                 "Accused series ${s} is outside the retained aggregate",
                 ("s", op.accused_series) );
      accused_found = true;
      break;
   }
   FC_ASSERT( accused_found, "Accused time names no retained oracle history" );

   // Same raw-vs-USD escrow basis as the challenge site (H2-03): the round-1
   // raw escrow must cover the declared USD face at the bonded-read basis.
   FC_ASSERT( op.dispute_bond_usd_cents >= GRAPHENE_H2_CHALLENGE_BOND_FLOOR_USD_CENTS,
              "Dispute bond below the $837.50 USD-terms floor" );
   FC_ASSERT( op.dispute_bond_usd_cents <= uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ),
              "Dispute bond USD-terms record exceeds the anti-overflow bound" );
   FC_ASSERT( fc::uint128_t( uint64_t( op.dispute_bond.value ) )
                 >= fc::uint128_t( op.dispute_bond_usd_cents )
                    * fc::uint128_t( GRAPHENE_H2_USD_BASIS_RAW_PER_CENT ),
              "raw escrow below declared USD face at bonded read" );
   FC_ASSERT( d.get_balance( op.challenger, asset_id_type() ).amount >= op.dispute_bond,
              "Dispute bond must be posted from transparent funds" );

   // X-02 (R9-I4): H1-exclusion on the challenge path. An oracle referenced
   // by any live bitasset binding prices an H1 smartcoin; dispute expiry
   // freezes unconditionally with no committee vote, and the H1
   // bound-consumer read guards on the same frozen flag -- the smartcoin
   // would behave as its feeds expire. H2-bonded oracles carry no bitasset
   // binding and stay fully disputable.
   FC_ASSERT( !h2_oracle_referenced_by_bitasset( d, op.oracle ),
              "Oracle ${o} is referenced by a live bitasset binding "
              "(H1 oracle not disputable through H2 machinery)",
              ("o", op.oracle) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type oracle_dispute_evaluator::do_apply( const oracle_dispute_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   d.adjust_balance( op.challenger, asset( -op.dispute_bond, asset_id_type() ) );
   const oracle_object& oracle = op.oracle(d);
   d.modify( oracle, [&now]( oracle_object& o ) {
      o.open_disputes += 1;
      o.last_dispute_time = now;
   } );
   const auto& new_dispute = d.create<oracle_dispute_object>(
         [&op, &now]( oracle_dispute_object& x ) {
      x.oracle                  = op.oracle;
      x.challenger              = op.challenger;
      x.defender                = op.defender;
      x.accused_time            = op.accused_time;
      x.accused_series          = op.accused_series;
      x.round                   = 1;
      x.challenger_bonds        = op.dispute_bond;
      x.defender_bonds          = share_type( 0 );
      x.round1_bond             = op.dispute_bond;
      x.round1_bond_usd_cents   = op.dispute_bond_usd_cents;
      x.challenger_bonds_usd_cents = op.dispute_bond_usd_cents;
      x.defender_bonds_usd_cents   = 0;
      x.evidence_memo           = op.evidence_memo;
      x.opened                  = now;
      x.round_deadline          = now + GRAPHENE_H2_VOTE_WINDOW_SEC;
      x.state                   = GRAPHENE_H2_CHALLENGE_OPEN;
   } );
   return object_id_type( new_dispute.id );
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_dispute_escalate_evaluator::do_evaluate( const oracle_dispute_escalate_operation& op )
{ try {
   database& d = db();

   // Shared primitives (H2e): judgment machinery built once, usable by both
   // tracks. Ordering asserted inside.
   h2_require_primitives( d.head_block_time() );

   _dispute = d.find( op.dispute );
   FC_ASSERT( nullptr != _dispute, "Dispute ${x} does not exist", ("x", op.dispute) );
   FC_ASSERT( _dispute->state == GRAPHENE_H2_CHALLENGE_OPEN,
              "Only an open dispute may be escalated" );
   FC_ASSERT( d.head_block_time() <= _dispute->round_deadline,
              "The round window has closed; escalation is over" );
   FC_ASSERT( op.escalator == _dispute->challenger || op.escalator == _dispute->defender,
              "Only the challenger or the defender may escalate" );
   FC_ASSERT( _dispute->round < GRAPHENE_H2_DISPUTE_MAX_ROUNDS,
              "Dispute rounds cap at ${m}", ("m", GRAPHENE_H2_DISPUTE_MAX_ROUNDS) );

   // The ladder climbs one rung at a time: rung r costs base x 2^(r-1), raw
   // and USD-terms alike, computed in 128-bit with an overflow guard.
   const uint8_t new_round = _dispute->round + 1;
   const fc::uint128_t expected_raw =
         fc::uint128_t( uint64_t( _dispute->round1_bond.value ) ) << ( new_round - 1 );
   const fc::uint128_t expected_usd =
         fc::uint128_t( _dispute->round1_bond_usd_cents ) << ( new_round - 1 );
   FC_ASSERT( expected_raw <= fc::uint128_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ),
              "Escalation rung overflows the share supply" );
   FC_ASSERT( expected_usd <= fc::uint128_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ),
              "Escalation rung USD record exceeds the anti-overflow bound" );
   FC_ASSERT( fc::uint128_t( uint64_t( op.round_bond.value ) ) == expected_raw,
              "Round bond must exactly double the ladder rung" );
   FC_ASSERT( op.round_bond_usd_cents == uint64_t( expected_usd ),
              "Round bond USD record must exactly double the ladder rung" );
   // Plain-uint64 side sums wrap silently, so the new sum is checked in
   // 128-bit: raw side sums use checked share_type math and throw safely.
   const uint64_t side_usd_old = ( op.escalator == _dispute->challenger )
         ? _dispute->challenger_bonds_usd_cents : _dispute->defender_bonds_usd_cents;
   FC_ASSERT( fc::uint128_t( side_usd_old ) + expected_usd
                 <= fc::uint128_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ),
              "Escalation side USD sum exceeds the anti-overflow bound" );
   FC_ASSERT( d.get_balance( op.escalator, asset_id_type() ).amount >= op.round_bond,
              "Round bond must be posted from transparent funds" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_dispute_escalate_evaluator::do_apply( const oracle_dispute_escalate_operation& op ) const
{ try {
   database& d = db();
   d.adjust_balance( op.escalator, asset( -op.round_bond, asset_id_type() ) );
   const auto now = d.head_block_time();
   d.modify( *_dispute, [&op, &now]( oracle_dispute_object& x ) {
      if( op.escalator == x.challenger )
      {
         x.challenger_bonds = x.challenger_bonds + op.round_bond;
         x.challenger_bonds_usd_cents += op.round_bond_usd_cents;
      }
      else
      {
         x.defender_bonds = x.defender_bonds + op.round_bond;
         x.defender_bonds_usd_cents += op.round_bond_usd_cents;
      }
      x.round += 1;
      x.round_deadline = now + GRAPHENE_H2_VOTE_WINDOW_SEC;
   } );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

namespace {

/// Shared vote-resolution consequences. The winning side's escrow returns in
/// full; the losing side's total forfeits through the 80/15/finder split.
/// Sustain additionally freezes the target and marks an accused producer bond
/// slashed (seizure math itself is H2c). The finder is the decisive voter when
/// the challenger loses, and the vindicated challenger when the defender loses.
void h2_apply_challenge_resolution( database& d, const vault_challenge_object& c,
                                    uint8_t resolution, account_id_type decisive_voter )
{
   const vault_object& vault = c.vault(d);
   share_type burn, pool, finder;
   if( resolution == GRAPHENE_H2_DISPUTE_SUSTAIN )
   {
      d.adjust_balance( c.challenger, asset( c.challenge_bond, asset_id_type() ) );
      d.modify( c, []( vault_challenge_object& m ) {
         m.finder = m.challenger;
         m.state = GRAPHENE_H2_CHALLENGE_SUSTAINED;
      } );
      // ISS-08 halt coherence: run the REVERT-vs-ABSORB transition before the
      // door closes (bonded price still live: this path freezes no oracle).
      h2_issue_on_pair_halt( d, vault.vault_pair );
      d.modify( vault, []( vault_object& v ) {
         v.open_challenges -= 1;
         v.frozen = true; // fail-closed: sustained theft/failure halts mints
      } );
      return;
   }
   // Exonerate and fast-reject both forfeit the challenger's full posted total
   // (fast-reject's "full" is the whole total, never a single rung): the two
   // resolutions differ in the recorded outcome, not in the economics.
   h2_split_forfeit( c.challenge_bond, c.challenge_bond_usd_cents, burn, pool, finder );
   const asset_dynamic_data_object& core_data = d.get_core_dynamic_data();
   d.modify( core_data, [&burn]( asset_dynamic_data_object& data ) {
      data.current_supply -= burn;
   } );
   // CQ-R9-04 (defense in depth): GOV-R9-04 refuses a party vote
   // before recording, so a decisive voter below cannot be the challenger.
   // Assert it at the money anyway: the finder slice is a capped payment
   // ($83.75) to whoever decides, and a future call site or a reordered gate
   // must never pay a party to decide its own target. The SUSTAIN branch
   // above pays the vindicated CHALLENGER by design (not a decisive voter)
   // and is deliberately outside this assert.
   FC_ASSERT( decisive_voter != c.challenger,
              "Decisive voter is the challenger; finder self-payment refused" );
   d.adjust_balance( decisive_voter, asset( finder, asset_id_type() ) );
   d.modify( c, [&resolution, &decisive_voter]( vault_challenge_object& m ) {
      m.finder = decisive_voter;
      m.state = ( resolution == GRAPHENE_H2_DISPUTE_FAST_REJECT )
                ? GRAPHENE_H2_CHALLENGE_FAST_REJECTED : GRAPHENE_H2_CHALLENGE_EXONERATED;
   } );
   d.modify( vault, [&pool]( vault_object& v ) {
      v.open_challenges -= 1;
      v.forfeit_pool_balance = v.forfeit_pool_balance + pool;
   } );
}

/// GOV-R9-02: anchor the committee unfreeze time-lock the instant an oracle's
/// last open dispute clears. Runs inside the object's modify lambda, so it
/// reads the post-decrement counter and records ONLY on the transition to 0 --
/// a still-open dispute leaves the previous anchor alone. oracle_unfreeze
/// checks `open_disputes == 0` before it ever reads the anchor, so the two
/// gates cannot disagree about whether a clear happened.
inline void h2_note_dispute_cleared( oracle_object& o, time_point_sec cleared_at )
{
   if( o.open_disputes == 0 )
      o.dispute_cleared_time = cleared_at;
}

void h2_apply_dispute_resolution( database& d, const oracle_dispute_object& x,
                                  uint8_t resolution, account_id_type decisive_voter )
{
   const oracle_object& oracle = x.oracle(d);
   const time_point_sec cleared_at = d.head_block_time();
   if( resolution == GRAPHENE_H2_DISPUTE_SUSTAIN )
   {
      d.adjust_balance( x.challenger, asset( x.challenger_bonds, asset_id_type() ) );
      if( x.defender_bonds > 0 )
      {
         share_type burn, pool, finder;
         h2_split_forfeit( x.defender_bonds, x.defender_bonds_usd_cents, burn, pool, finder );
         const asset_dynamic_data_object& core_data = d.get_core_dynamic_data();
         d.modify( core_data, [&burn]( asset_dynamic_data_object& data ) {
            data.current_supply -= burn;
         } );
         d.adjust_balance( x.challenger, asset( finder, asset_id_type() ) );
         d.modify( oracle, [&pool]( oracle_object& o ) {
            o.forfeit_pool_balance = o.forfeit_pool_balance + pool;
         } );
      }
      // The accused producer's bond is marked slashed: the only slash path.
      // A producer who never locked has no bond object; that is a no-op, not
      // an error. Seizure of the slashed bond is H2c.
      const auto& pair_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      const auto bitr = pair_idx.find( boost::make_tuple( x.oracle, x.defender ) );
      if( bitr != pair_idx.end() )
         d.modify( *bitr, []( producer_bond_object& b ) { b.slashed = true; } );
      d.modify( x, []( oracle_dispute_object& m ) {
         m.finder = m.challenger;
         m.state = GRAPHENE_H2_CHALLENGE_SUSTAINED;
      } );
      d.modify( oracle, [cleared_at]( oracle_object& o ) {
         o.open_disputes -= 1;
         // Fail-closed: a sustained bad print stops value promotion while the
         // raw aggregate stays transparent. R-02: the owner MUST NOT clear
         // this challenge-set freeze through oracle_update (refused while a
         // sustained/expired dispute names the oracle); only the committee
         // oracle_unfreeze op clears after resolution. Track A owner freezes
         // (no dispute history) still clear via oracle_update.
         // Slash stays flag-only here (slashed=true above); slash-to-seizure
         // is a follow-on phase, not half-built.
         o.options.frozen = true;
         // GOV-R9-02: the clear anchors the unfreeze time-lock (a 2/3-sustained
         // freeze is not undone by one member in the same breath).
         h2_note_dispute_cleared( o, cleared_at );
      } );
      return;
   }
   d.adjust_balance( x.defender, asset( x.defender_bonds, asset_id_type() ) );
   share_type burn, pool, finder;
   h2_split_forfeit( x.challenger_bonds, x.challenger_bonds_usd_cents, burn, pool, finder );
   const asset_dynamic_data_object& core_data = d.get_core_dynamic_data();
   d.modify( core_data, [&burn]( asset_dynamic_data_object& data ) {
      data.current_supply -= burn;
   } );
   // CQ-R9-04 (defense in depth): same self-payment ban as the
   // challenge track -- neither party may collect the finder slice as the
   // decisive voter. The SUSTAIN branch above pays the vindicated challenger
   // by design and stays outside this assert.
   FC_ASSERT( decisive_voter != x.challenger && decisive_voter != x.defender,
              "Decisive voter is a party to the dispute; finder self-payment refused" );
   d.adjust_balance( decisive_voter, asset( finder, asset_id_type() ) );
   d.modify( x, [&resolution, &decisive_voter]( oracle_dispute_object& m ) {
      m.finder = decisive_voter;
      m.state = ( resolution == GRAPHENE_H2_DISPUTE_FAST_REJECT )
                ? GRAPHENE_H2_CHALLENGE_FAST_REJECTED : GRAPHENE_H2_CHALLENGE_EXONERATED;
   } );
   d.modify( oracle, [cleared_at, &pool]( oracle_object& o ) {
      o.open_disputes -= 1;
      o.forfeit_pool_balance = o.forfeit_pool_balance + pool;
      // GOV-R9-02: exoneration/fast-reject clears the counter too, so the
      // anchor tracks the clear whatever the verdict (the unfreeze gate reads
      // it only while a freeze stands).
      h2_note_dispute_cleared( o, cleared_at );
   } );
}

} // namespace

// Defends against: chain-halt null deref on a correctly-typed id naming a
// nonexistent vote target (R24-01 / H2-24-01).
void_result challenge_vote_evaluator::do_evaluate( const challenge_vote_operation& op )
{ try {
   database& d = db();

   // Shared primitives (H2e): judgment machinery built once, usable by both
   // tracks. Ordering asserted inside.
   h2_require_primitives( d.head_block_time() );

   _challenge = nullptr;
   _dispute = nullptr;
   if( op.target.is<vault_challenge_id_type>() )
      _challenge = d.find( op.target.as<vault_challenge_id_type>() );
   else if( op.target.is<oracle_dispute_id_type>() )
      _dispute = d.find( op.target.as<oracle_dispute_id_type>() );
   else
      FC_ASSERT( false, "Vote target must be a vault challenge or an oracle dispute" );

   // R24-01 / H2-24-01: a correctly-typed id naming a nonexistent
   // object leaves both pointers null; the ternary below would null-deref in
   // consensus and halt every applying node. Fail closed instead.
   FC_ASSERT( _challenge != nullptr || _dispute != nullptr,
              "Vote target object does not exist" );

   const uint8_t state = ( _challenge != nullptr ) ? _challenge->state : _dispute->state;
   FC_ASSERT( state == GRAPHENE_H2_CHALLENGE_OPEN,
              "Only an open challenge or dispute may be voted on" );
   const fc::time_point_sec deadline = ( _challenge != nullptr )
         ? _challenge->deadline : _dispute->round_deadline;
   FC_ASSERT( d.head_block_time() <= deadline,
              "The vote window has closed; silence fails closed at maintenance" );

   const auto& member_idx = d.get_index_type<committee_member_index>()
                               .indices().get<by_account>();
   const auto member_itr = member_idx.find( op.voter );
   FC_ASSERT( member_itr != member_idx.end(),
              "Voter ${a} is not a seated committee member", ("a", op.voter) );
   // GOV-R9-01: the registry is permissionless (op-29, LTM only) and its rows
   // are never pruned, so membership alone lets K sybil registrations grow the
   // deciding set and shrink supermajority_of(N) below an attacker's reach.
   // The elected set is the gate; this check is additive and fail-closed --
   // the lookup above still identifies the committee_member_object.
    const auto& elected = d.get_global_properties().active_committee_members;
    FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
               "Voter ${a} is registered but not on the elected committee",
               ("a", op.voter) );
    // GOV-R9-04: neither side of the target may vote on it. The
    // challenge track names its challenger directly and its defender is the
    // VAULT's own authority (vault_challenge_object carries no defender
    // field); the dispute track names both sides. The walk below is the same
    // bounded authority-graph check challenge creation uses against the vault
    // (h2_authority_graphs_overlap), so a committee seat that merely SHARES
    // authority with a party is refused too -- identity alone is subsumed by
    // the walk (h2_collect_account_side inserts the root), but the explicit
    // identity asserts pin the finding's message and keep the refuse reason
    // stable whatever the walk's future bounds. Fail-closed: it rejects more
    // votes, never fewer, and the finder slice can therefore never resolve
    // to a party on the decisive path (CQ-R9-04's self-payment half is
    // asserted again at the payment site).
    if( _challenge != nullptr )
    {
       FC_ASSERT( op.voter != _challenge->challenger,
                  "Challenger may not vote on its own challenge" );
       // R17-E: vote leg is null-tolerant on a stranded row (see the expiry
       // sweep). A missing challenged vault is a terminal refusal, not a
       // chain-halting dismissal.
       const vault_object* voted_vault = d.find( _challenge->vault );
       FC_ASSERT( voted_vault != nullptr,
                  "Challenged vault ${v} no longer exists; the challenge is "
                  "stranded and further votes are refused",
                  ("v", _challenge->vault) );
       FC_ASSERT( !h2_authority_graphs_overlap( d, op.voter,
                    voted_vault->vault_authority ),
                  "Voter ${a} shares authority with the challenged vault; "
                  "the vault's authority side may not vote",
                  ("a", op.voter) );
    }
    else
    {
       FC_ASSERT( op.voter != _dispute->challenger && op.voter != _dispute->defender,
                  "Challenger and defender may not vote on their own dispute" );
       FC_ASSERT( !h2_authority_graphs_overlap( d, op.voter, _dispute->challenger ),
                  "Voter ${a} shares authority with the challenger", ("a", op.voter) );
       FC_ASSERT( !h2_authority_graphs_overlap( d, op.voter, _dispute->defender ),
                  "Voter ${a} shares authority with the defender (the accused producer)",
                  ("a", op.voter) );
    }
    const auto& votes = ( _challenge != nullptr ) ? _challenge->votes : _dispute->votes;
   FC_ASSERT( votes.find( op.voter ) == votes.end(),
              "Committee member ${a} has already voted on this target", ("a", op.voter) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result challenge_vote_evaluator::do_apply( const challenge_vote_operation& op ) const
{ try {
   database& d = db();
   // GOV-R17-02: the deciding set is the ELECTED set, not the
   // unpruned registry. Registration is permissionless (op-29, LTM only) and
   // registry rows are never pruned; GOV-R9-01 already refuses votes from
   // non-elected rows, but with the registry still in the denominator K sybil
   // registrations inflate supermajority_of(N) and the quorum bar so the
   // seated members cannot resolve anything -- the reverse side of the same
   // attacker-deniable vote path. Fail-closed preserved: the elected set is
   // non-empty from genesis (the assert below holds).
   const uint64_t deciding_set =
         d.get_global_properties().active_committee_members.size();
   FC_ASSERT( deciding_set > 0, "No deciding set is seated" );
   if( _challenge != nullptr )
   {
      d.modify( *_challenge, [&op]( vault_challenge_object& c ) {
         c.votes[ op.voter ] = op.decision;
      } );
       uint64_t for_decision = 0;
       for( const auto& vote : _challenge->votes )
          if( vote.second == op.decision )
             ++for_decision;
       // Quorum gates resolution, never recording: early votes persist and
       // accumulate toward the supermajority; silence fails closed at
       // maintenance, never by rejecting votes.
       if( !h2_quorum_met( _challenge->votes.size(), deciding_set ) )
          return void_result();
       if( for_decision >= h2_supermajority_of( deciding_set ) )
          h2_apply_challenge_resolution( d, *_challenge, op.decision, op.voter );
   }
   else
   {
      d.modify( *_dispute, [&op]( oracle_dispute_object& x ) {
         x.votes[ op.voter ] = op.decision;
      } );
       uint64_t for_decision = 0;
       for( const auto& vote : _dispute->votes )
          if( vote.second == op.decision )
             ++for_decision;
       // Quorum gates resolution, never recording: see the challenge branch.
       if( !h2_quorum_met( _dispute->votes.size(), deciding_set ) )
          return void_result();
       if( for_decision >= h2_supermajority_of( deciding_set ) )
          h2_apply_dispute_resolution( d, *_dispute, op.decision, op.voter );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void process_expired_h2_challenges( database& d )
{
   if( !HARDFORK_H2_BONDS_PASSED( d.head_block_time() ) )
      return; // pre-fork no such objects can exist; the sweep is a no-op
   const auto now = d.head_block_time();

   const auto& challenge_deadline_idx = d.get_index_type<vault_challenge_index>()
                                           .indices().get<by_challenge_deadline>();
   for( auto itr = challenge_deadline_idx.begin();
         itr != challenge_deadline_idx.end() && itr->deadline <= now; ++itr )
   {
      if( itr->state != GRAPHENE_H2_CHALLENGE_OPEN )
         continue;
      // R17-E: a stranded OPEN challenge row may point at a vault
      // that no longer exists (removal once admitted such a state). The sweep
      // is null-tolerant on the vault leg: skip the zombie rather than
      // dereference it and halt the chain. The row stays bounded (fixed
      // deadline index), the skip is deterministic, and no economics run on
      // a missing source.
      const vault_object* vault_src = d.find( itr->vault );
      if( vault_src == nullptr )
         continue;
      const vault_object& vault = *vault_src;
      // Expiry is inconclusive, never exoneration: the challenger's escrow
      // forfeits through the standard 80/15/finder split instead of
      // returning in full (cartel abstention past the deadline must never
      // equal vindication, and a costless freeze is a griefing primitive).
      // No decisive voter exists, so the finder slice returns to the
      // challenger; the pool slice accrues to the vault's forfeit pool; the
      // burn leaves supply. The vault still freezes fail-closed and still
      // resolves through vault_resolve's exit path: an expired challenge
      // requires the vault to fail maintenance or be provably drained (a
      // healthy vault with live claims stays frozen).
      share_type burn, pool, finder;
      h2_split_forfeit( itr->challenge_bond, itr->challenge_bond_usd_cents,
                        burn, pool, finder );
      const asset_dynamic_data_object& core_data = d.get_core_dynamic_data();
      d.modify( core_data, [&burn]( asset_dynamic_data_object& data ) {
         data.current_supply -= burn;
      } );
      d.adjust_balance( itr->challenger, asset( finder, asset_id_type() ) );
      // ISS-08 halt coherence: REVERT-vs-ABSORB before the door closes
      // (bonded price still live: this loop freezes no oracle).
      h2_issue_on_pair_halt( d, vault.vault_pair );
      d.modify( vault, [&pool]( vault_object& v ) {
         v.open_challenges -= 1;
         v.forfeit_pool_balance = v.forfeit_pool_balance + pool;
         v.frozen = true;
      } );
      d.modify( *itr, []( vault_challenge_object& c ) {
         c.state = GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN;
         c.finder = c.challenger;
      } );
   }

   const auto& dispute_deadline_idx = d.get_index_type<oracle_dispute_index>()
                                         .indices().get<by_dispute_deadline>();
   for( auto itr = dispute_deadline_idx.begin();
         itr != dispute_deadline_idx.end() && itr->round_deadline <= now; ++itr )
   {
      if( itr->state != GRAPHENE_H2_CHALLENGE_OPEN )
         continue;
      const oracle_object& oracle = itr->oracle(d);
      // Same inconclusive-expiry rule as the vault leg above: the
      // challenger's escrow forfeits through the split (finder slice back to
      // the challenger, pool slice to the oracle's forfeit pool, burn out of
      // supply). The defender's escrow returns in full -- the defender did
      // not open the inconclusive round.
      share_type burn, pool, finder;
      h2_split_forfeit( itr->challenger_bonds, itr->challenger_bonds_usd_cents,
                        burn, pool, finder );
      const asset_dynamic_data_object& core_data = d.get_core_dynamic_data();
      d.modify( core_data, [&burn]( asset_dynamic_data_object& data ) {
         data.current_supply -= burn;
      } );
      d.adjust_balance( itr->challenger, asset( finder, asset_id_type() ) );
      d.adjust_balance( itr->defender, asset( itr->defender_bonds, asset_id_type() ) );
      d.modify( *itr, []( oracle_dispute_object& x ) {
         x.state = GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN;
         x.finder = x.challenger;
      } );
      d.modify( oracle, [&pool, &now]( oracle_object& o ) {
         o.open_disputes -= 1;
         o.forfeit_pool_balance = o.forfeit_pool_balance + pool;
         // R-02: expiry freeze is challenge-set like sustain: owner
         // oracle_update MUST NOT clear it (refused); committee
         // oracle_unfreeze clears after resolution.
         o.options.frozen = true;
         // GOV-R9-02: expiry is a clear too -- it anchors the same unfreeze
         // time-lock, so a missed vote window cannot be converted into an
         // instant single-member unfreeze.
         h2_note_dispute_cleared( o, now );
      } );
   }
}

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::vault_challenge_object, (graphene::db::object),
                    (vault)
                    (challenger)
                    (challenge_bond)
                    (challenge_bond_usd_cents)
                    (evidence_memo)
                    (opened)
                    (deadline)
                    (votes)
                    (state)
                    (finder)
                    (executed)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::oracle_dispute_object, (graphene::db::object),
                    (oracle)
                    (challenger)
                    (defender)
                    (accused_time)
                    (accused_series)
                    (round)
                    (challenger_bonds)
                    (defender_bonds)
                    (round1_bond)
                    (round1_bond_usd_cents)
                    (challenger_bonds_usd_cents)
                    (defender_bonds_usd_cents)
                    (evidence_memo)
                    (opened)
                    (round_deadline)
                    (votes)
                    (state)
                    (finder)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::vault_challenge_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::oracle_dispute_object )
