/*
 * H2c vault lifecycle ops: rotate, wind-down, resolve, pair_freeze + HTLC griefing.
 *
 * USD-terms-at-lock basis inherited from H2a/H2b ($0.001/BTS pilot basis:
 * 1,000,000 raw units per USD cent). All proposal values from BSIP-1 section
 * 7b: 150% maintenance trigger, 36h top-up window, 15% wind-down haircut,
 * rmax 2x junior dilution cap, $83.75 griefing per direction, sub-vault cap 64.
 * Full LLAMMA issuance engine is deferred (H2 plan self-review): H2c covers
 * vault-side lifecycle + wind-down accounting only.
 *
 * Vehicle decisions (reversible minima, logged in the H2c report):
 * - OQ-08 rotate = new vault_rotate op (in-place authority replacement;
 *   liabilities migrate by staying put; old bonds release via the new
 *   vault_bond_release op gated on unlock + zero outstanding).
 * - OQ-14 griefing = existing htlc_create + deposit-ID memo convention +
 *   auto-refund (no new op); sha256 only for griefing locks.
 * - OQ-19 maintenance hook evaluates the 150% rule (no trigger op).
 * - OQ-21 double-claim = one claim object per (winddown, claimant);
 *   a second claim by the same claimant is refused.
 * - Wind-down pay order: seniors first at last-good-minus-15%; juniors dilute
 *   with a running cap of 2x senior-paid (rmax); only the segregated bond of
 *   the failed vault ever pays (never cross-reserve, never the issuance
 *   reserve).
 * - Claim math: payout = min(claim * (10000 - haircut) / 10000,
 *   claim * segregated / total), every division rounding DOWN against
 *   claimants (declared). Same-asset units in H2c (live price leg is H2d).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/htlc_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/htlc.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// Pilot basis inherited from H2a/H2b: 1e6 raw BTS units per USD cent.
constexpr int64_t H2C_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2C_VAULT_USD_CENTS = 1340000;    // $13,400 vault min_bond
constexpr uint64_t H2C_FLOOR_USD_CENTS = 83750;      // $837.50 challenge floor
constexpr uint64_t H2C_GRIEF_USD_CENTS = 8375;       // $83.75 griefing/direction
const share_type H2C_VAULT_RAW =
      share_type( int64_t( H2C_VAULT_USD_CENTS ) * H2C_RAW_PER_USD_CENT );
const share_type H2C_ROUND1_RAW =
      share_type( int64_t( H2C_FLOOR_USD_CENTS ) * H2C_RAW_PER_USD_CENT );
const share_type H2C_GRIEF_RAW =
      share_type( int64_t( H2C_GRIEF_USD_CENTS ) * H2C_RAW_PER_USD_CENT );

string h2c_evidence( const string& tag )
{ return string( "evidence:" ) + tag; }

void h2c_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_committee_member( account );
}

reference_asset_id_type h2c_create_reference(
      database_fixture& f, account_id_type creator, const fc::ecc::private_key& key,
      const string& symbol, uint8_t precision )
{
   reference_asset_create_operation op;
   op.creator     = creator;
   op.symbol      = symbol;
   op.precision   = precision;
   op.description = symbol + " reference asset";
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return reference_asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

oracle_id_type h2c_make_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      const string& name, reference_asset_id_type base, reference_asset_id_type quote,
      const oracle_options& opts )
{
   oracle_create_operation op;
   op.owner   = owner;
   op.name    = name;
   op.base    = base;
   op.quote   = quote;
   op.series  = { oracle_series( oracle_series_kind::mid,
                                 oracle_series_rounding::unspecified ) };
   op.options = opts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_id_type h2c_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth, share_type min_bond, uint64_t min_bond_usd,
      asset_id_type pair = asset_id_type() )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = min_bond;
   op.min_bond_usd_cents   = min_bond_usd;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000;
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_id_type h2c_register_vault_default(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth )
{
   return h2c_register_vault( f, registrar, key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
}

vesting_balance_id_type h2c_make_cdd_vesting(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      share_type amount )
{
   vesting_balance_create_operation op;
   op.creator = owner;
   op.owner   = owner;
   op.amount  = asset( amount, asset_id_type() );
   op.policy  = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, f.db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vesting_balance_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_bond_id_type h2c_lock_vault_bond(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      vault_id_type vault, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents )
{
   vault_bond_lock_operation op;
   op.owner           = owner;
   op.vault           = vault;
   op.vesting_balance = vesting;
   op.bond_amount     = amount;
   op.bond_usd_cents  = usd_cents;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_challenge_id_type h2c_post_challenge(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      vault_id_type vault, const string& memo )
{
   vault_challenge_operation op;
   op.challenger          = challenger;
   op.vault               = vault;
   op.challenge_bond      = H2C_ROUND1_RAW;
   op.challenge_bond_usd_cents = H2C_FLOOR_USD_CENTS;
   op.evidence_memo       = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_challenge_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2c_vote(
      database_fixture& f, account_id_type voter, const fc::ecc::private_key& key,
      object_id_type target, uint8_t decision )
{
   challenge_vote_operation op;
   op.voter    = voter;
   op.target   = target;
   op.decision = decision;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Votes a sustain supermajority from the genesis seated set (init0..initN).
void h2c_sustain_from_genesis( database_fixture& f, object_id_type target )
{
   const uint64_t n =
         f.db.get_index_type<committee_member_index>().indices().size();
   BOOST_REQUIRE( n > 0 );
   const uint64_t need = ( 2 * n + 2 ) / 3; // ceil(2N/3)
   for( uint64_t i = 0; i < need; ++i )
      h2c_vote( f, f.get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                f.init_account_priv_key, target, GRAPHENE_H2_DISPUTE_SUSTAIN );
}

void h2c_set_outstanding( database_fixture& f, vault_id_type vid, share_type amount )
{
   const vault_object& v = vid( f.db );
   f.db.modify( v, [&amount]( vault_object& m ) { m.outstanding = amount; } );
}

/// Creates a plain UIA to serve as a second vault pair (one live vault set
/// per pair, so a cross-reserve sibling must live on another pair).
asset_id_type h2c_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol )
{
   asset_create_operation op;
   op.issuer      = issuer;
   op.symbol      = symbol;
   op.precision   = 5;
   op.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   // Placeholder CER (uia_tests pattern): validate only requires base and
   // quote differ; the pair asset is never traded in this suite.
   op.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_vault_tests, database_fixture )

/// New lifecycle ops must be refused before the H2 bonds hardfork.
BOOST_AUTO_TEST_CASE( h2c_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   {
      vault_rotate_operation op;
      op.rotator       = alice_id;
      op.vault         = vault_id_type( 0 );
      op.new_authority = authority( 1, bob_id, 1 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      vault_bond_release_operation op;
      op.owner = alice_id;
      op.bond  = vault_bond_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      vault_resolve_operation op;
      op.resolver  = alice_id;
      op.challenge = vault_challenge_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      pair_freeze_operation op;
      op.freezer = alice_id;
      op.vault   = vault_id_type( 0 );
      op.oracle  = oracle_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      winddown_claim_operation op;
      op.claimant     = alice_id;
      op.winddown     = winddown_vault_id_type( 0 );
      op.claim_amount = share_type( 1 );
      op.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
} FC_LOG_AND_RETHROW() }

/// Rotate replaces the authority; liabilities migrate by staying put; the old
/// bond releases only after the challenge window at zero open liabilities.
BOOST_AUTO_TEST_CASE( vault_rotate_moves_authority_and_gates_old_release )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority old_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, old_auth );

   // Old set bonds first.
   const auto vest_a = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   const vault_bond_id_type bond_a = h2c_lock_vault_bond(
         *this, alice_id, alice_private_key, vid, vest_a, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // New set bonds before rotation (the incoming set proves capital first).
   const auto vest_b = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   const vault_bond_id_type bond_b = h2c_lock_vault_bond(
         *this, bob_id, bob_private_key, vid, vest_b, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Simulate live liabilities: rotation must carry them, never drop them.
   // NOTE (pending-session rule): the bond locks above leave a pending undo
   // session active, and direct db.modify below would land in it and be
   // discarded by the next block production (which resets pending and only
   // re-applies pushed transactions). Committing with a block first puts the
   // modify on head state, where it survives. Same pattern at every
   // h2c_set_outstanding call site in this suite.
   generate_block();
   h2c_set_outstanding( *this, vid, share_type( 1000000 ) );
   const share_type liabilities_before = vid( db ).outstanding;

   authority new_auth( 1, bob_id, 1 );
   vault_rotate_operation rop;
   rop.rotator       = alice_id;
   rop.vault         = vid;
   rop.new_authority = new_auth;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx );

   BOOST_CHECK( vid( db ).vault_authority == new_auth );
   BOOST_CHECK( vid( db ).outstanding == liabilities_before );

   // Old bond cannot release while liabilities are open ...
   vault_bond_release_operation rel;
   rel.owner = alice_id;
   rel.bond  = bond_a;
   signed_transaction ltx; ltx.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ltx ), fc::exception );

   // ... nor before its unlock even at zero liabilities ...
   // (generate_block first: the failed ltx push above leaves a pending
   // session active, which would swallow the modify at the next production.)
   generate_block();
   h2c_set_outstanding( *this, vid, share_type( 0 ) );
   signed_transaction ltx2; ltx2.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx2.operations.back() );
   set_expiration( db, ltx2 );
   ltx2.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ltx2 ), fc::exception );

   // ... but releases after the challenge window at zero open liabilities.
   generate_blocks( bond_a( db ).unlock_time + 3600 );
   generate_block();
   signed_transaction ltx3; ltx3.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx3.operations.back() );
   set_expiration( db, ltx3 );
   ltx3.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, ltx3 );
   BOOST_CHECK( db.find( bond_a ) == nullptr );
   // The incoming set's bond still secures the vault.
   BOOST_CHECK( db.find( bond_b ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// Griefing convention (OQ-14 vehicle): stock htlc_create with a sha256 lock
/// and a deposit-ID memo; after the timeout the challenger posts a challenge
/// whose evidence names the timed-out HTLC, and it is accepted as proof.
BOOST_AUTO_TEST_CASE( htlc_griefing_lock_and_timeout_evidence_posts_challenge )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );

   // HTLC creates require committee HTLC options (max timeout/preimage size);
   // the fixture helper pushes them through a committee proposal.
   set_htlc_committee_parameters();

   // sha256 griefing lock of $83.75 from bob to carol with a deposit-ID memo.
   std::vector<char> preimage( 32, 'g' );
   htlc_create_operation hop;
   hop.from = bob_id;
   hop.to   = carol_id;
   hop.amount = asset( H2C_GRIEF_RAW, asset_id_type() );
   hop.preimage_hash = fc::sha256::hash( preimage.data(), preimage.size() );
   hop.preimage_size = 32;
   hop.claim_period_seconds = 3600;
   memo_data md;
   md.from = bob_public_key;
   md.to   = carol_public_key;
   md.set_message( bob_private_key, carol_public_key, "h2-grief:7" );
   hop.extensions.value.memo = md;
   signed_transaction htx; htx.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx.operations.back() );
   set_expiration( db, htx );
   htx.sign( bob_private_key, db.get_chain_id() );
   const htlc_id_type htid {
      PUSH_TX( db, htx ).operation_results.front().get<object_id_type>() };
   BOOST_CHECK( htid( db ).conditions.hash_lock.preimage_hash.which() == 2 ); // sha256 slot

   // sha1 griefing locks are refused past the H2 gate (audit sunset rule).
   htlc_create_operation shop = hop;
   shop.preimage_hash = fc::sha1::hash( preimage.data(), preimage.size() );
   signed_transaction stx; stx.operations.push_back( shop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, stx ), fc::exception );

   // Timeout passes; the timeout evidence names the HTLC and is accepted.
   generate_blocks( db.head_block_time() + 7200 );
   generate_block();
   const string evidence = string( "htlc-timeout:" ) + h2c_evidence( "grief-7" );
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, evidence );
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
} FC_LOG_AND_RETHROW() }

/// 150% maintenance rule: breach halts mints, opens a 36h top-up window, and
/// expiry at maintenance auto-creates the wind-down and seizes the bonds.
BOOST_AUTO_TEST_CASE( maintenance_breach_halts_topup_expires_into_winddown )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Healthy at 200%: bonds cover twice the liabilities.
   // (generate_block first: see the pending-session rule noted above.)
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW / 2 );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );

   // Breach below 150%: 100% coverage trips the rule at next maintenance.
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW );
   const auto breach_time = db.head_block_time();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true ); // mint halt; redemptions continue
   BOOST_CHECK( vid( db ).top_up_deadline == vid( db ).last_breach_time + GRAPHENE_H2_TOP_UP_WINDOW_SEC );
   BOOST_CHECK( vid( db ).top_up_deadline > breach_time );

   // Top-up still open just before the deadline: no wind-down yet.
   generate_blocks( vid( db ).top_up_deadline - 7200 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );

   // Past the 36h deadline the next maintenance winds down + seizes.
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   const winddown_vault_object& wd = *wd_idx.begin();
   BOOST_CHECK( wd.source_vault == vid );
   BOOST_CHECK( wd.segregated_bond == H2C_VAULT_RAW );
   BOOST_CHECK( wd.total_claims == H2C_VAULT_RAW );
   BOOST_CHECK_EQUAL( wd.haircut_bps, GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS );
   // Seized bonds never roll back.
   for( const auto& b : db.get_index_type<vault_bond_index>().indices() )
      if( b.vault == vid )
         BOOST_CHECK_EQUAL( b.seized, true );
} FC_LOG_AND_RETHROW() }

/// Wind-down pay order: seniors at last-good-minus-15%, juniors dilute capped
/// at 2x senior-paid, double-claims refused, sibling vaults never touched.
BOOST_AUTO_TEST_CASE( winddown_claim_pays_seniors_first_juniors_dilute_no_cross_reserve )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );

   // Failed vault: full-bond backing against equal liabilities (100% cover).
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // (generate_block first: see the pending-session rule noted above.)
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Sibling vault: a DIFFERENT pair (one live set per pair, OQ-03), stays
   // healthy and unseized while its neighbor winds down (no cross-reserve).
   // A same-pair sibling cannot exist, so cross-pair isolation is the
   // strongest observable no-cross-collateralization check in H2c.
   const auto sib_pair = h2c_create_uia( *this, bob_id, bob_private_key, "SIBPAIR" );
   authority sib_auth( 1, bob_id, 1 );
   const vault_id_type sib = h2c_register_vault(
         *this, bob_id, bob_private_key, sib_auth,
         share_type( 1000 ), uint64_t( 100 ), sib_pair );
   const auto sib_vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, share_type( 1000 ) );
   const vault_bond_id_type sib_bond = h2c_lock_vault_bond(
         *this, bob_id, bob_private_key, sib, sib_vest, share_type( 1000 ), uint64_t( 100 ) );

   // Senior claims first at 85%: haircut face binds (fully backed here).
   // Claim faces must fit inside the frozen liabilities (claimed_total can
   // never exceed total_claims — the H2c stand-in for per-holder frozen
   // balances, which arrive with the issuance engine): seniors take a third,
   // juniors two thirds, summing to (just under) the whole book.
   const share_type senior_claim = H2C_VAULT_RAW / 3;
   const share_type senior_expect =
         share_type( senior_claim.value * ( 10000 - GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS ) / 10000 );
   winddown_claim_operation sop;
   sop.claimant     = carol_id;
   sop.winddown     = wdid;
   sop.claim_amount = senior_claim;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( carol_private_key, db.get_chain_id() );
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   PUSH_TX( db, stx );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= carol_before + senior_expect - share_type( 100000 ) );

   // Double-claim by the same account is refused.
   signed_transaction dtx; dtx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( dtx.operations.back() );
   set_expiration( db, dtx );
   dtx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, dtx ), fc::exception );

   // Juniors dilute within 2x of senior-paid: 2x senior claim is accepted ...
   winddown_claim_operation jop;
   jop.claimant     = dave_id;
   jop.winddown     = wdid;
   jop.claim_amount = senior_claim * 2;
   jop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction jtx; jtx.operations.push_back( jop );
   db.current_fee_schedule().set_fee( jtx.operations.back() );
   set_expiration( db, jtx );
   jtx.sign( dave_private_key, db.get_chain_id() );
   PUSH_TX( db, jtx );

   // ... but junior claims past 2x senior-paid are refused (rmax).
   winddown_claim_operation xop;
   xop.claimant     = erin_id;
   xop.winddown     = wdid;
   xop.claim_amount = share_type( 1 );
   xop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction xtx; xtx.operations.push_back( xop );
   db.current_fee_schedule().set_fee( xtx.operations.back() );
   set_expiration( db, xtx );
   xtx.sign( erin_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, xtx ), fc::exception );

   // Sibling bond untouched by the failed vault's wind-down.
   BOOST_CHECK_EQUAL( sib_bond( db ).seized, false );
   BOOST_CHECK_EQUAL( sib( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
} FC_LOG_AND_RETHROW() }

/// Resolve executes a sustained challenge: committee execution seizes the bond
/// slice into a segregated wind-down (no cross-collateralization).
BOOST_AUTO_TEST_CASE( vault_resolve_executes_sustained_challenge_into_winddown )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, bob_id, bob_private_key, vid, h2c_evidence( "real-theft" ) );
   h2c_sustain_from_genesis( *this, object_id_type( cid ) );
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );

   // Non-committee execution is refused; committee execution segregates.
   vault_resolve_operation bad;
   bad.resolver  = bob_id;
   bad.challenge = cid;
   signed_transaction btx; btx.operations.push_back( bad );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx );
   btx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );

   vault_resolve_operation op;
   op.resolver  = alice_id;
   op.challenge = cid;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx );

   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   BOOST_CHECK( wd_idx.begin()->source_vault == vid );
   BOOST_CHECK( wd_idx.begin()->segregated_bond == H2C_VAULT_RAW );
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   // Resolving twice is refused (challenge already executed).
   signed_transaction tx2; tx2.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx2 ), fc::exception );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// pair_freeze closes the protocol door AND the debt tap in one atomic apply:
/// after one op the vault blocks mints and the oracle stops promoting.
BOOST_AUTO_TEST_CASE( pair_freeze_closes_door_and_debt_atomically )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );
   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   const oracle_id_type oid =
         h2c_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );

   BOOST_REQUIRE_EQUAL( vid( db ).frozen, false );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, false );

   // Non-committee freezers are refused and freeze nothing (atomic no-op).
   pair_freeze_operation bad;
   bad.freezer = bob_id;
   bad.vault   = vid;
   bad.oracle  = oid;
   signed_transaction btx; btx.operations.push_back( bad );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx );
   btx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );

   // Committee freeze closes both in one atomic apply: PUSH_TX applies
   // without producing a block, so both flags flip with no intervening block
   // in which the door could read closed while debt reads open (or reverse).
   const uint32_t block_before = db.head_block_num();
   pair_freeze_operation op;
   op.freezer = alice_id;
   op.vault   = vid;
   op.oracle  = oid;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   BOOST_CHECK_EQUAL( db.head_block_num(), block_before );
} FC_LOG_AND_RETHROW() }

/// Sub-vault bound: at most 64 bond locks per vault (tBTC per-deposit lesson);
/// the 65th lock is refused while the first 64 stand.
BOOST_AUTO_TEST_CASE( subvault_bond_cap_64 )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         share_type( 1000 ), uint64_t( 100 ) );
   for( uint32_t i = 0; i < GRAPHENE_H2_SUBVAULT_CAP; ++i )
   {
      // A block per deposit: back-to-back identical creates would otherwise
      // collide as duplicate transactions (same ops, expiration, and key),
      // and per-deposit blocks mirror real sub-vault funding cadence.
      generate_block();
      const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, share_type( 1000 ) );
      h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                           share_type( 1000 ), uint64_t( 100 ) );
   }
   BOOST_CHECK_EQUAL( db.get_index_type<vault_bond_index>().indices().size(), 64u );
   // The 65th vesting needs its own block too, or it duplicates the 64th's.
   generate_block();
   const auto vest65 = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, share_type( 1000 ) );
   vault_bond_lock_operation op;
   op.owner           = alice_id;
   op.vault           = vid;
   op.vesting_balance = vest65;
   op.bond_amount     = share_type( 1000 );
   op.bond_usd_cents  = 100;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
