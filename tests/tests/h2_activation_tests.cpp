/*
 * H2e activation gates: per-leg activation heights, gateway-before-price
 * ordering, H1-exclusion, and tag/wire pins for every H2 op and object.
 *
 * BSIP-1 section 6 stages H2 as gateway Track B before price Track B, with
 * activation heights as consensus-reject rules (gateway height < price height
 * enforced in evaluators, never a sequencing promise) and H1 pairs excluded
 * from bonded medians. This suite proves the mechanism:
 *
 * - Leg ordering: the configured gateway height strictly precedes the price
 *   height; inverted and equal pairs are refused by the ordering predicate.
 * - Pre-activation: one op per gate (gateway / shared primitives / price) is
 *   refused before any leg activates.
 * - Staging window: between the gateway and price heights bonded custody
 *   (vault_register) is admitted while price-judgment ops (vault_challenge,
 *   oracle_bond_lock) are still refused; at the price height the refusal
 *   lifts for the same challenge.
 * - H1-exclusion: market-issued pairs and H1-bound pairs are refused at
 *   vault_register; a plain UIA registers (control).
 * - Pins: operation tags 83-96 and protocol-space object IDs 1.25.x-1.35.x
 *   are pinned, with pack/unpack round-trips over the appended-field ops
 *   (rotate co_signers, wind-down claim, fallback set).
 *
 * No new economics here: every value below reuses the H2a-H2d pilot basis
 * ($0.001/BTS, 1e6 raw units per USD cent).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/operations.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// Pilot basis inherited from H2a: 1e6 raw BTS units per USD cent.
constexpr int64_t H2G_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2G_VAULT_USD_CENTS = 1340000; // $13,400 proposal
constexpr uint64_t H2G_FLOOR_USD_CENTS = 83750;   // $837.50 challenge floor
const share_type H2G_VAULT_RAW =
      share_type( int64_t( H2G_VAULT_USD_CENTS ) * H2G_RAW_PER_USD_CENT );

void h2g_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_committee_member( account );
}

reference_asset_id_type h2g_create_reference(
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

oracle_id_type h2g_make_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      const string& name, reference_asset_id_type base, reference_asset_id_type quote )
{
   oracle_create_operation op;
   op.owner   = owner;
   op.name    = name;
   op.base    = base;
   op.quote   = quote;
   op.series  = { oracle_series( oracle_series_kind::mid,
                                 oracle_series_rounding::unspecified ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

/// Creates a plain UIA to serve as a vault pair candidate.
asset_id_type h2g_create_uia(
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

vault_register_operation h2g_register_op(
      account_id_type registrar, asset_id_type pair, const authority& vault_auth )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = H2G_VAULT_RAW;
   op.min_bond_usd_cents   = H2G_VAULT_USD_CENTS;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000; // 200% proposal
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   return op;
}

vault_id_type h2g_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      asset_id_type pair, const authority& vault_auth )
{
   vault_register_operation op = h2g_register_op( registrar, pair, vault_auth );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_challenge_operation h2g_challenge_op(
      account_id_type challenger, vault_id_type vault )
{
   vault_challenge_operation op;
   op.challenger               = challenger;
   op.vault                    = vault;
   op.challenge_bond           = share_type( 1000000 );
   op.challenge_bond_usd_cents = H2G_FLOOR_USD_CENTS;
   op.evidence_memo            = "evidence:staging-window";
   return op;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_activation_tests, database_fixture )

/// BSIP-1 section 6: the configured gateway height strictly precedes the
/// price height. Inversion (and equality) is refused by the predicate every
/// H2 gate helper asserts, so a mis-scheduled configuration can never stage
/// price judgment before bonded custody.
BOOST_AUTO_TEST_CASE( gateway_activation_precedes_price_by_rule )
{
   BOOST_CHECK( h2_legs_ordered( HARDFORK_H2_GATEWAY_TIME, HARDFORK_H2_PRICE_TIME ) );
   BOOST_CHECK( !h2_legs_ordered( HARDFORK_H2_PRICE_TIME, HARDFORK_H2_GATEWAY_TIME ) );
   BOOST_CHECK( !h2_legs_ordered( HARDFORK_H2_GATEWAY_TIME, HARDFORK_H2_GATEWAY_TIME ) );
}

/// One op per gate is refused before any leg activates: vault_register
/// (gateway leg), vault_challenge (shared primitives), oracle_bond_lock and
/// oracle_fallback_set (price leg).
BOOST_AUTO_TEST_CASE( all_three_gates_refuse_before_activation )
{ try {
   ACTORS( (alice) );
   fund( alice );

   {
      vault_register_operation rop =
            h2g_register_op( alice_id, asset_id_type(), authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   {
      vault_challenge_operation cop;
      cop.challenger               = alice_id;
      cop.vault                    = vault_id_type( 0 );
      cop.challenge_bond           = share_type( 1000000 );
      cop.challenge_bond_usd_cents = H2G_FLOOR_USD_CENTS;
      cop.evidence_memo            = "evidence:pre-activation";
      signed_transaction tx;
      tx.operations.push_back( cop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   {
      oracle_bond_lock_operation lop;
      lop.producer        = alice_id;
      lop.oracle          = oracle_id_type( 0 );
      lop.vesting_balance = vesting_balance_id_type( 0 );
      lop.bond_amount     = share_type( 1000000 );
      lop.bond_usd_cents  = GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS;
      signed_transaction tx;
      tx.operations.push_back( lop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   {
      oracle_fallback_set_operation fop;
      fop.owner  = alice_id;
      fop.oracle = oracle_id_type( 0 );
      signed_transaction tx;
      tx.operations.push_back( fop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
} FC_LOG_AND_RETHROW() }

/// Between the gateway and price heights bonded custody is admitted while
/// price judgment is still refused; at the price height the same challenge
/// posts. This is the observable gateway-before-price staging.
BOOST_AUTO_TEST_CASE( gateway_window_admits_custody_not_price )
{ try {
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000000LL ) );
   fund( bob, asset( 100000000000LL ) );

   // Gateway leg live: custody registers in the window.
   const asset_id_type pair = h2g_create_uia( *this, alice_id, alice_private_key, "GATE" );
   const vault_id_type vid = h2g_register_vault(
         *this, alice_id, alice_private_key, pair, authority( 1, alice_id, 1 ) );
   BOOST_CHECK( vid( db ).vault_pair == pair );

   // Shared primitives still dark: the same challenge the price height will
   // admit is refused in the window (gate fires before existence/terms).
   {
      vault_challenge_operation cop = h2g_challenge_op( bob_id, vid );
      signed_transaction tx;
      tx.operations.push_back( cop );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // Price leg still dark: producer bonding is refused in the window.
   {
      oracle_bond_lock_operation lop;
      lop.producer        = bob_id;
      lop.oracle          = oracle_id_type( 0 );
      lop.vesting_balance = vesting_balance_id_type( 0 );
      lop.bond_amount     = share_type( 1000000 );
      lop.bond_usd_cents  = GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS;
      signed_transaction tx;
      tx.operations.push_back( lop );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // At the price height the refusal lifts for the identical challenge.
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   {
      vault_challenge_operation cop = h2g_challenge_op( bob_id, vid );
      signed_transaction tx;
      tx.operations.push_back( cop );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      const vault_challenge_id_type cid = vault_challenge_id_type {
         PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };
      BOOST_CHECK( vid( db ).open_challenges == 1 );
      BOOST_CHECK( cid( db ).vault == vid );
   }
} FC_LOG_AND_RETHROW() }

/// H1-exclusion is consensus-reject at the custody door: a market-issued
/// pair and an H1-bound pair are both refused, while a plain UIA registers.
BOOST_AUTO_TEST_CASE( h1_pairs_excluded_from_bonded_custody )
{ try {
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 100000000000LL ) );
   h2g_make_committee_member( *this, alice );
   const auto bts_ref = h2g_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2g_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid =
         h2g_make_oracle( *this, alice_id, alice_private_key, "H1X.USD", usd_ref, bts_ref );

   // Plain market-issued pair: refused as legacy-track (never H2 custody).
   const asset_id_type mia_id = create_bitasset( "H1MIAX", alice_id ).get_id();
   {
      vault_register_operation rop =
            h2g_register_op( alice_id, mia_id, authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // H1-bound pair (mapping + explicit oracle binding, the H1 shape): refused
   // as H1-priced, with the H1 reason firing before the track reason. The
   // H1 binding validity needs the full T7c shape: a mapped UIA backing
   // home (core BTS carries no reference mapping), the MIA's own 1:1
   // mapping declared first (bind-time reads the CURRENT effective
   // mapping), then the explicit bind against the matching oracle.
   const asset_id_type coll_id = h2g_create_uia( *this, alice_id, alice_private_key, "H1COLL" );
   {
      asset_update_operation uop;
      uop.issuer          = alice_id;
      uop.asset_to_update = coll_id;
      uop.new_options     = coll_id( db ).options;
      reference_mapping cm;
      cm.reference        = bts_ref;
      cm.asset_amount     = 1;
      cm.reference_amount = 1;
      uop.new_options.extensions.value.reference_asset_mapping = cm;
      signed_transaction tx;
      tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE( coll_id( db ).options.extensions.value
                  .reference_asset_mapping.valid() );
   const asset_id_type bound_id = create_bitasset( "H1BOUNDX", alice_id, 100,
         charge_market_fee, 4, coll_id ).get_id();
   {
      asset_update_bitasset_operation mop;
      mop.issuer          = alice_id;
      mop.asset_to_update = bound_id;
      mop.new_options     = bound_id( db ).bitasset_data( db ).options;
      reference_mapping m;
      m.reference        = usd_ref;
      m.asset_amount     = 1;
      m.reference_amount = 1;
      mop.new_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( mop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   {
      asset_update_bitasset_operation bop;
      bop.issuer          = alice_id;
      bop.asset_to_update = bound_id;
      bop.new_options     = bound_id( db ).bitasset_data( db ).options;
      price_oracle b;
      b.oracle_id = oid;
      b.series    = 0;
      bop.new_options.extensions.value.price_oracle_binding = b;
      signed_transaction tx;
      tx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE( bound_id( db ).bitasset_data( db ).options.extensions.value
                  .price_oracle_binding.valid() );
   {
      vault_register_operation rop =
            h2g_register_op( alice_id, bound_id, authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // Control: a plain UIA on the same terms registers.
   const asset_id_type free_id = h2g_create_uia( *this, alice_id, alice_private_key, "FREE" );
   const vault_id_type vid = h2g_register_vault(
         *this, alice_id, alice_private_key, free_id, authority( 1, alice_id, 1 ) );
   BOOST_CHECK( vid( db ).vault_pair == free_id );
} FC_LOG_AND_RETHROW() }

/// Operation tags 83-96 are the on-chain numbering and must never move: a
/// later edit that appends out of order or renumbers fails here, not on a
/// live chain.
BOOST_AUTO_TEST_CASE( h2_op_tags_pinned_83_to_96 )
{
   using graphene::protocol::operation;
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_register_operation>::value ), 83 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_bond_lock_operation>::value ), 84 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_bond_lock_operation>::value ), 85 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_bond_release_operation>::value ), 86 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_challenge_operation>::value ), 87 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_dispute_operation>::value ), 88 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_dispute_escalate_operation>::value ), 89 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::challenge_vote_operation>::value ), 90 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_rotate_operation>::value ), 91 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_bond_release_operation>::value ), 92 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_resolve_operation>::value ), 93 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::pair_freeze_operation>::value ), 94 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::winddown_claim_operation>::value ), 95 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_fallback_set_operation>::value ), 96 );
}

/// Protocol-space object IDs 1.25.x-1.35.x are the on-chain numbering and
/// must never move.
BOOST_AUTO_TEST_CASE( h2_object_ids_pinned_25_to_35 )
{
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_object_type ), 25 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_bond_object_type ), 26 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::producer_bond_object_type ), 27 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_challenge_object_type ), 28 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::oracle_dispute_object_type ), 29 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::winddown_vault_object_type ), 30 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::winddown_claim_object_type ), 31 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::reward_pool_object_type ), 32 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::guard_state_object_type ), 33 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::tripwire_state_object_type ), 34 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::recovery_state_object_type ), 35 );
}

/// Appended-last fields survive pack/unpack with positions intact: the H2c
/// rotate co_signers (appended after extensions), the wind-down claim, and
/// the H2d fallback set with a backup pinned.
BOOST_AUTO_TEST_CASE( h2_appended_fields_round_trip )
{
   {
      vault_rotate_operation op;
      op.rotator       = account_id_type( 1 );
      op.vault         = vault_id_type( 2 );
      op.new_authority = authority( 2, account_id_type( 1 ), 1 );
      op.memo          = std::string( "rotate" );
      op.co_signers.insert( account_id_type( 3 ) );
      auto back = fc::raw::unpack<vault_rotate_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.rotator == op.rotator );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.co_signers == op.co_signers );
      BOOST_CHECK( back.memo == op.memo );
   }
   {
      winddown_claim_operation op;
      op.claimant     = account_id_type( 4 );
      op.winddown     = winddown_vault_id_type( 5 );
      op.claim_amount = share_type( 1000000 );
      op.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
      auto back = fc::raw::unpack<winddown_claim_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.claimant == op.claimant );
      BOOST_CHECK( back.winddown == op.winddown );
      BOOST_CHECK( back.claim_amount == op.claim_amount );
      BOOST_CHECK_EQUAL( int( back.tranche ), int( op.tranche ) );
   }
   {
      oracle_fallback_set_operation op;
      op.owner  = account_id_type( 6 );
      op.oracle = oracle_id_type( 7 );
      price_oracle b;
      b.oracle_id = oracle_id_type( 8 );
      b.series    = 1;
      op.fallback = b;
      auto back = fc::raw::unpack<oracle_fallback_set_operation>( fc::raw::pack( op ) );
      BOOST_REQUIRE( back.fallback.valid() );
      BOOST_CHECK( back.fallback->oracle_id == oracle_id_type( 8 ) );
      BOOST_CHECK_EQUAL( int( back.fallback->series ), 1 );
   }
}

BOOST_AUTO_TEST_SUITE_END()
