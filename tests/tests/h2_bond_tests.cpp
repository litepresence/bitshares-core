/*
 * H2a bond primitives: vault registration + vault/producer bond locks.
 *
 * USD-terms-at-lock basis (recorded, not recomputed): every bond and floor below
 * is denominated in USD cents at lock, converted to raw BTS smallest units at the
 * fixed pilot basis of $0.001/BTS (1000 BTS per USD, BTS precision 5, so exactly
 * 1,000,000 raw units per USD cent, pinned to
 * GRAPHENE_H2_USD_BASIS_RAW_PER_CENT by static_assert below). A BTS-price move
 * therefore cannot silently
 * re-size the economics: the usd_cents record is authoritative and the raw amount
 * is the basis-converted lock. The basis floor is ENFORCED at both lock sites
 * (H2-03): raw short of usd_cents x basis is refused in consensus.
 *
 * Proposals used (BSIP-1 section 7b): vault min_bond $13,400, oracle min_bond
 * $10,050, 7-day unbond, 24h publication advance (inventory OQ-23 was open with
 * no proposal, so the reversible minimum 24h increment was chosen and logged).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

/// H1-03 vacuity pin: pre-fork refusals must reach the hardfork gate, never
/// stop at the fee check (fee set, funded CORE payer; refusal must name H2).
void h2t_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
{
   try { PUSH_TX( db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( "H2" ) != std::string::npos
            && ( e.to_string().find( "hardfork" ) != std::string::npos
              || e.to_string().find( "activation" ) != std::string::npos ),
            what << " refused off-gate (vacuous, not gate proof): " << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED pre-fork" );
}

// $0.001/BTS pilot basis: 1000 BTS per USD at precision 5 => 1e6 raw units per USD cent.
constexpr int64_t H2_TEST_RAW_PER_USD_CENT = 1000000LL;
// Pinned to the enforced protocol basis: the suite and consensus can never
// drift apart silently.
static_assert( uint64_t( H2_TEST_RAW_PER_USD_CENT ) == GRAPHENE_H2_USD_BASIS_RAW_PER_CENT,
               "H2 pilot-basis mirror must equal the protocol escrow basis" );
constexpr uint64_t H2_TEST_VAULT_USD_CENTS = 1340000;   // $13,400 proposal
constexpr uint64_t H2_TEST_ORACLE_USD_CENTS = 1005000;  // $10,050 proposal
// Raw locks at the pilot basis (not constexpr: fc::safe has no constexpr ctor).
const share_type H2_TEST_VAULT_RAW =
      share_type( int64_t( H2_TEST_VAULT_USD_CENTS ) * H2_TEST_RAW_PER_USD_CENT );   // 1.34e12
const share_type H2_TEST_ORACLE_RAW =
      share_type( int64_t( H2_TEST_ORACLE_USD_CENTS ) * H2_TEST_RAW_PER_USD_CENT );  // 1.005e12

void h2_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_committee_member( account );
}

reference_asset_id_type h2_create_reference(
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

/// Creates a CDD vesting balance holding @p amount for @p owner. CDD is the H2a
/// bond vesting policy: coin-days accrue but nothing vests before start_claim.
vesting_balance_id_type h2_make_cdd_vesting(
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

oracle_id_type h2_make_oracle(
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

void h2_publish( database_fixture& f, oracle_id_type oid,
                 account_id_type who, const fc::ecc::private_key& key, int64_t quote )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = { oracle_value( 1, quote ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

vault_id_type h2_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth )
{
   vault_register_operation op;
   op.registrar           = registrar;
   op.pair                = asset_id_type();
   op.vault_authority     = vault_auth;
   op.min_bond            = H2_TEST_VAULT_RAW;
   op.min_bond_usd_cents  = H2_TEST_VAULT_USD_CENTS;
   op.bond_asset          = asset_id_type();
   op.secure_ratio_bps    = 20000; // 200% proposal
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_bond_tests, database_fixture )

/// A node running old code must never see an H2 bond op it cannot validate.
BOOST_AUTO_TEST_CASE( h2_bond_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (alice) );
   fund( alice );

   vault_register_operation rop;
   rop.registrar            = alice_id;
   rop.pair                 = asset_id_type();
   rop.vault_authority      = authority( 1, alice_id, 1 );
   rop.min_bond             = H2_TEST_VAULT_RAW;
   rop.min_bond_usd_cents   = H2_TEST_VAULT_USD_CENTS;
   rop.bond_asset           = asset_id_type();
   rop.secure_ratio_bps     = 20000;
   rop.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;

   signed_transaction tx;
   tx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   h2t_require_gate_refusal( db, tx, "vault_register pre-fork" );

   oracle_bond_lock_operation lop;
   lop.producer       = alice_id;
   lop.oracle         = oracle_id_type( 0 );
   lop.vesting_balance = vesting_balance_id_type( 0 );
   lop.bond_amount    = H2_TEST_ORACLE_RAW;
   lop.bond_usd_cents = H2_TEST_ORACLE_USD_CENTS;

   signed_transaction tx2;
   tx2.operations.push_back( lop );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   h2t_require_gate_refusal( db, tx2, "oracle_bond_lock pre-fork" );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( vault_registers_threshold_authority_and_terms )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin) );
   fund( alice );

   // 3-of-5 threshold custody: any three of the five members may act.
   authority vault_auth( 3, alice_id, 1, bob_id, 1, carol_id, 1, dave_id, 1, erin_id, 1 );
   const vault_id_type vid = h2_register_vault( *this, alice_id, alice_private_key, vault_auth );
   const vault_object& v = vid( db );

   BOOST_CHECK_EQUAL( v.vault_authority.weight_threshold, 3u );
   BOOST_CHECK_EQUAL( v.vault_authority.account_auths.size(), 5u );
   BOOST_CHECK( v.min_bond == H2_TEST_VAULT_RAW );
   BOOST_CHECK_EQUAL( v.min_bond_usd_cents, H2_TEST_VAULT_USD_CENTS );
   BOOST_CHECK_EQUAL( v.secure_ratio_bps, 20000u );
   BOOST_CHECK_EQUAL( v.outstanding.value, 0 );
   BOOST_CHECK_EQUAL( v.frozen, false );

   // One live vault set per pair (inventory OQ-03 reversible minimum): a second
   // registration against the same pair is refused.
   signed_transaction tx;
   vault_register_operation dup;
   dup.registrar            = alice_id;
   dup.pair                 = asset_id_type();
   dup.vault_authority      = authority( 1, alice_id, 1 );
   dup.min_bond             = H2_TEST_VAULT_RAW;
   dup.min_bond_usd_cents   = H2_TEST_VAULT_USD_CENTS;
   dup.bond_asset           = asset_id_type();
   dup.secure_ratio_bps     = 20000;
   dup.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   tx.operations.push_back( dup );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( bond_locks_vesting_pointer_with_7d_unlock )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 3000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2_register_vault( *this, alice_id, alice_private_key, vault_auth );

   // The bond encumbers an existing CDD vesting balance; funds never move into
   // the bond object itself, so the pointer must be immutable.
   const vesting_balance_id_type vbid =
         h2_make_cdd_vesting( *this, bob_id, bob_private_key, H2_TEST_VAULT_RAW );
   const fc::time_point_sec lock_head = db.head_block_time();

   vault_bond_lock_operation op;
   op.owner           = bob_id;
   op.vault           = vid;
   op.vesting_balance = vbid;
   op.bond_amount     = H2_TEST_VAULT_RAW;
   op.bond_usd_cents  = H2_TEST_VAULT_USD_CENTS;
   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( bob_private_key, db.get_chain_id() );
   const vault_bond_id_type bid {
      PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };

   const vault_bond_object& b = bid( db );
   BOOST_CHECK( b.vesting_balance == vbid );
   BOOST_CHECK( b.vault == vid );
   BOOST_CHECK( b.lock_time == lock_head );
   // Challenge window (7d here) bounds the unbond delay from below, so the
   // unlock lands exactly at head + 7d.
   BOOST_CHECK( b.unlock_time == lock_head + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   BOOST_CHECK( b.bond_usd_cents == H2_TEST_VAULT_USD_CENTS );
   BOOST_CHECK_EQUAL( b.seized, false );

   // A lock below the registered min_bond is refused: the raw floor holds.
   vault_bond_lock_operation short_op = op;
   short_op.bond_amount = H2_TEST_VAULT_RAW - 1;
   signed_transaction tx2;
   tx2.operations.push_back( short_op );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( bob_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx2 ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( publish_advances_producer_unlock )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   h2_make_committee_member( *this, alice );
   const auto bts_ref = h2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );

   const vesting_balance_id_type vbid =
         h2_make_cdd_vesting( *this, bob_id, bob_private_key, H2_TEST_ORACLE_RAW );

   oracle_bond_lock_operation lop;
   lop.producer        = bob_id;
   lop.oracle          = oid;
   lop.vesting_balance = vbid;
   lop.bond_amount     = H2_TEST_ORACLE_RAW;
   lop.bond_usd_cents  = H2_TEST_ORACLE_USD_CENTS;
   lop.bootstrap_weight = 1000;
   signed_transaction ltx;
   ltx.operations.push_back( lop );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( bob_private_key, db.get_chain_id() );
   const producer_bond_id_type pbid {
      PUSH_TX( db, ltx ).operation_results.front().get<object_id_type>() };

   const fc::time_point_sec unlock0 = pbid( db ).unlock_time;
   BOOST_CHECK( unlock0 == pbid( db ).lock_time + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );

   // Each live publication pushes the unlock out by the 24h advance: an active
   // producer can never drift into releasability while still publishing.
   h2_publish( *this, oid, bob_id, bob_private_key, 100 );
   const fc::time_point_sec unlock1 = pbid( db ).unlock_time;
   BOOST_CHECK( unlock1 == unlock0 + GRAPHENE_H2_BOND_ADVANCE_SEC );
} FC_LOG_AND_RETHROW() }

/// H2-03 producer-lock mirror: 1-satoshi raw against the exact $10,050 USD
/// record locks pre-fix (no raw check exists); the basis floor refuses it.
BOOST_AUTO_TEST_CASE( oracle_bond_lock_raw_shortfall_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   h2_make_committee_member( *this, alice );
   const auto bts_ref = h2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );

   const vesting_balance_id_type vbid =
         h2_make_cdd_vesting( *this, bob_id, bob_private_key, share_type( 1000000 ) );

   oracle_bond_lock_operation lop;
   lop.producer        = bob_id;
   lop.oracle          = oid;
   lop.vesting_balance = vbid;
   lop.bond_amount     = share_type( 1 );
   lop.bond_usd_cents  = H2_TEST_ORACLE_USD_CENTS;
   signed_transaction ltx;
   ltx.operations.push_back( lop );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ltx ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( release_refused_before_unlock_then_allowed )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   h2_make_committee_member( *this, alice );
   const auto bts_ref = h2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );

   const vesting_balance_id_type vbid =
         h2_make_cdd_vesting( *this, bob_id, bob_private_key, H2_TEST_ORACLE_RAW );

   oracle_bond_lock_operation lop;
   lop.producer        = bob_id;
   lop.oracle          = oid;
   lop.vesting_balance = vbid;
   lop.bond_amount     = H2_TEST_ORACLE_RAW;
   lop.bond_usd_cents  = H2_TEST_ORACLE_USD_CENTS;
   signed_transaction ltx;
   ltx.operations.push_back( lop );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( bob_private_key, db.get_chain_id() );
   const producer_bond_id_type pbid {
      PUSH_TX( db, ltx ).operation_results.front().get<object_id_type>() };

   // Pre-unlock release is refused while the bond still secures the oracle.
   oracle_bond_release_operation rel;
   rel.producer = bob_id;
   rel.bond     = pbid;
   signed_transaction rtx;
   rtx.operations.push_back( rel );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( bob_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, rtx ), fc::exception );

   // Past the unlock the encumbrance lifts; the vesting balance itself is
   // untouched (normal vesting rules still govern withdrawals).
   generate_blocks( db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC + 10 );
   generate_block();
   signed_transaction rtx2;
   rtx2.operations.push_back( rel );
   db.current_fee_schedule().set_fee( rtx2.operations.back() );
   set_expiration( db, rtx2 );
   rtx2.sign( bob_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx2 );
   BOOST_CHECK( db.find( pbid ) == nullptr );
   BOOST_CHECK( db.find( vbid ) != nullptr );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
