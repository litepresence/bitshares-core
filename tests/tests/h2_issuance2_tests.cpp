/*
 * ISSUANCE-2: soft bands + offset pool + batch-settle + REVERT/ABSORB + cap
 * function (BSIP-1 section 4 remainder, closes E-08).
 *
 * Attack-input-first throughout: every gate is exercised from the refusal
 * side at exact integer boundaries before the happy path is asserted.
 *
 * Suite price leg (100, 1): 100 BTS per face unit, so face(D) =
 * floor(D / 100) and payout(F) = floor(F * 100). Depth cases republish to
 * move bands/haircuts; every republished price is asserted live before use.
 *
 * Proposal constants pinned here (BSIP-1 section 7b + ISSUANCE-2): N_BANDS
 * 7, band tick 250bps (half-tick 125), exit fee 200bps, offset vest 604800s,
 * offset cap 64, pending cap 64, queue caps 8 / 1e11 BTS, k1/k2 5000bps.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/committee_member.hpp>
#include <graphene/protocol/fee_schedule.hpp>
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// ---- Pinned ISSUANCE-2 proposal constants ----
static_assert( GRAPHENE_H2_ISSUE_N_BANDS == 7, "soft bands must stay 7" );
static_assert( GRAPHENE_H2_ISSUE_BAND_TICK_BPS == 250, "band tick must stay 250bps" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_FEE_BPS == 200, "exit fee must stay 2%" );
static_assert( GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC == 604800, "offset vesting must stay 7 days" );
static_assert( GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS == 64, "offset ledger must stay capped at 64" );
static_assert( GRAPHENE_H2_ISSUE_PENDING_VEST_CAP == 64, "pending list must stay capped at 64" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT == 8, "exit queue count cap must stay 8" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS == 100000000000ULL, "exit queue value cap must stay 1e11" );
static_assert( GRAPHENE_H2_ISSUE_CAP_K1_BPS == 10000, "cap k1 must stay unity (load-bearing: cap memo)" );
static_assert( GRAPHENE_H2_ISSUE_CAP_K2_BPS == 5000, "cap k2 must stay 1/2" );
// Band edges pin the discretized LLAMMA grid (anchor at edges[3] = par).
static_assert( true, "band edge pins live in the cases below" );

// Suite price: base bond units per quote face unit (100 BTS per face).
constexpr int64_t H2J_BASE = 100;
constexpr int64_t H2J_QUOTE = 1;

void h2j_make_committee_member( database_fixture& f, const account_object& account )
{
   const account_object& live = account.get_id()( f.db );
   if( !live.is_lifetime_member() )
      f.upgrade_to_lifetime_member( live );
   const auto& idx = f.db.get_index_type<committee_member_index>()
                     .indices().get<by_account>();
   if( idx.find( account.get_id() ) == idx.end() )
      f.create_committee_member( live );
}

reference_asset_id_type h2j_create_reference(
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

oracle_id_type h2j_make_oracle(
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

vesting_balance_id_type h2j_make_cdd_vesting(
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

producer_bond_id_type h2j_lock_producer_bond(
      database_fixture& f, account_id_type producer, const fc::ecc::private_key& key,
      oracle_id_type oracle, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents )
{
   oracle_bond_lock_operation op;
   op.producer          = producer;
   op.oracle            = oracle;
   op.vesting_balance   = vesting;
   op.bond_amount       = amount;
   op.bond_usd_cents    = usd_cents;
   op.bootstrap_weight  = 0;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return producer_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2j_publish(
      database_fixture& f, oracle_id_type oid,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = { oracle_value( base_amount, quote_amount ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

asset_id_type h2j_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol )
{
   asset_create_operation op;
   op.issuer      = issuer;
   op.symbol      = symbol;
   op.precision   = 5;
   op.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   op.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_id_type h2j_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth, share_type min_bond, uint64_t min_bond_usd,
      asset_id_type pair )
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

vault_bond_id_type h2j_lock_vault_bond(
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

void h2j_freeze(
      database_fixture& f, account_id_type freezer, const fc::ecc::private_key& key,
      vault_id_type vault, oracle_id_type oracle )
{
   pair_freeze_operation op;
   op.freezer = freezer;
   op.vault   = vault;
   op.oracle  = oracle;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

struct h2j_door
{
   vault_id_type vault;
   asset_id_type pair;
   asset_id_type fxr;
   oracle_id_type oracle;
};

h2j_door h2j_open_door(
      database_fixture& f,
      const account_object& alice, const fc::ecc::private_key& alice_key,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const string& pair_sym, const string& fxr_sym,
      share_type min_bond, uint64_t min_bond_usd,
      const string& tag )
{
   h2j_make_committee_member( f, alice );
   const auto bts_ref = h2j_create_reference( f, alice.get_id(), alice_key, "BTS" + tag, 5 );
   const auto usd_ref = h2j_create_reference( f, alice.get_id(), alice_key, "USD" + tag, 4 );

   oracle_options opts;
   opts.producers[ bob.get_id() ] = oracle_producer_entry( 1 );
   const oracle_id_type oid = h2j_make_oracle(
         f, alice.get_id(), alice_key, "H2J.USD" + tag, bts_ref, usd_ref, opts );
   const share_type oracle_bond( 1000000000 );
   const auto vb = h2j_make_cdd_vesting( f, bob.get_id(), bob_key, oracle_bond );
   h2j_lock_producer_bond( f, bob.get_id(), bob_key, oid, vb, oracle_bond,
                           GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS );

   const asset_id_type pair = h2j_create_uia( f, alice.get_id(), alice_key, pair_sym );
   const asset_id_type fxr = h2j_create_uia( f, alice.get_id(), alice_key, fxr_sym );
   authority vault_auth( 1, alice.get_id(), 1 );
   const vault_id_type vid = h2j_register_vault(
         f, alice.get_id(), alice_key, vault_auth, min_bond, min_bond_usd, pair );

   h2j_freeze( f, alice.get_id(), alice_key, vid, oid );
   BOOST_REQUIRE( vid( f.db ).bound_oracle.valid() );
   f.generate_block();
   f.db.modify( vid( f.db ), []( vault_object& v ) { v.frozen = false; } );
   f.db.modify( oid( f.db ), []( oracle_object& o ) { o.options.frozen = false; } );

   h2j_publish( f, oid, bob.get_id(), bob_key, H2J_BASE, H2J_QUOTE );
   BOOST_REQUIRE( h2_read_pair_price( f.db, vid( f.db ), 0, f.db.head_block_time() ).valid() );

   h2j_door d;
   d.vault = vid;
   d.pair = pair;
   d.fxr = fxr;
   d.oracle = oid;
   return d;
}

void h2j_mint(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2j_door& d, share_type deposit_bts, share_type stable )
{
   hybrid_mint_operation op;
   op.minter        = minter;
   op.vault         = d.vault;
   op.deposit       = asset( deposit_bts, asset_id_type() );
   op.stable_amount = stable;
   op.fxr_asset     = d.fxr;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_mint_throws(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2j_door& d, share_type deposit_bts, share_type stable )
{
   hybrid_mint_operation op;
   op.minter        = minter;
   op.vault         = d.vault;
   op.deposit       = asset( deposit_bts, asset_id_type() );
   op.stable_amount = stable;
   op.fxr_asset     = d.fxr;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

vesting_balance_id_type h2j_redeem(
      database_fixture& f, account_id_type redeemer, const fc::ecc::private_key& key,
      const h2j_door& d, share_type burn_face )
{
   hybrid_redeem_operation op;
   op.redeemer = redeemer;
   op.vault    = d.vault;
   op.burn     = asset( burn_face, d.pair );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vesting_balance_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2j_transfer(
      database_fixture& f, account_id_type from, const fc::ecc::private_key& key,
      account_id_type to, asset amount )
{
   transfer_operation op;
   op.from   = from;
   op.to     = to;
   op.amount = amount;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_deposit(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_deposit_operation op;
   op.depositor = who;
   op.vault     = d.vault;
   op.deposit   = asset( amount_bts, asset_id_type() );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_deposit_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_deposit_operation op;
   op.depositor = who;
   op.vault     = d.vault;
   op.deposit   = asset( amount_bts, asset_id_type() );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

void h2j_offset_claim(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_claim_operation op;
   op.claimant = who;
   op.vault    = d.vault;
   op.amount   = amount_bts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_claim_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_claim_operation op;
   op.claimant = who;
   op.vault    = d.vault;
   op.amount   = amount_bts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

void h2j_exit_request(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type face )
{
   issuance_exit_request_operation op;
   op.requester = who;
   op.vault     = d.vault;
   op.face      = face;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_exit_request_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type face )
{
   issuance_exit_request_operation op;
   op.requester = who;
   op.vault     = d.vault;
   op.face      = face;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

const reserve_object* h2j_find_reserve( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<reserve_index>().indices().get<by_reserve_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

const offset_pool_object* h2j_find_pool( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<offset_pool_index>().indices().get<by_offset_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

/**
 * Refresh the bonded price, then cross the next maintenance with it live.
 * Maintenance-interval jumps age the consumed price past its 1-day lifetime,
 * so crossing cold would hold every queue/shortfall fail-closed (correct
 * consensus, useless test): approaching first, republishing (same value at
 * a new time IS a new promotion record), then crossing keeps the read live
 * AT the sweep. No vault/tripwire assertions here -- callers own them.
 */
void h2j_cross_maintenance_with_price(
      database_fixture& f, const h2j_door& d,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time - 300 );
   h2j_publish( f, d.oracle, who, key, base_amount, quote_amount );
   BOOST_REQUIRE( h2_read_pair_price( f.db, d.vault( f.db ), 0, f.db.head_block_time() ).valid() );
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time + 60 );
   f.generate_block();
}

share_type h2j_band_sum_bts( const reserve_object* r )
{
   share_type s( 0 );
   for( const share_type& b : r->band_bts )
      s += b;
   return s;
}

share_type h2j_band_sum_face( const reserve_object* r )
{
   share_type s( 0 );
   for( const share_type& b : r->band_stable )
      s += b;
   return s;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_issuance2_tests, database_fixture )

/// Half-tick move predicate pins (pure exact math, no chain needed):
/// 1% inside the 125bps half-tick is NOT a move; 10% is; the exact 125bps
/// boundary (81/80 at anchor 80/1) is NOT a move (inclusive headroom);
/// degenerate anchors never move (fail-closed).
BOOST_AUTO_TEST_CASE( band_move_predicate_pins )
{ try {
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 101, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 110, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 110, 1 ), oracle_value( 95, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 80, 1 ), oracle_value( 81, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 80, 1 ), oracle_value( 82, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 0, 0 ), oracle_value( 100, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 0, 1 ) ) );
   // Band grid pins: eight edges, anchor at par, 250bps minimum spacing.
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 0 ), 9000 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 1 ), 9500 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 2 ), 9750 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 3 ), 10000 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 4 ), 10250 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 5 ), 10500 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 6 ), 11000 );
   BOOST_CHECK_EQUAL( h2_issue_band_edge_bps( 7 ), 11500 );
   BOOST_CHECK_EQUAL( GRAPHENE_H2_ISSUE_N_BANDS, 7u );
} FC_LOG_AND_RETHROW() }

/// Absorb trigger + shortfall pins (pure exact math): exactly 100% does NOT
/// trigger; one unit under does; the shortfall CEILS (favoring the protocol:
/// a fractional hair absorbs whole).
BOOST_AUTO_TEST_CASE( absorb_trigger_and_shortfall_pins )
{ try {
   BOOST_CHECK( !h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                         oracle_value( 200, 1 ) ) );
   BOOST_CHECK( h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                        oracle_value( 201, 1 ) ) );
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 200000 ), share_type( 1000 ),
                                              oracle_value( 201, 1 ) ).value, 1000 );
   // Fractional shortfall ceils: (1000x201 - 200000)/1 = 1000 exact above;
   // at (1000, 7) vs 700000/7000: (7000x1000 - 700000x7)/7 = 300000 -> exact.
   // Ceil case: bts 1000, supply 11, price (100,1): (1100-1000)=100 exact;
   // bts 1000, supply 101, price (10,1): (1010-1000)=10 exact; fractional:
   // bts 1000, supply 100, price (201,20): (100x201 - 1000x20)/20 = 5 exact.
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 999 ), share_type( 100 ),
                                              oracle_value( 201, 20 ) ).value, 6 );
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 200000 ), share_type( 1000 ),
                                              oracle_value( 200, 1 ) ).value, 0 );
   BOOST_CHECK( !h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                         oracle_value( 0, 1 ) ) );
} FC_LOG_AND_RETHROW() }

/// Soft bands on the live book: genesis opens centered, sub-half-tick moves
/// never churn, consumed moves shift one step with floored quanta, drift
/// reverses, and the partition always sums to the totals.
BOOST_AUTO_TEST_CASE( bands_rebalance_on_consumed_moves_with_hysteresis )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYBAND", "HYBANDF", share_type( 1 ), uint64_t( 1 ), "1" );

   // Genesis: whole book in the active band 3, anchored at (100,1).
   // D=700000/M=1000: surplus 6000 face mints 6000 FXR at genesis parity.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );
   const reserve_object* r0 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r0 != nullptr );
   BOOST_REQUIRE_EQUAL( r0->band_bts.size(), 7u );
   BOOST_REQUIRE_EQUAL( r0->band_stable.size(), 7u );
   BOOST_CHECK( r0->band_bts[3] == share_type( 700000 ) );
   BOOST_CHECK( r0->band_stable[3] == share_type( 1000 ) );
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r0->band_bts[i] == share_type( 0 ) );
         BOOST_CHECK( r0->band_stable[i] == share_type( 0 ) );
      }
   BOOST_CHECK( r0->band_anchor == oracle_value( 100, 1 ) );

   // Sub-half-tick (+1%): a conversion adds to band 3 but shifts NOTHING.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 101, 1 );
   generate_block(); // reset the door counter (effective cap < used same-block)
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r1 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r1 != nullptr );
   BOOST_CHECK( r1->band_bts[3] == share_type( 707000 ) );
   BOOST_CHECK( r1->band_stable[3] == share_type( 1010 ) );
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r1->band_bts[i] == share_type( 0 ) );
         BOOST_CHECK( r1->band_stable[i] == share_type( 0 ) );
      }
   BOOST_CHECK( r1->band_anchor == oracle_value( 100, 1 ) );

   // Consumed move (+8.9%): one step up with FLOORED quanta.
   // Pre-shift band 3: (707000, 1010); quanta floor(707000/7)=101000 BTS,
   // floor(1010/7)=144 face. The mint below adds first (D=7003/M=10), so the
   // pre-shift source reads (714003, 1020): quanta 102000 / 145.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 110, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7003 ), share_type( 10 ) );
   const reserve_object* r2 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r2 != nullptr );
   BOOST_CHECK( r2->band_bts[4] == share_type( 102000 ) );
   BOOST_CHECK( r2->band_stable[4] == share_type( 145 ) );
   BOOST_CHECK( r2->band_bts[3] == share_type( 714003 - 102000 ) );
   BOOST_CHECK( r2->band_stable[3] == share_type( 1020 - 145 ) );
   BOOST_CHECK( r2->band_anchor == oracle_value( 110, 1 ) );
   // Conservation: the partition sums to the totals exactly.
   BOOST_CHECK( h2j_band_sum_bts( r2 ) == r2->bts_balance );
   BOOST_CHECK( h2j_band_sum_face( r2 ) == r2->stable_supply );

   // Drift down (-13.6%): one step back toward discount bands.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 95, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r3 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r3 != nullptr );
   BOOST_CHECK( r3->band_anchor == oracle_value( 95, 1 ) );
   BOOST_CHECK( r3->band_bts[2] > share_type( 0 ) );
   BOOST_CHECK( h2j_band_sum_bts( r3 ) == r3->bts_balance );
   BOOST_CHECK( h2j_band_sum_face( r3 ) == r3->stable_supply );

   // Half-tick boundary equality never moves: re-anchor at (80,1) via a down
   // move, then publish exactly +1.25% (81,1) and convert: no shift, anchor
   // holds. rmin still admits (book deep).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 80, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r4 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r4 != nullptr );
   BOOST_REQUIRE( r4->band_anchor == oracle_value( 80, 1 ) );
   const vector<share_type> before_bts = r4->band_bts;
   const vector<share_type> before_face = r4->band_stable;
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 81, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r5 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r5 != nullptr );
   BOOST_CHECK( r5->band_anchor == oracle_value( 80, 1 ) );
   // Only band 3 grew (the new deposit); every other band is untouched.
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r5->band_bts[i] == before_bts[i] );
         BOOST_CHECK( r5->band_stable[i] == before_face[i] );
      }
} FC_LOG_AND_RETHROW() }

/// Cap function, split gate: the fixed $2,000 keeps the shared per-block
/// counter semantics (genesis exact-fill admits), while the headroom leg
/// binds the MARGINAL conversion at the standing buffer (refuse/admit pair
/// at the exact leg boundary). k1 = UNITY is load-bearing (see the constant
/// memo): any k1 < 1 refuses healthy half-book redeems and at-headroom
/// top-ups, proven by the live-book cases elsewhere in this suite.
BOOST_AUTO_TEST_CASE( cap_function_three_way_min_with_k1 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   // Fixed-ceiling pins (genesis: headroom skipped, no tripwire): the full
   // $2,000 leg admits, one unit past it refuses -- the DOS bound is
   // unchanged from ISSUANCE-1.
   {
      const h2j_door d0 = h2j_open_door(
            *this, alice, alice_private_key, bob, bob_private_key,
            "HYCAP0", "HYCAP0F", share_type( 1 ), uint64_t( 1 ), "A" );
      const auto price = h2_read_pair_price( db, d0.vault( db ), 0, db.head_block_time() );
      BOOST_REQUIRE( price.valid() );
      BOOST_CHECK( h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                        share_type( 0 ),
                                        share_type( 200000000000LL ) ) );
      BOOST_CHECK( !h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                         share_type( 0 ),
                                         share_type( 200000000001LL ) ) );
      BOOST_CHECK( !h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                         share_type( 200000000000LL ),
                                         share_type( 1 ) ) );
   }

   // Headroom leg binds the marginal leg: D=140000/M=1000 opens at 140%
   // (headroom 100 face = 10000 BTS, leg bound 10000 at k1 = unity).
   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYCAP", "HYCAPF", share_type( 1 ), uint64_t( 1 ), "B" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 140000 ), share_type( 1000 ) );
   generate_block(); // reset the door counter; the headroom leg persists
   // Leg 12000 > 10000 refuses (rmin would admit: post 152000/1030 = 147%).
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 12000 ), share_type( 30 ) );
   // Leg 8000 <= 10000 admits (post 148000/1030 = 143.7% >= 130%).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 8000 ), share_type( 30 ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 148000 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1030 ) );
} FC_LOG_AND_RETHROW() }

/// Depth leg: unqualified depth (single pool, one window) REFUSES the door
/// outright, while the pool-less control pair admits on the same terms.
BOOST_AUTO_TEST_CASE( cap_function_unqualified_depth_refuses )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEP", "HYDEEPF", share_type( 1 ), uint64_t( 1 ), "C" );
   const h2j_door c = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEPC", "HYDEEPCF", share_type( 1 ), uint64_t( 1 ), "D" );

   // Both books open identically at 200% (D=2e10/M=1e8, inside the fixed
   // door): alice needs 1e7 face for the pool deposit below.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 100000000LL ) );
   h2j_mint( *this, alice_id, alice_private_key, c,
             share_type( 20000000000LL ), share_type( 100000000LL ) );
   generate_block();

   // One pool on d's pair, one deep exchange (2e8 BTS >= MIN_DEPTH) in the
   // current window only: the tripwire state exists but is unqualified
   // (empty old window AND a single pool) -- the door refuses.
   const asset_id_type lpa = h2j_create_uia( *this, alice_id, alice_private_key, "HYDEEPLP" );
   const liquidity_pool_object& pool = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpa, 0, 0 );
   deposit_to_liquidity_pool( alice_id, pool.get_id(),
                              asset( share_type( 1000000000 ), asset_id_type() ),
                              asset( share_type( 10000000 ), d.pair ) );
   exchange_with_liquidity_pool( alice_id, pool.get_id(),
                                 asset( share_type( 200000000 ), asset_id_type() ),
                                 asset( share_type( 1 ), d.pair ) );

   // Refusal side first: any conversion on the touched pair refuses...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 7000 ), share_type( 10 ) );
   // ...while the untouched control pair admits on identical terms.
   h2j_mint( *this, alice_id, alice_private_key, c,
             share_type( 7000 ), share_type( 10 ) );
   BOOST_CHECK( h2j_find_reserve( *this, c.pair )->bts_balance == share_type( 20000007000LL ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 20000000000LL ) );
} FC_LOG_AND_RETHROW() }

/// Depth leg binds when qualified: two pools observed across both windows
/// price door flow at half the demonstrated absorption.
BOOST_AUTO_TEST_CASE( cap_function_qualified_depth_binds )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 200000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEP2", "HYDEEP2F", share_type( 1000000000LL ), uint64_t( 1000000 ), "E" );

   // Deep 200% book (D=4.2e10/M=2.1e8, one block, inside the fixed door).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 42000000000LL ), share_type( 210000000LL ) );
   // Vault bond keeps the pair HEALTHY through the maintenance rotation
   // below (outstanding 2.1e8 needs >= 3.15e8 bonds).
   const auto vest = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                           share_type( 1000000000LL ) );
   h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, vest,
                        share_type( 1000000000LL ), uint64_t( 1000000 ) );

   // Two pools at the feed ratio (100:1), 1e10 BTS + 1e8 face each.
   const asset_id_type lpa = h2j_create_uia( *this, alice_id, alice_private_key, "HYDP2A" );
   const asset_id_type lpb = h2j_create_uia( *this, alice_id, alice_private_key, "HYDP2B" );
   const liquidity_pool_object& p1 = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpa, 0, 0 );
   const liquidity_pool_object& p2 = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpb, 0, 0 );
   deposit_to_liquidity_pool( alice_id, p1.get_id(),
                              asset( share_type( 10000000000LL ), asset_id_type() ),
                              asset( share_type( 100000000LL ), d.pair ) );
   deposit_to_liquidity_pool( alice_id, p2.get_id(),
                              asset( share_type( 10000000000LL ), asset_id_type() ),
                              asset( share_type( 100000000LL ), d.pair ) );
    // Round 1: 1e8 BTS through each pool (1% of pool: deviation ~1%, clean).
    exchange_with_liquidity_pool( alice_id, p1.get_id(),
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    exchange_with_liquidity_pool( alice_id, p2.get_id(),
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    // Pool IDs by value: object references do not survive the maintenance
    // rotation below, IDs do (diagnostic pin while the stale-ref mechanism
    // is characterized -- see task report).
    const liquidity_pool_id_type p1_id = p1.get_id();
    const liquidity_pool_id_type p2_id = p2.get_id();
    BOOST_REQUIRE( db.find( p1_id ) != nullptr );
    BOOST_REQUIRE( db.find( p2_id ) != nullptr );
    // Rotate: old window takes round 1 (evaluation stays clean: ~1% moves).
    generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
    generate_block();
    BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
    // The pools must survive the rotation as objects (IDs stay valid even
    // if the pre-rotation references went stale).
    BOOST_REQUIRE( db.find( p1_id ) != nullptr );
    BOOST_REQUIRE( db.find( p2_id ) != nullptr );
    // Round 2: same again into the fresh window.
    exchange_with_liquidity_pool( alice_id, p1_id,
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    exchange_with_liquidity_pool( alice_id, p2_id,
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
   // Refresh the consumed price for the probes below (the rotation jump
   // aged the opening publish): same value at a new time is a new record.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   generate_block(); // reset the door counter for the probes below

   // Qualified depth 4e8 -> leg floor(4e8 x 5000/10000) = 2e8 binds below
   // the headroom leg (~7.35e9) and the fixed ceiling.
   // D=2.5e8 refuses (rmin would admit: post ~199.9%)...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 250000000LL ), share_type( 1000000LL ) );
   // ...D=1.5e8 admits.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 150000000LL ), share_type( 1000000LL ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance
                == share_type( 42150000000LL ) );
} FC_LOG_AND_RETHROW() }

/// Offset pool: trigger boundary on the live book, 7-day vesting claims,
/// non-transferability by construction (no transfer path exists: every
/// transfer-like attempt leaves the ledger untouched), merge semantics.
BOOST_AUTO_TEST_CASE( offset_pool_absorbs_claims_vest_and_refuse_theft )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );
   fund( carol, asset( 30000000000LL ) );
   fund( dave, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYOFF", "HYOFFF", share_type( 100000 ), uint64_t( 100000 ), "F" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   // Real vault bond: the pair must stay HEALTHY through the three
   // maintenance crossings below (outstanding 1000 needs >= 1500 bonds;
   // otherwise the top-up ladder winds the vault down mid-test).
   {
      const auto hoard = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                              share_type( 100000 ) );
      h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, hoard,
                           share_type( 100000 ), uint64_t( 100000 ) );
   }
   generate_block();

   // Exactly 100% is NOT absorbable: no pool exists and maintenance books
   // nothing (uncovered stays 0).
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 200, 1 );
   BOOST_CHECK( h2j_find_pool( *this, d.pair ) == nullptr );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );

   // Below 100% with no pool: the remainder is RECORDED for the rmax junior
   // path (absorb-dilute with an empty pool).
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 201, 1 );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 1000 ) );

   // Bob funds the absorber: one entry, 7-day maturity.
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 50000 ) );
   const offset_pool_object* p0 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p0 != nullptr );
   BOOST_CHECK( p0->balance == share_type( 50000 ) );
   BOOST_REQUIRE_EQUAL( p0->claims.size(), 1u );
   BOOST_CHECK( p0->claims[0].owner == bob_id );
   BOOST_CHECK( p0->claims[0].amount == share_type( 50000 ) );
   const time_point_sec avail0 = p0->claims[0].available_after;
   BOOST_CHECK( avail0 == db.head_block_time() + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC );

   // Maintenance absorbs the recorded 1000 shortfall from the pool first.
   // Absorbers take the first loss pro-rata: balance 50000->49000 and the
   // claim 50000->floor(50000x49000/50000)=49000.
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 201, 1 );
   const offset_pool_object* p1 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p1 != nullptr );
   BOOST_CHECK( p1->balance == share_type( 49000 ) );
   BOOST_CHECK( p1->claims[0].amount == share_type( 49000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 201000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );

   // Premature claims refuse (time lock), strangers refuse (ownership),
   // over-claims refuse (mirror).
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, d, share_type( 1000 ) );
   h2j_offset_claim_throws( *this, carol_id, carol_private_key, d, share_type( 1000 ) );
    // Transfer-like attempts cannot touch the ledger: a plain BTS transfer
    // between strangers leaves pool balance and claims byte-identical...
    h2j_transfer( *this, carol_id, carol_private_key, dave_id,
                  asset( share_type( 1000 ), asset_id_type() ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 49000 ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims[0].amount == share_type( 49000 ) );
    // ...a vesting_balance_create from liquid BTS likewise leaves the ledger
    // untouched (pool claims fund only via offset_deposit and pay only via
    // offset_claim/absorb: there is no claim-derived source any
    // BTS-moving op can consume)...
    const vesting_balance_id_type carol_vb = h2j_make_cdd_vesting(
          *this, carol_id, carol_private_key, share_type( 1000 ) );
    BOOST_REQUIRE( db.find( carol_vb ) != nullptr );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 49000 ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims[0].amount == share_type( 49000 ) );
    // ...and the blind variants (transfer_to_blind / transfer_from_blind /
    // blind_transfer) have no ledger path by construction: they move account
    // balances into/out of blind commitments (protocol/confidential.hpp),
    // while the pool ledger is an internal vector on offset_pool_object that
    // only offset_deposit / offset_claim / h2_issue_absorb_pair ever
    // create/modify (grep: offset_pool_object appears only in
    // issuance.cpp + issuance_object.hpp/evaluator decls/index; zero
    // references in confidential_evaluator.cpp, transfer/market/vesting
    // evaluators). A blind op funded from claim-derived BTS would move the
    // already-paid liquid BTS (same as the plain transfer above), never the
    // ledger entry itself -- non-transferable by construction
    // (issuance_object.hpp:158-160).
   // ...repeat deposits MERGE (one entry per owner, latest maturity wins)...
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 10000 ) );
   const offset_pool_object* p2 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE_EQUAL( p2->claims.size(), 1u );
   BOOST_CHECK( p2->claims[0].amount == share_type( 59000 ) );
   BOOST_CHECK( p2->balance == share_type( 59000 ) );
   BOOST_CHECK( p2->claims[0].available_after >= avail0 );
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, d, share_type( 59001 ) );

   // After the 7-day vesting the claim pays liquid and the entry closes.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC + 100 );
   generate_block();
   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   h2j_offset_claim( *this, bob_id, bob_private_key, d, share_type( 59000 ) );
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount
                == bob_before + share_type( 59000 ) );
   BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims.empty() );

   // No pool, no claim: the reserveless door refuses.
   const h2j_door e = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYOFFE", "HYOFFEF", share_type( 1 ), uint64_t( 1 ), "G" );
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, e, share_type( 1 ) );
} FC_LOG_AND_RETHROW() }

/// Batch exits: two requests settle in ONE maintenance pass at ONE clearing
/// haircut (zero here: the book is covered), minus the floored 2% exit fee
/// that stays in the reserve. Face burns at request; the queue clears.
BOOST_AUTO_TEST_CASE( batch_exits_single_haircut_and_exit_fee )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );
   fund( carol, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYEXIT", "HYEXITF", share_type( 1 ), uint64_t( 1 ), "H" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 2000000 ), share_type( 10000 ) );
   // Carol holds exit face via a plain transfer (no new economics).
   h2j_transfer( *this, alice_id, alice_private_key, carol_id,
                 asset( share_type( 3000 ), d.pair ) );

   // Refusal side: dust (1 face -> gross floor(1x100)=100, fee eats 2, net
   // 98 -- admits; true dust needs a tiny price, covered elsewhere), the
   // full book (10000 == supply: redeem path only), and over-face.
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 10000 ) );

   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 3000 ) );
   h2j_exit_request( *this, carol_id, carol_private_key, d, share_type( 3000 ) );
   const reserve_object* rq = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( rq != nullptr );
   BOOST_REQUIRE_EQUAL( rq->exit_queue.size(), 2u );
   BOOST_CHECK( rq->stable_supply == share_type( 4000 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 4000 ) );

   const share_type alice_before = db.get_balance( alice_id, asset_id_type() ).amount;
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );

   // Covered book -> haircut 0 for the WHOLE batch: each pays
   // floor(300000 x 9800/10000) = 294000, identical per-face (no queue
   // jumping: position in the queue never matters).
   BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                == alice_before + share_type( 294000 ) );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 294000 ) );
   const reserve_object* rs = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( rs != nullptr );
   BOOST_CHECK( rs->exit_queue.empty() );
   // Fee routing: 2000000 - 588000 = 1412000 stays (2 x 6000 kept).
   BOOST_CHECK( rs->bts_balance == share_type( 1412000 ) );
   BOOST_CHECK( rs->stable_supply == share_type( 4000 ) );
} FC_LOG_AND_RETHROW() }

/// Suspension: a full queue (count cap) suspends FXR minting but not senior
/// flow; the batch settle lifts it. Both caps pin the same predicate.
BOOST_AUTO_TEST_CASE( exit_queue_suspends_fxr_mint_until_settled )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

    const h2j_door d = h2j_open_door(
          *this, alice, alice_private_key, bob, bob_private_key,
          "HYSUSP", "HYSUSPF", share_type( 2000000 ), uint64_t( 100000 ), "I" );
   // 200% book with zero surplus (value 20000 == 2 x 10000): no FXR yet.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 2000000 ), share_type( 10000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 0 ) );

   // Fill the queue to the count cap (8 requests; faces differ so no two
   // transactions share an ID -- duplicate txids are refused, not queued).
   for( int i = 0; i < 8; ++i )
      h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 100 + i ) );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->exit_queue.size(), 8u );
   // Ninth request refuses (count cap).
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 200 ) );
   generate_block(); // reset the door counter: the probes below must refuse
                     // on suspension alone, never on the shared door counter

   // A surplus-raising mint (D=260000/M=1000: over-collateralized, FXR>0)
   // refuses while suspended...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 260000 ), share_type( 1000 ) );
    // ...but senior-only flow still admits (near-par mint prices no FXR).
    h2j_mint( *this, alice_id, alice_private_key, d,
              share_type( 130000 ), share_type( 1000 ) );
    // Real vault bond: the pair must stay HEALTHY through the maintenance
    // crossing below (outstanding peaks at 10172, maintenance needs bonds /
    // outstanding >= 150%; otherwise the sweep freezes the door mid-test
    // and the post-settle mint refuses on the freeze, not the suspension).
    {
       const auto hoard = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                               share_type( 2000000 ) );
       h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, hoard,
                            share_type( 2000000 ), uint64_t( 100000 ) );
    }

    // The batch settles (haircut 0, 100-face nets floor(10000x0.98)=9800)
   // and the suspension lifts: the same FXR mint now admits.
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->exit_queue.empty() );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 260000 ), share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount > share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Value cap: queued value at the ceiling admits then suspends; past it
/// refuses. (Count leg pinned in the case above; both feed one predicate.)
BOOST_AUTO_TEST_CASE( exit_queue_value_cap_suspends_fxr )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYVAL", "HYVALF", share_type( 1 ), uint64_t( 1 ), "J" );
   // 3.6e11 BTS / 1.8e9 face across three blocks. The headroom leg
   // (k1 = unity) permits geometric scale-up only: each mint fits inside
   // the standing buffer (2e11 genesis, then 7e10 of 7e10 headroom, then
   // 9e10 of 9.45e10) -- no single conversion doubles a fat book.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 1000000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 70000000000LL ), share_type( 350000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 90000000000LL ), share_type( 450000000LL ) );

   // 6e8 face = 6e10 BTS queued (under the 1e11 value cap)...
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 600000000LL ) );
   // ...+4e8 face lands exactly ON the cap (equality admits)...
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 400000000LL ) );
   // ...any further face refuses (past the cap)...
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 1 ) );
   // ...and FXR minting suspends at the cap (value leg of the predicate).
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 260000 ), share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// R-06 front-run closure: the attacker's later request settles at the SAME
/// batch haircut as the victim's earlier one (no queue jumping, no
/// face-minus-haircut arber residual in the 36h window -- by construction).
BOOST_AUTO_TEST_CASE( frontrun_attempt_settles_at_batch_haircut )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYFRONT", "HYFRONTF", share_type( 1 ), uint64_t( 1 ), "K" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_transfer( *this, alice_id, alice_private_key, bob_id,
                 asset( share_type( 300 ), d.pair ) );

   // Victim queues first, attacker jumps the queue after seeing it.
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 300 ) );
   generate_block();
   h2j_exit_request( *this, bob_id, bob_private_key, d, share_type( 300 ) );

   // Price collapses 6x before the batch: obligations are 400 supply + 600
   // queued = 1000 face against 200000 BTS. Value floor(200000/600)=333 ->
   // coverage floor(333x10000/1000)=3330 -> haircut 6670 for the WHOLE batch
   // (queued face counts: a crash cannot overpay past the reserve).
   // The crash crosses maintenance live (refreshed right before the sweep).
   const share_type alice_before = db.get_balance( alice_id, asset_id_type() ).amount;
   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 600, 1 );

   // Both settle at the batch haircut: gross floor(300x600)=180000, factor
   // 10000-6670-200=3130 -> floor(180000x3130/10000)=56340, under the
   // pro-rata 60000. Identical per-face (position never matters),
   // haircutten (below gross), fee-bearing (below haircut-only 59715).
   BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                == alice_before + share_type( 56340 ) );
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount
                == bob_before + share_type( 56340 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->exit_queue.empty() );
   // The uncovered remainder (shortfall ceil((1000x600-200000)/1)=400000,
   // no pool) is recorded for the rmax junior path, not silently dropped.
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 400000 ) );
} FC_LOG_AND_RETHROW() }

/// REVERT: an unvested door output returns to its source on halt entry
/// (escrow cancelled, face back for claiming, reserve made whole).
BOOST_AUTO_TEST_CASE( halt_reverts_unvested_door_outputs )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYREV", "HYREVF", share_type( 1 ), uint64_t( 1 ), "L" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   // Redeem 500: escrow floor(500x100)-150 = 49850, pending list holds 1.
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(), 1u );

    // Halt entry (committee freeze): the unvested output REVERTS.
    h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );
    BOOST_CHECK( db.find( escrow ) == nullptr ); // escrow cancelled
    BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) ); // face back
    BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 1000 ) );
    BOOST_CHECK( d.vault( db ).outstanding == share_type( 1000 ) );
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 200000 ) ); // whole
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->pending_vestings.empty() );
    // REVERT is the exact inverse of redeem-apply (issuance.cpp:1166-1171):
    // the burned 500 face returns to the reserve liability AND its band
    // partition, so the round-trip closes (stable_supply 500->1000, band
    // face sum == supply). Without the stable leg the reserve would strand
    // 500 of restored BTS against 500 of missing liability.
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->stable_supply == share_type( 1000 ) );
    BOOST_CHECK( h2j_band_sum_bts( h2j_find_reserve( *this, d.pair ) )
                 == h2j_find_reserve( *this, d.pair )->bts_balance );
    BOOST_CHECK( h2j_band_sum_face( h2j_find_reserve( *this, d.pair ) )
                 == h2j_find_reserve( *this, d.pair )->stable_supply );
} FC_LOG_AND_RETHROW() }

/// ABSORB (pool leg): a below-100% position drinks from the offset pool
/// first on halt entry; the reserve is made whole, remainder zero.
BOOST_AUTO_TEST_CASE( halt_absorbs_shortfall_from_pool_first )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYABS", "HYABSF", share_type( 1 ), uint64_t( 1 ), "M" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 100000 ) );

   // Crash to (250,1): value floor(200000/250)=800 < 1000, shortfall
   // ceil((1000x250-200000)/1) = 50000. No pending (no redeems).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 250, 1 );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 50000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 250000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// ABSORB (dilute leg): when the pool cannot cover, it drains fully and the
/// remainder is RECORDED for the existing rmax junior path (never dropped).
BOOST_AUTO_TEST_CASE( halt_absorb_dilute_records_remainder )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDIL", "HYDILF", share_type( 1 ), uint64_t( 1 ), "N" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 20000 ) );

   // Same crash (shortfall 50000), pool holds 20000: drains, records 30000.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 250, 1 );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 0 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 220000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 30000 ) );
} FC_LOG_AND_RETHROW() }

/// STAND: a matured (settled) door output is never repriced -- the halt
/// prunes it and leaves escrow, face, supply, and reserve untouched.
BOOST_AUTO_TEST_CASE( halt_stands_settled_positions )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSTAND", "HYSTANDF", share_type( 1 ), uint64_t( 1 ), "O" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );

   // Let the 24h escrow mature (maintenance passes; the vault may TOPUP but
   // no halt transition runs outside freeze/wind-down entries), then refresh
   // the price (aged past its lifetime) and halt.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC + 100 );
   generate_block();
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   BOOST_REQUIRE( h2_read_pair_price( db, d.vault( db ), 0, db.head_block_time() ).valid() );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   // Stood: escrow intact, face NOT re-minted, book untouched, list pruned.
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_CHECK( db.find( escrow )->balance == asset( share_type( 49850 ), asset_id_type() ) );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 500 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 500 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 150150 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->pending_vestings.empty() );
} FC_LOG_AND_RETHROW() }

/// New-op gates: offset deposit/claim and exit requests refuse before the
/// price leg (direct + fee-vote + proposal containment, E-01 pattern) and
/// price post-leg.
BOOST_AUTO_TEST_CASE( issuance2_gates_refuse_before_the_price_leg )
{ try {
   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   {
      offset_deposit_operation op;
      op.depositor = alice_id;
      op.vault     = vault_id_type( 0 );
      op.deposit   = asset( share_type( 1000 ), asset_id_type() );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      offset_claim_operation op;
      op.claimant = alice_id;
      op.vault    = vault_id_type( 0 );
      op.amount   = share_type( 1000 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      issuance_exit_request_operation op;
      op.requester = alice_id;
      op.vault     = vault_id_type( 0 );
      op.face      = share_type( 1000 );
      signed_transaction tx; tx.operations.push_back( op );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.get_mutable_fees() = fee_schedule::get_default();
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<offset_deposit_operation>() );
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<offset_claim_operation>() );
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<issuance_exit_request_operation>() );
      cop.proposed_ops.emplace_back( cmuop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      offset_deposit_operation oop;
      oop.depositor = alice_id;
      oop.vault     = vault_id_type( 0 );
      oop.deposit   = asset( share_type( 1000 ), asset_id_type() );
      cop.proposed_ops.emplace_back( oop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }

   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.get_mutable_fees() = fee_schedule::get_default();
      cop.proposed_ops.emplace_back( cmuop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      PUSH_TX( db, tx, ~0 );
   }
} FC_LOG_AND_RETHROW() }

/// Fee defaults pin (spam math, E-01 pattern): all three new ops price
/// mempool noise at nonzero 5-BTS defaults, matching the door-op basis.
BOOST_AUTO_TEST_CASE( issuance2_fee_defaults_pinned_nonzero )
{ try {
   BOOST_CHECK_EQUAL( offset_deposit_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( offset_claim_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( issuance_exit_request_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<offset_deposit_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<offset_claim_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<issuance_exit_request_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
