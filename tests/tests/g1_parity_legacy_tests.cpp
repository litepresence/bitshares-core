/*
 * G1 Task 7 — legacy coexistence (BSIP-2 §2, GP-01/02/03, V-14).
 *
 * The parity fee-share (5% of market/settlement fee increments into the
 * per-asset parity pool) is gated on a per-asset opt-in,
 * `parity_fee_share_enabled`, appended-last on additional_asset_options
 * (absent == false). Every legacy asset (bit*, HONEST.*, gateway UIAs, CORE)
 * is absent-flagged, so post-fork fills on non-opted assets must leave
 * parity_pool untouched and credit 100% of the increment to the issuer
 * revenue fields — by construction, not by convention.
 *
 * TDD note: the three `legacy_*` cases below are written FIRST and must FAIL
 * on the pre-Task-7 tree (which routes 500bps on every asset through the
 * shared pay_market_fees choke point). They go green with the opt-in gate.
 * The `opted_in_*` cases pin the intended behavior for opted-in assets and
 * the production opt-in path (signed asset_update, post-STEALTH only).
 *
 * Consensus law: no floats, no unordered_*, head-block time only, integer
 * math with explicit floor/ceil, bounded state.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/market_object.hpp>
#include <graphene/chain/stealth_object.hpp>

#include <graphene/protocol/asset_ops.hpp>
#include <graphene/protocol/market.hpp>
#include <graphene/protocol/stealth.hpp>

#include <fc/io/raw.hpp>
#include <fc/reflect/variant.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;
using namespace graphene::protocol;

namespace {

// The task-7 opt-in flag lives appended-last on additional_asset_options.
// Absent (every legacy asset) == false: no diversion, ever.
bool parity_opted_in( const database& db, asset_id_type aid )
{
   const auto& e = aid( db ).options.extensions.value.parity_fee_share_enabled;
   return e.valid() && *e;
}

bool pool_has( const database& db, asset_id_type aid )
{
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr = st.parity_pool.find( aid );
   return itr != st.parity_pool.end() && itr->second.value != 0;
}

share_type pool_balance( const database& db, asset_id_type aid )
{
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr = st.parity_pool.find( aid );
   return ( itr == st.parity_pool.end() ) ? share_type( 0 ) : itr->second;
}

share_type acc_fees( const database& db, asset_id_type aid )
{
   return aid( db ).dynamic_asset_data_id( db ).accumulated_fees;
}

share_type acc_coll_fees( const database& db, asset_id_type aid )
{
   return aid( db ).dynamic_asset_data_id( db ).accumulated_collateral_fees;
}

/// Production opt-in path: the issuer enables the flag via a signed
/// asset_update_operation (committee-owned assets go through the same op
/// inside a committee proposal). Pre-STEALTH this must refuse (anti-split:
/// pre-fork nodes reject unknown extension fields on unpack).
void opt_in_parity_via_update( database_fixture& fix, const asset_object& a,
                               const fc::ecc::private_key& issuer_key )
{
   asset_update_operation uop;
   uop.issuer = a.issuer;
   uop.asset_to_update = a.get_id();
   uop.new_options = a.options;
   uop.new_options.extensions.value.parity_fee_share_enabled = true;
   fix.trx.operations.push_back( uop );
   fix.db.current_fee_schedule().set_fee( fix.trx.operations.back() );
   set_expiration( fix.db, fix.trx );
   fix.sign( fix.trx, issuer_key );
   PUSH_TX( fix.db, fix.trx );
   fix.trx.clear();
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE( g1_parity_legacy_tests, database_fixture )

/// Step 1 (RED pre-fix): a real limit-order fill on non-opted assets must
/// not divert anything. Maker receives LGB (fee 1000), taker receives LGA
/// (fee 1000); both increments land 100% in accumulated_fees.
BOOST_AUTO_TEST_CASE( legacy_limit_fill_routes_nothing )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000 ) );
   fund( bob, asset( 100000000 ) );

   // bitUSD-style legacy assets: charge market fees, NEVER opted in.
   const asset_object& lga = create_user_issued_asset( "LEGA", alice, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100 );
   const asset_object& lgb = create_user_issued_asset( "LEGB", bob, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100 );
   const asset_id_type lga_id = lga.get_id();
   const asset_id_type lgb_id = lgb.get_id();
   BOOST_REQUIRE( !parity_opted_in( db, lga_id ) );
   BOOST_REQUIRE( !parity_opted_in( db, lgb_id ) );
   issue_uia( alice, lga.amount( 1000000 ) );
   issue_uia( bob, lgb.amount( 1000000 ) );
   generate_block();

   const share_type acc_lga_0 = acc_fees( db, lga_id );
   const share_type acc_lgb_0 = acc_fees( db, lgb_id );

   // Alice rests (maker): sell 100000 LGA for 100000 LGB.
   // (Fresh lookups by id: block production resets the pending undo
   // session, so refs captured before a generate_block may dangle after.)
   create_sell_order( alice_id, lga_id( db ).amount( 100000 ), lgb_id( db ).amount( 100000 ) );
   // Bob crosses (taker): the match fills both orders 1:1 in one push.
   create_sell_order( bob_id, lgb_id( db ).amount( 100000 ), lga_id( db ).amount( 100000 ) );
   generate_block();

   // 1% maker fee on the 100000 LGB alice receives; 1% taker fee (= maker
   // rate, taker unset) on the 100000 LGA bob receives. Exact: no rounding.
   BOOST_CHECK_EQUAL( ( acc_fees( db, lgb_id ) - acc_lgb_0 ).value, 1000 );
   BOOST_CHECK_EQUAL( ( acc_fees( db, lga_id ) - acc_lga_0 ).value, 1000 );
   // Legacy invariant by construction: no pool entry on either leg, and the
   // joint identity holds on one denominator (routed + accumulated == fee).
   BOOST_CHECK( !pool_has( db, lga_id ) );
   BOOST_CHECK( !pool_has( db, lgb_id ) );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

/// Step 1 (RED pre-fix): a real liquidity-pool exchange on non-opted assets
/// must not divert anything on either leg (maker leg on the sells asset,
/// taker leg on the pays asset).
BOOST_AUTO_TEST_CASE( legacy_pool_exchange_routes_nothing )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (sam)(ted) );
   fund( sam, asset( 100000000 ) );
   fund( ted, asset( 100000000 ) );

   additional_asset_options_t sell_opts, pay_opts;
   sell_opts.value.taker_fee_percent = 100; // 1% taker (maker 1%)
   pay_opts.value.taker_fee_percent = 100;
   const asset_object& lpa = create_user_issued_asset( "LEPA", sam, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, sell_opts );
   const asset_object& lpb = create_user_issued_asset( "LEPB", ted, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, pay_opts );
   const asset_object& lps = create_user_issued_asset( "LEPS", sam, charge_market_fee );
   const asset_id_type lpa_id = lpa.get_id();
   const asset_id_type lpb_id = lpb.get_id();
   BOOST_REQUIRE( !parity_opted_in( db, lpa_id ) );
   BOOST_REQUIRE( !parity_opted_in( db, lpb_id ) );
   issue_uia( sam, lpa.amount( 10000000 ) );
   issue_uia( ted, lpa.amount( 10000000 ) );
   issue_uia( sam, lpb.amount( 10000000 ) );
   issue_uia( ted, lpb.amount( 10000000 ) );

   liquidity_pool_id_type lp_id = create_liquidity_pool( sam_id, lpa_id, lpb_id,
         lps.get_id(), 200, 300 ).get_id();
   deposit_to_liquidity_pool( sam_id, lp_id, lpa.amount( 100000 ), lpb.amount( 100000 ) );
   generate_block();
   set_expiration( db, trx );

   const share_type acc_lpa_0 = acc_fees( db, lpa_id );
   const share_type acc_lpb_0 = acc_fees( db, lpb_id );

   // Ted sells LPA into the pool. result.fees = [maker, taker, pool-taker].
   // (Fresh lookups by id — see the pending-session note in the limit test.)
   generic_exchange_operation_result result = exchange_with_liquidity_pool(
         ted_id, lp_id, lpa_id( db ).amount( 20000 ), lpb_id( db ).amount( 1 ) );
   BOOST_REQUIRE_EQUAL( result.fees.size(), 3u );
   BOOST_CHECK( result.fees[0].asset_id == lpa_id ); // maker on sells
   BOOST_CHECK( result.fees[1].asset_id == lpb_id ); // taker on pays
   BOOST_CHECK( result.fees[0].amount.value > 0 );
   BOOST_CHECK( result.fees[1].amount.value > 0 );

   // 100% of each market-fee leg lands in accumulated_fees — nothing routes.
   BOOST_CHECK_EQUAL( ( acc_fees( db, lpa_id ) - acc_lpa_0 ).value,
                      result.fees[0].amount.value );
   BOOST_CHECK_EQUAL( ( acc_fees( db, lpb_id ) - acc_lpb_0 ).value,
                      result.fees[1].amount.value );
   BOOST_CHECK( !pool_has( db, lpa_id ) );
   BOOST_CHECK( !pool_has( db, lpb_id ) );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

/// Positive control on the pool path: with the sold asset opted in, the real
/// pool-exchange maker leg splits 5/95 while the non-opted taker leg stays
/// 100% issuer revenue (denomination-preserving per-asset routing through
/// the same pay_market_fees choke point as limit fills).
BOOST_AUTO_TEST_CASE( opted_in_pool_exchange_routes_five_percent )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (sam)(ted) );
   fund( sam, asset( 100000000 ) );
   fund( ted, asset( 100000000 ) );

   additional_asset_options_t sell_opts, pay_opts;
   sell_opts.value.taker_fee_percent = 100; // 1% taker (maker 1%)
   pay_opts.value.taker_fee_percent = 100;
   const asset_object& lpa = create_user_issued_asset( "OPPA", sam, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, sell_opts );
   const asset_object& lpb = create_user_issued_asset( "OPPB", ted, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, pay_opts );
   const asset_object& lps = create_user_issued_asset( "OPPS", sam, charge_market_fee );
   const asset_id_type lpa_id = lpa.get_id();
   const asset_id_type lpb_id = lpb.get_id();
   issue_uia( sam, lpa.amount( 10000000 ) );
   issue_uia( ted, lpa.amount( 10000000 ) );
   issue_uia( sam, lpb.amount( 10000000 ) );
   issue_uia( ted, lpb.amount( 10000000 ) );

   // Only the sold asset opts in (issuer-signed production path).
   opt_in_parity_via_update( *this, lpa_id( db ), sam_private_key );
   BOOST_REQUIRE( parity_opted_in( db, lpa_id ) );
   BOOST_REQUIRE( !parity_opted_in( db, lpb_id ) );

   liquidity_pool_id_type lp_id = create_liquidity_pool( sam_id, lpa_id, lpb_id,
         lps.get_id(), 200, 300 ).get_id();
   deposit_to_liquidity_pool( sam_id, lp_id, lpa.amount( 100000 ), lpb.amount( 100000 ) );
   generate_block();
   set_expiration( db, trx );

   const share_type acc_lpa_0 = acc_fees( db, lpa_id );
   const share_type acc_lpb_0 = acc_fees( db, lpb_id );

   generic_exchange_operation_result result = exchange_with_liquidity_pool(
         ted_id, lp_id, lpa_id( db ).amount( 20000 ), lpb_id( db ).amount( 1 ) );
   BOOST_REQUIRE_EQUAL( result.fees.size(), 3u );
   BOOST_REQUIRE( result.fees[0].amount.value > 0 );
   BOOST_REQUIRE( result.fees[1].amount.value > 0 );

   // Maker leg (opted-in LPA): 5% pool / 95% issuer, exactly.
   const int64_t maker_fee = result.fees[0].amount.value;
   BOOST_CHECK_EQUAL( pool_balance( db, lpa_id ).value, maker_fee * 500 / 10000 );
   BOOST_CHECK_EQUAL( ( acc_fees( db, lpa_id ) - acc_lpa_0 ).value,
                      maker_fee - maker_fee * 500 / 10000 );
   BOOST_CHECK_EQUAL( pool_balance( db, lpa_id ).value
                      + ( acc_fees( db, lpa_id ) - acc_lpa_0 ).value, maker_fee );
   // Taker leg (non-opted LPB): 100% issuer, no pool.
   BOOST_CHECK_EQUAL( ( acc_fees( db, lpb_id ) - acc_lpb_0 ).value,
                      result.fees[1].amount.value );
   BOOST_CHECK( !pool_has( db, lpb_id ) );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

/// Step 1 (RED pre-fix) + exclusion pin: a real force-settlement on a
/// non-opted bitUSD-style asset. The market-fee leg (collateral UIA, 1%)
/// must not route, and the BSIP-87 force-settle slice must land 100% in
/// accumulated_collateral_fees (documented exclusion: collateral-denominated
/// issuer revenue is never parity-routed — see pay_force_settle_fees).
BOOST_AUTO_TEST_CASE( legacy_force_settle_routes_nothing )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (owner)(feeder)(paul)(rachel) );
   fund( owner, asset( 100000000 ) );
   fund( feeder, asset( 100000000 ) );
   fund( paul, asset( 100000000 ) );
   fund( rachel, asset( 100000000 ) );

   // Collateral UIA (charges 1% market fees) + bitUSD-style MIA on it.
   additional_asset_options_t coll_opts;
   coll_opts.value.taker_fee_percent = 100;
   const asset_object& coll = create_user_issued_asset( "LEGCOLL", owner, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, coll_opts );
   const asset_id_type coll_id = coll.get_id();

   asset_create_operation creator;
   creator.issuer = owner.id;
   creator.fee = asset();
   creator.symbol = "LEGBIT";
   creator.precision = 2;
   creator.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   creator.common_options.market_fee_percent = 100; // 1%
   creator.common_options.issuer_permissions = charge_market_fee;
   creator.common_options.flags = charge_market_fee;
   creator.common_options.core_exchange_rate = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   creator.bitasset_opts = bitasset_options();
   creator.bitasset_opts->force_settlement_offset_percent = 100; // 1%
   creator.bitasset_opts->short_backing_asset = coll_id;
   creator.bitasset_opts->extensions.value.force_settle_fee_percent = 300; // 3% BSIP-87
   trx.operations.push_back( creator );
   db.current_fee_schedule().set_fee( trx.operations.back() );
   set_expiration( db, trx );
   sign( trx, owner_private_key );
   PUSH_TX( db, trx );
   trx.clear();
   const asset_object& bit = get_asset( "LEGBIT" );
   const asset_id_type bit_id = bit.get_id();
   BOOST_REQUIRE( !parity_opted_in( db, coll_id ) );
   BOOST_REQUIRE( !parity_opted_in( db, bit_id ) );
   generate_block();
   set_expiration( db, trx );

   // Feed 1:1 with 175% MCR; paul borrows at 400% CR.
   // (Fresh lookups by id — see the pending-session note in the limit test.)
   update_feed_producers( bit_id( db ), { feeder_id } );
   price_feed feed;
   feed.maintenance_collateral_ratio = 1750;
   feed.maximum_short_squeeze_ratio = 1100;
   feed.settlement_price = bit_id( db ).amount( 1 ) / coll_id( db ).amount( 1 );
   publish_feed( bit_id, feeder_id, feed );

   issue_uia( paul_id, coll_id( db ).amount( 10000000 ) );
   const int64_t debt = 100000; // 1000.00 LEGBIT
   const int64_t backing = 400000; // 4000.00 LEGCOLL
   borrow( paul_id, bit_id( db ).amount( debt ), coll_id( db ).amount( backing ) );
   transfer( paul_id, rachel_id, bit_id( db ).amount( 20000 ) );
   generate_block();
   set_expiration( db, trx );

   const share_type acc_0 = acc_fees( db, coll_id );
   const share_type col_0 = acc_coll_fees( db, bit_id );

   force_settle( rachel_id, bit_id( db ).amount( 20000 ) );

   // Settle after the 24h delay (mirror force_settle_fee_tests timing).
   generate_blocks( db.head_block_time() + fc::hours( 20 ) );
   set_expiration( db, trx );
   publish_feed( bit_id( db ), feeder_id( db ), feed );
   generate_blocks( db.head_block_time() + fc::hours( 6 ) );
   set_expiration( db, trx );

   // The settlement executed: rachel holds collateral proceeds.
   const int64_t gain = db.get_balance( rachel_id, coll_id ).amount.value;
   BOOST_REQUIRE( gain > 0 );

   // Legacy invariant: the parity pool is completely empty — neither the
   // market-fee leg nor the BSIP-87 slice routed anything.
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   BOOST_CHECK( st.parity_pool.empty() );

   // Both legs non-vacuous and exact: solve gross == gain + fees, then pin
   // the 1% market slice and the 3%-of-remainder BSIP-87 slice land 100%.
   const int64_t acc = ( acc_fees( db, coll_id ) - acc_0 ).value;
   const int64_t bsip = ( acc_coll_fees( db, bit_id ) - col_0 ).value;
   BOOST_REQUIRE( acc > 0 ); // market leg ran (COLL charges 1%)
   BOOST_REQUIRE( bsip > 0 ); // BSIP-87 slice ran (3% set)
   const int64_t gross = gain + acc + bsip;
   BOOST_CHECK_EQUAL( acc, gross * 100 / 10000 );
   BOOST_CHECK_EQUAL( bsip, ( gross - acc ) * 300 / 10000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

/// Positive control: an opted-in asset splits 95/5 through a real fill
/// while the non-opted leg of the SAME fill stays 100% issuer revenue.
/// Opt-in travels the production path (signed asset_update, post-fork).
BOOST_AUTO_TEST_CASE( opted_in_limit_fill_splits_five_ninetyfive )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000 ) );
   fund( bob, asset( 100000000 ) );

   const asset_object& opta = create_user_issued_asset( "OPTA", alice, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100 );
   const asset_object& optb = create_user_issued_asset( "OPTB", bob, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100 );
   const asset_id_type opta_id = opta.get_id();
   const asset_id_type optb_id = optb.get_id();
   issue_uia( alice, opta.amount( 1000000 ) );
   issue_uia( bob, optb.amount( 1000000 ) );
   generate_block();
   set_expiration( db, trx );

   // Only OPTB opts in (issuer-signed production path).
   opt_in_parity_via_update( *this, optb_id( db ), bob_private_key );
   BOOST_REQUIRE( !parity_opted_in( db, opta_id ) );
   BOOST_REQUIRE( parity_opted_in( db, optb_id ) );
   generate_block();

   const share_type acc_a_0 = acc_fees( db, opta_id );
   const share_type acc_b_0 = acc_fees( db, optb_id );

   create_sell_order( alice_id, opta_id( db ).amount( 100000 ), optb_id( db ).amount( 100000 ) );
   create_sell_order( bob_id, optb_id( db ).amount( 100000 ), opta_id( db ).amount( 100000 ) );
   generate_block();

   // Maker leg receives 100000 OPTB @1% = 1000 fee: 50 pool + 950 issuer.
   BOOST_CHECK_EQUAL( pool_balance( db, optb_id ).value, 50 );
   BOOST_CHECK_EQUAL( ( acc_fees( db, optb_id ) - acc_b_0 ).value, 950 );
   // Taker leg receives 100000 OPTA @1% = 1000 fee: 100% issuer, no pool.
   BOOST_CHECK( !pool_has( db, opta_id ) );
   BOOST_CHECK_EQUAL( ( acc_fees( db, opta_id ) - acc_a_0 ).value, 1000 );
   // Joint identity on one denominator: routed + accumulated == full fee.
   BOOST_CHECK_EQUAL( pool_balance( db, optb_id ).value
                      + ( acc_fees( db, optb_id ) - acc_b_0 ).value, 1000 );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS, 500u );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

/// Positive control on the MIA path: with the collateral asset opted in,
/// the force-settle market-fee leg routes 5% to the COLLATERAL pool while
/// the BSIP-87 slice still lands 100% in accumulated_collateral_fees
/// (documented exclusion holds even for opted-in assets).
BOOST_AUTO_TEST_CASE( opted_in_force_settle_market_leg_routes_collateral_pool )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (owner)(feeder)(paul)(rachel) );
   fund( owner, asset( 100000000 ) );
   fund( feeder, asset( 100000000 ) );
   fund( paul, asset( 100000000 ) );
   fund( rachel, asset( 100000000 ) );

   additional_asset_options_t coll_opts;
   coll_opts.value.taker_fee_percent = 100;
   const asset_object& coll = create_user_issued_asset( "OPTCOLL", owner, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100, coll_opts );
   const asset_id_type coll_id = coll.get_id();

   asset_create_operation creator;
   creator.issuer = owner.id;
   creator.fee = asset();
   creator.symbol = "OPTBIT";
   creator.precision = 2;
   creator.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   creator.common_options.market_fee_percent = 100;
   creator.common_options.issuer_permissions = charge_market_fee;
   creator.common_options.flags = charge_market_fee;
   creator.common_options.core_exchange_rate = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   creator.bitasset_opts = bitasset_options();
   creator.bitasset_opts->force_settlement_offset_percent = 100;
   creator.bitasset_opts->short_backing_asset = coll_id;
   creator.bitasset_opts->extensions.value.force_settle_fee_percent = 300;
   trx.operations.push_back( creator );
   db.current_fee_schedule().set_fee( trx.operations.back() );
   set_expiration( db, trx );
   sign( trx, owner_private_key );
   PUSH_TX( db, trx );
   trx.clear();
   const asset_object& bit = get_asset( "OPTBIT" );
   const asset_id_type bit_id = bit.get_id();
   generate_block();
   set_expiration( db, trx );

   update_feed_producers( bit_id( db ), { feeder_id } );
   price_feed feed;
   feed.maintenance_collateral_ratio = 1750;
   feed.maximum_short_squeeze_ratio = 1100;
   feed.settlement_price = bit_id( db ).amount( 1 ) / coll_id( db ).amount( 1 );
   publish_feed( bit_id, feeder_id, feed );

   issue_uia( paul_id, coll_id( db ).amount( 10000000 ) );
   borrow( paul_id, bit_id( db ).amount( 100000 ), coll_id( db ).amount( 400000 ) );
   transfer( paul_id, rachel_id, bit_id( db ).amount( 20000 ) );

   // Opt in the COLLATERAL asset only (production path, post-fork).
   opt_in_parity_via_update( *this, coll_id( db ), owner_private_key );
   BOOST_REQUIRE( parity_opted_in( db, coll_id ) );
   BOOST_REQUIRE( !parity_opted_in( db, bit_id ) );
   generate_block();
   set_expiration( db, trx );

   const share_type acc_0 = acc_fees( db, coll_id );
   const share_type col_0 = acc_coll_fees( db, bit_id );

   force_settle( rachel_id, bit_id( db ).amount( 20000 ) );
   generate_blocks( db.head_block_time() + fc::hours( 20 ) );
   set_expiration( db, trx );
   publish_feed( bit_id( db ), feeder_id( db ), feed );
   generate_blocks( db.head_block_time() + fc::hours( 6 ) );
   set_expiration( db, trx );

   const int64_t gain = db.get_balance( rachel_id, coll_id ).amount.value;
   BOOST_REQUIRE( gain > 0 );

   // Market-fee increment I splits 5% pool / 95% issuer on the opted-in
   // collateral asset; the BSIP-87 slice S (3% of I's remainder) is NOT
   // routed — 100% to accumulated_collateral_fees. Solve and pin exactly.
   const int64_t routed = pool_balance( db, coll_id ).value;
   const int64_t acc = ( acc_fees( db, coll_id ) - acc_0 ).value;
   const int64_t bsip = ( acc_coll_fees( db, bit_id ) - col_0 ).value;
   BOOST_REQUIRE( routed > 0 && acc > 0 && bsip > 0 );
   const int64_t incr = routed + acc; // full market-fee increment
   const int64_t gross = gain + incr + bsip; // gross collateral proceeds
   BOOST_CHECK_EQUAL( incr, gross * 100 / 10000 ); // 1% market slice
   BOOST_CHECK_EQUAL( routed, incr * 500 / 10000 ); // 5% of it routes
   BOOST_CHECK_EQUAL( acc, incr - routed ); // 95% accumulates
   // 3% BSIP-87 slice on the remainder, unrouted by rule (exclusion pin).
   BOOST_CHECK_EQUAL( bsip, ( gross - incr ) * 300 / 10000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

/// Anti-split rule + wire stability: the flag cannot be set before STEALTH
/// (pre-fork nodes reject unknown extension fields on unpack, so a pre-fork
/// opt-in would fork the network); post-fork it sets, unsets, round-trips
/// through binary + variant, and defaults to absent (== false) on legacy.
BOOST_AUTO_TEST_CASE( parity_opt_in_settable_only_post_fork_and_wire_stable )
{ try {
   ACTORS( (issuer) );
   fund( issuer, asset( 100000000 ) );
   const asset_object& pre = create_user_issued_asset( "PREOPT", issuer, charge_market_fee,
         price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 100 );
   const asset_id_type pre_id = pre.get_id();

   // Legacy default: absent == false.
   BOOST_CHECK( !pre.options.extensions.value.parity_fee_share_enabled.valid() );
   BOOST_CHECK( !parity_opted_in( db, pre_id ) );

   // Pre-fork: asset_update carrying the flag refuses...
   {
      asset_update_operation uop;
      uop.issuer = issuer.id;
      uop.asset_to_update = pre_id;
      uop.new_options = pre_id( db ).options;
      uop.new_options.extensions.value.parity_fee_share_enabled = true;
      trx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( trx.operations.back() );
      set_expiration( db, trx );
      sign( trx, issuer_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear();
   }
   // ...and so does asset_create carrying the flag.
   {
      asset_create_operation cop;
      cop.issuer = issuer.id;
      cop.fee = asset();
      cop.symbol = "PREOPT2";
      cop.precision = 2;
      cop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
      cop.common_options.core_exchange_rate = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
      cop.common_options.extensions.value.parity_fee_share_enabled = true;
      trx.operations.push_back( cop );
      db.current_fee_schedule().set_fee( trx.operations.back() );
      set_expiration( db, trx );
      sign( trx, issuer_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear();
   }
   BOOST_CHECK( !parity_opted_in( db, pre_id ) );

   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );

   // Post-fork: set works through the production op, readback is exact.
   opt_in_parity_via_update( *this, pre_id( db ), issuer_private_key );
   {
      const auto& e = pre_id( db ).options.extensions.value.parity_fee_share_enabled;
      BOOST_REQUIRE( e.valid() );
      BOOST_CHECK_EQUAL( *e, true );
   }
   // Unset works too (opt-out stops future routing; existing pool drains).
   // (issuer re-fetched by id — see the pending-session note in the limit test.)
   {
      asset_update_operation uop;
      uop.issuer = issuer_id;
      uop.asset_to_update = pre_id;
      uop.new_options = pre_id( db ).options;
      uop.new_options.extensions.value.parity_fee_share_enabled.reset();
      trx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( trx.operations.back() );
      set_expiration( db, trx );
      sign( trx, issuer_private_key );
      PUSH_TX( db, trx );
      trx.clear();
      BOOST_CHECK( !parity_opted_in( db, pre_id ) );
   }

   // Wire stability: set and unset both round-trip through binary pack and
   // through variant (API/JSON), appended-last so legacy bytes still parse.
   {
      asset_options with_flag;
      with_flag.extensions.value.parity_fee_share_enabled = true;
      std::vector<char> packed = fc::raw::pack( with_flag );
      asset_options back = fc::raw::unpack<asset_options>( packed );
      BOOST_REQUIRE( back.extensions.value.parity_fee_share_enabled.valid() );
      BOOST_CHECK_EQUAL( *back.extensions.value.parity_fee_share_enabled, true );

      asset_options no_flag; // legacy shape: field absent
      std::vector<char> packed_legacy = fc::raw::pack( no_flag );
      BOOST_CHECK( packed_legacy.size() < packed.size() ); // flag adds bytes only when set
      asset_options back_legacy = fc::raw::unpack<asset_options>( packed_legacy );
      BOOST_CHECK( !back_legacy.extensions.value.parity_fee_share_enabled.valid() );

       fc::variant v;
       // Production serialization depth (object::to_variant uses
       // MAX_NESTING); the earlier draft's depth-2 bound cannot hold
       // asset_options' extension nesting — that failure was a test bug,
       // not a wire break (binary pack above already pins the bytes).
       fc::to_variant( with_flag, v, MAX_NESTING );
       asset_options via_json;
       fc::from_variant( v, via_json, MAX_NESTING );
      BOOST_REQUIRE( via_json.extensions.value.parity_fee_share_enabled.valid() );
      BOOST_CHECK_EQUAL( *via_json.extensions.value.parity_fee_share_enabled, true );
   }
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
