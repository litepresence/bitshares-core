#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/reference_asset_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/oracle.hpp>

#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {
constexpr int64_t RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t ORACLE_USD_CENTS = 1005000;
const share_type ORACLE_RAW = share_type( int64_t( ORACLE_USD_CENTS ) * RAW_PER_USD_CENT );
}

static reference_asset_id_type make_ref( database_fixture& f, account_id_type creator,
                                        const fc::ecc::private_key& key,
                                        const std::string& sym, uint8_t prec )
{
   if( !creator( f.db ).is_lifetime_member() ) {
      f.upgrade_to_lifetime_member( creator( f.db ) );
      f.create_and_seat_committee_member( creator( f.db ) );
      f.generate_block();
   }
   reference_asset_create_operation op;
   op.creator = creator;
   op.symbol = sym;
   op.precision = prec;
   op.description = sym + " ref";
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return reference_asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

static oracle_id_type make_foreign_oracle( database_fixture& f, account_id_type owner,
                                          const fc::ecc::private_key& key,
                                          account_id_type producer,
                                          reference_asset_id_type base,
                                          reference_asset_id_type quote )
{
   oracle_create_operation op;
   op.owner = owner;
   op.name = "FTX.TEST";
   op.base = base;
   op.quote = quote;
   op.series = { oracle_series( oracle_series_kind::foreign_tx,
                                oracle_series_rounding::unspecified ) };
   op.options.producers[producer] = oracle_producer_entry( 1 );
   op.options.minimum_producers = 1;
   op.options.value_lifetime_sec = 3600;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

static void lock_producer_bond( database_fixture& f, account_id_type producer,
                               const fc::ecc::private_key& key,
                               oracle_id_type oracle )
{
   vesting_balance_create_operation vop;
   vop.creator = producer;
   vop.owner = producer;
   vop.amount = asset( ORACLE_RAW, asset_id_type() );
   vop.policy = cdd_vesting_policy_initializer(
      GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, f.db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction vtx;
   vtx.operations.push_back( vop );
   f.db.current_fee_schedule().set_fee( vtx.operations.back() );
   set_expiration( f.db, vtx );
   vtx.sign( key, f.db.get_chain_id() );
   vesting_balance_id_type vid {
      PUSH_TX( f.db, vtx ).operation_results.front().get<object_id_type>() };

   oracle_bond_lock_operation bop;
   bop.producer = producer;
   bop.oracle = oracle;
   bop.vesting_balance = vid;
   bop.bond_amount = ORACLE_RAW;
   bop.bond_usd_cents = ORACLE_USD_CENTS;
   signed_transaction btx;
   btx.operations.push_back( bop );
   f.db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( f.db, btx );
   btx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, btx );
}

static foreign_tx_value make_ftv( foreign_chain_id chain, uint8_t b0, int64_t amount,
                                 uint64_t height )
{
   foreign_tx_value v;
   v.chain = chain;
   v.tx_id.hash[0] = b0;
   v.kind = foreign_tx_kind::lock;
   v.amount = amount;
   v.foreign_asset_id = 0;
   v.confirmation_height = height;
   return v;
}

static void promote_foreign( database_fixture& f, oracle_id_type oid,
                            const foreign_tx_value& val, time_point_sec t )
{
   // guard shell first
   h2_ensure_oracle_econ( f.db, oid );
   f.db.modify( oid( f.db ), [&]( oracle_object& o ) {
      o.consumed_foreign_value = std::vector<foreign_tx_value>{ val };
      o.consumed_foreign_value_time = t;
      if( !o.options.producers.empty() ) {
         account_id_type p = o.options.producers.begin()->first;
         o.submissions[p] = std::make_pair( t, std::vector<oracle_value>{} );
      }
   } );

   const auto& gidx = f.db.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
   const auto gitr = gidx.find( oid );
   if( gitr == gidx.end() ) return;
   const guard_state_object* g = &*gitr;
   // add promotion record
   uint32_t delay = f.db.get_global_properties().parameters.get_oracle_guard_delay_sec();
   uint32_t anchor = h2_osm_bucket_anchor( uint32_t( t.sec_since_epoch() ), delay );
   f.db.modify( *g, [&]( guard_state_object& gg ) {
      h2_promotion_record rec;
      rec.promote_time = t;
      rec.producer_count = oid( f.db ).options.minimum_producers;
      rec.anchor = anchor;
      rec.delay_sec = delay;
      gg.promotion_log.push_back( rec );
      // The foreign promotion proof reads the FOREIGN log (the price log is
      // the price path's; a foreign publish must never evict it).
      gg.foreign_promotion_log.push_back( rec );
      gg.last_promo_time = t;
   } );
}


BOOST_FIXTURE_TEST_SUITE( h3_foreign_tx_tests, database_fixture )

BOOST_AUTO_TEST_CASE( foreign_tx_value_round_trips )
{
   foreign_tx_value v;
   v.chain = foreign_chain_id::ethereum;
   v.tx_id.hash[0] = 0xAB;
   v.kind = foreign_tx_kind::unlock;
   v.amount = 12345;
   v.foreign_asset_id = 7;
   v.confirmation_height = 999;
   auto back = fc::raw::unpack<foreign_tx_value>( fc::raw::pack( v ) );
   BOOST_CHECK( back.chain == foreign_chain_id::ethereum );
   BOOST_CHECK_EQUAL( back.tx_id.hash[0], 0xAB );
   BOOST_CHECK( back.kind == foreign_tx_kind::unlock );
   BOOST_CHECK_EQUAL( back.amount, 12345 );
   BOOST_CHECK_EQUAL( back.foreign_asset_id, 7 );
   BOOST_CHECK_EQUAL( back.confirmation_height, 999u );
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_publishes_lock_promoted_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, oid );
   foreign_tx_value val = make_ftv( foreign_chain_id::bitcoin, 1, 1000, 10 );
   time_point_sec t = db.head_block_time();
   promote_foreign( *this, oid, val, t );
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::live );
   BOOST_REQUIRE( got.valid() );
   BOOST_CHECK( got->tx_id.hash[0] == 1 );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_stale_live_not_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, oid );
   foreign_tx_value val = make_ftv( foreign_chain_id::bitcoin, 2, 1000, 10 );
   time_point_sec t = db.head_block_time() - 4000;
   promote_foreign( *this, oid, val, t );
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::live );
   BOOST_CHECK( !got.valid() );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_stale_age_exempt_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, oid );
   foreign_tx_value val = make_ftv( foreign_chain_id::bitcoin, 3, 1000, 10 );
   time_point_sec t = db.head_block_time() - 4000;
   promote_foreign( *this, oid, val, t );
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::age_exempt );
   BOOST_CHECK( got.valid() );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_unbonded_not_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   // no bond
   foreign_tx_value val = make_ftv( foreign_chain_id::bitcoin, 4, 1000, 10 );
   promote_foreign( *this, oid, val, db.head_block_time() );
   // need guard shell
   h2_ensure_oracle_econ( db, oid );
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::live );
   BOOST_CHECK( !got.valid() );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_frozen_not_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, oid );
   foreign_tx_value val = make_ftv( foreign_chain_id::bitcoin, 5, 1000, 10 );
   promote_foreign( *this, oid, val, db.head_block_time() );
   // freeze
   db.modify( oid( db ), []( oracle_object& o ){ o.options.frozen = true; } );
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::live );
   BOOST_CHECK( !got.valid() );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_oracle_never_consumed_not_readable )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, oid );
   // no consumed value
   auto got = h2_read_foreign_tx( db, oid, db.head_block_time(), h2_price_liveness::live );
   BOOST_CHECK( !got.valid() );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_CASE( foreign_tx_match_by_tx_id_equality )
{
   try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   const auto bts_ref = make_ref( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = make_ref( *this, alice_id, alice_private_key, "USD", 4 );

   // oracle 1
   const oracle_id_type o1 = make_foreign_oracle( *this, alice_id, alice_private_key, bob_id, bts_ref, usd_ref );
   lock_producer_bond( *this, bob_id, bob_private_key, o1 );

   // oracle 2 (distinct name)
   oracle_create_operation op;
   op.owner = alice_id;
   op.name = "FTX.TEST2";
   op.base = bts_ref;
   op.quote = usd_ref;
   op.series = { oracle_series( oracle_series_kind::foreign_tx, oracle_series_rounding::unspecified ) };
   op.options.producers[bob_id] = oracle_producer_entry( 1 );
   op.options.minimum_producers = 1;
   op.options.value_lifetime_sec = 3600;
   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type o2 { PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };

   generate_block();
   set_expiration( db, trx );
   // bond for o2
   vesting_balance_create_operation vop;
   vop.creator = bob_id; vop.owner = bob_id;
   vop.amount = asset( ORACLE_RAW, asset_id_type() );
   vop.policy = cdd_vesting_policy_initializer( GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction vtx; vtx.operations.push_back( vop );
   db.current_fee_schedule().set_fee( vtx.operations.back() );
   set_expiration( db, vtx ); vtx.sign( bob_private_key, db.get_chain_id() );
   vesting_balance_id_type vid { PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };
   oracle_bond_lock_operation bop;
   bop.producer = bob_id; bop.oracle = o2; bop.vesting_balance = vid;
   bop.bond_amount = ORACLE_RAW; bop.bond_usd_cents = ORACLE_USD_CENTS;
   signed_transaction btx; btx.operations.push_back( bop );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx ); btx.sign( bob_private_key, db.get_chain_id() );
   PUSH_TX( db, btx );

   generate_block();
   set_expiration( db, trx );

   foreign_tx_value v1 = make_ftv( foreign_chain_id::bitcoin, 10, 1000, 10 );
   foreign_tx_value v2 = make_ftv( foreign_chain_id::bitcoin, 20, 2000, 20 );
   promote_foreign( *this, o1, v1, db.head_block_time() );
   promote_foreign( *this, o2, v2, db.head_block_time() );

   auto g1 = h2_read_foreign_tx( db, o1, db.head_block_time(), h2_price_liveness::live );
   auto g2 = h2_read_foreign_tx( db, o2, db.head_block_time(), h2_price_liveness::live );
   BOOST_REQUIRE( g1.valid() && g2.valid() );
   BOOST_CHECK( g1->tx_id != g2->tx_id );
   } FC_LOG_AND_RETHROW()
}

BOOST_AUTO_TEST_SUITE_END()