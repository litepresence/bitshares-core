/*
 * Oracles: named price series independent of any asset.
 *
 * The aggregation tests below are the ones that matter. An oracle's whole purpose is to be the
 * number other things trust, so the interesting cases are not "does a value round-trip" but
 * "what happens when producers disagree, go quiet, or all move at once".
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/market_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/proposal_object.hpp>
#include <graphene/chain/reference_asset_object.hpp>
#include <graphene/chain/witness_object.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/asset_ops.hpp>

#include <fc/io/raw.hpp>

#include <functional>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

// Shared Rev-2 test helpers (file scope: used by the suites below and by oracle_fixture).
namespace {

/// One Rev-2 published value: that many base smallest-units equal that many quote
/// smallest-units.
oracle_value rv( int64_t base_amount, int64_t quote_amount )
{
   return oracle_value( base_amount, quote_amount );
}

oracle_series rseries( oracle_series_kind kind, oracle_series_rounding rounding )
{
   return oracle_series( kind, rounding );
}

/// Makes @p account a committee member (lifetime upgrade first: committee membership
/// requires it). Used to satisfy the reference-asset creation gate in tests.
void rev2_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

/// Creates a reference asset, returning its id. Caller must satisfy the creation gate
/// (committee member while creation is committee-only).
reference_asset_id_type rev2_create_reference(
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

/// Declares (or replaces) the reference mapping of a market-issued asset. Issuer-declared:
/// nobody else may say what the issuer's token tracks.
void rev2_declare_mapping( database_fixture& f, const asset_object& mia,
                           account_id_type issuer, const fc::ecc::private_key& key,
                           const reference_mapping& mapping )
{
   asset_update_bitasset_operation op;
   op.issuer          = issuer;
   op.asset_to_update = mia.get_id();
   op.new_options     = mia.bitasset_data( f.db ).options;
   op.new_options.extensions.value.reference_asset_mapping = mapping;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void rev2_declare_mapping_1to1( database_fixture& f, const asset_object& mia,
                                account_id_type issuer, const fc::ecc::private_key& key,
                                reference_asset_id_type ref )
{
   reference_mapping m;
   m.reference        = ref;
   m.asset_amount     = 1;
   m.reference_amount = 1;
   rev2_declare_mapping( f, mia, issuer, key, m );
}

oracle_id_type rev2_make_oracle( database_fixture& f,
      account_id_type owner, const fc::ecc::private_key& key, const string& name,
      reference_asset_id_type base, reference_asset_id_type quote,
      const vector<oracle_series>& series, const oracle_options& opts )
{
   oracle_create_operation op;
   op.owner  = owner;
   op.name   = name;
   op.base   = base;
   op.quote  = quote;
   op.series = series;
   op.options = opts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type { PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void rev2_publish( database_fixture& f, oracle_id_type oid,
                   account_id_type who, const fc::ecc::private_key& key,
                   const vector<oracle_value>& values )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = values;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// The single mid series every pre-existing (Rev-1-era) test oracle declares. Rev-1
/// oracles carried exactly one price; under Rev-2 that is one mid series with no
/// declared rounding.
inline vector<oracle_series> rev2_single_mid_series()
{
   return { rseries( oracle_series_kind::mid, oracle_series_rounding::unspecified ) };
}

/// H1-03 vacuity pin: pre-fork refusals must reach the hardfork gate, never
/// stop at the fee check (fee set, funded CORE payer; refusal must name it).
inline void rev2_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
{
   try { PUSH_TX( db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( "oracle hardfork" ) != std::string::npos,
            what << " refused off-gate (vacuous, not gate proof): " << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED pre-fork" );
}

} // namespace

BOOST_AUTO_TEST_SUITE( oracle_name_tests )

BOOST_AUTO_TEST_CASE( valid_and_invalid_oracle_names )
{
   BOOST_CHECK( is_valid_oracle_name( "BTC.USD" ) );
   BOOST_CHECK( is_valid_oracle_name( "BTS" ) );
   BOOST_CHECK( is_valid_oracle_name( "EUR-USD" ) );
   BOOST_CHECK( is_valid_oracle_name( "GOLD.XAU.2026" ) );

   BOOST_CHECK( !is_valid_oracle_name( "AB" ) );            // too short
   BOOST_CHECK( !is_valid_oracle_name( std::string( 33, 'A' ) ) ); // too long
   // Lowercase is rejected so that "btc.usd" cannot sit alongside "BTC.USD" as a lookalike.
   BOOST_CHECK( !is_valid_oracle_name( "btc.usd" ) );
   BOOST_CHECK( !is_valid_oracle_name( "BTC USD" ) );       // space
   BOOST_CHECK( !is_valid_oracle_name( "BTC_USD" ) );       // underscore
   BOOST_CHECK( !is_valid_oracle_name( ".BTCUSD" ) );       // leading separator
   BOOST_CHECK( !is_valid_oracle_name( "BTCUSD." ) );       // trailing separator
   BOOST_CHECK( !is_valid_oracle_name( "BTC..USD" ) );      // repeated separator
   BOOST_CHECK( !is_valid_oracle_name( "BTC.-USD" ) );      // mixed repeated separator
}

BOOST_AUTO_TEST_CASE( an_unknown_aggregation_method_is_refused )
{
   oracle_options opts;
   opts.producers[ account_id_type( 1 ) ] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;

   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );
   BOOST_CHECK_NO_THROW( opts.validate() );
   BOOST_CHECK( oracle_aggregation_method::median_of_latest == opts.get_aggregation() );

   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_over_window );
   BOOST_CHECK_NO_THROW( opts.validate() );
   BOOST_CHECK( oracle_aggregation_method::median_over_window == opts.get_aggregation() );

   // The method travels as a plain integer, so deserialisation no longer rejects an unknown
   // one the way it would for a reflected enum -- validate() has to. Without this, nodes
   // would be asked to agree on an aggregation none of them implements.
   opts.aggregation = 2;
   BOOST_CHECK_THROW( opts.validate(), fc::exception );
   opts.aggregation = 255;
   BOOST_CHECK_THROW( opts.validate(), fc::exception );
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE( oracle_tests, database_fixture )


/// Every oracle operation must be refused before the hardfork, or a node running this code
/// could produce a block that a node running the previous release cannot validate.
BOOST_AUTO_TEST_CASE( oracle_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (alice) );
   fund( alice );

   // Rev-2 oracles quote reference assets; pre-fork none can exist, so the op names two
   // ids that resolve to nothing -- the hardfork gate fires before any of that matters.
   // Fee set on the funded payer so the refusal reaches the gate (H1-03).
   oracle_create_operation op;
   op.owner       = alice_id;
   op.name        = "BTC.USD";
   op.base        = reference_asset_id_type( 0 );
   op.quote       = reference_asset_id_type( 1 );
   op.series      = rev2_single_mid_series();
   op.options.producers[alice_id] = oracle_producer_entry( 1 );

   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   rev2_require_gate_refusal( db, tx, "oracle_create pre-fork" );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( create_publish_and_aggregate )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice );
   fund( bob );
   fund( carol );
   fund( dave );
   rev2_make_committee_member( *this, alice );

   // Rev-2: the pair is two reference assets. BTS stands in for the core asset's role in
   // these aggregation tests; what matters is the ratio arithmetic, which is unchanged.
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // three producers, quorum of two
   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "CORE.USD";
   cop.description = "core against a test dollar";
   cop.base        = bts_ref;
   cop.quote       = usd_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id]   = oracle_producer_entry( 1 );
   cop.options.producers[carol_id] = oracle_producer_entry( 1 );
   cop.options.producers[dave_id]  = oracle_producer_entry( 1 );
   cop.options.minimum_producers   = 2;
   cop.options.value_lifetime_sec  = 3600;

   signed_transaction tx;
   tx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   auto ptx = PUSH_TX( db, tx );
   const oracle_id_type oid { ptx.operation_results.front().get<object_id_type>() };

   // a fresh oracle asserts nothing
   BOOST_CHECK( !oid(db).current_value.valid() );

   auto publish = [&]( account_id_type who, const fc::ecc::private_key& key, int64_t quote ) {
      rev2_publish( *this, oid, who, key, { rv( 1, quote ) } );
   };

   // one submission is below quorum, so still no value -- not a value derived from one source
   publish( bob_id, bob_private_key, 100 );
   BOOST_CHECK( !oid(db).current_value.valid() );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 0u );

   // two submissions reach quorum; lower median of {100, 200} is 100
   publish( carol_id, carol_private_key, 200 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 1, 100 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );

   // three submissions: median of {100, 200, 300} is 200
   publish( dave_id, dave_private_key, 300 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 1, 200 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 3u );
} FC_LOG_AND_RETHROW() }

/// A non-producer must not be able to move the number, whatever else it can do on chain.
BOOST_AUTO_TEST_CASE( a_non_producer_cannot_publish )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(mallory) );
   fund( alice );
   fund( bob );
   fund( mallory );
   rev2_make_committee_member( *this, alice );

   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "CORE.USD";
   cop.base        = bts_ref;
   cop.quote       = usd_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;

   signed_transaction tx;
   tx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };

   oracle_publish_operation pop;
   pop.producer  = mallory_id;
   pop.oracle_id = oid;
   pop.values    = { rv( 1, 1 ) };
   signed_transaction bad;
   bad.operations.push_back( pop );
   db.current_fee_schedule().set_fee( bad.operations.back() );
   set_expiration( db, bad );
   bad.sign( mallory_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, bad ), fc::exception );

   // and the owner is not implicitly a producer either
   pop.producer = alice_id;
   signed_transaction owner_tx;
   owner_tx.operations.push_back( pop );
   db.current_fee_schedule().set_fee( owner_tx.operations.back() );
   set_expiration( db, owner_tx );
   owner_tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, owner_tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Rev-2 values carry no asset ids -- a bare (base, quote) amount pair -- so there is
/// nothing to invert: the orientation is fixed by the oracle's own (base, quote). What
/// the submission must still satisfy is positivity: a null or non-positive value would
/// otherwise be carried into the aggregate, where a zero reads as "free" downstream.
BOOST_AUTO_TEST_CASE( a_non_positive_value_is_refused )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );
   rev2_make_committee_member( *this, alice );

   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "CORE.USD";
   cop.base        = bts_ref;
   cop.quote       = usd_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;

   signed_transaction tx;
   tx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };

   auto try_publish = [&]( int64_t base_amount, int64_t quote_amount ) {
      oracle_publish_operation pop;
      pop.producer  = bob_id;
      pop.oracle_id = oid;
      pop.values    = { rv( base_amount, quote_amount ) };
      signed_transaction bad;
      bad.operations.push_back( pop );
      db.current_fee_schedule().set_fee( bad.operations.back() );
      set_expiration( db, bad );
      bad.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, bad );
   };

   GRAPHENE_REQUIRE_THROW( try_publish( 0, 100 ), fc::exception );
   GRAPHENE_REQUIRE_THROW( try_publish( 100, 0 ), fc::exception );
   GRAPHENE_REQUIRE_THROW( try_publish( -100, 100 ), fc::exception );
   BOOST_CHECK( !oid(db).current_value.valid() );

   try_publish( 1, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 1, 100 ) );
} FC_LOG_AND_RETHROW() }

/// Names identify oracles to humans, so a duplicate is how a consumer gets pointed at the
/// wrong series.
BOOST_AUTO_TEST_CASE( oracle_names_are_unique )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );
   rev2_make_committee_member( *this, alice );

   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   auto make = [&]( account_id_type owner, const fc::ecc::private_key& key ) {
      oracle_create_operation cop;
      cop.owner       = owner;
      cop.name        = "CORE.USD";
      cop.base        = bts_ref;
      cop.quote       = usd_ref;
      cop.series      = rev2_single_mid_series();
      cop.options.producers[owner] = oracle_producer_entry( 1 );
      cop.options.minimum_producers = 1;
      signed_transaction tx;
      tx.operations.push_back( cop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( key, db.get_chain_id() );
      return PUSH_TX( db, tx );
   };

   make( alice_id, alice_private_key );
   // a different owner does not get to reuse the name
   GRAPHENE_REQUIRE_THROW( make( bob_id, bob_private_key ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()

/// Builds and pushes an oracle_create, returning the new id. Factored out because most of the
/// interesting tests differ only in the options they set.
///
/// Rev-2: oracles quote reference assets, so the fixture bootstraps a BTS reference (standing
/// in for the core asset's role) and a USD reference. Values are (base, quote) amount pairs;
/// val(n) reads "1 BTS is worth N USD" the way usd_per_core did as a price.
struct oracle_fixture : database_fixture
{
   reference_asset_id_type bts_ref;
   reference_asset_id_type usd_ref;
   bool references_ready = false;

   void setup_references( account_id_type creator, const fc::ecc::private_key& key )
   {
      rev2_make_committee_member( *this, creator(db) );
      bts_ref = rev2_create_reference( *this, creator, key, "BTS", 5 );
      usd_ref = rev2_create_reference( *this, creator, key, "USD", 4 );
      references_ready = true;
   }

   /// value = base/quote, so val(n) reads "1 BTS is worth N USD". Note that a *larger* n
   /// is a numerically *smaller* value in this orientation, since the ratio is 1/n.
   /// Ordering, and therefore the median, is by that ratio.
   oracle_value val( int64_t n ) const
   {
      return rv( 1, n );
   }

   oracle_id_type make_oracle( account_id_type owner, const fc::ecc::private_key& key,
                               const string& name, const oracle_options& opts )
   {
      BOOST_REQUIRE( references_ready );
      return rev2_make_oracle( *this, owner, key, name,
                               bts_ref, usd_ref, rev2_single_mid_series(), opts );
   }

   void publish( oracle_id_type oid, account_id_type who, const fc::ecc::private_key& key,
                 int64_t n )
   {
      rev2_publish( *this, oid, who, key, { val( n ) } );
   }

   void update_options( oracle_id_type oid, account_id_type owner,
                        const fc::ecc::private_key& key, const oracle_options& opts )
   {
      oracle_update_operation op;
      op.owner       = owner;
      op.oracle_id   = oid;
      op.new_options = opts;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
};

BOOST_FIXTURE_TEST_SUITE( oracle_behaviour_tests, oracle_fixture )

/// A submission that has aged past value_lifetime_sec must stop counting. An oracle that kept
/// quoting a price nobody is still asserting is worse than one that reports nothing.
BOOST_AUTO_TEST_CASE( a_stale_submission_stops_counting )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.value_lifetime_sec  = 600;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // let both submissions age out, then have one producer republish
   generate_blocks( db.head_block_time() + 601 );
   set_expiration( db, trx );
   publish( oid, bob_id, bob_private_key, 100 );

   // carol's value is stale, so only one live submission remains -- below quorum
   BOOST_CHECK( !oid(db).current_value.valid() );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 0u );

   // carol republishing restores quorum
   publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );
} FC_LOG_AND_RETHROW() }

/// H1-FINAL-02 (round-16; RED first at the pre-fix tree): a transient quorum
/// gap must not destroy the rate limiter's baseline. Pre-fix the quorum-loss
/// branch reset consumed_value, so the owner could paste an arbitrary-size
/// price step in one promotion: rotate the producers away (baseline wiped),
/// then rotate back with a spiked submission -- the re-entry promotion took
/// the first-promotion branch and skipped the move check entirely.
BOOST_AUTO_TEST_CASE( r32_quorum_gap_keeps_consumed_baseline )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.value_lifetime_sec  = 600;
   opts.guard_rate_limit    = true;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );

   // Outage: rotate the quorum away -- live submissions drop below the minimum.
   oracle_options gap = opts;
   gap.producers.clear();
   gap.producers[dave_id] = oracle_producer_entry( 1 );
   gap.minimum_producers  = 1;
   update_options( oid, alice_id, alice_private_key, gap );
   BOOST_CHECK( !oid(db).current_value.valid() );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 0u );
   // The baseline survives (RED pre-fix: this reset consumed_value).
   BOOST_CHECK( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );

   // Restore: dave joins the set; bob's stored submission is still live.
   oracle_options back = gap;
   back.producers[bob_id] = oracle_producer_entry( 1 );
   update_options( oid, alice_id, alice_private_key, back );
   BOOST_CHECK( oid(db).consumed_value.valid() );

   // dave's spiked paste is move-checked against the surviving baseline and
   // held: the owner cannot ride the outage to an arbitrary price step.
   publish( oid, dave_id, dave_private_key, 250 );
   BOOST_CHECK( oid(db).rate_limited );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );
   // The never-destroyed reference pair is stamped and current.
   BOOST_REQUIRE( oid(db).last_good_value.valid() );
   BOOST_CHECK( oid(db).last_good_value->at( 0 ) == val( 100 ) );
   BOOST_CHECK( oid(db).last_good_time.valid() );
} FC_LOG_AND_RETHROW() }

/// H1-FINAL-01 (round-16; RED first at the pre-fix tree): submissions is
/// pruned to the current producer set. Pre-fix the aggregation only SKIPPED
/// rows for removed producers (it never erased them), so owner rotation left
/// every removed producer's row behind forever and per-publish work grew
/// O(rotations) on every node.
BOOST_AUTO_TEST_CASE( r32_submissions_pruned_to_current_producer_set )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(eve) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave ); fund( eve );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 600;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 100 );
   publish( oid, dave_id,  dave_private_key,  100 );
   BOOST_REQUIRE_EQUAL( oid(db).submissions.size(), 3u );

   // Rotation prunes immediately: rows for producers outside the set are gone.
   oracle_options one_bob = opts;
   one_bob.producers.clear();
   one_bob.producers[bob_id] = oracle_producer_entry( 1 );
   update_options( oid, alice_id, alice_private_key, one_bob );
   BOOST_CHECK_EQUAL( oid(db).submissions.size(), 1u );
   // Flush: the rotation loop's first {bob} update is byte-identical to this one.
   generate_block();

   oracle_options one_eve = one_bob;
   one_eve.producers.clear();
   one_eve.producers[eve_id] = oracle_producer_entry( 1 );
   update_options( oid, alice_id, alice_private_key, one_eve );
   BOOST_CHECK_EQUAL( oid(db).submissions.size(), 0u );
   generate_block();

   // Repeated rotations stay bounded: the map never holds more rows than the
   // set has, whatever the rotation count.
   for( int i = 0; i < 8; ++i )
   {
      for( const auto& who : { bob_id, carol_id } )
      {
         oracle_options one = one_eve;
         one.producers.clear();
         one.producers[who] = oracle_producer_entry( 1 );
         update_options( oid, alice_id, alice_private_key, one );
         publish( oid, who, who == bob_id ? bob_private_key : carol_private_key, 100 );
         BOOST_CHECK_EQUAL( oid(db).submissions.size(), 1u );
         // Flush the pending session: the next iteration's update for the same
         // producer is byte-identical (same ref block, expiration, options,
         // signature) and would be refused as a duplicate transaction.
         generate_block();
      }
   }
} FC_LOG_AND_RETHROW() }

/// Weight is the difference between an oracle and a plain vote count.
BOOST_AUTO_TEST_CASE( weights_shift_the_median )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );
   // bob outweighs the other two combined, so his value is the median whatever they say
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 10 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 300 );
   publish( oid, dave_id,  dave_private_key,  400 );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

   // with equal weights the same three submissions give the middle value instead
   oracle_options equal = opts;
   equal.producers[bob_id] = oracle_producer_entry( 1 );
   update_options( oid, alice_id, alice_private_key, equal );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 300 ) );
} FC_LOG_AND_RETHROW() }

/// A minority disagreeing with the rest is filtered out.
BOOST_AUTO_TEST_CASE( an_outlier_is_excluded_while_quorum_survives )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.max_deviation_ppm   = 100000;   // 10%
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   // establish a baseline of 100
   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

   // dave publishes wildly off; two honest submissions still meet quorum, so he is dropped
   publish( oid, dave_id, dave_private_key, 100000 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );
} FC_LOG_AND_RETHROW() }

/// ...but when everyone moves together, that is a real crash and the oracle must follow it.
/// Freezing here is the failure mode the quorum-aware rule exists to prevent.
BOOST_AUTO_TEST_CASE( when_every_producer_moves_together_the_oracle_moves )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.max_deviation_ppm   = 100000;   // 10%
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // both producers report a 10x move, far outside the deviation bound. Excluding them would
   // leave zero submissions and break quorum, so they are believed.
   publish( oid, bob_id,   bob_private_key,   1000 );
   publish( oid, carol_id, carol_private_key, 1000 );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 1000 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );
} FC_LOG_AND_RETHROW() }

/// Removing a producer is what an owner does when that producer misbehaves, so it has to bite
/// straight away rather than when its last submission happens to expire.
BOOST_AUTO_TEST_CASE( removing_a_producer_takes_effect_immediately )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   publish( oid, bob_id,   bob_private_key,   100 );
   publish( oid, carol_id, carol_private_key, 200 );
   publish( oid, dave_id,  dave_private_key,  300 );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 200 ) );

   // drop dave; his stored submission must stop counting at once
   oracle_options without_dave;
   without_dave.producers[bob_id] = oracle_producer_entry( 1 );
   without_dave.producers[carol_id] = oracle_producer_entry( 1 );
   without_dave.minimum_producers   = 2;
   update_options( oid, alice_id, alice_private_key, without_dave );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );
   // median of {100, 200} with the upper-median convention
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

   // and dave can no longer publish at all
   GRAPHENE_REQUIRE_THROW( publish( oid, dave_id, dave_private_key, 500 ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// A windowed median must not be movable by one block's worth of prices.
BOOST_AUTO_TEST_CASE( a_windowed_median_resists_a_single_spike )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers  = 1;
   opts.value_lifetime_sec = 86400;
   opts.aggregation        = static_cast<uint8_t>( oracle_aggregation_method::median_over_window );
   // A window commensurate with the test's own timescale. History samples at
   // window_sec/MAX_HISTORY, so a day-long window buckets at ~22 minutes and publishes five
   // seconds apart all collapse into one sample -- there would be no history to damp with.
   // That is not the sampler being wrong, it is a day-long window genuinely having seen only
   // seconds of data; the old ring hid it by keeping every publish regardless of spacing.
   opts.window_sec         = 300;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   // a settled history at 100
   for( int i = 0; i < 5; ++i )
   {
      publish( oid, bob_id, bob_private_key, 100 );
      generate_block();
      set_expiration( db, trx );
   }
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

   // one spike does not move the windowed median, even though it is the latest value
   publish( oid, bob_id, bob_private_key, 100000 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );
   // the spike is recorded though: the window holds it, it is simply outvoted
   BOOST_CHECK( oid(db).history.back().second.at( 0 ) == val( 100000 ) );
} FC_LOG_AND_RETHROW() }

/// Policy is the owner's alone. A producer that could edit the producer set could appoint
/// itself a majority.
BOOST_AUTO_TEST_CASE( only_the_owner_may_update_or_delete )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = make_oracle( alice_id, alice_private_key, "CORE.USD", opts );

   oracle_options grab = opts;
   grab.producers[bob_id] = oracle_producer_entry( 1000 );
   GRAPHENE_REQUIRE_THROW( update_options( oid, bob_id, bob_private_key, grab ), fc::exception );

   oracle_delete_operation dop;
   dop.owner     = bob_id;
   dop.oracle_id = oid;
   signed_transaction tx;
   tx.operations.push_back( dop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( bob_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );

   // the owner can
   dop.owner = alice_id;
   signed_transaction ok;
   ok.operations.push_back( dop );
   db.current_fee_schedule().set_fee( ok.operations.back() );
   set_expiration( db, ok );
   ok.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, ok );
   BOOST_CHECK( nullptr == db.find( oid ) );
} FC_LOG_AND_RETHROW() }

/**
 * REGRESSION: the deviation filter must not let a minority capture the price.
 *
 * The filter drops submissions far from a reference and keeps the survivors. It used to
 * reference the LAST PUBLISHED VALUE, which inverted the security model: on a genuine price
 * move it is the HONEST producers who deviate -- they are reporting the new price -- while a
 * producer repeating the old number sits inside the band and survives. The survivors became
 * the entire live set, so one stale producer outvoted an honest majority; and because
 * current_value never moved, neither did the band, so the capture held indefinitely.
 *
 * The reference is now the round's own weighted median, which is the majority's number by
 * construction, so the outlier is what gets trimmed. Four of five producers report a move
 * from 100 to 200 and win immediately; mallory, still saying 100, is the one dropped.
 */
BOOST_AUTO_TEST_CASE( the_deviation_filter_cannot_let_a_minority_capture_the_price )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (owner)(p1)(p2)(p3)(p4)(mallory) );

   setup_references( owner_id, owner_private_key );
   oracle_options opts;
   opts.producers[ p1_id ] = oracle_producer_entry( 1 );
   opts.producers[ p2_id ] = oracle_producer_entry( 1 );
   opts.producers[ p3_id ] = oracle_producer_entry( 1 );
   opts.producers[ p4_id ] = oracle_producer_entry( 1 );
   opts.producers[ mallory_id ] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;      // the shipped default
   opts.max_deviation_ppm = 100000; // 10% band -- a plausible "manipulation resistance" setting
   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );

   const auto oid = make_oracle( owner_id, owner_private_key, "CORE.USD", opts );

   // Everyone agrees the price is 100. (val is 1/n, so a bigger n is a lower price.)
   publish( oid, p1_id, p1_private_key, 100 );
   publish( oid, p2_id, p2_private_key, 100 );
   publish( oid, p3_id, p3_private_key, 100 );
   publish( oid, p4_id, p4_private_key, 100 );
   publish( oid, mallory_id, mallory_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

   // The market moves hard. The four honest producers report it; mallory does not.
   // A block between rounds keeps mallory's repeated submission from being a byte-identical
   // transaction, which the chain would reject as a duplicate.
   generate_block();
   set_expiration( db, trx );
   publish( oid, p1_id, p1_private_key, 200 );
   publish( oid, p2_id, p2_private_key, 200 );
   publish( oid, p3_id, p3_private_key, 200 );
   publish( oid, p4_id, p4_private_key, 200 );
   publish( oid, mallory_id, mallory_private_key, 100 );

   // The band is anchored on this round's median, so mallory is the outlier and is trimmed.
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK_MESSAGE( oid(db).current_value->at( 0 ) == val( 200 ),
                        "the honest majority must win" );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 4 );

   // And it is not a one-round lag: the band is anchored to a value mallory controls, so
   // republishing the same number holds the oracle there indefinitely.
   for( int round = 0; round < 5; ++round )
   {
      generate_block();
      set_expiration( db, trx );
      publish( oid, p1_id, p1_private_key, 200 );
      publish( oid, p2_id, p2_private_key, 200 );
      publish( oid, p3_id, p3_private_key, 200 );
      publish( oid, p4_id, p4_private_key, 200 );
      publish( oid, mallory_id, mallory_private_key, 100 );
   }
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 200 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 4 );

} FC_LOG_AND_RETHROW() }

/**
 * The same oracle without the filter behaves as a median should: the honest majority wins
 * immediately. The filter is the whole difference.
 */
BOOST_AUTO_TEST_CASE( without_the_deviation_filter_the_majority_wins )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (owner)(p1)(p2)(p3)(p4)(mallory) );

   setup_references( owner_id, owner_private_key );
   oracle_options opts;
   opts.producers[ p1_id ] = oracle_producer_entry( 1 );
   opts.producers[ p2_id ] = oracle_producer_entry( 1 );
   opts.producers[ p3_id ] = oracle_producer_entry( 1 );
   opts.producers[ p4_id ] = oracle_producer_entry( 1 );
   opts.producers[ mallory_id ] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   opts.max_deviation_ppm = 0;      // off
   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );

   const auto oid = make_oracle( owner_id, owner_private_key, "CORE.USD", opts );

   publish( oid, p1_id, p1_private_key, 100 );
   publish( oid, p2_id, p2_private_key, 100 );
   publish( oid, p3_id, p3_private_key, 100 );
   publish( oid, p4_id, p4_private_key, 100 );
   publish( oid, mallory_id, mallory_private_key, 100 );

   generate_block();
   set_expiration( db, trx );
   publish( oid, p1_id, p1_private_key, 200 );
   publish( oid, p2_id, p2_private_key, 200 );
   publish( oid, p3_id, p3_private_key, 200 );
   publish( oid, p4_id, p4_private_key, 200 );
   publish( oid, mallory_id, mallory_private_key, 100 );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 200 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 5 );
} FC_LOG_AND_RETHROW() }


/**
 * GOVERNANCE: der Eigentümer kann den gemeldeten Wert allein durch Umgewichten drehen.
 *
 * oracle_update prüft nur, dass der Aufrufer der Eigentümer ist. Keine Verzögerung, keine
 * Sperrfrist, keine Obergrenze auf die Änderung. Der Test zeigt die Folge: ohne dass ein
 * einziger Produzent seine Meldung ändert, springt der Wert -- weil der gewichtete Median
 * auf eine andere Meldung fällt.
 *
 * Das ist kein Fehler im Median, sondern eine Eigenschaft des Vertrauensmodells: wer das
 * Oracle besitzt, bestimmt, wessen Stimme zählt. Der Test hält es fest, damit niemand
 * das Oracle für vertrauensminimiert hält, was es nicht ist.
 */
BOOST_AUTO_TEST_CASE( the_owner_can_flip_the_value_by_reweighting_alone )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (owner)(p1)(p2)(p3) );

   setup_references( owner_id, owner_private_key );
   oracle_options opts;
   opts.producers[ p1_id ] = oracle_producer_entry( 1 );
   opts.producers[ p2_id ] = oracle_producer_entry( 1 );
   opts.producers[ p3_id ] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );
   const auto oid = make_oracle( owner_id, owner_private_key, "GOV.TEST", opts );

   publish( oid, p1_id, p1_private_key, 100 );
   publish( oid, p2_id, p2_private_key, 200 );
   publish( oid, p3_id, p3_private_key, 300 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_TEST_MESSAGE( "  drei Produzenten melden 100 / 200 / 300, gleiches Gewicht" );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 200 ) );
   BOOST_TEST_MESSAGE( "  Median: 200" );

   // Nur die Gewichte ändern. Keine neue Meldung.
   generate_block();
   set_expiration( db, trx );
   oracle_options heavy = opts;
   heavy.producers[ p1_id ] = oracle_producer_entry( 10 );   // p1 überstimmt die anderen beiden zusammen
   update_options( oid, owner_id, owner_private_key, heavy );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_TEST_MESSAGE( "  Eigentümer setzt p1 auf Gewicht 10, ohne neue Meldung" );
   BOOST_TEST_MESSAGE( "  neuer Wert entspricht jetzt p1s Meldung" );
   BOOST_CHECK_MESSAGE( oid(db).current_value->at( 0 ) == val( 100 ),
                        "Umgewichten allein hat den Wert nicht gedreht" );

   // Und wieder zurück, ebenso sofort.
   generate_block();
   set_expiration( db, trx );
   oracle_options heavy3 = opts;
   heavy3.producers[ p3_id ] = oracle_producer_entry( 10 );
   update_options( oid, owner_id, owner_private_key, heavy3 );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 300 ) );
   BOOST_TEST_MESSAGE( "  ==> der Eigentümer kann den Wert jederzeit auf jede vorliegende" );
   BOOST_TEST_MESSAGE( "      Meldung setzen, sofort und ohne Ankündigung" );
} FC_LOG_AND_RETHROW() }

/**
 * KOLLUSION: wie viele Produzenten müssen zusammenarbeiten, um den Wert zu bestimmen?
 *
 * Bei gleichen Gewichten ist die Antwort die halbe Menge, aufgerundet -- das ist die
 * Definition des Medians. Der Test misst es für fünf und für sieben Produzenten, damit die
 * Zahl belegt statt behauptet ist, und prüft zugleich, dass einer weniger NICHT reicht.
 */
BOOST_AUTO_TEST_CASE( measure_the_collusion_threshold_of_the_median )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (owner)(a1)(a2)(a3)(a4)(a5)(a6)(a7) );
   setup_references( owner_id, owner_private_key );
   const std::vector<account_id_type> ids {
      a1_id, a2_id, a3_id, a4_id, a5_id, a6_id, a7_id };
   const std::vector<fc::ecc::private_key> keys {
      a1_private_key, a2_private_key, a3_private_key, a4_private_key,
      a5_private_key, a6_private_key, a7_private_key };

   for( size_t n : { size_t(5), size_t(7) } )
   {
      generate_block();
      set_expiration( db, trx );
      oracle_options opts;
      for( size_t i = 0; i < n; ++i ) opts.producers[ ids[i] ] = oracle_producer_entry( 1 );
      opts.minimum_producers = 1;
      opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );
      const auto oid = make_oracle( owner_id, owner_private_key,
                                    "COL" + std::to_string( n ), opts );

      // Ehrlich: alle melden 100.
      for( size_t i = 0; i < n; ++i ) publish( oid, ids[i], keys[i], 100 );
      BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );

      size_t needed = 0;
      for( size_t k = 1; k <= n && 0 == needed; ++k )
      {
         generate_block();
         set_expiration( db, trx );
         // k Kolludierende melden 999, der Rest bleibt bei 100.
         for( size_t i = 0; i < k; ++i ) publish( oid, ids[i], keys[i], 999 );
         for( size_t i = k; i < n; ++i ) publish( oid, ids[i], keys[i], 100 );
         if( oid(db).current_value->at( 0 ) == val( 999 ) ) needed = k;
      }
      const size_t expected = n / 2 + 1;
      BOOST_TEST_MESSAGE( "  " << n << " Produzenten: " << needed
                          << " müssen kolludieren (erwartet " << expected << ")" );
      BOOST_CHECK_EQUAL( needed, expected );
   }
   BOOST_TEST_MESSAGE( "  ==> die Schwelle ist die einfache Mehrheit der Gewichte," );
   BOOST_TEST_MESSAGE( "      nicht mehr und nicht weniger" );
} FC_LOG_AND_RETHROW() }

/**
 * ÖKONOMIE: was kostet es, ein Oracle zu manipulieren?
 *
 * Die ehrliche Antwort ist unbequem: on-chain fast nichts. Eine Veröffentlichung kostet die
 * Netzwerkgebühr und sonst gar nichts -- es gibt keinen Einsatz, keine Kaution, nichts, das
 * bei einer Falschmeldung verloren ginge. Der Test hält das fest, indem er misst, was ein
 * Produzent für beliebig viele Falschmeldungen bezahlt.
 *
 * Die Sicherheit des Oracles ruht damit vollständig auf der Auswahl der Produzenten durch
 * den Eigentümer, nicht auf irgendeinem ökonomischen Anreiz. Das ist eine Entwurfsentschei-
 * dung, keine Lücke -- aber sie muss ausgesprochen sein, damit niemand einen Einsatz
 * vermutet, den es nicht gibt.
 */
BOOST_AUTO_TEST_CASE( measure_the_on_chain_cost_of_publishing_a_false_value )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (owner)(liar) );
   fund( liar, asset(10000000) );

   setup_references( owner_id, owner_private_key );
   oracle_options opts;
   opts.producers[ liar_id ] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   opts.aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );
   const auto oid = make_oracle( owner_id, owner_private_key, "COST.TEST", opts );

   const int64_t before = get_balance( liar_id, asset_id_type() );
   for( int i = 0; i < 10; ++i )
   {
      generate_block();
      set_expiration( db, trx );
      publish( oid, liar_id, liar_private_key, 100 + i );   // jedes Mal ein anderer Unsinn
   }
   const int64_t after = get_balance( liar_id, asset_id_type() );

   BOOST_TEST_MESSAGE( "  10 Falschmeldungen kosteten in der Testfixture "
                       << ( before - after ) << " (dort sind alle Gebuehren 0)" );
   BOOST_TEST_MESSAGE( "  Protokoll-Standardgebuehr je Veroeffentlichung: "
                       << ( GRAPHENE_BLOCKCHAIN_PRECISION / 10 ) << " = 0,1 BTS" );
   BOOST_TEST_MESSAGE( "  hinterlegter Einsatz, der bei einer Falschmeldung verfaellt: 0" );
   BOOST_TEST_MESSAGE( "  ==> die Kosten einer Luege sind durch die Gebuehr gedeckelt und" );
   BOOST_TEST_MESSAGE( "      voellig unabhaengig vom angerichteten Schaden. Die Sicherheit" );
   BOOST_TEST_MESSAGE( "      des Oracles ruht allein auf der Auswahl der Produzenten." );

   // Die eigentliche Zusicherung ist nicht die Gebuehrenhoehe -- die haengt an der
   // Gebuehrentabelle -- sondern dass eine Falschmeldung NICHTS ausser der Gebuehr kostet:
   // sie wird angenommen, sie bleibt stehen, und nichts wird eingezogen.
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK_MESSAGE( oid(db).current_value->at( 0 ) == val( 109 ),
                        "die letzte Falschmeldung wurde nicht uebernommen" );
   BOOST_CHECK_MESSAGE( get_balance( liar_id, asset_id_type() ) >= after,
                        "nach der Veroeffentlichung wurde nachtraeglich etwas eingezogen" );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()


BOOST_FIXTURE_TEST_SUITE( oracle_binding_tests, oracle_fixture )

namespace {

/// Binds (or, with an empty optional, unbinds) an oracle as a smartcoin's price source.
void set_price_oracle( database_fixture& f, const asset_object& mia,
                       account_id_type issuer, const fc::ecc::private_key& key,
                       const optional<oracle_id_type>& oid )
{
   asset_update_bitasset_operation op;
   op.issuer          = issuer;
   op.asset_to_update = mia.get_id();
   op.new_options     = mia.bitasset_data( f.db ).options;
   op.new_options.extensions.value.price_oracle_id = oid;

   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

} // namespace

/// The whole point of the feature: a smartcoin's settlement price coming from an oracle
/// rather than from per-asset feeds.
BOOST_AUTO_TEST_CASE( a_smartcoin_takes_its_settlement_price_from_a_bound_oracle )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   // a smartcoin backed by CORE, issued by alice, mapped 1:1 to its own reference.
   // (The core side needs no declaration: it maps 1:1 to "BTS" by protocol rule.)
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   // an oracle quoting MIA-ref/BTS-ref, which is the orientation a settlement price uses
   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "MIA.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.producers[carol_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers   = 2;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   auto pub = [&]( account_id_type who, const fc::ecc::private_key& key, int64_t core_amount ) {
      rev2_publish( *this, oid, who, key, { rv( 1, core_amount ) } );
   };

   pub( bob_id,   bob_private_key,   10 );
   pub( carol_id, carol_private_key, 10 );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // before binding, the smartcoin has no feed at all
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, oid );

   // binding alone must publish the price through, without waiting for the next publish
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 10, asset_id_type() ) ) );
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );

   // a new value reaches the smartcoin in the same block it is published
   pub( bob_id,   bob_private_key,   20 );
   pub( carol_id, carol_private_key, 20 );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 20, asset_id_type() ) ) );

   // unbinding returns the asset to the legacy feed path, which has no feeds here.
   // (A block first: with no other option changed, the unbind would otherwise be a
   // byte-identical repeat of the mapping-declare transaction above, which the chain
   // rejects as a duplicate.)
   generate_block();
   set_expiration( db, trx );
   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, {} );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( oid(db).subscribers.empty() );
} FC_LOG_AND_RETHROW() }

/// A mismatched oracle would margin-call every position on the asset, so the binding is
/// checked once at bind time rather than trusted on every read.
BOOST_AUTO_TEST_CASE( an_oracle_quoting_the_wrong_pair_cannot_be_bound )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );
   // a reference no mapping points at, for the wrong-quote case
   const auto other_ref = rev2_create_reference( *this, alice_id, alice_private_key, "XAU", 4 );

   // quoted the wrong way round: BTS-ref/MIA-ref instead of MIA-ref/BTS-ref
   oracle_create_operation inverted;
   inverted.owner       = alice_id;
   inverted.name        = "CORE.MIA";
   inverted.base        = bts_ref;
   inverted.quote       = mia_ref;
   inverted.series      = rev2_single_mid_series();
   inverted.options.producers[bob_id] = oracle_producer_entry( 1 );
   inverted.options.minimum_producers = 1;
   signed_transaction t1;
   t1.operations.push_back( inverted );
   db.current_fee_schedule().set_fee( t1.operations.back() );
   set_expiration( db, t1 );
   t1.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type bad_id { PUSH_TX( db, t1 ).operation_results.front().get<object_id_type>() };

   GRAPHENE_REQUIRE_THROW(
      set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, bad_id ), fc::exception );

   // right base, wrong quote: MIA-ref/XAU-ref when the asset is backed by CORE (BTS-ref)
   oracle_create_operation wrong_quote;
   wrong_quote.owner       = alice_id;
   wrong_quote.name        = "MIA.OTHER";
   wrong_quote.base        = mia_ref;
   wrong_quote.quote       = other_ref;
   wrong_quote.series      = rev2_single_mid_series();
   wrong_quote.options.producers[bob_id] = oracle_producer_entry( 1 );
   wrong_quote.options.minimum_producers = 1;
   signed_transaction t2;
   t2.operations.push_back( wrong_quote );
   db.current_fee_schedule().set_fee( t2.operations.back() );
   set_expiration( db, t2 );
   t2.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type wq_id { PUSH_TX( db, t2 ).operation_results.front().get<object_id_type>() };

   GRAPHENE_REQUIRE_THROW(
      set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, wq_id ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Deleting the price source out from under a smartcoin would leave it unable to margin call.
BOOST_AUTO_TEST_CASE( a_bound_oracle_cannot_be_deleted )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "MIA.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, oid );

   auto del = [&]() {
      oracle_delete_operation dop;
      dop.owner     = alice_id;
      dop.oracle_id = oid;
      signed_transaction tx;
      tx.operations.push_back( dop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   };

   GRAPHENE_REQUIRE_THROW( del(), fc::exception );

   // once the asset lets go, the oracle can be removed. (A block first, as above: the
   // unbind would otherwise repeat the mapping-declare transaction byte for byte.)
   generate_block();
   set_expiration( db, trx );
   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, {} );
   del();
   BOOST_CHECK( nullptr == db.find( oid ) );
} FC_LOG_AND_RETHROW() }

/// Losing quorum must remove the smartcoin's price rather than freeze it at the last value.
BOOST_AUTO_TEST_CASE( losing_quorum_clears_the_bound_assets_feed )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "MIA.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.producers[carol_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers   = 2;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   auto pub = [&]( account_id_type who, const fc::ecc::private_key& key, int64_t n ) {
      rev2_publish( *this, oid, who, key, { rv( 1, n ) } );
   };

   pub( bob_id,   bob_private_key,   10 );
   pub( carol_id, carol_private_key, 10 );
   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, oid );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Let the submissions age. Without this they carry the current head block time, so the
   // shortened lifetime below would still count them as live and the test would prove nothing.
   generate_block();
   set_expiration( db, trx );

   // shorten the lifetime so nothing published so far still counts
   oracle_options tighter;
   tighter.producers[bob_id] = oracle_producer_entry( 1 );
   tighter.producers[carol_id] = oracle_producer_entry( 1 );
   tighter.minimum_producers   = 2;
   tighter.value_lifetime_sec  = 1;    // everything published so far is now stale
   {
      oracle_update_operation uop;
      uop.owner       = alice_id;
      uop.oracle_id   = oid;
      uop.new_options = tighter;
      signed_transaction tx;
      tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   BOOST_CHECK( !oid(db).current_value.valid() );
   // and the smartcoin must see that immediately, not keep quoting a dead price
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
} FC_LOG_AND_RETHROW() }

/// Binding is not allowed at creation: the oracle's base reference has to be the smartcoin's
/// mapping, which cannot be checked before the smartcoin exists. Bind with
/// asset_update_bitasset once the asset has an id.
BOOST_AUTO_TEST_CASE( a_price_oracle_cannot_be_set_when_creating_an_asset )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "MIA.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   asset_create_operation acop;
   acop.issuer = alice_id;
   acop.symbol = "MIATWO";
   acop.precision = 2;
   acop.common_options.core_exchange_rate = price( asset(1,asset_id_type(1)), asset(1) );
   acop.bitasset_opts = bitasset_options();
   acop.bitasset_opts->extensions.value.price_oracle_id = oid;

   signed_transaction tx;
   tx.operations.push_back( acop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }


/**
 * Regression: a bound smartcoin must not go on quoting an oracle whose producers have stopped.
 *
 * This is not the "quorum was lost" case already covered above, which is noticed because an
 * oracle_update forces a recompute. Here NOTHING happens: no publish, no update, just time
 * passing. current_value is only recomputed when a producer publishes, so the oracle keeps its
 * last aggregate for ever, and a consumer that asks only current_value.valid() never learns
 * that value_lifetime_sec elapsed.
 *
 * What made it self-perpetuating rather than merely stale is update_expired_feeds(), which runs
 * EVERY BLOCK over exactly those assets whose feed has expired. It called
 * update_bitasset_current_feed() on each, which re-stamped current_feed_publication_time to the
 * current head time while carrying the dead oracle price. The feed expired for one block and was
 * resurrected the next, indefinitely -- by the very routine whose job is to retire expired feeds.
 *
 * The fixed end state is a CURRENT feed carrying a NULL settlement price, which is exactly what
 * the legacy path produces when fewer than minimum_feeds are live -- so nothing downstream needs
 * a new case, and margin calls simply do not run. The guarantee under test is that the price is
 * gone and stays gone, not that the feed object is flagged expired.
 */
BOOST_AUTO_TEST_CASE( a_smartcoin_stops_quoting_an_oracle_whose_producers_went_silent )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIASILENT", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAS", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   const uint32_t lifetime = 60;   // short, so the test does not need hours of blocks

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "SILENT.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers  = 1;
   cop.options.value_lifetime_sec = lifetime;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   // One publish, then silence.
   rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 1, 10 ) } );

   // Bind, and shorten the asset's own feed lifetime so the expiry path is reachable in a
   // handful of blocks rather than a day.
   {
      asset_update_bitasset_operation op;
      op.issuer          = alice_id;
      op.asset_to_update = mia_id;
      op.new_options     = mia_id(db).bitasset_data(db).options;
      op.new_options.feed_lifetime_sec = lifetime;
      op.new_options.extensions.value.price_oracle_id = oid;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Let the value age past its lifetime. No publishes, no updates -- only blocks.
   generate_blocks( db.head_block_time() + fc::seconds( lifetime * 3 ) );
   set_expiration( db, trx );

   const auto now = db.head_block_time();

   // The stored aggregate is untouched, because nothing recomputed it. That is precisely why
   // asking current_value.valid() is not a freshness test.
   BOOST_CHECK( oid(db).current_value.valid() );
   BOOST_CHECK( !oid(db).is_value_live( now ) );

   // The consumer must not be quoting it any more.
   const auto& bad = mia_id(db).bitasset_data(db);
   BOOST_CHECK_MESSAGE( bad.current_feed.settlement_price.is_null(),
                        "the smartcoin is still quoting a price from an oracle that stopped "
                        "publishing " << ( now - oid(db).current_value_time ).to_seconds()
                        << "s ago, against a lifetime of " << lifetime << "s" );

   // And it must STAY gone. This is the part the bug got wrong: update_expired_feeds() runs
   // every block over expired feeds, so a resurrection would happen within one block of the
   // check above and be invisible to a single assertion.
   generate_blocks( db.head_block_time() + fc::seconds( lifetime * 2 ) );
   set_expiration( db, trx );
   BOOST_CHECK_MESSAGE(
      mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null(),
      "the dead oracle's price came back after further blocks" );
} FC_LOG_AND_RETHROW() }

/**
 * The stamp itself: a bound feed carries the time the ORACLE VALUE was formed, not the time the
 * feed happened to be refreshed. Getting this wrong is what let an expired feed be revived.
 */
BOOST_AUTO_TEST_CASE( a_bound_feed_is_stamped_with_the_oracle_value_time )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIASTAMP", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAF", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "STAMP.CORE";
   cop.base        = mia_ref;
   cop.quote       = bts_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 1, 10 ) } );
   set_price_oracle( *this, mia_id(db), alice_id, alice_private_key, oid );

   const auto value_time = oid(db).current_value_time;
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed_publication_time == value_time );

   // Move the head on WITHOUT publishing, then force a refresh. The stamp must still be the
   // value's own time -- if it tracked head time, the feed's expiry would keep sliding.
   generate_blocks( db.head_block_time() + fc::seconds( 30 ) );
   set_expiration( db, trx );
   BOOST_CHECK( db.head_block_time() > value_time );
   BOOST_CHECK_EQUAL( mia_id(db).bitasset_data(db).current_feed_publication_time.sec_since_epoch(),
                      value_time.sec_since_epoch() );
} FC_LOG_AND_RETHROW() }


/**
 * Regression: the window a windowed median covers must follow window_sec, not the publish rate.
 *
 * History is a fixed ring of GRAPHENE_ORACLE_MAX_HISTORY entries. Appending one per publish
 * made the span it covers a function of how often producers publish: at one publish per block
 * the ring holds about five minutes, so an oracle configured for an hour -- or a day -- was
 * really taking its median over five minutes, and nothing reported the discrepancy.
 *
 * The perverse part is that it is not an attack. It is what happens when the oracle works well:
 * the more diligently the producers publish, the weaker the damping they were configured to get.
 */
BOOST_AUTO_TEST_CASE( a_windowed_median_covers_its_configured_window_however_often_producers_publish )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIAWINDOW", alice_id );
   const auto mia_id = mia.get_id();
   (void)mia_id;

   const uint32_t window = 3600;

   oracle_create_operation cop;
   cop.owner       = alice_id;
   cop.name        = "WINDOW.CORE";
   cop.base        = bts_ref;
   cop.quote       = usd_ref;
   cop.series      = rev2_single_mid_series();
   cop.options.producers[bob_id] = oracle_producer_entry( 1 );
   cop.options.minimum_producers = 1;
   cop.options.aggregation       = static_cast<uint8_t>( oracle_aggregation_method::median_over_window );
   cop.options.window_sec        = window;
   signed_transaction ctx;
   ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( alice_private_key, db.get_chain_id() );
   const oracle_id_type oid { PUSH_TX( db, ctx ).operation_results.front().get<object_id_type>() };

   auto pub = [&]( int64_t n ) {
      rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 1, n ) } );
   };

   // Publish every block for comfortably more blocks than the ring can hold.
   const int publishes = GRAPHENE_ORACLE_MAX_HISTORY * 2;
   for( int i = 0; i < publishes; ++i )
   {
      pub( 100 );
      generate_block();
      set_expiration( db, trx );
   }

   const auto& hist = oid(db).history;
   BOOST_REQUIRE( !hist.empty() );
   BOOST_CHECK_LE( hist.size(), size_t( GRAPHENE_ORACLE_MAX_HISTORY ) );

   // Entries must be spaced by at least the bucket, so a full ring spans the whole window.
   const int64_t bucket = std::max<int64_t>(
      1, int64_t( window ) / int64_t( GRAPHENE_ORACLE_MAX_HISTORY ) );
   for( size_t i = 1; i < hist.size(); ++i )
   {
      const int64_t gap = ( hist[i].first - hist[i-1].first ).to_seconds();
      BOOST_CHECK_MESSAGE( gap >= bucket,
                           "history entries " << (i-1) << " and " << i << " are only "
                           << gap << "s apart, below the " << bucket << "s bucket" );
   }

   // With one publish per block the ring used to saturate and cover only
   // MAX_HISTORY * block_interval seconds. It must now still reach back over everything
   // published, because far fewer slots were consumed.
   const int64_t covered = ( db.head_block_time() - hist.front().first ).to_seconds();
   const int64_t naive_span = int64_t( GRAPHENE_ORACLE_MAX_HISTORY )
                            * int64_t( db.get_global_properties().parameters.block_interval );
   BOOST_CHECK_MESSAGE( covered > naive_span,
                        "history reaches back only " << covered << "s; appending per publish "
                        "would have given " << naive_span << "s, so nothing improved" );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE( oracle_wire_format_tests )

/**
 * price_oracle_id was appended to bitasset_options::ext, which is embedded in
 * asset_create_operation and asset_update_bitasset_operation -- both on chain since genesis.
 *
 * graphene's extension<T> encodes a count followed by (field index, value) pairs, with indices
 * assigned by declaration order in FC_REFLECT. Appending is therefore safe and inserting is
 * catastrophic: every pre-existing field would shift by one and every historical asset
 * operation would decode into the wrong fields. This pins the numbering so a later edit that
 * inserts rather than appends fails here rather than on a live chain.
 */
BOOST_AUTO_TEST_CASE( appending_price_oracle_id_did_not_shift_existing_extension_tags )
{
   auto packed_ext_of = []( const bitasset_options& o ) {
      return fc::raw::pack( o.extensions );
   };

   // no extensions at all: a single zero count byte, exactly as before this change
   bitasset_options none;
   auto empty = packed_ext_of( none );
   BOOST_REQUIRE_EQUAL( empty.size(), 1u );
   BOOST_CHECK_EQUAL( int( empty[0] ), 0 );

   // one field set: count 1, then that field's index. The indices below are the on-chain
   // numbering and must never change.
   struct { const char* name; int expected_index; std::function<void(bitasset_options&)> set; } cases[] = {
      { "initial_collateral_ratio",     0, []( bitasset_options& o ){ o.extensions.value.initial_collateral_ratio = 1750; } },
      { "maintenance_collateral_ratio", 1, []( bitasset_options& o ){ o.extensions.value.maintenance_collateral_ratio = 1750; } },
      { "maximum_short_squeeze_ratio",  2, []( bitasset_options& o ){ o.extensions.value.maximum_short_squeeze_ratio = 1100; } },
      { "margin_call_fee_ratio",        3, []( bitasset_options& o ){ o.extensions.value.margin_call_fee_ratio = 10; } },
      { "force_settle_fee_percent",     4, []( bitasset_options& o ){ o.extensions.value.force_settle_fee_percent = 10; } },
      { "black_swan_response_method",   5, []( bitasset_options& o ){ o.extensions.value.black_swan_response_method = 1; } },
      { "price_oracle_id",              6, []( bitasset_options& o ){ o.extensions.value.price_oracle_id = oracle_id_type(7); } },
   };

   for( const auto& c : cases )
   {
      bitasset_options o;
      c.set( o );
      auto bytes = packed_ext_of( o );
      BOOST_REQUIRE_MESSAGE( bytes.size() >= 2, c.name );
      BOOST_CHECK_MESSAGE( 1 == int( bytes[0] ), std::string( "count for " ) + c.name );
      BOOST_CHECK_MESSAGE( c.expected_index == int( bytes[1] ),
                           std::string( "extension tag for " ) + c.name + " changed" );
   }

   // and a round trip through the new field leaves the others untouched
   bitasset_options o;
   o.extensions.value.black_swan_response_method = 1;
   o.extensions.value.price_oracle_id = oracle_id_type(7);
   auto back = fc::raw::unpack<bitasset_options>( fc::raw::pack( o ) );
   BOOST_REQUIRE( back.extensions.value.price_oracle_id.valid() );
   BOOST_CHECK( *back.extensions.value.price_oracle_id == oracle_id_type(7) );
   BOOST_REQUIRE( back.extensions.value.black_swan_response_method.valid() );
   BOOST_CHECK_EQUAL( int( *back.extensions.value.black_swan_response_method ), 1 );
   BOOST_CHECK( !back.extensions.value.initial_collateral_ratio.valid() );
}

/**
 * reference_asset_mapping was appended LAST to bitasset_options::ext. Same rule as above:
 * its tag (7, after price_oracle_id at 6) must never shift.
 */
BOOST_AUTO_TEST_CASE( appending_reference_asset_mapping_did_not_shift_existing_extension_tags )
{
   bitasset_options o;
   reference_mapping m;
   m.reference = reference_asset_id_type( 2 );
   m.asset_amount = 100;
   m.reference_amount = 1;
   o.extensions.value.reference_asset_mapping = m;

   auto bytes = fc::raw::pack( o.extensions );
   BOOST_REQUIRE( bytes.size() >= 2 );
   BOOST_CHECK_EQUAL( int( bytes[0] ), 1 );
   BOOST_CHECK_EQUAL( int( bytes[1] ), 7 );

   auto back = fc::raw::unpack<bitasset_options>( fc::raw::pack( o ) );
   BOOST_REQUIRE( back.extensions.value.reference_asset_mapping.valid() );
   BOOST_CHECK( back.extensions.value.reference_asset_mapping->reference
                == reference_asset_id_type( 2 ) );
   BOOST_CHECK_EQUAL( back.extensions.value.reference_asset_mapping->asset_amount.value, 100 );
   BOOST_CHECK_EQUAL( back.extensions.value.reference_asset_mapping->reference_amount.value, 1 );
}


BOOST_AUTO_TEST_SUITE_END()

/**
 * Rev-2 oracle tests (Track B Task 6): reference assets, mappings, multi-series oracles,
 * per-producer outlier exclusion, and the consumer conversion formula.
 *
 * Revision 2 prices oracles in reference assets instead of on-chain asset ids; on-chain
 * assets declare which reference asset they track. See ORACLE-DESIGN.md (Reference assets,
 * Mapping, Oracles, Series, Consumers, Aggregation, Outlier handling, Consensus safety).
 */
BOOST_FIXTURE_TEST_SUITE( oracle_rev2_tests, database_fixture )

namespace {

/// One published value per series: that many base smallest-units equal that many quote
/// smallest-units. Both positive int64; comparison stays exact by 128-bit cross-multiplication.
/// (rv/rseries/rev2_* helpers live in the anonymous namespace above, shared with the
/// migrated Rev-1 suites.)

} // namespace

/// T6a: reference assets are created behind the committee gate, symbols are unique within
/// their own namespace, precision is immutable, and an issuer declares a 1:1 mapping.
BOOST_AUTO_TEST_CASE( t6a_reference_asset_create_and_mapping_declare )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   // While creation is committee-only, an ordinary account cannot create one.
   {
      reference_asset_create_operation op;
      op.creator   = alice_id;
      op.symbol    = "USD";
      op.precision = 4;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // A committee member can.
   rev2_make_committee_member( *this, alice );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   {
      const auto& ref = usd_ref(db);
      BOOST_CHECK_EQUAL( ref.symbol, "USD" );
      BOOST_CHECK_EQUAL( int( ref.precision ), 4 );
      BOOST_CHECK( ref.creator == alice_id );
   }

   // The namespace is the reference assets' own: reusing the symbol fails even for a
   // committee member with a different precision -- and that also shows precision cannot
   // be changed by recreating (there is no update operation at all, so what is stored
   // at creation is final).
   rev2_make_committee_member( *this, bob );
   GRAPHENE_REQUIRE_THROW(
      rev2_create_reference( *this, bob_id, bob_private_key, "USD", 2 ), fc::exception );
   BOOST_CHECK_EQUAL( usd_ref(db).precision, 4 );

   // Opening creation via the chain parameter lets anyone create.
   {
      auto& gpo = db.get_global_properties();
      db.modify( gpo, []( global_property_object& p ) {
         p.parameters.extensions.value.allow_public_reference_asset_creation = true;
      } );
   }
   const auto bts_ref = rev2_create_reference( *this, bob_id, bob_private_key, "BTS", 5 );
   BOOST_CHECK_EQUAL( bts_ref(db).precision, 5 );

   // An issuer declares a 1:1 mapping of its own smartcoin to the reference asset.
   const asset_object& mia = create_bitasset( "HONESTUSD", alice_id );
   reference_mapping m;
   m.reference         = usd_ref;
   m.asset_amount      = 1;
   m.reference_amount  = 1;
   rev2_declare_mapping( *this, mia, alice_id, alice_private_key, m );
   const auto& stored = mia.get_id()(db).bitasset_data(db).options
                           .extensions.value.reference_asset_mapping;
   BOOST_REQUIRE( stored.valid() );
   BOOST_CHECK( stored->reference == usd_ref );
   BOOST_CHECK_EQUAL( stored->asset_amount.value, 1 );
   BOOST_CHECK_EQUAL( stored->reference_amount.value, 1 );
} FC_LOG_AND_RETHROW() }

/// New Rev-2 state must be refused before the hardfork, like every oracle field before it.
BOOST_AUTO_TEST_CASE( t6a_rev2_state_is_refused_before_the_hardfork )
{ try {
   ACTORS( (alice) );
   fund( alice );

   // reference_asset_create before the fork
   {
      reference_asset_create_operation op;
      op.creator   = alice_id;
      op.symbol    = "USD";
      op.precision = 4;
      signed_transaction tx;
      tx.operations.push_back( op );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // a reference mapping on a bitasset before the fork
   {
      const asset_object& mia = create_bitasset( "PREFORKT", alice_id );
      asset_update_bitasset_operation op;
      op.issuer          = alice_id;
      op.asset_to_update = mia.get_id();
      op.new_options     = mia.bitasset_data( db ).options;
      reference_mapping m;
      m.reference        = reference_asset_id_type( 0 );
      m.asset_amount     = 1;
      m.reference_amount = 1;
      op.new_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
} FC_LOG_AND_RETHROW() }

/// T6b: an oracle over a reference pair (USD/BTS) with two producers publishing per-series
/// values aggregates each series independently.
BOOST_AUTO_TEST_CASE( t6b_oracle_over_reference_pair_with_two_producers )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );

   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;

   // Two series: both mid, one rounded down and one rounded up.
   const vector<oracle_series> series = {
      rseries( oracle_series_kind::mid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::up ),
   };
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "USD.BTS",
                                     usd_ref, bts_ref, series, opts );
   BOOST_CHECK( !oid(db).current_value.valid() );

   // One submission is below quorum.
   rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 100, 2000 ), rv( 100, 1900 ) } );
   BOOST_CHECK( !oid(db).current_value.valid() );

   // Two submissions reach quorum; each series takes the upper median of {2000-quote,
   // 2100-quote} and {1900-quote, 2000-quote} respectively, i.e. the SMALLER ratio in
   // each (base/quote with fixed base: a larger quote is a smaller price, and the upper
   // median picks index size/2 of the ascending sort).
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 100, 2100 ), rv( 100, 2000 ) } );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_REQUIRE_EQUAL( oid(db).current_value->size(), 2u );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 100, 2000 ) );
   BOOST_CHECK( oid(db).current_value->at( 1 ) == rv( 100, 1900 ) );
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );

   // History records one entry holding a value per series.
   BOOST_REQUIRE( !oid(db).history.empty() );
   BOOST_CHECK_EQUAL( oid(db).history.back().second.size(), 2u );
} FC_LOG_AND_RETHROW() }

/// T6c: a single submission must satisfy bid <= ask and down-rounded <= up-rounded;
/// violating either rejects the whole submission.
BOOST_AUTO_TEST_CASE( t6c_publish_enforces_series_relations )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;

   const vector<oracle_series> series = {
      rseries( oracle_series_kind::bid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::ask, oracle_series_rounding::up ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::up ),
   };
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "USD.BTS",
                                     usd_ref, bts_ref, series, opts );

   // bid 100/200 = 0.5 <= ask 100/190 ~= 0.526, down-mid 0.5 <= up-mid 0.526: accepted.
   rev2_publish( *this, oid, bob_id, bob_private_key,
                 { rv( 100, 200 ), rv( 100, 190 ), rv( 100, 200 ), rv( 100, 190 ) } );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // bid 100/100 = 1.0 > ask 100/190: the whole submission is rejected, nothing changes.
   GRAPHENE_REQUIRE_THROW(
      rev2_publish( *this, oid, bob_id, bob_private_key,
                    { rv( 100, 100 ), rv( 100, 190 ), rv( 100, 200 ), rv( 100, 190 ) } ),
      fc::exception );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 100, 200 ) );

   // down-mid 100/200 = 0.5 > up-mid 100/210 ~= 0.476: rejected as well.
   GRAPHENE_REQUIRE_THROW(
      rev2_publish( *this, oid, bob_id, bob_private_key,
                    { rv( 100, 200 ), rv( 100, 190 ), rv( 100, 200 ), rv( 100, 210 ) } ),
      fc::exception );
   BOOST_CHECK( oid(db).current_value->at( 2 ) == rv( 100, 200 ) );

   // wrong arity (fewer values than series) is rejected, not padded.
   GRAPHENE_REQUIRE_THROW(
      rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 100, 200 ) } ),
      fc::exception );
} FC_LOG_AND_RETHROW() }

/// T6d: the spec's Series proof as a test -- aggregation runs per series over the SAME
/// producer set, so bid <= ask survives the median.
BOOST_AUTO_TEST_CASE( t6d_aggregation_preserves_bid_leq_ask_after_median )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );

   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;

   const vector<oracle_series> series = {
      rseries( oracle_series_kind::bid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::ask, oracle_series_rounding::up ),
   };
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "USD.BTS",
                                     usd_ref, bts_ref, series, opts );

   // Every producer's bid <= its ask (base fixed at 1000; a larger quote is a smaller price):
   //   bids 400/1000=0.4, 500/1000=0.5, 600/1000=0.6
   //   asks 450/1000=0.45, 550/1000=0.55, 650/1000=0.65
   rev2_publish( *this, oid, bob_id, bob_private_key,     { rv( 400, 1000 ), rv( 450, 1000 ) } );
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 500, 1000 ), rv( 550, 1000 ) } );
   rev2_publish( *this, oid, dave_id, dave_private_key,   { rv( 600, 1000 ), rv( 650, 1000 ) } );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_REQUIRE_EQUAL( oid(db).current_value->size(), 2u );
   // middle of three in each series
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 500, 1000 ) );
   BOOST_CHECK( oid(db).current_value->at( 1 ) == rv( 550, 1000 ) );
   // and the relation holds after aggregation
   BOOST_CHECK( !( oid(db).current_value->at( 1 ) < oid(db).current_value->at( 0 ) ) );
} FC_LOG_AND_RETHROW() }

/// T6e: the outlier filter excludes a PRODUCER from all series or from none -- otherwise
/// the bid median and the ask median would be taken over different sets and the
/// aggregated bid could exceed the aggregated ask.
BOOST_AUTO_TEST_CASE( t6e_outlier_exclusion_covers_all_series_of_a_producer )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );

   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.max_deviation_ppm   = 500000; // 50%: mids 20% apart are fine, a 100x bid is not

   const vector<oracle_series> series = {
      rseries( oracle_series_kind::bid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::unspecified ),
   };
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "USD.BTS",
                                     usd_ref, bts_ref, series, opts );

   // bids: bob and carol agree at 0.5, dave reports 0.001 -- deviant in this series.
   // mids: 0.4 / 0.6 / 0.5, each within 50% of the round median 0.5 -- dave is NOT
   // deviant in this series, but must still be excluded from it.
   rev2_publish( *this, oid, bob_id, bob_private_key,     { rv( 500, 1000 ), rv( 400, 1000 ) } );
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 500, 1000 ), rv( 600, 1000 ) } );
   rev2_publish( *this, oid, dave_id, dave_private_key,   { rv( 1, 1000 ),   rv( 500, 1000 ) } );

   BOOST_REQUIRE( oid(db).current_value.valid() );
   // quorum intact over the two honest producers
   BOOST_CHECK_EQUAL( oid(db).current_value_producer_count, 2u );
   // bid: median of {0.5, 0.5}
   BOOST_CHECK( oid(db).current_value->at( 0 ) == rv( 500, 1000 ) );
   // mid: median of {0.4, 0.6} with the upper-median convention is 0.6 -- dave's 0.5
   // is NOT counted. Per-series exclusion would have kept it and reported 0.5.
   BOOST_CHECK( oid(db).current_value->at( 1 ) == rv( 600, 1000 ) );
} FC_LOG_AND_RETHROW() }

/// T6f: the consumer conversion formula (s_a.b.c_r) vs (s_r.q.c_a). With 1:1 mappings
/// the oracle value passes through with no arithmetic; across precisions the product is
/// exact in 256 bits, GCD-reduced, scaled down past GRAPHENE_MAX_SHARE_SUPPLY only when
/// needed, rounding the way the chosen series declares.
BOOST_AUTO_TEST_CASE( t6f_consumer_conversion_exactness_and_rounding )
{
   const asset_id_type debt_id( 1 );
   const asset_id_type backing_id( 0 );

   // 1:1 mappings in smallest units on both sides: the oracle value itself, no arithmetic.
   {
      reference_mapping debt_map, backing_map;
      debt_map.reference = reference_asset_id_type( 0 );
      debt_map.asset_amount = 1; debt_map.reference_amount = 1;
      backing_map.reference = reference_asset_id_type( 1 );
      backing_map.asset_amount = 1; backing_map.reference_amount = 1;

      const price p = convert_oracle_value_to_price(
            rv( 12345, 67890 ), debt_map, debt_id, backing_map, backing_id,
            oracle_series_rounding::down );
      BOOST_CHECK( p == price( asset( 12345, debt_id ), asset( 67890, backing_id ) ) );
   }

   // Cross-precision: debt maps 100:1 (like a 6-precision USDT against a 4-precision USD
   // reference), backing is 1:1. (100.b.1) vs (1.q.1) with (b,q) = (3,4): 300 vs 4,
   // GCD 4 -> 75 vs 1, both far below the supply cap so no scaling.
   {
      reference_mapping debt_map, backing_map;
      debt_map.reference = reference_asset_id_type( 0 );
      debt_map.asset_amount = 100; debt_map.reference_amount = 1;
      backing_map.reference = reference_asset_id_type( 1 );
      backing_map.asset_amount = 1; backing_map.reference_amount = 1;

      const price p = convert_oracle_value_to_price(
            rv( 3, 4 ), debt_map, debt_id, backing_map, backing_id,
            oracle_series_rounding::down );
      BOOST_CHECK( p == price( asset( 75, debt_id ), asset( 1, backing_id ) ) );
   }

   // Scale-down with declared rounding: debt maps 2:1, backing 1:1, oracle value at the
   // supply cap (1e15, 1e15-1). N = 2e15, D = 1e15-1, coprime, N past the cap so both
   // sides halve (scale 2). Down floors the odd side, up ceils it; the even side is
   // exact either way.
   {
      reference_mapping debt_map, backing_map;
      debt_map.reference = reference_asset_id_type( 0 );
      debt_map.asset_amount = 2; debt_map.reference_amount = 1;
      backing_map.reference = reference_asset_id_type( 1 );
      backing_map.asset_amount = 1; backing_map.reference_amount = 1;

      const int64_t cap = GRAPHENE_MAX_SHARE_SUPPLY;
      const price down_p = convert_oracle_value_to_price(
            rv( cap, cap - 1 ), debt_map, debt_id, backing_map, backing_id,
            oracle_series_rounding::down );
      BOOST_CHECK( down_p == price( asset( cap, debt_id ), asset( 499999999999999, backing_id ) ) );

      const price up_p = convert_oracle_value_to_price(
            rv( cap, cap - 1 ), debt_map, debt_id, backing_map, backing_id,
            oracle_series_rounding::up );
      BOOST_CHECK( up_p == price( asset( cap, debt_id ), asset( 500000000000000, backing_id ) ) );
      BOOST_CHECK( down_p != up_p );
   }
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Rev-2 consumer bindings, Task 7: explicit {oracle, series} smartcoin bindings with
 * bind-time AND read-time validity, UIA mapping home, BTS precision rule, futures-style
 * validity, and the F5 stale-subscriber prune rule.
 *
 * T7a smartcoin binds {oracle, series} explicitly; drift fails closed + prune rule.
 * T7b multi-series bind without a series choice is REFUSED (F3).
 * T7c UIA-collateral mapping home: MIA backed by a mapped UIA binds and converts (F4).
 * T7d BTS reference creation with precision != 5 is REFUSED (F2).
 * T7e futures-style binding validity: underlying reference + collateral mapping +
 *     oracle/series check, validity only (no matching engine changes).
 * T7f two smartcoins of different issuers share one USD/BTS oracle and settle identically.
 */
BOOST_FIXTURE_TEST_SUITE( oracle_task7_tests, oracle_fixture )

namespace {

/// Binds (or, with an empty optional, unbinds) an explicit {oracle, series} as a
/// smartcoin's price source. The Task 7 replacement for the series-naming legacy bind.
void rev2_bind_series( database_fixture& f, const asset_object& mia,
                       account_id_type issuer, const fc::ecc::private_key& key,
                       const optional<price_oracle>& binding )
{
   asset_update_bitasset_operation op;
   op.issuer          = issuer;
   op.asset_to_update = mia.get_id();
   op.new_options     = mia.bitasset_data( f.db ).options;
   op.new_options.extensions.value.price_oracle_binding = binding;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void rev2_bind_explicit( database_fixture& f, const asset_object& mia,
                         account_id_type issuer, const fc::ecc::private_key& key,
                         oracle_id_type oid, uint16_t series, uint32_t expiry_height )
{
   price_oracle b;
   b.oracle_id = oid;
   b.series    = series;
   b.expiry_height = expiry_height;
   rev2_bind_series( f, mia, issuer, key, b );
}

/// Far-future consensus expiry for binds that do not exercise expiry: strictly in the
/// future (the bind gate requires it) and far enough out that no test's block advance
/// crosses it. Expiry tests bind near-term heights through the overload above instead.
uint32_t rev2_far_future_expiry( database_fixture& f )
{
   return f.db.head_block_num() + 1000000000;
}

void rev2_bind_explicit( database_fixture& f, const asset_object& mia,
                         account_id_type issuer, const fc::ecc::private_key& key,
                         oracle_id_type oid, uint16_t series )
{
   rev2_bind_explicit( f, mia, issuer, key, oid, series, rev2_far_future_expiry( f ) );
}

/// Legacy bind without a series choice (Task 6 path). Multi-series oracles must refuse it.
void rev2_bind_legacy( database_fixture& f, const asset_object& mia,
                       account_id_type issuer, const fc::ecc::private_key& key,
                       oracle_id_type oid )
{
   asset_update_bitasset_operation op;
   op.issuer          = issuer;
   op.asset_to_update = mia.get_id();
   op.new_options     = mia.bitasset_data( f.db ).options;
   op.new_options.extensions.value.price_oracle_id = oid;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void rev2_unbind_all( database_fixture& f, const asset_object& mia,
                      account_id_type issuer, const fc::ecc::private_key& key )
{
   asset_update_bitasset_operation op;
   op.issuer          = issuer;
   op.asset_to_update = mia.get_id();
   op.new_options     = mia.bitasset_data( f.db ).options;
   op.new_options.extensions.value.price_oracle_binding   = {};
   op.new_options.extensions.value.price_oracle_id = {};
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Sets (or, with an empty optional, clears) the UIA mapping home: the reference mapping
/// in the asset's common options (F4). Only meaningful on non-market-issued assets.
void rev2_set_uia_mapping( database_fixture& f, const asset_object& uia,
                           account_id_type issuer, const fc::ecc::private_key& key,
                           const optional<reference_mapping>& m )
{
   asset_update_operation op;
   op.issuer          = issuer;
   op.asset_to_update = uia.get_id();
   op.new_options     = uia.options;
   op.new_options.extensions.value.reference_asset_mapping = m;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void rev2_delete_oracle( database_fixture& f, oracle_id_type oid,
                         account_id_type owner, const fc::ecc::private_key& key )
{
   oracle_delete_operation op;
   op.owner     = owner;
   op.oracle_id = oid;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

} // namespace

/// T7a-1: an explicit {oracle, series} bind feeds the smartcoin from the CHOSEN series,
/// mapping drift fails closed at read time, and restoring the mapping resumes the feed
/// without rebinding (drift never auto-unbinds).
BOOST_AUTO_TEST_CASE( t7a_explicit_series_binding_with_drift_and_resume )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIATEST", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   // Two mid series so the two published values can be told apart: series 0 quotes 20,
   // series 1 quotes 10. Reading series[0] by mistake would show 20, not 10. (The
   // down-rounded series 0 value must not exceed the up-rounded series 1 value of the
   // same kind -- the publish evaluator enforces down <= up.)
   const vector<oracle_series> series = {
      rseries( oracle_series_kind::mid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::up ),
   };
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "MIA.CORE",
                                      mia_ref, bts_ref, series, opts );
   rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 1, 20 ), rv( 1, 10 ) } );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // Bind series 1 explicitly: the feed must carry 10, proving the choice, not series[0].
   rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key, oid, 1 );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 10, asset_id_type() ) ) );

   // Drift the mapping: the binding no longer matches, so the read yields no price.
   reference_mapping drifted;
   drifted.reference = usd_ref;
   drifted.asset_amount = 1;
   drifted.reference_amount = 1;
   rev2_declare_mapping( *this, mia_id(db), alice_id, alice_private_key, drifted );
   BOOST_CHECK_MESSAGE( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null(),
                        "a mapping-drifted binding must fail closed, not keep quoting" );

   // The drifted binding is NOT auto-removed: restoring the mapping resumes the same feed
   // with no rebind. (In a fresh block: the restore tx is byte-identical to the initial
   // declare, which the chain rejects as a duplicate within one block.)
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );
   generate_block();
   set_expiration( db, trx );
   rev2_declare_mapping_1to1( *this, mia_id(db), alice_id, alice_private_key, mia_ref );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 10, asset_id_type() ) ) );

   // A live binding still blocks deletion.
   GRAPHENE_REQUIRE_THROW( rev2_delete_oracle( *this, oid, alice_id, alice_private_key ),
                           fc::exception );

   // Unbind, then deletion succeeds.
   generate_block();
   set_expiration( db, trx );
   rev2_unbind_all( *this, mia_id(db), alice_id, alice_private_key );
   BOOST_CHECK( oid(db).subscribers.empty() );
   rev2_delete_oracle( *this, oid, alice_id, alice_private_key );
   BOOST_CHECK( nullptr == db.find( oid ) );
} FC_LOG_AND_RETHROW() }

/// T7a-2 (F5): a mapping-drifted subscriber is STALE. It yields no price, and -- the prune
/// rule -- it must not block oracle_delete forever: deletion prunes it (clearing the dead
/// binding on the asset) and proceeds.
BOOST_AUTO_TEST_CASE( t7a_mapping_drift_prunes_stale_subscriber_on_delete )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIADRIFT", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAD", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "DRIFT.CORE",
                                      mia_ref, bts_ref, rev2_single_mid_series(), opts );
   rev2_publish( *this, oid, bob_id, bob_private_key, { rv( 1, 10 ) } );

   rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Drift: no price, but the subscriber entry stays (no auto-unbind).
   reference_mapping drifted;
   drifted.reference = usd_ref;
   drifted.asset_amount = 1;
   drifted.reference_amount = 1;
   rev2_declare_mapping( *this, mia_id(db), alice_id, alice_private_key, drifted );
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_REQUIRE_EQUAL( oid(db).subscribers.size(), 1u );

   // The stale entry does not block deletion: it is pruned, the dead binding cleared.
   rev2_delete_oracle( *this, oid, alice_id, alice_private_key );
   BOOST_CHECK( nullptr == db.find( oid ) );
   const auto& exts = mia_id(db).bitasset_data(db).options.extensions.value;
   BOOST_CHECK( !exts.price_oracle_binding.valid() );
   BOOST_CHECK( !exts.price_oracle_id.valid() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
} FC_LOG_AND_RETHROW() }

/// T7b (F3): a bind that names no series is REFUSED against a multi-series oracle, as is
/// an explicit series index outside the oracle's declared list. A valid explicit choice
/// on the same oracle works (control).
BOOST_AUTO_TEST_CASE( t7b_multi_series_bind_without_series_choice_is_refused )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIAMULTI", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAM", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   const vector<oracle_series> series = {
      rseries( oracle_series_kind::bid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::ask, oracle_series_rounding::up ),
   };
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "MULTI.CORE",
                                      mia_ref, bts_ref, series, opts );
   BOOST_REQUIRE_EQUAL( oid(db).series.size(), 2u );

   // Legacy bind names no series: refused against a two-series oracle.
   GRAPHENE_REQUIRE_THROW( rev2_bind_legacy( *this, mia_id(db), alice_id, alice_private_key, oid ),
                           fc::exception );
   BOOST_CHECK( oid(db).subscribers.empty() );

   // Explicit but out of range: refused as well.
   GRAPHENE_REQUIRE_THROW( rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key,
                                               oid, 2 ),
                           fc::exception );
   BOOST_CHECK( oid(db).subscribers.empty() );

   // Control: naming a declared series binds.
   rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );
} FC_LOG_AND_RETHROW() }

/// T7c-1 (F4): a market-issued asset backed by a USER-ISSUED asset binds and converts
/// through the UIA's mapping home. The UIA maps 100:1 (6-precision token against a
/// 4-precision USD reference); the conversion crosses that scale exactly.
BOOST_AUTO_TEST_CASE( t7c_mia_backed_by_mapped_uia_binds_and_converts )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAT", 4 );

   // Collateral UIA, precision 6, mapped 100:1 onto USD(4) at creation -- the mapping home
   // for non-market-issued assets.
   reference_mapping uia_map;
   uia_map.reference = usd_ref;
   uia_map.asset_amount = 100;
   uia_map.reference_amount = 1;
   additional_asset_options_t uia_ext;
   uia_ext.value.reference_asset_mapping = uia_map;
   const asset_object& uia = create_user_issued_asset(
      "UCOLL", bob, charge_market_fee,
      price( asset( 1, asset_id_type(1) ), asset( 1 ) ), 6, 100, std::move( uia_ext ) );
   const auto uia_id = uia.get_id();
   {
      const auto& stored = uia_id(db).options.extensions.value.reference_asset_mapping;
      BOOST_REQUIRE( stored.valid() );
      BOOST_CHECK( stored->reference == usd_ref );
   }

   // Smartcoin backed by that UIA (user-issued backing is allowed for non-committee MIAs),
   // mapped 1:1 to its own reference.
   const asset_object& mia = create_bitasset( "MIAUIA", alice_id, 100, charge_market_fee,
                                              4, uia_id );
   const auto mia_id = mia.get_id();
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   // Oracle over MIAT/USD, the orientation a settlement price uses.
   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "MIA.USD",
                                      mia_ref, usd_ref, rev2_single_mid_series(), opts );
   // (b, q) = (100 MIAT units, 2000 USD units). Debt 1:1, collateral 100:1:
   // N = 1*100*1 = 100, D = 1*2000*100 = 200000, GCD 100 -> 1 vs 2000.
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 100, 2000 ) } );

   rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 2000, uia_id ) ) );
} FC_LOG_AND_RETHROW() }

/// T7c-2 (F4 rules): the UIA mapping home accepts a valid mapping and refuses a dangling
/// reference; a market-issued asset may NOT carry the UIA-home mapping (its mapping lives
/// in bitasset options, and two homes would disagree about what the token tracks).
BOOST_AUTO_TEST_CASE( t7c_uia_mapping_home_rules )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice ); fund( bob );
   rev2_make_committee_member( *this, alice );

   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_object& uia = create_user_issued_asset(
      "UHOME", bob, charge_market_fee,
      price( asset( 1, asset_id_type(1) ), asset( 1 ) ), 2, 100,
      additional_asset_options_t() );
   const auto uia_id = uia.get_id();

   // A mapping to a reference asset that does not exist is refused.
   {
      reference_mapping bad;
      bad.reference = reference_asset_id_type( 999 );
      bad.asset_amount = 1;
      bad.reference_amount = 1;
      GRAPHENE_REQUIRE_THROW( rev2_set_uia_mapping( *this, uia_id(db), bob_id, bob_private_key,
                                                    bad ),
                              fc::exception );
   }

   // A valid mapping stores and reads back.
   {
      reference_mapping m;
      m.reference = usd_ref;
      m.asset_amount = 1;
      m.reference_amount = 1;
      rev2_set_uia_mapping( *this, uia_id(db), bob_id, bob_private_key, m );
      const auto& stored = uia_id(db).options.extensions.value.reference_asset_mapping;
      BOOST_REQUIRE( stored.valid() );
      BOOST_CHECK( stored->reference == usd_ref );
   }

   // A market-issued asset carrying the UIA-home mapping is refused, at creation...
   {
      asset_create_operation acop;
      acop.issuer = alice_id;
      acop.symbol = "MIABAD";
      acop.precision = 4;
      acop.common_options.core_exchange_rate = price( asset(1,asset_id_type(1)), asset(1) );
      acop.bitasset_opts = bitasset_options();
      reference_mapping m;
      m.reference = usd_ref;
      m.asset_amount = 1;
      m.reference_amount = 1;
      acop.common_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( acop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // ...and at update.
   {
      const asset_object& mia = create_bitasset( "MIAHOME", alice_id );
      asset_update_operation op;
      op.issuer = alice_id;
      op.asset_to_update = mia.get_id();
      op.new_options = mia.options;
      reference_mapping m;
      m.reference = usd_ref;
      m.asset_amount = 1;
      m.reference_amount = 1;
      op.new_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
} FC_LOG_AND_RETHROW() }

/// T7d (F2): the core asset maps 1:1 to the "BTS" reference by protocol rule, and the core
/// asset has precision 5 -- so a BTS reference at any other precision would silently
/// mis-scale every core-quoted conversion. Creation with precision != 5 is refused.
BOOST_AUTO_TEST_CASE( t7d_bts_reference_precision_is_fixed )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice );
   rev2_make_committee_member( *this, alice );

   auto try_create = [&]( const string& symbol, uint8_t precision ) {
      reference_asset_create_operation op;
      op.creator   = alice_id;
      op.symbol    = symbol;
      op.precision = precision;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   };

   GRAPHENE_REQUIRE_THROW( try_create( "BTS", 4 ), fc::exception );
   GRAPHENE_REQUIRE_THROW( try_create( "BTS", 6 ), fc::exception );
   GRAPHENE_REQUIRE_THROW( try_create( "BTS", 0 ), fc::exception );

   // Control: BTS at precision 5 creates, and other symbols are unaffected by the rule.
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   BOOST_CHECK_EQUAL( int( bts_ref(db).precision ), 5 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 2 );
   BOOST_CHECK_EQUAL( int( usd_ref(db).precision ), 2 );
} FC_LOG_AND_RETHROW() }

/// T7e: futures-style binding validity -- an underlying reference asset, an on-chain
/// collateral asset, an oracle and a series. Valid iff the series is declared,
/// oracle.base is the underlying, and oracle.quote is the collateral's mapped reference.
/// Validity only: no market object and no matching-engine changes in this stage.
BOOST_AUTO_TEST_CASE( t7e_futures_style_binding_validity )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );
   rev2_make_committee_member( *this, alice );

   const auto btc_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTC", 8 );
   const auto usd_ref = rev2_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const auto xau_ref = rev2_create_reference( *this, alice_id, alice_private_key, "XAU", 4 );
   const auto bts_ref = rev2_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );

   // Collateral UIA mapped 1:1 onto USD; contract size counts in BTC smallest units, so no
   // BTC token is needed -- the underlying is named directly as a reference asset.
   reference_mapping uia_map;
   uia_map.reference = usd_ref;
   uia_map.asset_amount = 1;
   uia_map.reference_amount = 1;
   additional_asset_options_t uia_ext;
   uia_ext.value.reference_asset_mapping = uia_map;
   const asset_object& uia = create_user_issued_asset(
      "UCOLL", bob, charge_market_fee,
      price( asset( 1, asset_id_type(1) ), asset( 1 ) ), 4, 100, std::move( uia_ext ) );
   const auto uia_id = uia.get_id();

   const vector<oracle_series> series = {
      rseries( oracle_series_kind::mid, oracle_series_rounding::down ),
      rseries( oracle_series_kind::mid, oracle_series_rounding::up ),
   };
   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "BTC.USD",
                                      btc_ref, usd_ref, series, opts );
   const oracle_object& o = oid(db);

   // Valid: underlying BTC, USD-mapped collateral, declared series.
   BOOST_CHECK( is_futures_binding_valid( o, 0, btc_ref, uia_map ) );
   BOOST_CHECK( is_futures_binding_valid( o, 1, btc_ref, uia_map ) );

   // Wrong underlying, wrong collateral reference, undeclared series: all invalid.
   BOOST_CHECK( !is_futures_binding_valid( o, 0, usd_ref, uia_map ) );
   reference_mapping xau_map = uia_map;
   xau_map.reference = xau_ref;
   BOOST_CHECK( !is_futures_binding_valid( o, 0, btc_ref, xau_map ) );
   BOOST_CHECK( !is_futures_binding_valid( o, 2, btc_ref, uia_map ) );

   // Core collateral resolves through the BTS protocol rule: a BTC/BTS oracle with CORE
   // collateral is valid.
   const auto oid2 = rev2_make_oracle( *this, alice_id, alice_private_key, "BTC.CORE",
                                       btc_ref, bts_ref, rev2_single_mid_series(), opts );
   reference_mapping core_map;
   core_map.reference = bts_ref;
   core_map.asset_amount = 1;
   core_map.reference_amount = 1;
   BOOST_CHECK( is_futures_binding_valid( oid2(db), 0, btc_ref, core_map ) );
   BOOST_CHECK( !is_futures_binding_valid( oid2(db), 0, btc_ref, uia_map ) );

   // Drifted collateral mapping invalidates a previously valid binding.
   reference_mapping drifted = uia_map;
   drifted.reference = xau_ref;
   rev2_set_uia_mapping( *this, uia_id(db), bob_id, bob_private_key, drifted );
   const auto& stored = uia_id(db).options.extensions.value.reference_asset_mapping;
   BOOST_REQUIRE( stored.valid() );
   BOOST_CHECK( !is_futures_binding_valid( o, 0, btc_ref, *stored ) );
} FC_LOG_AND_RETHROW() }

/// T7f: one USD/BTS oracle feeds two smartcoins of different issuers, both mapped 1:1.
/// Both settle identically from the same published value -- the sharing the Rev-2 basis
/// exists for.
BOOST_AUTO_TEST_CASE( t7f_two_smartcoins_share_one_oracle )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   const asset_object& mia1 = create_bitasset( "MIAONE", alice_id );
   const auto mia1_id = mia1.get_id();
   rev2_declare_mapping_1to1( *this, mia1, alice_id, alice_private_key, usd_ref );

   const asset_object& mia2 = create_bitasset( "MIATWO", bob_id );
   const auto mia2_id = mia2.get_id();
   // A different issuer declares the same 1:1 mapping on its own asset.
   {
      asset_update_bitasset_operation op;
      op.issuer          = bob_id;
      op.asset_to_update = mia2_id;
      op.new_options     = mia2.bitasset_data( db ).options;
      reference_mapping m;
      m.reference        = usd_ref;
      m.asset_amount     = 1;
      m.reference_amount = 1;
      op.new_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "USD.CORE",
                                      usd_ref, bts_ref, rev2_single_mid_series(), opts );
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 1, 25 ) } );

   rev2_bind_explicit( *this, mia1_id(db), alice_id, alice_private_key, oid, 0 );
   rev2_bind_explicit( *this, mia2_id(db), bob_id, bob_private_key, oid, 0 );
   BOOST_REQUIRE_EQUAL( oid(db).subscribers.size(), 2u );

   const auto& feed1 = mia1_id(db).bitasset_data(db).current_feed.settlement_price;
   const auto& feed2 = mia2_id(db).bitasset_data(db).current_feed.settlement_price;
   BOOST_REQUIRE( !feed1.is_null() );
   BOOST_REQUIRE( !feed2.is_null() );
   BOOST_CHECK( feed1 == price( asset( 1, mia1_id ), asset( 25, asset_id_type() ) ) );
   BOOST_CHECK( feed2 == price( asset( 1, mia2_id ), asset( 25, asset_id_type() ) ) );
   // Full price equality can never hold across two assets (the base asset ids differ);
   // "settle identically" means the same ratio from the same oracle value.
   BOOST_CHECK_MESSAGE( feed1.base.amount == feed2.base.amount && feed1.quote == feed2.quote,
                        "two consumers of one oracle must settle identically" );

   // One publish moves both in the same block.
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 1, 30 ) } );
   BOOST_CHECK( mia1_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia1_id ), asset( 30, asset_id_type() ) ) );
   BOOST_CHECK( mia2_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia2_id ), asset( 30, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T7g (MUSE-R01 H2 latch/sunset): once an asset has carried an explicit
/// binding, the expiry-free legacy path closes for it permanently. Unbind
/// explicit, then rebind legacy (the recorded expiry dodge) is refused, and
/// the latch survives the unbind; a never-explicit asset still binds legacy
/// (t9d boundary kept).
BOOST_AUTO_TEST_CASE( t7g_legacy_rebind_after_explicit_is_refused )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   const asset_object& mia = create_bitasset( "MIALATCH", alice_id );
   const auto mia_id = mia.get_id();
   const auto mia_ref = rev2_create_reference( *this, alice_id, alice_private_key, "MIAL", 2 );
   rev2_declare_mapping_1to1( *this, mia, alice_id, alice_private_key, mia_ref );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers = 1;
   const auto oid = rev2_make_oracle( *this, alice_id, alice_private_key, "LATCH.CORE",
                                      mia_ref, bts_ref, rev2_single_mid_series(), opts );
   rev2_publish( *this, oid, carol_id, carol_private_key, { rv( 1, 10 ) } );

   // Explicit first bind latches the asset...
   rev2_bind_explicit( *this, mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).options.extensions.value
                  .explicit_oracle_bound_once.valid() );
   BOOST_REQUIRE( *mia_id(db).bitasset_data(db).options.extensions.value
                  .explicit_oracle_bound_once );
   // ...unbind keeps the latch (the feed nulls, the history does not)...
   generate_block();
   set_expiration( db, trx );
   rev2_unbind_all( *this, mia_id(db), alice_id, alice_private_key );
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_REQUIRE( *mia_id(db).bitasset_data(db).options.extensions.value
                  .explicit_oracle_bound_once );
   // ...and the legacy rebind (the expiry dodge) is refused.
   generate_block();
   set_expiration( db, trx );
   GRAPHENE_REQUIRE_THROW( rev2_bind_legacy( *this, mia_id(db), alice_id, alice_private_key, oid ),
                           fc::exception );
   const auto& exts = mia_id(db).bitasset_data(db).options.extensions.value;
   BOOST_CHECK( !exts.price_oracle_id.valid() );
   BOOST_CHECK( !exts.price_oracle_binding.valid() );

   // Control: a never-explicit asset still binds legacy (t9d boundary kept).
   const asset_object& mia2 = create_bitasset( "MIALATCH2", alice_id );
   const auto mia2_id = mia2.get_id();
   rev2_declare_mapping_1to1( *this, mia2, alice_id, alice_private_key, mia_ref );
   rev2_bind_legacy( *this, mia2_id(db), alice_id, alice_private_key, oid );
   BOOST_REQUIRE( mia2_id(db).bitasset_data(db).options.extensions.value
                  .price_oracle_id.valid() );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( oracle_wire_format_task7_tests )

/**
 * price_oracle was appended LAST to bitasset_options::ext (tag 8, after
 * reference_asset_mapping at 7). Same rule as the earlier pins: the tag must never shift.
 */
BOOST_AUTO_TEST_CASE( appending_price_oracle_did_not_shift_existing_extension_tags )
{
   bitasset_options o;
   price_oracle b;
   b.oracle_id = oracle_id_type( 3 );
   b.series    = 1;
   o.extensions.value.price_oracle_binding = b;

   auto bytes = fc::raw::pack( o.extensions );
   BOOST_REQUIRE( bytes.size() >= 2 );
   BOOST_CHECK_EQUAL( int( bytes[0] ), 1 );
   BOOST_CHECK_EQUAL( int( bytes[1] ), 8 );

   auto back = fc::raw::unpack<bitasset_options>( fc::raw::pack( o ) );
   BOOST_REQUIRE( back.extensions.value.price_oracle_binding.valid() );
   BOOST_CHECK( back.extensions.value.price_oracle_binding->oracle_id == oracle_id_type( 3 ) );
   BOOST_CHECK_EQUAL( int( back.extensions.value.price_oracle_binding->series ), 1 );
   BOOST_CHECK( !back.extensions.value.price_oracle_id.valid() );
}

/**
 * The consensus expiry height was appended LAST inside price_oracle (after series),
 * not as a new extension tag: expiry travels with the binding through operator==,
 * subscriber diffing and delete-liveness, and a binding without an expiry cannot be
 * expressed. The ext-level tag above (8) is unchanged by this; the struct's own
 * encoding carries the height and round-trips it.
 */
BOOST_AUTO_TEST_CASE( price_oracle_expiry_round_trips )
{
   price_oracle b;
   b.oracle_id     = oracle_id_type( 3 );
   b.series        = 1;
   b.expiry_height = 123456789;
   auto back = fc::raw::unpack<price_oracle>( fc::raw::pack( b ) );
   BOOST_CHECK( back.oracle_id == oracle_id_type( 3 ) );
   BOOST_CHECK_EQUAL( int( back.series ), 1 );
   BOOST_CHECK_EQUAL( back.expiry_height, 123456789u );

   // A pre-expiry encoding carried only two fields. It must never decode into a live
   // binding with a defaulted height: short buffers fail instead of defaulting, so an
   // old payload is rejected, never silently treated as unexpiring.
   std::vector<char> old_bytes = fc::raw::pack( oracle_id_type( 3 ) );
   auto series_bytes = fc::raw::pack( uint16_t( 1 ) );
   old_bytes.insert( old_bytes.end(), series_bytes.begin(), series_bytes.end() );
   BOOST_CHECK_THROW( fc::raw::unpack<price_oracle>( old_bytes ), fc::exception );
}

/**
 * The UIA mapping home was appended LAST to additional_asset_options (tag 3, after
 * taker_fee_percent at 2). Pins the numbering the same way.
 */
BOOST_AUTO_TEST_CASE( uia_reference_mapping_has_a_stable_extension_tag )
{
   additional_asset_options_t ext;
   reference_mapping m;
   m.reference        = reference_asset_id_type( 1 );
   m.asset_amount     = 100;
   m.reference_amount = 1;
   ext.value.reference_asset_mapping = m;

   auto bytes = fc::raw::pack( ext );
   BOOST_REQUIRE( bytes.size() >= 2 );
   BOOST_CHECK_EQUAL( int( bytes[0] ), 1 );
   BOOST_CHECK_EQUAL( int( bytes[1] ), 3 );

   auto back = fc::raw::unpack<additional_asset_options_t>( fc::raw::pack( ext ) );
   BOOST_REQUIRE( back.value.reference_asset_mapping.valid() );
   BOOST_CHECK( back.value.reference_asset_mapping->reference == reference_asset_id_type( 1 ) );
   BOOST_CHECK_EQUAL( back.value.reference_asset_mapping->asset_amount.value, 100 );
   BOOST_CHECK_EQUAL( back.value.reference_asset_mapping->reference_amount.value, 1 );
}

/**
 * explicit_oracle_bound_once was appended LAST to bitasset_options::ext (tag 9,
 * after price_oracle_binding at 8). Same rule: the tag must never shift, and the
 * earlier tags are untouched by the append.
 */
BOOST_AUTO_TEST_CASE( explicit_latch_has_a_stable_extension_tag )
{
   bitasset_options o;
   o.extensions.value.explicit_oracle_bound_once = true;

   auto bytes = fc::raw::pack( o.extensions );
   BOOST_REQUIRE( bytes.size() >= 2 );
   BOOST_CHECK_EQUAL( int( bytes[0] ), 1 );
   BOOST_CHECK_EQUAL( int( bytes[1] ), 9 );

   auto back = fc::raw::unpack<bitasset_options>( fc::raw::pack( o ) );
   BOOST_REQUIRE( back.extensions.value.explicit_oracle_bound_once.valid() );
   BOOST_CHECK_EQUAL( *back.extensions.value.explicit_oracle_bound_once, true );
   BOOST_CHECK( !back.extensions.value.price_oracle_id.valid() );
}

BOOST_AUTO_TEST_SUITE_END()

/**
 * Track B Task 8: Track A guards on new pairs (TDD).
 *
 * T8a rate-limit: aggregate movement bounded per maintenance interval (5%). A spike
 * beyond the bound holds the last-good consumed value + flag, never jumps.
 * T8b OSM-style delay: the median computed at block N is consumable for
 * margin/settlement only at N + delay (proposal: 1h, chain parameter). The test uses a
 * committee-set short delay and proves the mechanism, not the hour.
 * T8c emergency freeze: a per-oracle freeze flag halts consumption and fails margin
 * actions closed; unfreeze by vote resumes.
 * T8d reputation log: per-producer liveness/deviation history accrues on-chain and is
 * queryable (no economics attached).
 * T8e legacy-untouched: legacy-feed expectations pinned byte-for-byte; zero modified
 * legacy cases allowed.
 *
 * Guards are new-pairs-only: only oracle-bound consumers read the guarded
 * (consumed) value. Legacy feed paths behave byte-identically (T8e).
 */

/// Guard-test fixture: guard oracles quote <debt-ref, BTS> so a smartcoin mapped 1:1
/// to debt-ref and backed by core binds exactly like the Task 7 two-consumer test.
struct guard_fixture : oracle_fixture
{
   oracle_id_type make_guard_oracle( account_id_type owner, const fc::ecc::private_key& key,
                                     const string& name, const oracle_options& opts,
                                     reference_asset_id_type debt_ref )
   {
      BOOST_REQUIRE( references_ready );
      return rev2_make_oracle( *this, owner, key, name, debt_ref, bts_ref,
                               rev2_single_mid_series(), opts );
   }

   void guard_publish( oracle_id_type oid, account_id_type who,
                       const fc::ecc::private_key& key, int64_t n )
   {
      rev2_publish( *this, oid, who, key, { rv( 1, n ) } );
   }

   asset_id_type make_mapped_mia( const string& sym, account_id_type issuer,
                                  const fc::ecc::private_key& key,
                                  reference_asset_id_type debt_ref )
   {
      const asset_object& mia = create_bitasset( sym, issuer );
      const auto mia_id = mia.get_id();
      rev2_declare_mapping_1to1( *this, mia, issuer, key, debt_ref );
      return mia_id;
   }

   void set_frozen( oracle_id_type oid, account_id_type owner,
                    const fc::ecc::private_key& key, bool frozen )
   {
      oracle_options opts = oid(db).options;
      opts.frozen = frozen;
      update_options( oid, owner, key, opts );
   }

   /// Local explicit-bind helper. (The Task 7 rev2_bind_explicit lives in that
   /// suite's scope; this is the same operation, duplicated so this suite stands alone.)
   /// The short form binds with a far-future consensus expiry so guard tests that do
   /// not exercise expiry keep passing the bind gate; expiry tests pass near-term
   /// heights through the long form.
   void bind_explicit( const asset_object& mia, account_id_type issuer,
                       const fc::ecc::private_key& key, oracle_id_type oid, uint16_t series,
                       uint32_t expiry_height )
   {
      asset_update_bitasset_operation op;
      op.issuer          = issuer;
      op.asset_to_update = mia.get_id();
      op.new_options     = mia.bitasset_data( db ).options;
      price_oracle b;
      b.oracle_id = oid;
      b.series    = series;
      b.expiry_height = expiry_height;
      op.new_options.extensions.value.price_oracle_binding = b;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   void bind_explicit( const asset_object& mia, account_id_type issuer,
                       const fc::ecc::private_key& key, oracle_id_type oid, uint16_t series )
   {
      bind_explicit( mia, issuer, key, oid, series, db.head_block_num() + 1000000000 );
   }
};

BOOST_FIXTURE_TEST_SUITE( oracle_guard_tests, guard_fixture )

/// T8a: a 10x spike holds the last-good consumed value and raises the flag, never jumps.
/// The deviation filter is OFF (max_deviation_ppm = 0) so the raw aggregate provably
/// moves and only the guard holds the consumed value.
BOOST_AUTO_TEST_CASE( t8a_rate_limit_holds_last_good_and_flags )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );

   // New pair opting into the rate limit (delay left off: isolated by the flag).
   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.value_lifetime_sec  = 7 * 86400;
   opts.max_deviation_ppm   = 0;
   opts.guard_rate_limit    = true;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );

   guard_publish( oid, bob_id, bob_private_key, 100 );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   guard_publish( oid, dave_id, dave_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );

   const auto mia_id = make_mapped_mia( "MIA8A", alice_id, alice_private_key, usd_ref );
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );

   // Everyone moves 10x at once: quorum survives, the filter is off, so the raw
   // aggregate MUST move. The guard must hold the consumed value instead.
   generate_block();
   set_expiration( db, trx );
   guard_publish( oid, bob_id, bob_private_key, 1000 );
   guard_publish( oid, carol_id, carol_private_key, 1000 );
   guard_publish( oid, dave_id, dave_private_key, 1000 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 1000 ) );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );
   BOOST_CHECK( oid(db).rate_limited );
   BOOST_CHECK_GE( oid(db).guard_hits, 1u );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );

   // Per-interval reset: past the maintenance boundary the counter restarts (block
   // production replays pending publishes, so the re-hold count reads at least 1),
   // and returning in-band clears flag and counter exactly.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 5 );
   set_expiration( db, trx );
   guard_publish( oid, bob_id, bob_private_key, 100 );
   BOOST_CHECK( oid(db).rate_limited );
   BOOST_CHECK_GE( oid(db).guard_hits, 1u );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   guard_publish( oid, dave_id, dave_private_key, 100 );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );
   BOOST_CHECK( !oid(db).rate_limited );
   BOOST_CHECK_EQUAL( oid(db).guard_hits, 0u );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T8b: the median computed at block N is consumable only at N + delay. The committee
/// sets a short delay by vote; the test proves the mechanism, not the hour.
BOOST_AUTO_TEST_CASE( t8b_delay_holds_value_until_delay_passes )
{ try {
   // Pre-fork the delay parameter is refused through the proposal path.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.extensions.value.oracle_guard_delay_sec = 120;
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      GRAPHENE_CHECK_THROW( PUSH_TX( db, trx, ~0 ), fc::exception );
      trx.clear();
      BOOST_CHECK( !db.get_global_properties().parameters
                        .extensions.value.oracle_guard_delay_sec.valid() );
   }

   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   // The committee votes a short delay for the test pair's chain.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      // H1-FINAL-06/R17G: sub-minute delays are refused by the coded floor
      // (chain_parameters validate, GRAPHENE_ORACLE_GUARD_MIN_DELAY_SEC); the
      // suite votes the smallest whole-hour delay in the PS-R17-01 stall
      // classes instead (7200s = 2h: pre-R17G it self-erases its queue).
      cmuop.new_parameters.extensions.value.oracle_guard_delay_sec = 7200;
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      processed_transaction ptx = PUSH_TX( db, trx, ~0 );
      trx.clear();
      proposal_id_type prop_id { ptx.operation_results[0].get<object_id_type>() };

      proposal_update_operation uop;
      uop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      // Explicit target: a defaulted (1.10.0) target would hit whichever
      // proposal was created first in this test; review_period_time lives at
      // expiration - review, so approving a proposal created more than
      // moments ago is refused.
      uop.proposal = prop_id;
      uop.active_approvals_to_add = { get_account("init0").get_id(), get_account("init1").get_id(),
                                      get_account("init2").get_id(), get_account("init3").get_id(),
                                      get_account("init4").get_id(), get_account("init5").get_id(),
                                      get_account("init6").get_id(), get_account("init7").get_id() };
      trx.operations.push_back( uop );
      PUSH_TX( db, trx, ~0 );
      trx.clear();

      generate_blocks( prop_id( db ).expiration_time + 5 );
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time );
      generate_block();
      BOOST_REQUIRE_EQUAL( db.get_global_properties().parameters
                              .get_oracle_guard_delay_sec(), 7200u );
   }
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   opts.guard_delay         = true; // new pair opting into the OSM delay
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );

   // Computed at block N: raw is live, but nothing is consumable yet.
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( !oid(db).consumed_value.valid() );

   // A bound asset fails closed until the delay passes: no price, not a stale one.
   const auto mia_id = make_mapped_mia( "MIA8B", alice_id, alice_private_key, usd_ref );
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Past N + delay the same value becomes consumable and the feed goes live.
   // Delay is 7200 now (the coded floor above); one mid-delay publish keeps a
   // live bucket; the jump crosses the ripening.
   generate_blocks( db.head_block_time() + 180 );
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   generate_blocks( db.head_block_time() + 7300 );
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );
   BOOST_CHECK( oid(db).consumed_value->at( 0 ) == val( 100 ) );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T8b2 (R17G, PS-R17-01): the guard-delay queue must promote the oldest sample
/// when it ripens at the committee delay, even when an honest producer publishes
/// at block cadence (the production shape). Pre-R17G the capacity trim ran BEFORE
/// the ripen scan with bucket = delay/16, so 16 buckets spanned exactly <= the
/// delay: the oldest entry was erased at its ripening block and no sample ever
/// reached age >= delay -- the gated pair's feed stayed null forever at the
/// production delay values (3600 default, plus 7200/43200 and every whole-hour
/// value in the stall classes). RED here at 3600 (default) and 7200 (voted),
/// GREEN with bucket = delay/(MAX_PENDING-1): the 16th arrival lands at the
/// delay boundary with the queue not yet clipped, so the ripen scan sees the
/// ripe oldest entry.
BOOST_AUTO_TEST_CASE( t8b2_guard_delay_promotes_oldest_sample_block_cadence_r17g )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );
   // The committee has never set the extension: the default delay (3600,
   // protocol/oracle.hpp) is what every production pair sees; pin it here so
   // the regression is written against the exact value under test.
   BOOST_REQUIRE_EQUAL( db.get_global_properties().parameters
                          .get_oracle_guard_delay_sec(), 3600u );

   // H1-FINAL-06 floor: a sub-minute vote is refused at validate, pre-fork
   // the whole extension is refused anyway (t8b pins that shape) — probe the
   // post-fork refusal here at 90s, then the floor boundary value (3600)
   // landing cleanly.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.extensions.value.oracle_guard_delay_sec = 90;
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      GRAPHENE_CHECK_THROW( PUSH_TX( db, trx, ~0 ), fc::exception );
      trx.clear();
      // Boundary value: exactly the floor is legal (probes nothing else).
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      cmuop.new_parameters.extensions.value.oracle_guard_delay_sec = 3600;
      cop.proposed_ops.clear();
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      PUSH_TX( db, trx, ~0 );
      trx.clear();
   }

   ACTORS( (alice)(carol) );
   fund( alice ); fund( carol );
   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   opts.guard_delay         = true;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );

   // Publish at BLOCK cadence from t0: one publish per block (same value, so
   // no rate-limit leg). With bucket = floor(delay/16) = 225 for the default
   // 3600 the queue grows ~1 entry per 225s; the 17th arrival clips the oldest
   // entry at exactly its ripening age and the consumed value must never seed
   // pre-fix.
   const auto t0 = db.head_block_time();
   fc::optional<int64_t> first_age_3600;
   for( int i = 0; i < 1220; ++i )
   {
      guard_publish( oid, carol_id, carol_private_key, 100 );
      generate_block();
      set_expiration( db, trx );
      if( !first_age_3600.valid() && oid(db).consumed_value.valid() )
         first_age_3600 = int64_t( ( db.head_block_time() - t0 ).to_seconds() ) - 3; // the block that promoted
      // While the delay still holds: no premature promotion.
      if( ( db.head_block_time() - t0 ).to_seconds() < 3000 )
         BOOST_CHECK( !oid(db).consumed_value.valid() );
      if( first_age_3600.valid() )
         break;
   }
   BOOST_REQUIRE_MESSAGE( first_age_3600.valid(),
      "R17G RED: guard delay 3600 never promoted any sample at block cadence "
      "(queue self-erases every ripe sample)" );
   BOOST_CHECK_GE( *first_age_3600, int64_t( 3594 ) );
   BOOST_CHECK_LE( *first_age_3600, int64_t( 3660 ) );

   // Second leg: a committee-voted delay inside the same stall class. 7200
   // (old bucket = floor(7200/16) = 450; 16 entries spanning 6750, so the
   // 17th arrival at 7200 clipped the oldest entry at exactly its ripening
   // age; the fixed bucket 480 lets the queue reach the boundary intact).
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.extensions.value.oracle_guard_delay_sec = 7200;
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      processed_transaction ptx = PUSH_TX( db, trx, ~0 );
      trx.clear();
      proposal_id_type prop_id { ptx.operation_results[0].get<object_id_type>() };

      proposal_update_operation uop;
      uop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      // Explicit target: without this the default (1.10.0) hits the earlier
      // floor-probe proposal, and approvals past review_period_time are refused.
      uop.proposal = prop_id;
      uop.active_approvals_to_add = { get_account("init0").get_id(), get_account("init1").get_id(),
                                      get_account("init2").get_id(), get_account("init3").get_id(),
                                      get_account("init4").get_id(), get_account("init5").get_id(),
                                      get_account("init6").get_id(), get_account("init7").get_id() };
      trx.operations.push_back( uop );
      PUSH_TX( db, trx, ~0 );
      trx.clear();

      generate_blocks( prop_id( db ).expiration_time + 5 );
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time );
      generate_block();
      set_expiration( db, trx );
      BOOST_REQUIRE_EQUAL( db.get_global_properties().parameters
                              .get_oracle_guard_delay_sec(), 7200u );
   }
   // A fresh delay opt-in under the new delay: freshly published samples age
   // from here, so this leg measures the voted delay end to end.
   const auto oid2 = make_guard_oracle( alice_id, alice_private_key, "USD.CORE2", opts, usd_ref );
   const auto t2 = db.head_block_time();
   fc::optional<int64_t> first_age_7200;
   for( int i = 0; i < 2460; ++i )
   {
      guard_publish( oid2, carol_id, carol_private_key, 100 );
      generate_block();
      set_expiration( db, trx );
      if( !first_age_7200.valid() && oid2(db).consumed_value.valid() )
         first_age_7200 = int64_t( ( db.head_block_time() - t2 ).to_seconds() ) - 3;
      if( first_age_7200.valid() )
         break;
   }
   BOOST_REQUIRE_MESSAGE( first_age_7200.valid(),
      "R17G RED: guard delay 7200 never promoted any sample at block cadence" );
   BOOST_CHECK_GE( *first_age_7200, int64_t( 7194 ) );
   BOOST_CHECK_LE( *first_age_7200, int64_t( 7260 ) );
} FC_LOG_AND_RETHROW() }

/// T8c: freeze halts consumption and fails margin actions closed; unfreeze by vote
/// resumes the feed.
BOOST_AUTO_TEST_CASE( t8c_freeze_halts_consumption_and_unfreeze_by_vote_resumes )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( oid(db).consumed_value.valid() );

   const auto mia_id = make_mapped_mia( "MIA8C", alice_id, alice_private_key, usd_ref );
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0 );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Borrowing works while the oracle is live: the margin path is open.
   BOOST_REQUIRE( nullptr != borrow( bob, asset( 500, mia_id ), asset( 100000, asset_id_type() ) ) );

   // The owner freezes: consumption halts, the bound feed goes null, and margin
   // actions fail closed instead of trading on the frozen price.
   set_frozen( oid, alice_id, alice_private_key, true );
   BOOST_REQUIRE( oid(db).options.frozen );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   GRAPHENE_REQUIRE_THROW(
      borrow( dave, asset( 500, mia_id ), asset( 100000, asset_id_type() ) ), fc::exception );

   // Unfreeze by vote: alice proposes the unfreeze and approves it; execution on
   // approval resumes the oracle without any further action.
   proposal_id_type pid;
   {
      proposal_create_operation pcop;
      pcop.fee_paying_account = alice_id;
      oracle_update_operation unfreeze;
      unfreeze.owner     = alice_id;
      unfreeze.oracle_id = oid;
      oracle_options live = oid(db).options;
      live.frozen = false;
      unfreeze.new_options = live;
      pcop.proposed_ops = { op_wrapper( unfreeze ) };
      pcop.expiration_time = db.head_block_time() + 100;
      pcop.fee = pcop.calculate_fee(
            db.current_fee_schedule().get<proposal_create_operation>() );
      signed_transaction tx;
      tx.operations = { pcop };
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      pid = proposal_id_type{ db.push_transaction( tx ).operation_results[0]
                                                   .get<object_id_type>() };
   }
   BOOST_REQUIRE( nullptr != db.find( pid ) );
   {
      proposal_update_operation puop;
      puop.fee_paying_account = alice_id;
      puop.proposal = pid;
      puop.active_approvals_to_add = { alice_id };
      puop.fee = puop.calculate_fee(
            db.current_fee_schedule().get<proposal_update_operation>() );
      signed_transaction tx;
      tx.operations = { puop };
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_CHECK( db.find( pid ) == nullptr );
   BOOST_CHECK( !oid(db).options.frozen );

   // A fresh publish resumes the feed at the same price with no rebind. In a fresh
   // block: the pre-freeze publish is byte-identical, which the chain would reject
   // as a duplicate within one block.
   generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T8d: per-producer liveness/deviation history accrues on-chain and is queryable.
/// No economics attached: counts only, never weights, rewards, or slashing.
BOOST_AUTO_TEST_CASE( t8d_reputation_accrues_and_is_queryable )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.minimum_producers   = 2;
   opts.value_lifetime_sec  = 7 * 86400;
   opts.max_deviation_ppm   = 100000; // 10%: a 2x deviant is an outlier, noise is not
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );

   guard_publish( oid, bob_id, bob_private_key, 100 );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   guard_publish( oid, dave_id, dave_private_key, 100 );
   BOOST_REQUIRE( oid(db).current_value.valid() );

   // Every publisher accrued liveness with no deviations yet.
   BOOST_REQUIRE_EQUAL( oid(db).reputation.size(), 3u );
   for( const auto& entry : oid(db).reputation )
   {
      BOOST_CHECK_GE( entry.second.publish_count, 1u );
      BOOST_CHECK_GE( entry.second.live_count, 1u );
      BOOST_CHECK_EQUAL( entry.second.outlier_count, 0u );
   }

   // Bob deviates 2x alone: the quorum-aware filter excludes him while quorum survives,
   // and his deviation is recorded without touching his weight or anyone's funds.
   guard_publish( oid, bob_id, bob_private_key, 200 );
   BOOST_REQUIRE( oid(db).current_value.valid() );
   BOOST_CHECK( oid(db).current_value->at( 0 ) == val( 100 ) );
   BOOST_REQUIRE( oid(db).reputation.find( bob_id ) != oid(db).reputation.end() );
   BOOST_CHECK_EQUAL( oid(db).reputation.find( bob_id )->second.publish_count, 2u );
   BOOST_CHECK_GE( oid(db).reputation.find( bob_id )->second.outlier_count, 1u );
   BOOST_CHECK_EQUAL( oid(db).options.producers.find( bob_id )->second.weight, 1u );

   // The history travels the API wire: pack/unpack round-trips the counts exactly.
   const auto rep = oid(db).reputation.find( bob_id )->second;
   const auto rep_back = fc::raw::unpack<oracle_producer_reputation>( fc::raw::pack( rep ) );
   BOOST_CHECK_EQUAL( rep_back.publish_count, rep.publish_count );
   BOOST_CHECK_EQUAL( rep_back.live_count, rep.live_count );
   BOOST_CHECK_EQUAL( rep_back.outlier_count, rep.outlier_count );
} FC_LOG_AND_RETHROW() }

/// T8e: legacy-untouched. A witness-fed smartcoin with no oracle binding anywhere
/// keeps byte-identical feed behaviour: legacy median expectations pinned exactly.
BOOST_AUTO_TEST_CASE( t8e_legacy_feed_path_is_untouched )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice );

   // Default (witness-account) issuer: a witness-fed legacy asset, exactly the
   // bitasset_tests shape. No oracle binding anywhere on this asset.
   const asset_object& legacy = create_bitasset( "LEGACY8E" );
   const asset_id_type legacy_id = legacy.get_id();
   const asset_id_type core_id = asset_id_type();
   const auto& ext = legacy_id(db).bitasset_data(db).options.extensions.value;
   BOOST_REQUIRE( !ext.price_oracle_id.valid() );
   BOOST_REQUIRE( !ext.price_oracle_binding.valid() );

   const auto& global_props = db.get_global_properties();
   std::vector<account_id_type> active_witnesses;
   for( const witness_id_type& wit_id : global_props.active_witnesses )
      active_witnesses.push_back( wit_id(db).witness_account );
   BOOST_REQUIRE_GE( active_witnesses.size(), 3u );

   publish_feed( active_witnesses[0], core_id, 1, legacy_id, 300, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 300.0 );
   publish_feed( active_witnesses[1], core_id, 1, legacy_id, 100, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 300.0 );
   publish_feed( active_witnesses[2], core_id, 1, legacy_id, 1, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 100.0 );
   BOOST_CHECK( legacy_id(db).bitasset_data(db).current_feed
                   .maintenance_collateral_ratio
                == GRAPHENE_DEFAULT_MAINTENANCE_COLLATERAL_RATIO );
} FC_LOG_AND_RETHROW() }

/// V-02 (audit-round-2): bounded oracle state has attack-input coverage. The 65th
/// subscriber bind is refused (asset_evaluator.cpp:914); the delay queue needs no
/// refusal path by design — it self-trims to GRAPHENE_ORACLE_GUARD_MAX_PENDING
/// with time-bucketed sampling — so the test pins the bound instead.
BOOST_AUTO_TEST_CASE( t8f_subscriber_cap_refuses_and_pending_queue_bounded )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(carol) );
   fund( alice ); fund( carol );

   setup_references( alice_id, alice_private_key );
   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   opts.guard_delay         = true;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CAP", opts, usd_ref );

   // 64 subscribers bind cleanly; the 65th is refused and the set stays at 64.
   for( int i = 0; i < 64; ++i )
   {
      const auto mia_id = make_mapped_mia( "CAP" + std::to_string( i ),
                                           alice_id, alice_private_key, usd_ref );
      bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0 );
   }
   BOOST_REQUIRE_EQUAL( oid(db).subscribers.size(), 64u );
   const auto over_id = make_mapped_mia( "CAPOVER", alice_id, alice_private_key, usd_ref );
   BOOST_CHECK_THROW( bind_explicit( over_id(db), alice_id, alice_private_key, oid, 0 ),
                      fc::exception );
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 64u );

   // 20 publishes across 20 time buckets: the queue never exceeds its bound.
   for( int i = 0; i < 20; ++i )
   {
      guard_publish( oid, carol_id, carol_private_key, 100 + i );
      generate_blocks( db.head_block_time() + 300 );
   }
   BOOST_CHECK( oid(db).pending_queue.size() <= 16u );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()

/**
 * H1-EXP: consensus expiry-height on explicit {oracle, series} bindings.
 *
 * Every explicit binding carries the head block number past which it yields no
 * price. Past expiry the read path fails closed (null feed, same shape as mapping
 * drift), which blocks new debt through the existing null-settlement-price rule
 * while existing positions stand. A live binding is immutable (no extend, no
 * re-point); unbinding is allowed but nulls the feed in that block, so life can
 * never be extended seamlessly. The legacy price_oracle_id path is pinned, not
 * closed (t9d): it carries no expiry by design and stays out of scope.
 */
BOOST_FIXTURE_TEST_SUITE( oracle_expiry_tests, guard_fixture )

/// T9a: binding with a consensus expiry is a happy path while head <= expiry: the
/// stored height is exact, the subscriber set tracks the pair, the feed reads the
/// chosen series, and margin actions work.
BOOST_AUTO_TEST_CASE( t9a_bind_with_expiry_feeds_while_live )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9A", alice_id, alice_private_key, usd_ref );

   // Attack-first: with no binding there is no price, so no debt either.
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK_THROW( borrow( bob, asset( 500, mia_id ), asset( 100000, asset_id_type() ) ),
                      fc::exception );

   const uint32_t expiry = db.head_block_num() + 100;
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0, expiry );

   const auto& stored = mia_id(db).bitasset_data(db).options.extensions.value
                           .price_oracle_binding;
   BOOST_REQUIRE( stored.valid() );
   BOOST_CHECK_EQUAL( stored->expiry_height, expiry );
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );
   BOOST_REQUIRE( nullptr != borrow( bob, asset( 500, mia_id ),
                                     asset( 100000, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T9b: the boundary is exact -- live AT the expiry height, null past it. The null
/// materializes on the next feed refresh (here: the next publish), the same lazy
/// shape mapping drift has always had: oracles publish continuously, and every
/// refresh past expiry fails the binding closed.
BOOST_AUTO_TEST_CASE( t9b_expiry_boundary_is_exact )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9B", alice_id, alice_private_key, usd_ref );
   const uint32_t expiry = db.head_block_num() + 10;
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0, expiry );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   while( db.head_block_num() < expiry )
      generate_block();
   BOOST_REQUIRE_EQUAL( db.head_block_num(), expiry );

   // A refresh AT the expiry height still reads: live while head <= expiry.
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // One block past it the same refresh fails closed, and stays failed.
   generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE_EQUAL( db.head_block_num(), expiry + 1 );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // And it stays null on further refreshes: expiry is terminal, never transient.
   generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
} FC_LOG_AND_RETHROW() }

/// T9c: post-expiry the pair rejects NEW debt automatically (null feed, existing
/// borrow rule, no committee action involved) while an EXISTING position stands --
/// expiry freezes growth, it does not liquidate. And an oracle with only expired
/// consumers becomes deletable: expired bindings prune, they never strand.
BOOST_AUTO_TEST_CASE( t9c_post_expiry_blocks_new_debt_but_keeps_positions )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice ); fund( bob ); fund( carol ); fund( dave );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9C", alice_id, alice_private_key, usd_ref );
   const uint32_t expiry = db.head_block_num() + 10;
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0, expiry );

   // Local delete helper: rev2_delete_oracle lives in the Task 7 suite's scope, so
   // this suite spells the same operation inline.
   auto delete_oracle = [&]( oracle_id_type o )
   {
      oracle_delete_operation op;
      op.owner     = alice_id;
      op.oracle_id = o;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   };

   // A position opened while live...
   const auto* opened = borrow( bob, asset( 500, mia_id ), asset( 100000, asset_id_type() ) );
   BOOST_REQUIRE( nullptr != opened );
   const auto order_id = opened->id;

   // While live the oracle cannot be deleted out from under the pair...
   BOOST_CHECK_THROW( delete_oracle( oid ), fc::exception );
   BOOST_CHECK( db.find( oid ) != nullptr );

   // ...crosses expiry, and the next refresh fails the pair closed.
   while( db.head_block_num() <= expiry )
      generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // New debt is refused through the untouched null-settlement-price rule...
   BOOST_CHECK_THROW( borrow( dave, asset( 500, mia_id ), asset( 100000, asset_id_type() ) ),
                      fc::exception );
   // ...while the pre-expiry position stands: no liquidation, no auto-close.
   BOOST_CHECK( db.find<call_order_object>( order_id ) != nullptr );

   // ...but with only expired consumers left, the oracle deletes: expired bindings
   // prune (the F5 rule), they never strand an oracle undeletable.
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );
   delete_oracle( oid );
   BOOST_CHECK( db.find( oid ) == nullptr );
   // ...and the prune cleared the dead binding rather than leaving a dangling one.
   const auto& exts = mia_id(db).bitasset_data(db).options.extensions.value;
   BOOST_CHECK( !exts.price_oracle_binding.valid() );
   BOOST_CHECK( !exts.price_oracle_id.valid() );
} FC_LOG_AND_RETHROW() }

/// T9d: legacy pin. An unbound witness-fed pair executes byte-identical code (exact
/// medians), and a legacy price_oracle_id bind carries no expiry and reads through
/// block advances that would have expired an explicit binding. The legacy path is
/// out of scope for expiry BY DECISION (see the bind evaluator comment): this test
/// pins the boundary so a later change cannot silently move it -- including the
/// residual dodge (unbind explicit, rebind legacy) recorded for H2 sunset.
BOOST_AUTO_TEST_CASE( t9d_legacy_pairs_ignore_expiry )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   // Part 1: no binding anywhere -- the t8e medians, exactly.
   const asset_object& legacy = create_bitasset( "LEGACY9D" );
   const asset_id_type legacy_id = legacy.get_id();
   const asset_id_type core_id = asset_id_type();
   const auto& global_props = db.get_global_properties();
   std::vector<account_id_type> active_witnesses;
   for( const witness_id_type& wit_id : global_props.active_witnesses )
      active_witnesses.push_back( wit_id(db).witness_account );
   BOOST_REQUIRE_GE( active_witnesses.size(), 3u );
   publish_feed( active_witnesses[0], core_id, 1, legacy_id, 300, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 300.0 );
   publish_feed( active_witnesses[1], core_id, 1, legacy_id, 100, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 300.0 );
   publish_feed( active_witnesses[2], core_id, 1, legacy_id, 1, core_id );
   BOOST_CHECK_EQUAL(
      legacy_id(db).bitasset_data(db).current_feed.settlement_price.to_real(), 100.0 );

   // Part 2: a legacy-id-bound pair has no expiry field and outlives block advances.
   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9D", alice_id, alice_private_key, usd_ref );
   {
      asset_update_bitasset_operation op;
      op.issuer          = alice_id;
      op.asset_to_update = mia_id;
      op.new_options     = mia_id(db).bitasset_data(db).options;
      op.new_options.extensions.value.price_oracle_id = oid;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   const auto& bound = mia_id(db).bitasset_data(db).options.extensions.value;
   BOOST_REQUIRE( bound.price_oracle_id.valid() );
   BOOST_REQUIRE( !bound.price_oracle_binding.valid() );
   BOOST_REQUIRE( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Fifty blocks with a fresh refresh at the end: still quoting, no expiry to pass.
   for( int i = 0; i < 50; ++i )
      generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price
                == price( asset( 1, mia_id ), asset( 100, asset_id_type() ) ) );
} FC_LOG_AND_RETHROW() }

/// T9e: a live binding is immutable. Every in-place change -- extending the height,
/// shortening it, re-pointing at another oracle -- is refused, directly. Unbinding
/// is the only allowed transition, and it nulls the feed in that block: life can
/// never be extended seamlessly.
BOOST_AUTO_TEST_CASE( t9e_live_binding_is_immutable )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   const auto oid2 = make_guard_oracle( alice_id, alice_private_key, "USD.TWO", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   guard_publish( oid2, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9E", alice_id, alice_private_key, usd_ref );
   const uint32_t expiry = db.head_block_num() + 100;
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0, expiry );

   auto try_set_binding = [&]( const optional<price_oracle>& b )
   {
      asset_update_bitasset_operation op;
      op.issuer          = alice_id;
      op.asset_to_update = mia_id;
      op.new_options     = mia_id(db).bitasset_data(db).options;
      op.new_options.extensions.value.price_oracle_binding = b;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   };
   auto bound_as = [&]( oracle_id_type o, uint16_t s, uint32_t e )
   {
      price_oracle b;
      b.oracle_id = o;
      b.series    = s;
      b.expiry_height = e;
      return optional<price_oracle>( b );
   };

   // Extending the height is refused...
   BOOST_CHECK_THROW( try_set_binding( bound_as( oid, 0, expiry + 1000 ) ), fc::exception );
   // ...shortening it is refused too: ANY change to a live binding is, not just +.
   BOOST_CHECK_THROW( try_set_binding( bound_as( oid, 0, expiry - 50 ) ), fc::exception );
   // ...re-pointing at another oracle (with a fresh height beside it) is refused...
   BOOST_CHECK_THROW( try_set_binding( bound_as( oid2, 0, expiry + 1000 ) ), fc::exception );
   // ...a binding with no height at all is refused...
   BOOST_CHECK_THROW( try_set_binding( bound_as( oid, 0, 0 ) ), fc::exception );
   // ...and the stored binding is untouched by every refused route.
   BOOST_CHECK( mia_id(db).bitasset_data(db).options.extensions.value
                   .price_oracle_binding->expiry_height == expiry );
   BOOST_CHECK_EQUAL( oid(db).subscribers.size(), 1u );
   BOOST_CHECK( oid2(db).subscribers.empty() );

   // Unbinding is the one allowed transition -- and the feed dies in that block.
   // (Fresh block first: the unbind tx would otherwise be byte-identical to the
   // mapping-declaration tx above -- same head, same expiration -- and the chain
   // rejects it as a duplicate, cf. t8c.)
   generate_block();
   set_expiration( db, trx );
   try_set_binding( optional<price_oracle>() );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   BOOST_CHECK( oid(db).subscribers.empty() );
   BOOST_CHECK_THROW( borrow( bob, asset( 500, mia_id ), asset( 100000, asset_id_type() ) ),
                      fc::exception );
} FC_LOG_AND_RETHROW() }

/// T9f: no extend path through proposals, parameters, or the oracle side. A
/// proposal-wrapped extend fails at execution like the direct route; no chain
/// parameter touches the height; and past expiry neither an oracle policy update
/// nor a mapping restore revives the feed -- expiry dominates resumption (contrast
/// the drift-resume path, where restoring the mapping resumes with no rebind).
BOOST_AUTO_TEST_CASE( t9f_no_extend_path_through_proposals_or_parameters )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );
   const auto eur_ref = rev2_create_reference( *this, alice_id, alice_private_key, "EUR", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9F", alice_id, alice_private_key, usd_ref );
   const uint32_t expiry = db.head_block_num() + 10;
   bind_explicit( mia_id(db), alice_id, alice_private_key, oid, 0, expiry );

   // A proposal wrapping an extend: creation passes the fork gate, but execution runs
   // the same bind evaluator as the direct route and fails -- the height stands.
   proposal_id_type pid;
   {
      asset_update_bitasset_operation extend;
      extend.issuer          = alice_id;
      extend.asset_to_update = mia_id;
      extend.new_options     = mia_id(db).bitasset_data(db).options;
      price_oracle bigger = *extend.new_options.extensions.value.price_oracle_binding;
      bigger.expiry_height = expiry + 1000;
      extend.new_options.extensions.value.price_oracle_binding = bigger;

      proposal_create_operation pcop;
      pcop.fee_paying_account = alice_id;
      pcop.proposed_ops = { op_wrapper( extend ) };
      pcop.expiration_time = db.head_block_time() + 100;
      pcop.fee = pcop.calculate_fee(
            db.current_fee_schedule().get<proposal_create_operation>() );
      signed_transaction tx;
      tx.operations = { pcop };
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      pid = proposal_id_type{ db.push_transaction( tx ).operation_results[0]
                                                   .get<object_id_type>() };
   }
   BOOST_REQUIRE( nullptr != db.find( pid ) );
   // Execution runs the same bind evaluator as the direct route and refuses: the
   // approval itself succeeds (proposal failures are recorded, not thrown -- the
   // proposal stays with its fail_reason set and retries at expiration, where it
   // fails again), but the height stands and the refusal is on chain to see.
   {
      proposal_update_operation puop;
      puop.fee_paying_account = alice_id;
      puop.proposal = pid;
      puop.active_approvals_to_add = { alice_id };
      puop.fee = puop.calculate_fee(
            db.current_fee_schedule().get<proposal_update_operation>() );
      signed_transaction tx;
      tx.operations = { puop };
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_CHECK( mia_id(db).bitasset_data(db).options.extensions.value
                   .price_oracle_binding->expiry_height == expiry );
   BOOST_REQUIRE( !pid(db).fail_reason.empty() );
   BOOST_CHECK( pid(db).fail_reason.find( "immutable" ) != std::string::npos );

   // No chain parameter feeds the expiry predicate: flipping one leaves the height
   // and the live feed exactly where they were.
   {
      auto& gpo = db.get_global_properties();
      db.modify( gpo, []( global_property_object& p ) {
         p.parameters.extensions.value.oracle_guard_delay_sec = 120;
      } );
   }
   BOOST_CHECK( mia_id(db).bitasset_data(db).options.extensions.value
                   .price_oracle_binding->expiry_height == expiry );
   BOOST_CHECK( !mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // Past expiry the feed is null...
   while( db.head_block_num() <= expiry )
      generate_block();
   set_expiration( db, trx );
   guard_publish( oid, carol_id, carol_private_key, 100 );
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // ...an oracle policy update (which refreshes subscribers) does not revive it...
   {
      oracle_update_operation uop;
      uop.owner       = alice_id;
      uop.oracle_id   = oid;
      uop.new_options = oid(db).options;
      signed_transaction tx;
      tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );

   // ...and neither does breaking then restoring the mapping: expiry dominates
   // resumption, so the restored pair stays dark with no rebind.
   rev2_declare_mapping_1to1( *this, mia_id(db), alice_id, alice_private_key, eur_ref );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
   rev2_declare_mapping_1to1( *this, mia_id(db), alice_id, alice_private_key, usd_ref );
   BOOST_CHECK( mia_id(db).bitasset_data(db).current_feed.settlement_price.is_null() );
} FC_LOG_AND_RETHROW() }

/// T9g (H1-12 strictly-future bind): the consensus expiry height must be
/// STRICTLY in the future at bind time (asset_evaluator.cpp bind-time half).
/// Attack-first: expiry == 0 (absent) and expiry == head (already live at the
/// binding block) both refuse; only head + 1 admits. Without the strictness
/// (> vs >=) an attacker binds an already-dead height and the pair reads a
/// binding that can never feed (dead-on-arrival latch with a subscriber).
BOOST_AUTO_TEST_CASE( t9g_bind_expiry_must_be_strictly_future )
{ try {
   generate_blocks( HARDFORK_ORACLE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice ); fund( bob ); fund( carol );

   setup_references( alice_id, alice_private_key );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.minimum_producers   = 1;
   opts.value_lifetime_sec  = 7 * 86400;
   const auto oid = make_guard_oracle( alice_id, alice_private_key, "USD.CORE", opts, usd_ref );
   guard_publish( oid, carol_id, carol_private_key, 100 );

   const auto mia_id = make_mapped_mia( "MIA9G", alice_id, alice_private_key, usd_ref );

   auto try_bind = [&]( uint32_t expiry ) -> std::string
   {
      asset_update_bitasset_operation op;
      op.issuer          = alice_id;
      op.asset_to_update = mia_id;
      op.new_options     = mia_id(db).bitasset_data(db).options;
      price_oracle b;
      b.oracle_id = oid;
      b.series    = 0;
      b.expiry_height = expiry;
      op.new_options.extensions.value.price_oracle_binding = b;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      try { PUSH_TX( db, tx ); }
      catch ( const fc::exception& e ) { return e.to_string(); }
      return std::string();
   };

   // Absent height refuses...
   BOOST_CHECK_MESSAGE( try_bind( 0 ).find( "consensus expiry height" ) != std::string::npos,
                        "expiry 0 must refuse at the bind-time gate" );
   // ...the live head height refuses (strictly future, never >=)...
   const uint32_t head = db.head_block_num();
   BOOST_CHECK_MESSAGE( try_bind( head ).find( "must be in the future" ) != std::string::npos,
                        "expiry == head must refuse: strictly future, never >=" );
   // ...while head + 1 admits (control: the gate is exact, not over-broad).
   BOOST_CHECK_MESSAGE( try_bind( head + 1 ).empty(), "expiry head+1 must bind" );
   BOOST_REQUIRE( mia_id(db).bitasset_data(db).options.extensions.value
                  .price_oracle_binding.valid() );
   BOOST_CHECK_EQUAL( mia_id(db).bitasset_data(db).options.extensions.value
                      .price_oracle_binding->expiry_height, head + 1 );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE( oracle_guard_wire_tests )

/**
 * oracle_guard_delay_sec was appended LAST to chain_parameters::ext (tag 5, after
 * allow_public_reference_asset_creation at 4). The tag must never shift, and the
 * getter defaults to the 1h proposal value while the field is absent.
 */
BOOST_AUTO_TEST_CASE( guard_delay_chain_parameter_tag_is_stable )
{
   chain_parameters p;
   BOOST_CHECK_EQUAL( p.get_oracle_guard_delay_sec(),
                      GRAPHENE_ORACLE_GUARD_DEFAULT_DELAY_SEC );
   p.extensions.value.oracle_guard_delay_sec = 120;
   auto bytes = fc::raw::pack( p.extensions );
   BOOST_REQUIRE( bytes.size() >= 2 );
   BOOST_CHECK_EQUAL( int( bytes[0] ), 1 );
   BOOST_CHECK_EQUAL( int( bytes[1] ), 5 );

   auto back = fc::raw::unpack<chain_parameters>( fc::raw::pack( p ) );
   BOOST_REQUIRE( back.extensions.value.oracle_guard_delay_sec.valid() );
   BOOST_CHECK_EQUAL( int( *back.extensions.value.oracle_guard_delay_sec ), 120 );
   BOOST_CHECK_EQUAL( back.get_oracle_guard_delay_sec(), 120u );
}

/**
 * frozen was appended AFTER extensions on oracle_options (never inserted before it),
 * so pre-existing field positions are unchanged and the flag round-trips.
 */
BOOST_AUTO_TEST_CASE( oracle_options_frozen_flag_round_trips )
{
   oracle_options o;
   o.producers[ account_id_type( 1 ) ] = oracle_producer_entry( 1 );
   o.minimum_producers = 1;
   BOOST_CHECK( !o.frozen );
   o.frozen = true;
   auto back = fc::raw::unpack<oracle_options>( fc::raw::pack( o ) );
   BOOST_CHECK( back.frozen );
   BOOST_REQUIRE_EQUAL( back.producers.size(), 1u );
   BOOST_CHECK_EQUAL( back.minimum_producers, 1u );
}

/**
 * The guard opt-in flags were appended after frozen (never inserted): pre-existing
 * positions unchanged, both flags round-trip, both default OFF (passthrough).
 */
BOOST_AUTO_TEST_CASE( oracle_options_guard_flags_round_trip )
{
   oracle_options o;
   BOOST_CHECK( !o.guard_rate_limit );
   BOOST_CHECK( !o.guard_delay );
   o.guard_rate_limit = true;
   o.guard_delay = true;
   auto back = fc::raw::unpack<oracle_options>( fc::raw::pack( o ) );
   BOOST_CHECK( back.guard_rate_limit );
   BOOST_CHECK( back.guard_delay );
   BOOST_CHECK( !back.frozen );
}

BOOST_AUTO_TEST_SUITE_END()
