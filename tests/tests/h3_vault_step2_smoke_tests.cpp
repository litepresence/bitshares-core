#include <boost/test/unit_test.hpp>

#include <graphene/chain/vault_object.hpp>

#include <fc/io/raw.hpp>

using namespace graphene::chain;

BOOST_AUTO_TEST_SUITE( h3_vault_step2_smoke_tests )

BOOST_AUTO_TEST_CASE( default_backing_chain_is_bitshares )
{
   vault_object v;
   BOOST_CHECK_EQUAL( v.backing_chain, 0 );
   BOOST_CHECK( v.backing_asset.empty() );
   BOOST_CHECK( !h2_vault_is_foreign_backed( v ) );
}

BOOST_AUTO_TEST_CASE( foreign_backing_chain_sets_helper )
{
   vault_object v;
   v.backing_chain = 1;
   v.backing_asset = "BTC";
   BOOST_CHECK( h2_vault_is_foreign_backed( v ) );
}

BOOST_AUTO_TEST_CASE( backing_fields_round_trip_serialization )
{
   vault_object v;
   v.backing_chain = 2;
   v.backing_asset = "ETH";
   auto back = fc::raw::unpack<vault_object>( fc::raw::pack( v ) );
   BOOST_CHECK_EQUAL( back.backing_chain, 2 );
   BOOST_CHECK_EQUAL( back.backing_asset, "ETH" );
}

BOOST_AUTO_TEST_CASE( secure_ratio_still_enforced )
{
   vault_object v;
   v.secure_ratio_bps = 20000;
   BOOST_CHECK( v.mint_within_secure_ratio( share_type( 20000 ), share_type( 10000 ) ) );
   BOOST_CHECK( !v.mint_within_secure_ratio( share_type( 10000 ), share_type( 10000 ) ) );
}

BOOST_AUTO_TEST_SUITE_END()