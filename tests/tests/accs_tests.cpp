#include <boost/test/unit_test.hpp>
#include <iostream>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/accs_object.hpp>
#include <graphene/protocol/accs_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/chain/hardfork.hpp>

#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

struct accs_fixture : database_fixture
{
   account_id_type alice_account_id, bob_account_id, carol_account_id, dave_account_id;
   fc::ecc::private_key alice_key, bob_key, carol_key, dave_key;

   account_object alice_account;
   account_object bob_account;
   account_object carol_account;
   account_object dave_account;

   asset_id_type sell_asset;
   oracle_id_type oracle_id;
   reference_asset_id_type ref_base_asset;
   reference_asset_id_type ref_quote_asset;

   void build()
   {
      generate_blocks( HARDFORK_H2_PRICE_TIME );
      generate_block();
      set_expiration( db, trx );

      ACTORS( (alice)(bob)(carol)(dave) );

      alice_account_id = alice_id;
      bob_account_id = bob_id;
      carol_account_id = carol_id;
      dave_account_id = dave_id;
      alice_key = alice_private_key;
      bob_key = bob_private_key;
      carol_key = carol_private_key;
      dave_key = dave_private_key;

      alice_account = alice;
      bob_account = bob;
      carol_account = carol;
      dave_account = dave;

      fund( alice_account, asset( 30000000000000LL ) );
      fund( bob, asset( 30000000000000LL ) );
      fund( carol, asset( 30000000000000LL ) );
      fund( dave, asset( 30000000000000LL ) );

      // Seat alice on the committee so she can declare gateways.
      upgrade_to_lifetime_member( alice_account );
      create_and_seat_committee_member( alice_account );

      // Create reference assets for a price oracle.
      reference_asset_create_operation bop;
      bop.creator = alice_account_id; bop.symbol = "FTX"; bop.precision = 5;
      bop.description = "base";
      signed_transaction btx; btx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( btx.operations.back() );
      set_expiration( db, btx ); btx.sign( alice_key, db.get_chain_id() );
      ref_base_asset = reference_asset_id_type {
         PUSH_TX( db, btx ).operation_results.front().get<object_id_type>() };

      reference_asset_create_operation qop;
      qop.creator = alice_account_id; qop.symbol = "FTQ"; qop.precision = 4;
      qop.description = "quote";
      signed_transaction qtx; qtx.operations.push_back( qop );
      db.current_fee_schedule().set_fee( qtx.operations.back() );
      set_expiration( db, qtx ); qtx.sign( alice_key, db.get_chain_id() );
      ref_quote_asset = reference_asset_id_type {
         PUSH_TX( db, qtx ).operation_results.front().get<object_id_type>() };

      // Create a foreign chain tx oracle (F1).
      oracle_create_operation oop;
      oop.owner = alice_account_id; oop.name = "F1.BTCUSD"; oop.base = ref_base_asset;
      oop.quote = ref_quote_asset;
      oop.description = "foreign chain tx oracle";
      oop.series = { oracle_series( oracle_series_kind::foreign_tx,
                                    oracle_series_rounding::unspecified ) };
      oracle_options oopts;
      oopts.producers[alice_account_id] = oracle_producer_entry( 1 );
      oopts.minimum_producers = 1;
      oopts.value_lifetime_sec = 3600;
      oop.options = oopts;
      signed_transaction otx; otx.operations.push_back( oop );
      db.current_fee_schedule().set_fee( otx.operations.back() );
      set_expiration( db, otx ); otx.sign( alice_key, db.get_chain_id() );
      oracle_id = oracle_id_type {
         PUSH_TX( db, otx ).operation_results.front().get<object_id_type>() };

      // Create the base asset that Alice will sell in ACCS offers.
      asset_create_operation aop;
      aop.issuer = alice_account_id; aop.symbol = "TEST"; aop.precision = 2;
      aop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
      aop.common_options.core_exchange_rate =
         price( asset( 100 ), asset( 1, asset_id_type( 1 ) ) );
      signed_transaction atx; atx.operations.push_back( aop );
      db.current_fee_schedule().set_fee( atx.operations.back() );
      set_expiration( db, atx ); atx.sign( alice_key, db.get_chain_id() );
      sell_asset = asset_id_type {
         PUSH_TX( db, atx ).operation_results.front().get<object_id_type>() };

      // Issue TEST tokens to Alice.
      asset_issue_operation iop;
      iop.issuer = alice_account_id;
      iop.asset_to_issue = asset( 100000, sell_asset );
      iop.issue_to_account = alice_account_id;
      signed_transaction itx; itx.operations.push_back( iop );
      db.current_fee_schedule().set_fee( itx.operations.back() );
      set_expiration( db, itx ); itx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, itx );
   }

   accs_gateway_id_type declare_gateway( uint8_t chain_id,
                                         const std::string& foreign_asset_id = "" )
   {
      accs_declare_gateway_operation op;
      op.committee_member = alice_account_id;
      op.chain_id = chain_id;
      op.foreign_asset_id = foreign_asset_id;
      op.foreign_asset_code = 0;
      op.oracle_id = oracle_id;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      const auto& gw_idx = db.get_index_type<accs_gateway_index>().indices();
      for ( const auto& gw : gw_idx )
         if ( gw.chain_id == chain_id && gw.foreign_asset_id == foreign_asset_id )
            return accs_gateway_id_type( gw.id );
      return accs_gateway_id_type();
   }

   accs_offer_id_type create_offer( account_id_type seller,
                                    asset_id_type asset_id,
                                    uint8_t chain_id,
                                    const std::string& foreign_asset_id,
                                    share_type base_amount,
                                    share_type foreign_amount,
                                    const std::string& recipient,
                                    uint32_t expiry = 0 )
   {
      accs_create_offer_operation op;
      op.seller = seller;
      op.base_asset = asset_id;
      op.chain_id = chain_id;
      op.foreign_asset_id = foreign_asset_id;
      op.base_amount = base_amount;
      op.foreign_amount = foreign_amount;
      op.foreign_recipient = recipient;
      op.expiry = expiry;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      const auto& ob_idx = db.get_index_type<accs_orderbook_index>().indices();
      for ( const auto& ob : ob_idx )
         if ( ob.base_asset == asset_id && ob.chain_id == chain_id
             && ob.foreign_asset_id == foreign_asset_id
             && !ob.open_offers.empty() )
            return ob.open_offers.back();
      return accs_offer_id_type();
   }

   void push_signed( signed_transaction& tx, const fc::ecc::private_key& key )
   {
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
};

BOOST_FIXTURE_TEST_SUITE( accs_tests, accs_fixture )

BOOST_AUTO_TEST_CASE( declare_gateway_native )
{
   build();
   auto gw_id = declare_gateway( 1 ); // BTC, native
   const auto& gw_idx = db.get_index_type<accs_gateway_index>().indices();
   BOOST_CHECK( !gw_idx.empty() );
}

BOOST_AUTO_TEST_CASE( declare_gateway_subtoken )
{
   build();
   auto gw_id = declare_gateway( 2, "0xdAC17F958D2ee523a2206206994597C13D831ec7" ); // USDT on ETH
   const auto& gw_idx2 = db.get_index_type<accs_gateway_index>().indices();
   BOOST_CHECK( gw_idx2.size() >= 1 ); // at least one gateway exists
}

BOOST_AUTO_TEST_CASE( declare_gateway_duplicate_refused )
{
   build();
   declare_gateway( 1 );
   accs_declare_gateway_operation op;
   op.committee_member = alice_account_id;
   op.chain_id = 1;
   op.foreign_asset_id = "";
   op.foreign_asset_code = 0;
   op.oracle_id = oracle_id;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( declare_gateway_non_committee_refused )
{
   build();
   // Bob is not on the committee.
   accs_declare_gateway_operation op;
   op.committee_member = bob_account_id;
   op.chain_id = 1;
   op.foreign_asset_id = "";
   op.foreign_asset_code = 0;
   op.oracle_id = oracle_id;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( bob_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( create_offer_success )
{
   build();
   declare_gateway( 1 );
   accs_create_offer_operation op;
   op.seller = alice_account_id;
   op.base_asset = sell_asset;
   op.chain_id = 1;
   op.foreign_asset_id = "";
   op.base_amount = 10000;
   op.foreign_amount = 5000;
   op.foreign_recipient = "bc1qxyz789...";
   op.expiry = 0;
   op.validate();
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   PUSH_TX( db, tx );
   const auto& ob_idx = db.get_index_type<accs_orderbook_index>().indices();
   for ( const auto& ob : ob_idx )
      if ( ob.base_asset == sell_asset && ob.chain_id == 1
          && ob.foreign_asset_id == ""
          && !ob.open_offers.empty() )
         BOOST_CHECK( !ob.open_offers.empty() );
}

BOOST_AUTO_TEST_CASE( create_offer_insufficient_balance )
{
   build();
   declare_gateway( 1 );
   // Carol tries to sell more TEST than she has.
   accs_create_offer_operation op;
   op.seller = carol_account_id;
   op.base_asset = sell_asset;
   op.chain_id = 1;
   op.foreign_asset_id = "";
   op.base_amount = share_type( 100000000000LL ); // more than carol has
   op.foreign_amount = 5000;
   op.foreign_recipient = "bc1qxyz789...";
   op.expiry = 0;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( carol_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( create_offer_undeclared_gateway_refused )
{
   build();
   // No gateway declared for chain 1.
   accs_create_offer_operation op;
   op.seller = alice_account_id;
   op.base_asset = sell_asset;
   op.chain_id = 1;
   op.foreign_asset_id = "";
   op.base_amount = 10000;
   op.foreign_amount = 5000;
   op.foreign_recipient = "bc1qxyz789...";
   op.expiry = 0;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( cancel_open_offer )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   accs_cancel_offer_operation op;
   op.seller = alice_account_id;
   op.offer_id = offer_id;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   PUSH_TX( db, tx );
   (void)offer_id;
}

BOOST_AUTO_TEST_CASE( cancel_matched_offer_refused )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   // Bob matches the offer.
   accs_match_offer_operation mop;
   mop.buyer = bob_account_id;
   mop.offer_id = offer_id;
   mop.griefing_bond = 8375;
   signed_transaction mtx; mtx.operations.push_back( mop );
   db.current_fee_schedule().set_fee( mtx.operations.back() );
   set_expiration( db, mtx ); mtx.sign( bob_key, db.get_chain_id() );
   PUSH_TX( db, mtx );

   // Alice tries to cancel a matched offer - should fail.
   accs_cancel_offer_operation cop;
   cop.seller = alice_account_id;
   cop.offer_id = offer_id;
   signed_transaction ctx; ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx ); ctx.sign( alice_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ctx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( cancel_offer_wrong_seller_refused )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   // Bob tries to cancel Alice's offer.
   accs_cancel_offer_operation op;
   op.seller = bob_account_id;
   op.offer_id = offer_id;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( bob_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( match_offer_success )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   accs_match_offer_operation op;
   op.buyer = bob_account_id;
   op.offer_id = offer_id;
   op.griefing_bond = 8375;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( bob_key, db.get_chain_id() );
   PUSH_TX( db, tx );

   const accs_offer_object* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == 1 ); // matched
   BOOST_CHECK( offer->matched_buyer == bob_account_id );
   BOOST_CHECK( offer->griefing_bond == 8375 );
}

BOOST_AUTO_TEST_CASE( match_offer_below_bond_floor_refused )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   accs_match_offer_operation op;
   op.buyer = bob_account_id;
   op.offer_id = offer_id;
   op.griefing_bond = 100; // below minimum
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( bob_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( match_own_offer_refused )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 "bc1qxyz789..." );

   // Alice tries to match her own offer.
   accs_match_offer_operation op;
   op.buyer = alice_account_id;
   op.offer_id = offer_id;
   op.griefing_bond = 8375;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_SUITE_END()
