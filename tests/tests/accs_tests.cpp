#include <boost/test/unit_test.hpp>
#include <iostream>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/accs_object.hpp>
#include <graphene/chain/accs_evaluator.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/accs_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/chain/hardfork.hpp>

#include <fc/crypto/hex.hpp>
#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;
using namespace graphene::protocol;

namespace {
// Per-chain recipient format contract (spec 3.1 "validated per chain"):
// conservative charset + length bounds; no address checksums in consensus.
const std::string VALID_RECIPIENT_BTC = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const std::string VALID_RECIPIENT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7";
const std::string VALID_RECIPIENT_SOL = "4wLY4ZcWLn6kzscD9VV6kBjqDwTvXSYvBG3jqv7YzaXX";

constexpr int64_t RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t ORACLE_USD_CENTS = 1005000;
const share_type ORACLE_RAW = share_type( int64_t( ORACLE_USD_CENTS ) * RAW_PER_USD_CENT );

std::string tx_hash_hex( const graphene::protocol::foreign_tx_value& v )
{
   return fc::to_hex( reinterpret_cast<const char*>( v.tx_id.hash.data() ), 32 );
}
}

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
                                         const std::string& foreign_asset_id = "",
                                         uint64_t fee_bump = 0 )
   {
      accs_declare_gateway_operation op;
      op.committee_member = alice_account_id;
      op.chain_id = chain_id;
      op.foreign_asset_id = foreign_asset_id;
      op.foreign_asset_code = 0;
      op.oracle_id = oracle_id;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      if( fee_bump > 0 )
         tx.operations.back().get<accs_declare_gateway_operation>().fee.amount += fee_bump;
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      const auto& gw_idx = db.get_index_type<accs_gateway_index>().indices();
      for ( const auto& gw : gw_idx )
         if ( gw.chain_id == chain_id && gw.foreign_asset_id == foreign_asset_id )
            return accs_gateway_id_type( gw.id );
      return accs_gateway_id_type();
   }

   void declare_gateway_expect_throw( uint8_t chain_id )
   {
      accs_declare_gateway_operation op;
      op.committee_member = alice_account_id;
      op.chain_id = chain_id;
      op.foreign_asset_id = "";
      op.foreign_asset_code = 0;
      op.oracle_id = oracle_id;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   void deactivate_gateway( uint8_t chain_id, const std::string& foreign_asset_id = "" )
   {
      accs_deactivate_gateway_operation op;
      op.committee_member = alice_account_id;
      op.chain_id = chain_id;
      op.foreign_asset_id = foreign_asset_id;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   accs_offer_id_type create_offer( account_id_type seller,
                                    asset_id_type asset_id,
                                    uint8_t chain_id,
                                    const std::string& foreign_asset_id,
                                    share_type base_amount,
                                    share_type foreign_amount,
                                    const std::string& recipient,
                                    uint32_t expiry = 0,
                                    const fc::ecc::private_key& key = fc::ecc::private_key(),
                                    uint64_t fee_bump = 0 )
   {
      const fc::ecc::private_key& signer =
         ( key == fc::ecc::private_key() ) ? alice_key : key;
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
      if( fee_bump > 0 )
         tx.operations.back().get<accs_create_offer_operation>().fee.amount += fee_bump;
      set_expiration( db, tx ); tx.sign( signer, db.get_chain_id() );
      PUSH_TX( db, tx );
      const auto& ob_idx = db.get_index_type<accs_orderbook_index>().indices();
      for ( const auto& ob : ob_idx )
         if ( ob.base_asset == asset_id && ob.chain_id == chain_id
             && ob.foreign_asset_id == foreign_asset_id
             && !ob.open_offers.empty() )
            return ob.open_offers.back();
      return accs_offer_id_type();
   }

   void match_offer( accs_offer_id_type offer_id, account_id_type buyer,
                     const fc::ecc::private_key& key, share_type bond = 8375 )
   {
      accs_match_offer_operation op;
      op.buyer = buyer;
      op.offer_id = offer_id;
      op.griefing_bond = bond;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   void match_offer_unique( accs_offer_id_type offer_id, account_id_type buyer,
                            const fc::ecc::private_key& key )
   {
      // Same-shape match as match_offer with a one-atom-higher bond so the tx
      // id differs from a structurally identical prior match inside one block.
      match_offer( offer_id, buyer, key, 8376 );
   }

   void fulfill_offer( accs_offer_id_type offer_id, account_id_type publisher,
                       const fc::ecc::private_key& key, const std::string& hash,
                       share_type amount )
   {
      accs_fulfill_operation op;
      op.publisher = publisher;
      op.offer_id = offer_id;
      op.foreign_tx_hash = hash;
      op.amount = amount;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   void claim_griefing( accs_offer_id_type offer_id, account_id_type claimer,
                        const fc::ecc::private_key& key )
   {
      accs_claim_griefing_operation op;
      op.claimer = claimer;
      op.offer_id = offer_id;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   /// Lock a live producer bond for the fixture's oracle producer (needed by
   /// fulfill's attestor check; mirrors the F1 foreign-tx test recipe).
   void lock_producer_bond( account_id_type producer, const fc::ecc::private_key& key )
   {
      vesting_balance_create_operation vop;
      vop.creator = producer;
      vop.owner = producer;
      vop.amount = asset( ORACLE_RAW, asset_id_type() );
      vop.policy = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC,
         db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
      signed_transaction vtx; vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx ); vtx.sign( key, db.get_chain_id() );
      vesting_balance_id_type vid {
         PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };

      oracle_bond_lock_operation bop;
      bop.producer = producer;
      bop.oracle = oracle_id;
      bop.vesting_balance = vid;
      bop.bond_amount = ORACLE_RAW;
      bop.bond_usd_cents = ORACLE_USD_CENTS;
      signed_transaction btx; btx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( btx.operations.back() );
      set_expiration( db, btx ); btx.sign( key, db.get_chain_id() );
      PUSH_TX( db, btx );
   }

   /// Publish + promote a lock record through the F1 oracle shell so fulfill's
   /// h2_read_foreign_tx can read it (mirrors the F1 foreign-tx test recipe).
   graphene::protocol::foreign_tx_value promote_lock( uint8_t hash_b0, int64_t amount,
                                            uint64_t height )
   {
      graphene::protocol::foreign_tx_value val;
      val.chain = graphene::protocol::foreign_chain_id::bitcoin;
      val.tx_id.hash[0] = hash_b0;
      val.kind = graphene::protocol::foreign_tx_kind::lock;
      val.amount = amount;
      val.foreign_asset_id = 0;
      val.confirmation_height = height;
      val.confirmation_count = 100;

      h2_ensure_oracle_econ( db, oracle_id );
      db.modify( oracle_id( db ), [&]( oracle_object& o ) {
         o.consumed_foreign_value = std::vector<graphene::protocol::foreign_tx_value>{ val };
         o.consumed_foreign_value_time = db.head_block_time();
         if( !o.options.producers.empty() ) {
            account_id_type p = o.options.producers.begin()->first;
            o.submissions[p] = std::make_pair( db.head_block_time(),
               std::vector<oracle_value>{} );
         }
      } );

      const auto& gidx = db.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
      const auto gitr = gidx.find( oracle_id );
      if( gitr == gidx.end() ) return val;
      const guard_state_object* g = &*gitr;
      uint32_t delay = db.get_global_properties().parameters.get_oracle_guard_delay_sec();
      uint32_t anchor = graphene::protocol::h2_osm_bucket_anchor( uint32_t( db.head_block_time().sec_since_epoch() ), delay );
      db.modify( *g, [&]( guard_state_object& gg ) {
         h2_promotion_record rec;
         rec.promote_time = db.head_block_time();
         rec.producer_count = oracle_id( db ).options.minimum_producers;
         rec.anchor = anchor;
         rec.delay_sec = delay;
         gg.promotion_log.push_back( rec );
         gg.foreign_promotion_log.push_back( rec );
         gg.last_promo_time = db.head_block_time();
      } );
      return val;
   }

   /// Full path to a matched offer on the bitcoin native gateway, ready for
   /// fulfill: declares gateway 0, creates + matches the offer.
   accs_offer_id_type prepare_match_btc( account_id_type seller,
                                         const fc::ecc::private_key& key,
                                         share_type base_amount = 10000,
                                         share_type foreign_amount = 5000,
                                         account_id_type buyer = account_id_type() )
   {
      account_id_type b = ( buyer == account_id_type() ) ? bob_account_id : buyer;
      declare_gateway( 0 );
      auto offer_id = create_offer( seller, sell_asset, 0, "",
                                    base_amount, foreign_amount, VALID_RECIPIENT_BTC,
                                    0, key );
      match_offer( offer_id, b, bob_key );
      return offer_id;
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
   auto gw_id = declare_gateway( 1 ); // ETH, native
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
   op.foreign_recipient = VALID_RECIPIENT_ETH;
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
   op.foreign_recipient = VALID_RECIPIENT_ETH;
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
   op.foreign_recipient = VALID_RECIPIENT_ETH;
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
                                 VALID_RECIPIENT_ETH );

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
                                 VALID_RECIPIENT_ETH );

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
                                 VALID_RECIPIENT_ETH );

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
                                 VALID_RECIPIENT_ETH );

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
                                 VALID_RECIPIENT_ETH );

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
                                 VALID_RECIPIENT_ETH );

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

// ---------------------------------------------------------------------------
// F1F2-C01 / I01 / I02: durable, instance-independent consumed-tx set
// ---------------------------------------------------------------------------

/// Consume a tx through fulfill, deactivate the gateway, redeclare it, then
/// attempt to consume the same tx through a fresh offer: must refuse. The
/// consumed-tx set is keyed by (chain_id, foreign_asset_id, tx) on a durable
/// record and survives every gateway lifecycle event.
BOOST_AUTO_TEST_CASE( f1f2_c01_redeclaration_does_not_reset_consumed_tx )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA1, 5000, 100 );
   std::string hash = tx_hash_hex( val );
   fulfill_offer( offer_id, alice_account_id, alice_key, hash, 5000 );

   deactivate_gateway( 0 );
   declare_gateway( 0, "", 1 ); // redeclare the (0, "") pair; fee bump keeps
                                // the tx id distinct from the first declare

   auto offer2 = create_offer( alice_account_id, sell_asset, 0, "", 10000, 5000,
                               VALID_RECIPIENT_BTC, 0, alice_key, 1 );
   match_offer_unique( offer2, bob_account_id, bob_key );
   BOOST_CHECK_THROW(
      fulfill_offer( offer2, alice_account_id, alice_key, hash, 5000 ),
      fc::exception );

   // The durable set still holds the consumed tx: one record for the pair.
   const auto& cidx = db.get_index_type<accs_consumed_tx_index>()
                         .indices().get<by_chain_asset_tx>();
   BOOST_REQUIRE( cidx.find( boost::make_tuple( uint8_t(0), std::string(),
                                                val.tx_id ) ) != cidx.end() );
}

/// The same tx hash in a different case still refuses when the decoded bytes
/// match a consumed tx: comparison is byte equality on canonical lowercase
/// hex enforced at validate().
BOOST_AUTO_TEST_CASE( fulfill_noncanonical_case_hash_still_refused )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA2, 5000, 100 );
   std::string hash = tx_hash_hex( val );
   fulfill_offer( offer_id, alice_account_id, alice_key, hash, 5000 );

   deactivate_gateway( 0 );
   declare_gateway( 0, "", 1 );
   auto offer2 = create_offer( alice_account_id, sell_asset, 0, "", 10000, 5000,
                               VALID_RECIPIENT_BTC, 0, alice_key, 1 );
   match_offer_unique( offer2, bob_account_id, bob_key );
   std::string upper(hash);
   for( auto& c : upper ) c = std::toupper( static_cast<unsigned char>( c ) );
   BOOST_CHECK_THROW(
      fulfill_offer( offer2, alice_account_id, alice_key, upper, 5000 ),
      fc::exception );
}

/// Replay against the same (not redeclared) gateway: a second matched offer
/// cannot be fulfilled with an already-consumed tx hash.
BOOST_AUTO_TEST_CASE( fulfill_replay_same_tx_refused )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA3, 5000, 100 );
   std::string hash = tx_hash_hex( val );
   fulfill_offer( offer_id, alice_account_id, alice_key, hash, 5000 );

   auto offer2 = create_offer( alice_account_id, sell_asset, 0, "", 10000, 5000,
                               VALID_RECIPIENT_BTC, 0, alice_key, 1 );
   match_offer_unique( offer2, bob_account_id, bob_key );
   BOOST_CHECK_THROW(
      fulfill_offer( offer2, alice_account_id, alice_key, hash, 5000 ),
      fc::exception );
}

/// The durable consumed-tx set is hard-capped per (chain, asset) pair. At the
/// cap fulfill fails closed: the tx is not consumed, no guard is evicted, and
/// the record count does not grow past the cap.
BOOST_AUTO_TEST_CASE( consumed_set_cap_fails_closed )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xC0, 5000, 100 );
   val.tx_id.hash[31] = 0xFF; // distinct from the seeded bytes below
   std::string hash = tx_hash_hex( val );

   for( uint32_t i = 0; i < GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR; ++i )
      db.create<accs_consumed_tx_object>( [&]( accs_consumed_tx_object& c ) {
         c.chain_id = 0;
         c.foreign_asset_id = "";
         c.tx.hash[0] = uint8_t( i & 0xff );
         c.tx.hash[1] = uint8_t( ( i >> 8 ) & 0xff );
         c.consumed_block = 1;
      } );
   // The counter is op-path state resynced from rows at (re)declaration;
   // the direct-row seeding above models a pair whose durable set has
   // reached the cap, so the counter reads the cap too.
   const auto& gwsm_idx = db.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   auto gwsm_itr = gwsm_idx.find( boost::make_tuple( uint8_t(0), std::string() ) );
   BOOST_REQUIRE( gwsm_itr != gwsm_idx.end() );
   db.modify( *gwsm_itr, []( accs_gateway_object& g ) {
      g.consumed_tx_count = GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR;
   } );

   BOOST_CHECK_THROW(
      fulfill_offer( offer_id, alice_account_id, alice_key, hash, 5000 ),
      fc::exception );

   const auto& cidx = db.get_index_type<accs_consumed_tx_index>()
                         .indices().get<by_chain_asset_tx>();
   BOOST_REQUIRE( cidx.find( boost::make_tuple( uint8_t(0), std::string(),
                                                val.tx_id ) ) == cidx.end() );
   auto lower = cidx.lower_bound( boost::make_tuple( uint8_t(0), std::string(),
                                                     graphene::protocol::foreign_tx_id() ) );
   auto upper = cidx.lower_bound( boost::make_tuple( uint8_t(1), std::string(),
                                                     graphene::protocol::foreign_tx_id() ) );
   BOOST_CHECK_EQUAL( std::distance( lower, upper ),
                      static_cast<long>( GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR ) );
}

// ---------------------------------------------------------------------------
// F1F2-I08 (partial): fulfill / claim / maintenance / replay coverage
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE( fulfill_equality_match_releases_escrow_to_buyer )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA4, 5000, 100 );
   std::string hash = tx_hash_hex( val );
   share_type bob_bts_before = db.get_balance( bob_account_id, asset_id_type() ).amount;
   share_type bob_test_before = db.get_balance( bob_account_id, sell_asset ).amount;
   fulfill_offer( offer_id, alice_account_id, alice_key, hash, 5000 );
   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == static_cast<uint8_t>( accs_offer_state::fulfilled ) );
   BOOST_CHECK_EQUAL( db.get_balance( bob_account_id, sell_asset ).amount.value,
                      ( bob_test_before + 10000 ).value );
   BOOST_CHECK_EQUAL( db.get_balance( bob_account_id, asset_id_type() ).amount.value,
                      ( bob_bts_before + 8375 ).value );
}

BOOST_AUTO_TEST_CASE( fulfill_wrong_tx_hash_refused )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA5, 5000, 100 );
   auto other = val; other.tx_id.hash[0] = 0xA6;
   BOOST_CHECK_THROW(
      fulfill_offer( offer_id, alice_account_id, alice_key, tx_hash_hex( other ), 5000 ),
      fc::exception );
}

BOOST_AUTO_TEST_CASE( fulfill_wrong_amount_refused )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA7, 5000, 100 );
   BOOST_CHECK_THROW(
      fulfill_offer( offer_id, alice_account_id, alice_key, tx_hash_hex( val ), 4999 ),
      fc::exception );
}

BOOST_AUTO_TEST_CASE( fulfill_zeroes_escrow_and_griefing_bond )
{
   build();
   lock_producer_bond( alice_account_id, alice_key );
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   auto val = promote_lock( 0xA8, 5000, 100 );
   fulfill_offer( offer_id, alice_account_id, alice_key, tx_hash_hex( val ), 5000 );
   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK_EQUAL( offer->escrow_balance.value, 0 );
   BOOST_CHECK_EQUAL( offer->griefing_bond.value, 0 );
}

BOOST_AUTO_TEST_CASE( claim_griefing_before_sla_refused )
{
   build();
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   BOOST_CHECK_THROW( claim_griefing( offer_id, alice_account_id, alice_key ),
                      fc::exception );
}

BOOST_AUTO_TEST_CASE( claim_griefing_after_sla_pays_seller_and_returns_escrow )
{
   build();
   share_type alice_test_before = db.get_balance( alice_account_id, sell_asset ).amount;
   auto offer_id = prepare_match_btc( alice_account_id, alice_key );
   share_type alice_bts_at_match = db.get_balance( alice_account_id, asset_id_type() ).amount;
   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   db.modify( *offer, []( accs_offer_object& o ) { o.sla_deadline = 1; } );

   accs_claim_griefing_operation cop;
   cop.claimer = alice_account_id;
   cop.offer_id = offer_id;
   signed_transaction ctx; ctx.operations.push_back( cop );
   asset claim_fee = db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx ); ctx.sign( alice_key, db.get_chain_id() );
   PUSH_TX( db, ctx );

   offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == static_cast<uint8_t>( accs_offer_state::expired ) );
   BOOST_CHECK_EQUAL( offer->escrow_balance.value, 0 );
   BOOST_CHECK_EQUAL( offer->griefing_bond.value, 0 );
   // Bond moved to the seller minus the claim fee; escrow restored exactly.
   BOOST_CHECK_EQUAL( db.get_balance( alice_account_id, asset_id_type() ).amount.value,
                      ( alice_bts_at_match + 8375 - claim_fee.amount ).value );
   BOOST_CHECK_EQUAL( db.get_balance( alice_account_id, sell_asset ).amount.value,
                      alice_test_before.value );
}

BOOST_AUTO_TEST_CASE( expired_offer_released_by_maintenance_sweep )
{
   build();
   declare_gateway( 1 );
   uint32_t head = db.head_block_num();
   share_type alice_before = db.get_balance( alice_account_id, sell_asset ).amount;
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 VALID_RECIPIENT_ETH, head + 200 );
   generate_blocks( head + 201 );
   process_accs_maintenance( db );
   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == static_cast<uint8_t>( accs_offer_state::expired ) );
   BOOST_CHECK_EQUAL( offer->escrow_balance.value, 0 );
   BOOST_CHECK_EQUAL( db.get_balance( alice_account_id, sell_asset ).amount.value,
                      alice_before.value );
}

BOOST_AUTO_TEST_CASE( open_offer_not_released_before_expiry )
{
   build();
   declare_gateway( 1 );
   uint32_t head = db.head_block_num();
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 VALID_RECIPIENT_ETH, head + 200 );
   process_accs_maintenance( db );
   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == static_cast<uint8_t>( accs_offer_state::open ) );
   BOOST_CHECK_EQUAL( offer->escrow_balance.value, 10000 );
}

// ---------------------------------------------------------------------------
// ACCS-I06 (F1F2-I02): offer vectors are bounded
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE( accs_i06_offer_vectors_are_bounded )
{
   build();
   declare_gateway( 2 ); // one orderbook: (TEST, 2, "")

   // Issue TEST to bob, carol, dave so they can escrow their own offers.
   auto issue_test = [&]( account_id_type to, share_type amount,
                          const fc::ecc::private_key& recv_key )
   {
      asset_issue_operation iop;
      iop.issuer = alice_account_id;
      iop.asset_to_issue = asset( amount, sell_asset );
      iop.issue_to_account = to;
      signed_transaction tx; tx.operations.push_back( iop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      (void)recv_key;
   };
   issue_test( bob_account_id, share_type( 5000 ), bob_key );
   issue_test( carol_account_id, share_type( 5000 ), carol_key );
   issue_test( dave_account_id, share_type( 5000 ), dave_key );

   // Per-account cap: alice creates ACCOUNT_CAP offers, then is refused while
   // the orderbook cap is still far away. Offer expiry offsets keep every tx
   // id unique inside one block (identical ops would collide on tx id).
   uint32_t head = db.head_block_num();
   for( uint32_t i = 0; i < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ACCOUNT; ++i )
      create_offer( alice_account_id, sell_asset, 2, "", 10, 10,
                    VALID_RECIPIENT_SOL, head + 300 + i );
   BOOST_CHECK_THROW(
      create_offer( alice_account_id, sell_asset, 2, "", 10, 10, VALID_RECIPIENT_SOL ),
      fc::exception );
   // A different account is unbound by alice's cap.
   auto bob_offer = create_offer( bob_account_id, sell_asset, 2, "", 10, 10,
                                  VALID_RECIPIENT_SOL, head + 600, bob_key );

   // Per-orderbook cap: fill the same orderbook to its cap with other
   // accounts (each account below the per-account cap), then refuse.
   for( uint32_t i = 1; i < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ACCOUNT; ++i )
      create_offer( bob_account_id, sell_asset, 2, "", 10, 10,
                    VALID_RECIPIENT_SOL, head + 600 + i, bob_key );
   for( uint32_t i = 0; i < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ACCOUNT - 6; ++i )
      create_offer( carol_account_id, sell_asset, 2, "", 10, 10,
                    VALID_RECIPIENT_SOL, head + 901 + i, carol_key );
   for( uint32_t i = 0; i < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ACCOUNT - 18; ++i )
      create_offer( dave_account_id, sell_asset, 2, "", 10, 10,
                    VALID_RECIPIENT_SOL, head + 1251 + i, dave_key );
   const auto& ob_idx = db.get_index_type<accs_orderbook_index>().indices();
   for( const auto& ob : ob_idx )
      if( ob.base_asset == sell_asset && ob.chain_id == 2
          && ob.foreign_asset_id == "" )
         BOOST_CHECK_EQUAL( ob.open_offers.size(), GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ORDERBOOK );
   BOOST_CHECK_THROW(
      create_offer( carol_account_id, sell_asset, 2, "", 10, 10,
                    VALID_RECIPIENT_SOL, head + 1251, carol_key ),
      fc::exception );
   (void)bob_offer;
}

// ---------------------------------------------------------------------------
// ACCS-M09 / M06 / M08 / N05 and the refactor invariants (M07 / M10 / M11)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE( match_refused_against_deactivated_gateway )
{
   build();
   declare_gateway( 1 );
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 VALID_RECIPIENT_ETH );
   deactivate_gateway( 1 );
   accs_match_offer_operation op;
   op.buyer = bob_account_id;
   op.offer_id = offer_id;
   op.griefing_bond = 8375;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( bob_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_CASE( create_offer_recipient_format_enforced )
{
   build();
   declare_gateway( 0 );
   declare_gateway( 1 );
   declare_gateway( 2 );

   // BTC: too short, forbidden charset (dash), then a well-formed address.
   BOOST_CHECK_THROW( create_offer( alice_account_id, sell_asset, 0, "", 10000,
                                    5000, "bc1q" ), fc::exception );
   BOOST_CHECK_THROW( create_offer( alice_account_id, sell_asset, 0, "", 10000,
                                    5000, std::string( 40, 'a' ) + "--" ),
                      fc::exception );
   create_offer( alice_account_id, sell_asset, 0, "", 10000, 5000,
                 VALID_RECIPIENT_BTC );

   // ETH: non-hex letter, wrong length, then a well-formed address.
   BOOST_CHECK_THROW( create_offer( alice_account_id, sell_asset, 1, "", 10000,
                                    5000, "0xdac17f958d2ee523a2206206994597c13d831ecg" ),
                      fc::exception );
   BOOST_CHECK_THROW( create_offer( alice_account_id, sell_asset, 1, "", 10000,
                                    5000, "0xdac17f958d2ee523a2206206994597c13d831ec" ),
                      fc::exception );
   create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                 VALID_RECIPIENT_ETH );

   // SOL: base58-forbidden '0', then a well-formed address.
   std::string sol_bad = VALID_RECIPIENT_SOL;
   sol_bad.replace( 0, 1, 1, '0' );
   BOOST_CHECK_THROW( create_offer( alice_account_id, sell_asset, 2, "", 10000,
                                    5000, sol_bad ), fc::exception );
   create_offer( alice_account_id, sell_asset, 2, "", 10000, 5000,
                 VALID_RECIPIENT_SOL );
}

BOOST_AUTO_TEST_CASE( declare_gateway_chain_out_of_range_refused )
{
   build();
   BOOST_CHECK_THROW( declare_gateway_expect_throw( 3 ), fc::exception );
}

BOOST_AUTO_TEST_CASE( redeclaration_reuses_inactive_record )
{
   build();
   declare_gateway( 1 );
   deactivate_gateway( 1 );
   declare_gateway( 1, "", 1 ); // redeclare after deactivation; fee bump
                                // keeps the tx id distinct from the first
   const auto& gw_idx = db.get_index_type<accs_gateway_index>().indices();
   size_t n = 0;
   for( const auto& gw : gw_idx )
      if( gw.chain_id == 1 && gw.foreign_asset_id == "" )
         ++n;
   BOOST_CHECK_EQUAL( n, 1 );
}

BOOST_AUTO_TEST_CASE( offer_lifecycle_release_invariants )
{
   build();
   declare_gateway( 1 );
   share_type alice_before = db.get_balance( alice_account_id, sell_asset ).amount;
   auto offer_id = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                                 VALID_RECIPIENT_ETH );

   accs_cancel_offer_operation op;
   op.seller = alice_account_id;
   op.offer_id = offer_id;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( alice_key, db.get_chain_id() );
   PUSH_TX( db, tx );

   const auto* offer = db.find( offer_id );
   BOOST_REQUIRE( offer != nullptr );
   BOOST_CHECK( offer->state == static_cast<uint8_t>( accs_offer_state::cancelled ) );
   BOOST_CHECK_EQUAL( offer->escrow_balance.value, 0 );
   BOOST_CHECK_EQUAL( db.get_balance( alice_account_id, sell_asset ).amount.value,
                      alice_before.value );
}

BOOST_AUTO_TEST_CASE( orderbooks_are_distinct_per_pair )
{
   build();
   declare_gateway( 1 );
   declare_gateway( 2 );
   auto o1 = create_offer( alice_account_id, sell_asset, 1, "", 10000, 5000,
                           VALID_RECIPIENT_ETH );
   auto o2 = create_offer( alice_account_id, sell_asset, 2, "", 10000, 5000,
                           VALID_RECIPIENT_SOL );
   const auto& ob_idx = db.get_index_type<accs_orderbook_index>().indices();
   BOOST_CHECK_EQUAL( ob_idx.size(), 2 );
   const auto* off1 = db.find( o1 );
   const auto* off2 = db.find( o2 );
   BOOST_REQUIRE( off1 != nullptr && off2 != nullptr );
   BOOST_CHECK( off1->orderbook != off2->orderbook );
}

/// The declaration-time counter resync is per (chain, asset) pair: rows
/// consumed on a different chain must not inflate this pair's counter.
/// (F1F2-C01 follow-up: cross-pair over-count in the resync loop.)
BOOST_AUTO_TEST_CASE( accs_consumed_tx_count_resync_is_per_pair )
{
   build();
   // Seed consumed rows on chain 2 (a different chain than the one declared).
   for( uint32_t i = 0; i < 5; ++i )
      db.create<accs_consumed_tx_object>( [&]( accs_consumed_tx_object& c ) {
         c.chain_id = 2;
         c.foreign_asset_id = "other-pair";
         c.tx.hash[0] = uint8_t( i );
         c.consumed_block = 1;
      } );

   // Declare a chain-1 gateway; its counter must reflect only chain-1 rows.
   declare_gateway( 1 );
   const auto& gw_idx = db.get_index_type<accs_gateway_index>()
                           .indices().get<by_chain_asset>();
   auto gw = gw_idx.find( boost::make_tuple( uint8_t(1), std::string() ) );
   BOOST_REQUIRE( gw != gw_idx.end() );
   BOOST_CHECK_EQUAL( gw->consumed_tx_count, 0u );
}

BOOST_AUTO_TEST_SUITE_END()
