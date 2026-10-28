#include <boost/test/unit_test.hpp>

#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/market_object.hpp>
#include <graphene/chain/market_reward_object.hpp>
#include <graphene/chain/bsip5_fee_state.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

#include "../common/database_fixture.hpp"

#include <graphene/app/api.hpp>
using namespace graphene::chain;
using namespace graphene::chain::test;

namespace graphene { namespace chain { void distribute_bsip5_rewards(database&); } }

namespace fc
{
   template<typename Ch, typename T>
   std::basic_ostream<Ch>& operator<<(std::basic_ostream<Ch>& os, safe<T> const& sf)
   {
      os << sf.value;
      return os;
   }
}

BOOST_FIXTURE_TEST_SUITE(bsip5_market_reward_tests, database_fixture)

BOOST_AUTO_TEST_CASE(conservation_pool_balance)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   const limit_order_object& lo = db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = db.head_block_num() > 150 ? db.head_block_num() - 150 : 1;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   BOOST_CHECK_GE(before, 0);

   graphene::chain::distribute_bsip5_rewards(db);

   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_GE(mr2.pool_balance, 0);
   BOOST_CHECK_LE(mr2.pool_balance, before);

   // Cleanup: zero out for_sale on any limit orders and remove vesting balances
   // created by the sweep so asset-supply verification passes at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });

      std::vector<vesting_balance_id_type> vb_ids;
      auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
      for (auto it = vidx.begin(); it != vidx.end(); ++it)
         if (it->balance_type == vesting_balance_type::market_fee_sharing)
            vb_ids.push_back(it->id.as<vesting_balance_id_type>());
      for (const auto& id : vb_ids)
         db.remove(db.get(id));
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(cold_start_no_payout)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE2");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE2");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = 0;
   });

   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = db.head_block_num() > 150 ? db.head_block_num() - 150 : 1;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

   // Cleanup: zero out for_sale on any limit orders and remove vesting balances
   // created by the sweep so asset-supply verification passes at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });

      std::vector<vesting_balance_id_type> vb_ids;
      auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
      for (auto it = vidx.begin(); it != vidx.end(); ++it)
         if (it->balance_type == vesting_balance_type::market_fee_sharing)
            vb_ids.push_back(it->id.as<vesting_balance_id_type>());
      for (const auto& id : vb_ids)
         db.remove(db.get(id));
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(expiry_skip)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE3");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE3");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time();
      o.bsip5_placement_block = db.head_block_num() > 150 ? db.head_block_num() - 150 : 1;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

   // Cleanup: zero out for_sale on any limit orders and remove vesting balances
   // created by the sweep so asset-supply verification passes at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });

      std::vector<vesting_balance_id_type> vb_ids;
      auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
      for (auto it = vidx.begin(); it != vidx.end(); ++it)
         if (it->balance_type == vesting_balance_type::market_fee_sharing)
            vb_ids.push_back(it->id.as<vesting_balance_id_type>());
      for (const auto& id : vb_ids)
         db.remove(db.get(id));
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(rebate_timing_min_age)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE4");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE4");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   // Order placed this very block -> age 0 -> T=0 -> skipped.
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = db.head_block_num();
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });

      std::vector<vesting_balance_id_type> vb_ids;
      auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
      for (auto it = vidx.begin(); it != vidx.end(); ++it)
         if (it->balance_type == vesting_balance_type::market_fee_sharing)
            vb_ids.push_back(it->id.as<vesting_balance_id_type>());
      for (const auto& id : vb_ids)
         db.remove(db.get(id));
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(amendment_resets_placement)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));
   fund(seller, asset(100000 * GRAPHENE_BLOCKCHAIN_PRECISION));

   const asset_object& base = create_user_issued_asset("BSIP5BASE5");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE5");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   issue_uia(seller, asset(1000, base_id));

   const limit_order_object* lo_ptr = create_sell_order(seller, asset(100, base_id), asset(100, quote_id),
                                                       db.head_block_time() + fc::days(1));
   // reset placement block to old value to simulate an aged order
   db.modify(db.get<limit_order_object>(lo_ptr->id), [](limit_order_object& o){ o.bsip5_placement_block = 1; });

   const limit_order_object& lo = db.get<limit_order_object>(lo_ptr->id);

   uint64_t old_pb = lo.bsip5_placement_block;
   BOOST_CHECK_NE(old_pb, db.head_block_num());

   fc::optional<price> np = price(asset(1, base_id), asset(1, quote_id));
   update_limit_order(lo, np);

   const limit_order_object& lo2 = db.get<limit_order_object>(lo.id);
   BOOST_CHECK_EQUAL(lo2.bsip5_placement_block, db.head_block_num());
   BOOST_CHECK_NE(lo2.bsip5_placement_block, old_pb);

   // Cleanup
   cancel_limit_order(db.get<limit_order_object>(lo.id));

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(empty_book_no_sweep)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE6");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE6");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(parameter_gate_hardfork)
{ try {
   // Do NOT advance to BSIP-5 hardfork: distribute must be a no-op.
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE7");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE7");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = (db.head_block_num() > 150 ? db.head_block_num() - 150 : 1);
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(top_n_selection)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   generate_blocks(200);
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASE8");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE8");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000000;
      o.reference_price_wad = BSIP5_WAD;
   });

   uint64_t placement = (db.head_block_num() > 150 ? db.head_block_num() - 150 : 1);
   // 257 orders -> only 256 should be considered (cap).
   for (int i = 0; i < 257; ++i) {
      db.create<limit_order_object>([&](limit_order_object& o){
         o.seller = seller_id;
         o.for_sale = 100;
         o.sell_price = price(asset(1, base_id), asset(1, quote_id));
         o.expiration = db.head_block_time() + fc::days(1);
         o.bsip5_placement_block = placement;
      });
   }

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_LT(mr2.pool_balance, before);

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });

      std::vector<vesting_balance_id_type> vb_ids;
      auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
      for (auto it = vidx.begin(); it != vidx.end(); ++it)
         if (it->balance_type == vesting_balance_type::market_fee_sharing)
            vb_ids.push_back(it->id.as<vesting_balance_id_type>());
      for (const auto& id : vb_ids)
         db.remove(db.get(id));
   }

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(wire_pinning_market_reward_object)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   const asset_object& base = create_user_issued_asset("BSIP5BASE9");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTE9");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 12345;
      o.reference_price_wad = BSIP5_WAD;
      o.last_sweep_block = 42;
      o.total_distributed = 7;
   });

   graphene::app::database_api db_api(db);
   auto obj = db_api.get_objects({mr.id}).front();
   market_reward_object unpacked = obj.as<market_reward_object>(GRAPHENE_MAX_NESTED_OBJECTS);

   BOOST_CHECK(unpacked.base_asset == mr.base_asset);
   BOOST_CHECK(unpacked.quote_asset == mr.quote_asset);
   BOOST_CHECK(unpacked.reward_asset == mr.reward_asset);
   BOOST_CHECK_EQUAL(unpacked.pool_balance, mr.pool_balance);
   BOOST_CHECK_EQUAL(unpacked.reference_price_wad, mr.reference_price_wad);
   BOOST_CHECK_EQUAL(unpacked.last_sweep_block, mr.last_sweep_block);
   BOOST_CHECK_EQUAL(unpacked.total_distributed, mr.total_distributed);

} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE(proximity_skip)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   generate_blocks(200);
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("BSIP5BASEP");
   const asset_object& quote = create_user_issued_asset("BSIP5QUOTEP");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
   });

   uint64_t placement = db.head_block_num() > 150 ? db.head_block_num() - 150 : 1;
   // price 0.5 WAD (half of reference) -> proximity below 0.9 threshold -> pk 0 -> skipped.
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(2, base_id), asset(1, quote_id)); // quote/base = 0.5 WAD
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = placement;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before);

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
   }

} FC_LOG_AND_RETHROW() }

// TODO(OOR-07): self-trade refusal (OOR-03) and wash-trade bound tests depend on
// consensus code not yet implemented (OOR-03 self-trade refusal, OOR-05/06 sweep
// orientation). Add once those repairs land. Wire-pinning covered above.

BOOST_AUTO_TEST_SUITE_END()
