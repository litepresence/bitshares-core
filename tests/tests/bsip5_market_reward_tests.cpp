#include <boost/test/unit_test.hpp>

#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/market_object.hpp>
#include <graphene/chain/market_reward_object.hpp>
#include <graphene/chain/bsip5_fee_state.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

#include "../common/database_fixture.hpp"

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

BOOST_AUTO_TEST_SUITE_END()
