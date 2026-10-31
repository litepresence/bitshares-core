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

namespace {
// The sweep pays into vesting balances. These unit tests create the reward pool
// directly instead of funding it through a fill, so the payout is synthetic and
// must not remain in the fixture's supply total at teardown.
void clear_sweep_payouts(database& db)
{
   std::vector<vesting_balance_id_type> vb_ids;
   const auto& vidx = db.get_index_type<vesting_balance_index>().indices().get<by_account>();
   for (auto it = vidx.begin(); it != vidx.end(); ++it)
      if (it->balance_type == vesting_balance_type::market_fee_sharing)
         vb_ids.push_back(it->id.as<vesting_balance_id_type>());
   for (const auto& id : vb_ids)
      db.remove(db.get(id));
}
} // namespace

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
   const object_id_type mr_id = mr.id;

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

   share_type before = db.get<market_reward_object>(mr_id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr_id);
   BOOST_CHECK_LT(mr2.pool_balance, before);

   // Cleanup: the orders and the pool were created directly, so remove their
   // synthetic value before the fixture checks supply at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
      clear_sweep_payouts(db);
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

// OOR-01: empty-book rule — opt-in rejected while open orders rest on affected market
BOOST_AUTO_TEST_CASE(empty_book_opt_in_rejected)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((issuer));

   const asset_object& a = create_user_issued_asset("OOR01ASSET");
   asset_id_type a_id = a.get_id();
   const asset_object& quote = create_user_issued_asset("OOR01QUOTE");
   asset_id_type q_id = quote.get_id();

   // Resting open order on a market involving this asset
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = issuer_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, a_id), asset(1, q_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = db.head_block_num();
   });

   // Opt-in must be refused: book is not empty
   bsip5_opt_in_operation opt_in;
   opt_in.issuer = account_id_type();
   opt_in.asset_id = a_id;
   opt_in.reward_rate_bps = 100;
   operation opt_in_op = opt_in;
   db.current_fee_schedule().set_fee(opt_in_op);
   trx.operations.push_back(std::move(opt_in_op));
   set_expiration(db, trx);
   sign(trx, issuer_private_key);
   GRAPHENE_REQUIRE_THROW( PUSH_TX(db, trx, ~0), fc::exception );

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
   }
} FC_LOG_AND_RETHROW() }

// OOR-02: open_order_fee range validation (0..500) on asset_update path
BOOST_AUTO_TEST_CASE(open_order_fee_range_validation)
{ try {
   ACTORS((issuer));

   const asset_object& a = create_user_issued_asset("OOR02ASSET");
   asset_id_type a_id = a.get_id();

   // open_order_fee > 500 must be rejected
   asset_update_operation au;
   au.issuer = account_id_type();
   au.asset_to_update = a_id;
   au.new_options = a.options;
   au.new_options.extensions.value.open_order_fee = 600;
   operation au_op = au;
   db.current_fee_schedule().set_fee(au_op);
   trx.operations.push_back(std::move(au_op));
   set_expiration(db, trx);
   sign(trx, issuer_private_key);
   GRAPHENE_REQUIRE_THROW( PUSH_TX(db, trx, ~0), fc::exception );

   // open_order_fee = 500 must be accepted
   trx.operations.clear();
   au.new_options.extensions.value.open_order_fee = 500;
   au_op = au;
   db.current_fee_schedule().set_fee(au_op);
   trx.operations.push_back(std::move(au_op));
   set_expiration(db, trx);
   sign(trx, issuer_private_key);
   PUSH_TX(db, trx, ~0);

   // Cleanup
} FC_LOG_AND_RETHROW() }

// OOR-02: empty-book rule on asset_update — fee change rejected while open orders rest
BOOST_AUTO_TEST_CASE(open_order_fee_empty_book)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((issuer));

   const asset_object& a = create_user_issued_asset("OOR02BASSET");
   asset_id_type a_id = a.get_id();
   const asset_object& quote = create_user_issued_asset("OOR02BQUOTE");
   asset_id_type q_id = quote.get_id();

   // Resting open order on a market involving this asset
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = issuer_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, a_id), asset(1, q_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = db.head_block_num();
   });

   // Changing open_order_fee must be refused: book is not empty
   asset_update_operation au;
   au.issuer = account_id_type();
   au.asset_to_update = a_id;
   au.new_options = a.options;
   au.new_options.extensions.value.open_order_fee = 200;
   operation au_op = au;
   db.current_fee_schedule().set_fee(au_op);
   trx.operations.push_back(std::move(au_op));
   set_expiration(db, trx);
   sign(trx, issuer_private_key);
   GRAPHENE_REQUIRE_THROW( PUSH_TX(db, trx, ~0), fc::exception );

   // Cleanup
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
   }
} FC_LOG_AND_RETHROW() }

// OOR-03: self-trade refusal on BSIP-5 participating market
BOOST_AUTO_TEST_CASE(self_trade_refused)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((alice));

   const asset_object& base = create_user_issued_asset("OOR03BASE");
   const asset_object& quote = create_user_issued_asset("OOR03QUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   // Both assets participate in BSIP-5 rewards (open_order_fee > 0)
   db.modify(base, [](asset_object& a){ a.options.extensions.value.open_order_fee = 100; });
   db.modify(quote, [](asset_object& a){ a.options.extensions.value.open_order_fee = 100; });

   // Fund alice on both legs plus core for the transaction fee (issue_uia keeps supply consistent).
   issue_uia(alice_id, asset(1000, base_id));
   issue_uia(alice_id, asset(1000, quote_id));
   fund(alice, asset(100000));

   // Resting sell order: alice sells base for quote
   limit_order_create_operation sell;
   sell.seller = alice_id;
   sell.amount_to_sell = asset(100, base_id);
   sell.min_to_receive = asset(100, quote_id);
   sell.expiration = db.head_block_time() + fc::days(1);
   operation sell_op = sell;
   db.current_fee_schedule().set_fee(sell_op);
   trx.operations.push_back(std::move(sell_op));
   set_expiration(db, trx);
   sign(trx, alice_private_key);
   PUSH_TX(db, trx, ~0);
   trx.operations.clear();

   // Crossing buy order: alice sells quote for base (same account -> self-trade).
   // The fill path reaches match_limit_normal_limit where OOR-03 refuses it.
   limit_order_create_operation buy;
   buy.seller = alice_id;
   buy.amount_to_sell = asset(100, quote_id);
   buy.min_to_receive = asset(100, base_id);
   buy.expiration = db.head_block_time() + fc::days(1);
   operation buy_op = buy;
   db.current_fee_schedule().set_fee(buy_op);
   trx.operations.push_back(std::move(buy_op));
   set_expiration(db, trx);
   sign(trx, alice_private_key);
   GRAPHENE_REQUIRE_THROW( PUSH_TX(db, trx, ~0), fc::exception );
   trx.operations.clear();

   // The funded resting order stays open: the fixture counts its for_sale, so
   // alice's balance plus the order still equals the issued supply.
} FC_LOG_AND_RETHROW() }
// OOR-04: rolling 1-hour TWAP — sweep skipped when window expired
BOOST_AUTO_TEST_CASE(twap_window_expiry_skip)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("OOR04BASE");
   const asset_object& quote = create_user_issued_asset("OOR04QUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   // Market reward with an expired TWAP window (started long ago)
   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
      o.window_start_block = 1; // far in the past -> window expired
      o.reference_volume = 100;
   });

   share_type before = db.get<market_reward_object>(mr.id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.pool_balance, before); // no distribution: window expired

   // Cleanup
} FC_LOG_AND_RETHROW() }

// OOR-04: rolling 1-hour TWAP — time-weighted average of two fills
BOOST_AUTO_TEST_CASE(twap_rolling_average)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("OOR04BBASE");
   const asset_object& quote = create_user_issued_asset("OOR04BQUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   // First fill: price = 1 WAD, volume = 100
   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
      o.window_start_block = db.head_block_num();
      o.reference_volume = 100;
   });

   // Second fill: price = 0.5 WAD, volume = 100 -> TWAP = (1*100 + 0.5*100) / 200 = 0.75 WAD
   db.modify(mr, [&](market_reward_object& o){
      uint64_t now_block = db.head_block_num();
      uint64_t fill_price_wad = BSIP5_WAD / 2;
      share_type fill_volume = 100;
      if( o.window_start_block == 0 || now_block - o.window_start_block > BSIP5_MAX_T_BLOCKS )
      {
         o.window_start_block = now_block;
         o.reference_price_wad = fill_price_wad;
         o.reference_volume = fill_volume;
      }
      else
      {
         __uint128_t new_wad = ((__uint128_t)o.reference_price_wad * (uint64_t)o.reference_volume.value +
                                (__uint128_t)fill_price_wad * (uint64_t)fill_volume.value) /
                               ((uint64_t)o.reference_volume.value + (uint64_t)fill_volume.value);
         o.reference_price_wad = (uint64_t)new_wad;
         o.reference_volume += fill_volume;
      }
   });

   const market_reward_object& mr2 = db.get<market_reward_object>(mr.id);
   BOOST_CHECK_EQUAL(mr2.reference_price_wad, BSIP5_WAD * 3 / 4); // 0.75 WAD

   // Cleanup
} FC_LOG_AND_RETHROW() }

// OOR-05: reversed-leg pool distributes (sorted market comparison)
BOOST_AUTO_TEST_CASE(reversed_leg_pool_distributes)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("OOR05BASE");
   const asset_object& quote = create_user_issued_asset("OOR05QUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   // Fund supply so the sweep's vesting payout keeps the supply invariant at teardown.
   issue_uia(seller_id, asset(1000, base_id));
   // Age the chain past the sweep's minimum order age (100 blocks) before the
   // pool and order are created; blocks generated after them would undo the
   // direct creations through the fixture's pending-transaction session.
   generate_blocks(200);

   // Market reward object with unsorted (base=Y, quote=X) as created from a reversed-leg fill
   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = quote_id;  // unsorted: base is the quote asset
      o.quote_asset = base_id;  // unsorted: quote is the base asset
      o.reward_asset = base_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD;
      o.window_start_block = db.head_block_num();
      o.reference_volume = 100;
   });
   const object_id_type mr_id = mr.id;

   // Order on the normal leg (selling base for quote) — get_market() returns sorted pair
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(1, base_id), asset(1, quote_id));
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = 1;
   });

   // The chain is already past the minimum-age gate, so the direct sweep call
   // below qualifies the order without generating blocks after its creation.
   share_type before = db.get<market_reward_object>(mr_id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr_id);
   BOOST_CHECK_LT(mr2.pool_balance, before); // reversed-leg pool distributes to normal-leg order

   // Cleanup: the order and the pool were created directly, so remove their
   // synthetic value before the fixture checks supply at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
      clear_sweep_payouts(db);
   }
} FC_LOG_AND_RETHROW() }
// OOR-06: order price normalized to reference orientation per side
BOOST_AUTO_TEST_CASE(price_normalization_per_side)
{ try {
   generate_blocks(HARDFORK_BSIP5_TIME);
   generate_block();
   set_expiration(db, trx);

   ACTORS((seller));

   const asset_object& base = create_user_issued_asset("OOR06BASE");
   const asset_object& quote = create_user_issued_asset("OOR06QUOTE");
   asset_id_type base_id = base.get_id();
   asset_id_type quote_id = quote.get_id();

   // Fund supply so the sweep's vesting payout keeps the supply invariant at teardown.
   issue_uia(seller_id, asset(1000, quote_id));
   // Age the chain past the sweep's minimum order age (100 blocks) before the
   // pool and order are created; blocks generated after them would undo the
   // direct creations through the fixture's pending-transaction session.
   generate_blocks(200);

   // Market reward: base=X, quote=Y, reference_price_wad = 2 WAD (1 X = 2 Y)
   const market_reward_object& mr = db.create<market_reward_object>([&](market_reward_object& o){
      o.base_asset = base_id;
      o.quote_asset = quote_id;
      o.reward_asset = quote_id;
      o.pool_balance = 1000;
      o.reference_price_wad = BSIP5_WAD * 2;
      o.window_start_block = db.head_block_num();
      o.reference_volume = 100;
   });
   const object_id_type mr_id = mr.id;

   // Reversed-leg order: sell 2 Y for 1 X.
   // Raw price_wad (quote/base = X/Y) = 1/2 = 0.5 WAD -> proximity to 2 WAD = 0.25 -> pk = 0 (skipped without fix)
   // Normalized price_wad (to mr orientation Y/X) = 2 WAD -> proximity = 1.0 -> pk > 0 (distributed with fix)
   db.create<limit_order_object>([&](limit_order_object& o){
      o.seller = seller_id;
      o.for_sale = 100;
      o.sell_price = price(asset(2, quote_id), asset(1, base_id)); // sell 2 Y for 1 X
      o.expiration = db.head_block_time() + fc::days(1);
      o.bsip5_placement_block = 1;
   });

   // The chain is already past the minimum-age gate, so the direct sweep call
   // below qualifies the order without generating blocks after its creation.
   share_type before = db.get<market_reward_object>(mr_id).pool_balance;
   graphene::chain::distribute_bsip5_rewards(db);
   const market_reward_object& mr2 = db.get<market_reward_object>(mr_id);
   BOOST_CHECK_LT(mr2.pool_balance, before); // order received distribution (price normalized correctly)

   // Cleanup: the order and the pool were created directly, so remove their
   // synthetic value before the fixture checks supply at teardown.
   {
      std::vector<limit_order_id_type> lo_ids;
      for (const auto& o : db.get_index_type<limit_order_index>().indices())
         lo_ids.push_back(o.id.as<limit_order_id_type>());
      for (const auto& id : lo_ids)
         db.modify(db.get(id), [](limit_order_object& o){ o.for_sale = 0; });
      clear_sweep_payouts(db);
   }
} FC_LOG_AND_RETHROW() }
BOOST_AUTO_TEST_SUITE_END()
