#include <graphene/chain/abpool.hpp>
#include <graphene/chain/types.hpp>
#include <graphene/protocol/liquidity_pool.hpp>

#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>

#include <boost/test/unit_test.hpp>

using namespace graphene::chain;

BOOST_AUTO_TEST_SUITE( abpool_math_tests )

BOOST_AUTO_TEST_CASE( virtual_offsets_valid )
{
   for (uint64_t w_num : {1, 2, 4}) {
      for (uint64_t w_den : {5}) {
         if (w_num >= w_den) continue;
         auto vo = compute_abpool_virtual_offsets(w_num, w_den, 1000, 10000);
         BOOST_REQUIRE(vo.first > 0);
         BOOST_REQUIRE(vo.second > 0);
      }
   }
}

BOOST_AUTO_TEST_CASE( virtual_offsets_invalid )
{
   BOOST_CHECK(compute_abpool_virtual_offsets(0, 5, 1000, 10000) == std::make_pair((uint64_t)0, (uint64_t)0));
   BOOST_CHECK(compute_abpool_virtual_offsets(5, 5, 1000, 10000) == std::make_pair((uint64_t)0, (uint64_t)0));
   BOOST_CHECK(compute_abpool_virtual_offsets(1, 5, 0, 10000) == std::make_pair((uint64_t)0, (uint64_t)0));
   BOOST_CHECK(compute_abpool_virtual_offsets(1, 5, 10000, 1000) == std::make_pair((uint64_t)0, (uint64_t)0));
}

BOOST_AUTO_TEST_CASE( swap_monotonicity )
{
   uint64_t w_num = 2, w_den = 5;
   auto vo = compute_abpool_virtual_offsets(w_num, w_den, 1000, 10000);
   uint64_t xv = vo.first, yv = vo.second;
   uint64_t real_x = 1000000, real_y = 1000000;
   uint64_t prev_dy = 0;
   for (uint64_t dx : {1000, 5000, 10000, 50000, 100000}) {
      auto dy = compute_abpool_dy(real_x, real_y, xv, yv, w_num, w_den, dx);
      BOOST_REQUIRE(dy > 0);
      BOOST_CHECK(dy > prev_dy);
      prev_dy = dy;
   }
}

BOOST_AUTO_TEST_CASE( dy_bounds )
{
   uint64_t w_num = 2, w_den = 5;
   auto vo = compute_abpool_virtual_offsets(w_num, w_den, 1000, 10000);
   uint64_t xv = vo.first, yv = vo.second;
   uint64_t real_x = 1000000, real_y = 1000000;
   for (uint64_t dx : {100, 1000, 10000}) {
      auto dy = compute_abpool_dy(real_x, real_y, xv, yv, w_num, w_den, dx);
      BOOST_CHECK(dy > 0);
      BOOST_CHECK(dy <= real_y);
   }
}

BOOST_AUTO_TEST_CASE( dy_zero_on_invalid )
{
   BOOST_CHECK(compute_abpool_dy(1000, 1000, 10, 10, 0, 5, 100) == 0);
   BOOST_CHECK(compute_abpool_dy(1000, 1000, 10, 10, 2, 5, 0) == 0);
}

// AB-07: wire-format pinning — liquidity_pool_create_operation with AB
// curve extension must round-trip through raw serialization.
BOOST_AUTO_TEST_CASE( liquidity_pool_create_wire_roundtrip )
{
   using namespace graphene::protocol;

   liquidity_pool_create_operation op;
   op.fee = asset(50 * GRAPHENE_BLOCKCHAIN_PRECISION);
   op.account = account_id_type(1);
   op.asset_a = asset_id_type(2);
   op.asset_b = asset_id_type(3);
   op.share_asset = asset_id_type(4);
   op.taker_fee_percent = 10;
   op.withdrawal_fee_percent = 5;

   op.extensions.value.curve_type = 2;
   op.extensions.value.ab_weight_num = 2;
   op.extensions.value.ab_weight_den = 5;
   op.extensions.value.ab_p_low = 1000;
   op.extensions.value.ab_p_high = 10000;

   auto packed = fc::raw::pack(op);
   liquidity_pool_create_operation unpacked = fc::raw::unpack<liquidity_pool_create_operation>(packed);

   BOOST_CHECK(unpacked.extensions.value.curve_type.valid());
   BOOST_CHECK(*unpacked.extensions.value.curve_type == 2);
   BOOST_CHECK(unpacked.extensions.value.ab_weight_num.valid());
   BOOST_CHECK(*unpacked.extensions.value.ab_weight_num == 2);
   BOOST_CHECK(unpacked.extensions.value.ab_weight_den.valid());
   BOOST_CHECK(*unpacked.extensions.value.ab_weight_den == 5);
   BOOST_CHECK(unpacked.extensions.value.ab_p_low.valid());
   BOOST_CHECK(*unpacked.extensions.value.ab_p_low == 1000);
   BOOST_CHECK(unpacked.extensions.value.ab_p_high.valid());
   BOOST_CHECK(*unpacked.extensions.value.ab_p_high == 10000);
   BOOST_CHECK(unpacked.taker_fee_percent == 10);
   BOOST_CHECK(unpacked.withdrawal_fee_percent == 5);
}

BOOST_AUTO_TEST_SUITE_END()
#include <graphene/protocol/liquidity_pool.hpp>

BOOST_AUTO_TEST_SUITE( abpool_validate_tests )

BOOST_AUTO_TEST_CASE( validate_curve_type )
{
   using namespace graphene::protocol;
   liquidity_pool_create_operation op;
   op.asset_a = asset_id_type(1);
   op.asset_b = asset_id_type(2);
   op.share_asset = asset_id_type(3);
   // default curve_type unset -> valid
   BOOST_CHECK_NO_THROW( op.validate() );

   op.extensions.value.curve_type = 3;
   BOOST_CHECK_THROW( op.validate(), fc::exception );

   op.extensions.value.curve_type = 2;
   // missing AB params -> invalid
   BOOST_CHECK_THROW( op.validate(), fc::exception );

   op.extensions.value.ab_weight_num = 2;
   op.extensions.value.ab_weight_den = 5;
   op.extensions.value.ab_p_low = 1000;
   op.extensions.value.ab_p_high = 10000;
   BOOST_CHECK_NO_THROW( op.validate() );

   // weight not in (0,1)
   op.extensions.value.ab_weight_num = 5;
   BOOST_CHECK_THROW( op.validate(), fc::exception );
   op.extensions.value.ab_weight_num = 2;

   // bounds invalid
   op.extensions.value.ab_p_low = 10000;
   op.extensions.value.ab_p_high = 1000;
   BOOST_CHECK_THROW( op.validate(), fc::exception );
}

BOOST_AUTO_TEST_SUITE_END()

using namespace graphene::chain::test;

BOOST_FIXTURE_TEST_SUITE( abpool_smoke_tests, database_fixture )

BOOST_AUTO_TEST_CASE( abpool_create_deposit_withdraw )
{
   try {
      generate_blocks( HARDFORK_AB_POOL_TIME );
      set_expiration( db, trx );

      ACTORS((sam));

      const asset_object& core = asset_id_type()(db);
      const asset_object& usd = create_user_issued_asset( "MYUSD", sam, charge_market_fee );
      const asset_object& lpa = create_user_issued_asset( "LPATEST", sam, charge_market_fee );

      asset_id_type core_id = core.get_id();
      asset_id_type usd_id = usd.get_id();
      asset_id_type lpa_id = lpa.get_id();

      int64_t init_amount = 10000000 * GRAPHENE_BLOCKCHAIN_PRECISION;
      fund( sam, asset(init_amount) );
      issue_uia( sam, usd.amount(init_amount) );

      liquidity_pool_create_operation op =
         make_liquidity_pool_create_op( sam_id, core.get_id(), usd.get_id(), lpa.get_id(), 0, 0 );
      op.extensions.value.curve_type = 2;
      op.extensions.value.ab_weight_num = 2;
      op.extensions.value.ab_weight_den = 5;
      op.extensions.value.ab_p_low = 1000;
      op.extensions.value.ab_p_high = 10000;

      trx.operations.clear();
      trx.operations.push_back( op );
      for( auto& o : trx.operations ) db.current_fee_schedule().set_fee(o);
      trx.validate();
      set_expiration( db, trx );
      processed_transaction ptx = PUSH_TX(db, trx, ~0);
      trx.operations.clear();
      verify_asset_supplies(db);

      const liquidity_pool_object& lpo =
         db.get<liquidity_pool_object>( *ptx.operation_results.front().get<generic_operation_result>().new_objects.begin() );
      liquidity_pool_id_type lp_id = lpo.get_id();

      BOOST_CHECK( lpo.curve_type == 2 );

      deposit_to_liquidity_pool( sam_id, lp_id, asset( 1000, core_id ), asset( 1200, usd_id ) );

      withdraw_from_liquidity_pool( sam_id, lp_id, asset( 100, lpa_id ) );

   } catch (fc::exception& e) {
      edump((e.to_detail_string()));
      throw;
   }
}

BOOST_AUTO_TEST_SUITE_END()
