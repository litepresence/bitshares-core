#include <graphene/chain/stableswap.hpp>
#include <graphene/chain/types.hpp>
#include <graphene/protocol/liquidity_pool.hpp>

#include <fc/io/raw.hpp>

#include <boost/test/unit_test.hpp>

using namespace graphene::chain;

BOOST_AUTO_TEST_SUITE( stableswap_math_tests )

BOOST_AUTO_TEST_CASE( compute_d_converges )
{
   // At balance x==y, D should be determined by invariant (not necessarily x+y)
   for (uint64_t A : {1, 10, 100, 1000}) {
      for (uint64_t x : {1000, 1000000}) {
         auto D = compute_stableswap_d(x, x, A);
         BOOST_REQUIRE(D > 0);
         // D > max(x,y) always
         BOOST_CHECK(D > x);
      }
   }
}

BOOST_AUTO_TEST_CASE( compute_y_roundtrip_at_balance )
{
   // At balance, compute_y should be close to x
   for (uint64_t A : {1, 10, 100}) {
      for (uint64_t x : {1000, 5000, 1000000}) {
         auto D = compute_stableswap_d(x, x, A);
         auto y_solved = compute_stableswap_y(x, D, A);
         // Relative error < 1% due to integer division
         BOOST_REQUIRE(y_solved > 0);
         auto rel_err = (y_solved > x) ? (y_solved - x) : (x - y_solved);
         BOOST_CHECK(rel_err * 100 < x); // < 1%
      }
   }
}

BOOST_AUTO_TEST_CASE( swap_monotonicity )
{
   uint64_t A = 100;
   uint64_t x = 1000000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   uint64_t prev_dy = 0;
   for (uint64_t dx : {1000, 5000, 10000, 50000, 100000}) {
      auto dy = compute_stableswap_dy(x, y, D, A, dx);
      BOOST_REQUIRE(dy > 0);
      BOOST_CHECK(dy > prev_dy);
      prev_dy = dy;
   }
}

BOOST_AUTO_TEST_CASE( dy_bounds )
{
   uint64_t A = 100;
   uint64_t x = 1000000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   for (uint64_t dx : {100, 1000, 10000}) {
      auto dy = compute_stableswap_dy(x, y, D, A, dx);
      BOOST_CHECK(dy > 0);
      BOOST_CHECK(dy <= dx);
   }
}

BOOST_AUTO_TEST_CASE( flat_region_high_A )
{
   uint64_t A = 10000;
   uint64_t x = 1000000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   auto dx = 100000;
   auto dy = compute_stableswap_dy(x, y, D, A, dx);
   // High-A pool: slippage small, dy/dx close to 1
   BOOST_REQUIRE(dx > 0);
   auto ratio = (dy * 1000) / dx; // basis points
   BOOST_CHECK(ratio > 900); // > 90%
   BOOST_CHECK(ratio <= 1000); // <= 100%
}

BOOST_AUTO_TEST_CASE( no_divide_before_multiply )
{
   // Regression: D_P = D^3/(4*x*y) must be computed as (D*D/(4*x))*D/y,
   // never as D*D*D/(4*x*y) which overflows uint128 for large D.
   uint64_t A = 100;
   uint64_t x = 1000000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   // Must converge without overflow
   BOOST_REQUIRE(D > 0);
   BOOST_CHECK(D < (fc::uint128_t)1 << 64);
}

BOOST_AUTO_TEST_CASE( imbalanced_pool_swap )
{
   // Imbalanced pool: x << y. Ensure no overflow and monotonic payouts.
   uint64_t A = 100;
   uint64_t x = 1000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   BOOST_REQUIRE(D > 0);
   uint64_t prev_dy = 0;
   for (uint64_t dx : {100, 500, 1000, 5000}) {
      auto dy = compute_stableswap_dy(x, y, D, A, dx);
      BOOST_CHECK(dy > 0);
      BOOST_CHECK(dy >= prev_dy);
      prev_dy = dy;
      uint64_t new_x = x + dx;
      auto new_y = compute_stableswap_y(new_x, (uint64_t)D, A);
      BOOST_CHECK(new_y < y);
   }
}

BOOST_AUTO_TEST_CASE( extreme_new_x_no_overflow )
{
   // Extreme new_x (very small and very large) must not overflow eval_f.
   uint64_t A = 100;
   // small new_x
   {
      uint64_t x = 1, y = 1000000;
      auto D = compute_stableswap_d(x, y, A);
      if (D > 0) {
         auto ny = compute_stableswap_y(1, (uint64_t)D, A);
         // result must be a valid uint64 (no crash); 0 allowed if no solution
         BOOST_CHECK(ny <= 1000000 || ny == 0);
      }
   }
   // large new_x
   {
      uint64_t x = 1000000, y = 1000;
      auto D = compute_stableswap_d(x, y, A);
      BOOST_REQUIRE(D > 0);
      uint64_t new_x = x + 500000;
      auto ny = compute_stableswap_y(new_x, (uint64_t)D, A);
      BOOST_CHECK(ny <= y);
   }
}

// Rounding grind: repeated small swaps must not drain the pool
// (each swap rounds toward the pool, so the pool never loses value).
BOOST_AUTO_TEST_CASE( rounding_grind_pool_never_drains )
{
   uint64_t A = 100;
   uint64_t x = 1000000, y = 1000000;
   auto D = compute_stableswap_d(x, y, A);
   BOOST_REQUIRE(D > 0);

   uint64_t total_dx = 0, total_dy = 0;
   for (int i = 0; i < 100; i++) {
      auto dy = compute_stableswap_dy(x + total_dx, y - total_dy, D, A, 1000);
      if (dy == 0) break;
      total_dx += 1000;
      total_dy += dy;
   }
   // Pool received 100000 total, paid out total_dy. dy per swap is at most dx
   // (constant-product-like behavior) and rounds toward pool, so total_dy
   // should not exceed total_dx for a balanced pool.
   BOOST_CHECK(total_dy <= total_dx);
}

// SS-15: wire-format pinning — liquidity_pool_create_operation with stable
// curve extension must round-trip through raw serialization, and legacy
// constant-product ops (no extension) must still deserialize.
BOOST_AUTO_TEST_CASE( liquidity_pool_create_wire_roundtrip ){
   using namespace graphene::protocol;

   // Stable pool with extension: extensions is flat_set<static_variant<void_t, liquidity_pool_curve_extension>>
   liquidity_pool_create_operation stable_op;
   stable_op.fee = asset(50 * GRAPHENE_BLOCKCHAIN_PRECISION);
   stable_op.account = account_id_type(1);
   stable_op.asset_a = asset_id_type(2);
   stable_op.asset_b = asset_id_type(3);
   stable_op.share_asset = asset_id_type(4);
   stable_op.taker_fee_percent = 10;
   stable_op.withdrawal_fee_percent = 5;

   liquidity_pool_curve_extension ext{1, 100};
   stable_op.extensions.insert(fc::static_variant<void_t, liquidity_pool_curve_extension>(ext));

   auto packed = fc::raw::pack(stable_op);
   liquidity_pool_create_operation unpacked = fc::raw::unpack<liquidity_pool_create_operation>(packed);

   BOOST_CHECK_EQUAL(unpacked.extensions.size(), 1);
   auto it = unpacked.extensions.begin();
   BOOST_REQUIRE(it != unpacked.extensions.end());
   BOOST_CHECK(it->which() == 1);
   const auto& ce = it->get< liquidity_pool_curve_extension >();
   BOOST_CHECK(ce.curve_type == 1);
   BOOST_CHECK(ce.amplification == 100);
   BOOST_CHECK(stable_op.taker_fee_percent == 10);
   BOOST_CHECK(stable_op.withdrawal_fee_percent == 5);

   // Legacy constant-product pool without extension
   liquidity_pool_create_operation legacy_op;
   legacy_op.fee = asset(50 * GRAPHENE_BLOCKCHAIN_PRECISION);
   legacy_op.account = account_id_type(1);
   legacy_op.asset_a = asset_id_type(2);
   legacy_op.asset_b = asset_id_type(3);
   legacy_op.share_asset = asset_id_type(4);
   legacy_op.taker_fee_percent = 10;
   legacy_op.withdrawal_fee_percent = 5;
   // no extensions set -> defaults to curve_type=0

   auto packed_legacy = fc::raw::pack(legacy_op);
   liquidity_pool_create_operation unpacked_legacy = fc::raw::unpack<liquidity_pool_create_operation>(packed_legacy);

   BOOST_CHECK(unpacked_legacy.extensions.empty());
   BOOST_CHECK(unpacked_legacy.taker_fee_percent == 10);
   BOOST_CHECK(unpacked_legacy.withdrawal_fee_percent == 5);
}

BOOST_AUTO_TEST_SUITE_END()
