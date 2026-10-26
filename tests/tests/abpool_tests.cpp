#include <graphene/chain/abpool.hpp>
#include <graphene/chain/types.hpp>

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

BOOST_AUTO_TEST_SUITE_END()