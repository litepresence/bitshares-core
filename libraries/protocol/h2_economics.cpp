/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <graphene/protocol/h2_economics.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <fc/io/raw.hpp>

#include <algorithm>
#include <numeric>

namespace graphene { namespace protocol {

namespace {
   using boost::multiprecision::uint256_t;
   constexpr uint64_t PPM_DENOM = 1000000;
}

void h2_tripwire_sample::validate()const
{
   FC_ASSERT( price.base_amount > share_type( 0 ) && price.quote_amount > share_type( 0 ),
              "Tripwire sample price must be positive on both sides" );
   FC_ASSERT( volume > 0, "Tripwire sample volume must be positive" );
}

bool operator==( const h2_tripwire_sample& a, const h2_tripwire_sample& b )
{
   return a.price == b.price && a.volume == b.volume && a.source_pool == b.source_pool;
}

bool h2_deviation_breaches( const oracle_value& market, const oracle_value& feed,
                            uint32_t threshold_ppm )
{
   // |market/feed - 1| = |mb*fq - mq*fb| / (mq*fb), compared against
   // threshold_ppm/1e6 by cross-multiplication. Signed legs cannot occur
   // (validate requires positive amounts), but the absolute difference is
   // taken branch-free-safe via explicit ordering: consensus-critical code
   // must not depend on signed-overflow-undefined behavior.
   FC_ASSERT( market.base_amount > share_type( 0 ) && market.quote_amount > share_type( 0 )
              && feed.base_amount > share_type( 0 ) && feed.quote_amount > share_type( 0 ),
              "Deviation legs must be positive ratios" );
   const uint256_t cross_market = uint256_t( uint64_t( market.base_amount.value ) )
                                * uint256_t( uint64_t( feed.quote_amount.value ) );
   const uint256_t cross_feed = uint256_t( uint64_t( market.quote_amount.value ) )
                              * uint256_t( uint64_t( feed.base_amount.value ) );
   const uint256_t distance = cross_market >= cross_feed
                              ? cross_market - cross_feed
                              : cross_feed - cross_market;
   // distance * 1e6 > threshold * mq * fb  <=>  breach. Strictly greater: the
   // bound itself is inclusive headroom, matching the H1 deviates_too_far
   // convention (mid < low || mid > high).
   const uint256_t lhs = distance * PPM_DENOM;
   const uint256_t rhs = uint256_t( threshold_ppm )
                       * uint256_t( uint64_t( market.quote_amount.value ) )
                       * uint256_t( uint64_t( feed.base_amount.value ) );
   return lhs > rhs;
}

share_type h2_pro_rata( share_type pool, uint64_t weight, uint64_t total_weight )
{
   if( pool <= share_type( 0 ) || weight == 0 || total_weight == 0 )
      return share_type( 0 );
   const uint256_t payout = uint256_t( uint64_t( pool.value ) )
                          * uint256_t( weight )
                          / uint256_t( total_weight );
   return share_type( int64_t( uint64_t( payout ) ) );
}

share_type h2_convert_face_to_bond( share_type face, const oracle_value& price )
{
   if( face <= share_type( 0 ) )
      return share_type( 0 );
   FC_ASSERT( price.base_amount > share_type( 0 ) && price.quote_amount > share_type( 0 ),
              "Conversion price must be a positive ratio" );
   const uint256_t converted = uint256_t( uint64_t( face.value ) )
                             * uint256_t( uint64_t( price.base_amount.value ) )
                             / uint256_t( uint64_t( price.quote_amount.value ) );
   // Saturate instead of truncating: the 64-bit narrowing below WRAPS on an
   // absurd bonded price, and a wrapped ratio is not a smaller seat, it is a
   // different one -- zero (a claim book with no pool, so every claim is
   // refused and the pair can never be re-registered) or a value that no
   // longer matches the filed exit formula. The wind-down seat and the
   // claim payout both read this ratio, so the guard belongs here, with the
   // same shape as its siblings (h2_issue_face_to_bts,
   // libraries/chain/issuance.cpp).
   if( converted > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( converted ) ) );
}

optional<h2_tripwire_sample> h2_volume_weighted_median(
      const vector<h2_tripwire_sample>& samples )
{
   if( samples.empty() )
      return optional<h2_tripwire_sample>();
   // Index sort: the input order never affects the outcome (total order
   // below), so gathering order across pools cannot fork the median.
   vector<size_t> order( samples.size() );
   std::iota( order.begin(), order.end(), 0u );
   std::sort( order.begin(), order.end(),
              [&samples]( size_t a, size_t b )
   {
      const h2_tripwire_sample& x = samples[a];
      const h2_tripwire_sample& y = samples[b];
      // Exact price compare: xb* yq vs yb*xq in 128-bit (int64 legs: the
      // widest product is ~1e30, inside uint128's ~3.4e38).
      const fc::uint128_t x_cross = fc::uint128_t( uint64_t( x.price.base_amount.value ) )
                                  * fc::uint128_t( uint64_t( y.price.quote_amount.value ) );
      const fc::uint128_t y_cross = fc::uint128_t( uint64_t( y.price.base_amount.value ) )
                                  * fc::uint128_t( uint64_t( x.price.quote_amount.value ) );
      if( x_cross != y_cross )
         return x_cross < y_cross;
      if( x.price.quote_amount != y.price.quote_amount )
         return x.price.quote_amount.value < y.price.quote_amount.value;
      if( x.price.base_amount != y.price.base_amount )
         return x.price.base_amount.value < y.price.base_amount.value;
      if( x.volume != y.volume )
         return x.volume < y.volume;
      return x.source_pool < y.source_pool;
   } );
   uint256_t total = 0;
   for( const auto& s : samples )
      total += s.volume;
   uint256_t accumulated = 0;
   for( const size_t i : order )
   {
      accumulated += samples[i].volume;
      if( accumulated * 2 > total )
         return samples[i];
   }
   return samples[ order.back() ]; // unreachable while total > 0
}

void oracle_fallback_set_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee must be non-negative" );
   if( fallback.valid() )
   {
      FC_ASSERT( fallback->oracle_id != oracle,
                 "An oracle cannot fall back to itself (single backup, never a chain)" );
      fallback->validate();
   }
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::h2_tripwire_sample )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_fallback_set_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_fallback_set_operation )
