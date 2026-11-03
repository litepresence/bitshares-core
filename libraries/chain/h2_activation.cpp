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
#include <graphene/chain/h2_activation.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>

namespace graphene { namespace chain {

bool h2_legs_ordered( const fc::time_point_sec& bonds,
                       const fc::time_point_sec& gateway,
                       const fc::time_point_sec& price )
{
   return bonds < gateway && gateway < price;
}

// R3-04: the legacy two-argument h2_legs_ordered(gateway, price) shim is
// removed (was here): it pinned HARDFORK_H2_BONDS_TIME implicitly and let a
// caller assert gateway<price while bypassing the BONDS leg entirely. All
// in-tree callers use the three-argument authoritative form.

namespace detail {
   /// The BSIP-1 section 6 invariant (E-03: BONDS < GATEWAY < PRICE), checked
   /// first by every H2 gate so an inverted schedule fails closed on all H2
   /// paths at once.
   void h2_require_leg_ordering()
   {
      FC_ASSERT( h2_legs_ordered( HARDFORK_H2_BONDS_TIME,
                                  HARDFORK_H2_GATEWAY_TIME,
                                  HARDFORK_H2_PRICE_TIME ),
                 "H2 activations must order BONDS < GATEWAY < PRICE "
                 "(BSIP-1 section 6): inverted schedule refused" );
   }
}

void h2_require_primitives( const fc::time_point_sec& now )
{
   detail::h2_require_leg_ordering();
   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( now ),
              "Not allowed until the H2 bonds hardfork" );
}

void h2_require_gateway_leg( const fc::time_point_sec& now )
{
   detail::h2_require_leg_ordering();
   // E-03: gateway custody requires challenge machinery live first, so Dec
   // 2029 vaults never form in an unchallengeable window.
   FC_ASSERT( HARDFORK_H2_BONDS_PASSED( now ),
              "Not allowed until the H2 bonds hardfork" );
   FC_ASSERT( HARDFORK_H2_GATEWAY_PASSED( now ),
              "Not allowed until the H2 gateway activation" );
}

void h2_require_price_leg( const fc::time_point_sec& now )
{
   detail::h2_require_leg_ordering();
   FC_ASSERT( HARDFORK_H2_PRICE_PASSED( now ),
              "Not allowed until the H2 price activation" );
}

bool h2_pair_has_h1_binding( const asset_object& pair, const database& d )
{
   if( !pair.is_market_issued() )
      return false;
   return pair.bitasset_data( d ).options.extensions.value
          .price_oracle_binding.valid();
}

} } // graphene::chain
