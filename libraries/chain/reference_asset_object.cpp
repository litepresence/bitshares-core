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
#include <graphene/chain/reference_asset_object.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/oracle_object.hpp>

namespace graphene { namespace chain {

optional<reference_mapping> get_effective_reference_mapping( const database& d, asset_id_type asset )
{
   // The core asset's issuer is the null account, which cannot sign an update declaring a
   // mapping, so the protocol maps it 1:1 to the reference asset named "BTS" whenever that
   // reference exists. Before the committee creates it (or if it is ever removed, which
   // nothing in this stage permits while referenced), the core asset simply has no mapping
   // and consumers fail closed.
   if( asset == asset_id_type() )
   {
      const auto& idx = d.get_index_type<reference_asset_index>().indices().get<by_reference_symbol>();
      const auto itr = idx.find( GRAPHENE_REFERENCE_ASSET_BTS_SYMBOL );
      if( itr == idx.end() )
         return {};
      reference_mapping m;
      m.reference = itr->get_id();
      m.asset_amount = 1;
      m.reference_amount = 1;
      return m;
   }
   const asset_object* a = d.find( asset );
   if( nullptr == a )
      return {};
   if( a->is_market_issued() )
      return a->bitasset_data( d ).options.extensions.value.reference_asset_mapping;
   // The UIA mapping home (F4): a non-market-issued asset declares what it tracks in its
   // common options. This is what lets an MIA backed by a UIA, or a futures market
   // collateralized in one, bind an oracle. A market-issued asset must NOT set this (its
   // mapping lives in bitasset options); the asset evaluators refuse it there.
   return a->options.extensions.value.reference_asset_mapping;
}

bool is_smartcoin_binding_valid( const oracle_object& o, uint16_t series_idx,
                                 const reference_mapping& debt_mapping,
                                 const reference_mapping& backing_mapping )
{
   return series_idx < o.series.size()
          && o.base == debt_mapping.reference
          && o.quote == backing_mapping.reference;
}

bool is_futures_binding_valid( const oracle_object& o, uint16_t series_idx,
                               reference_asset_id_type underlying,
                               const reference_mapping& collateral_mapping )
{
   return series_idx < o.series.size()
          && o.base == underlying
          && o.quote == collateral_mapping.reference;
}

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::reference_asset_object, (graphene::db::object),
                    (creator)
                    (symbol)
                    (precision)
                    (description)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reference_asset_object )
