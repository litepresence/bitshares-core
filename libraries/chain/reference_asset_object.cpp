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
   if( nullptr == a || !a->is_market_issued() )
      return {};
   return a->bitasset_data( d ).options.extensions.value.reference_asset_mapping;
}

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::reference_asset_object, (graphene::db::object),
                    (creator)
                    (symbol)
                    (precision)
                    (description)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reference_asset_object )
