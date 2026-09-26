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
#pragma once

#include <graphene/chain/types.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

class database;

/**
 * The reference symbol the core asset (1.3.0) maps to by protocol rule. Reserving the
 * name this way is safe only while creation is committee-only; opening creation without
 * per-name approval would let anyone define what BTS means. Recorded here so the rule
 * has exactly one spelling.
 */
constexpr const char* GRAPHENE_REFERENCE_ASSET_BTS_SYMBOL = "BTS";

/**
 * @return the reference mapping in force for @p asset, if any.
 *
 * The core asset maps 1:1 to the reference asset named "BTS" by protocol rule (its issuer
 * is the null account and cannot declare anything); every other asset maps only through
 * the reference_asset_mapping its issuer declared in its bitasset options. Absent while
 * the BTS reference does not exist, or when an issuer declared nothing -- consumers fail
 * closed on an absent mapping.
 */
optional<reference_mapping> get_effective_reference_mapping( const database& d, asset_id_type asset );

/**
 *  @brief A unit a price can be quoted in. On chain it is only a symbol and a precision.
 *  @ingroup object
 *  @ingroup protocol
 *
 *  Nobody holds a reference asset. An oracle quotes a price between two of them, and an
 *  on-chain asset declares which one it tracks (see reference_mapping). Reference assets
 *  live in their own namespace: the reference asset "USD" and the smartcoin "USD" are
 *  different things. Symbol and precision are immutable -- there is no update operation,
 *  because every value ever published against a reference asset is counted in its
 *  smallest unit and rescaling would silently reinterpret all of them.
 *
 *  The core asset (1.3.0) needs no stored mapping: its issuer is the null account, which
 *  cannot sign, so the protocol maps it 1:1 to the reference asset named "BTS" whenever
 *  that reference exists. See database::get_effective_reference_mapping().
 */
class reference_asset_object
   : public abstract_object<reference_asset_object, protocol_ids, reference_asset_object_type>
{
   public:
      account_id_type creator;    ///< Paid the creation fee; committee-only while gated
      string          symbol;     ///< Unique among reference assets, e.g. "USD"
      uint8_t         precision = 0;
      string          description;
};

struct by_reference_symbol; ///< unique, and how humans address a reference asset
struct by_reference_creator;

/**
* @ingroup object_index
*/
using reference_asset_multi_index_type = multi_index_container<
   reference_asset_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_reference_symbol>,
         member< reference_asset_object, string, &reference_asset_object::symbol >
      >,
      ordered_unique< tag<by_reference_creator>,
         composite_key< reference_asset_object,
            member< reference_asset_object, account_id_type, &reference_asset_object::creator >,
            member< object, object_id_type, &object::id >
         >
      >
   >
>;

/**
* @ingroup object_index
*/
using reference_asset_index = generic_index<reference_asset_object, reference_asset_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reference_asset_object )

FC_REFLECT_TYPENAME( graphene::chain::reference_asset_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reference_asset_object )
