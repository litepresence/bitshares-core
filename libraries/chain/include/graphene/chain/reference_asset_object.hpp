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
class oracle_object;

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
 * is the null account and cannot declare anything); a market-issued asset maps through
 * the reference_asset_mapping its issuer declared in its bitasset options; any other
 * asset (a UIA) maps through the reference_asset_mapping in its common asset options --
 * the mapping home for non-market-issued assets, which is what lets an MIA backed by a
 * UIA, or a futures market collateralized in one, bind an oracle. Absent while the BTS
 * reference does not exist, or when an issuer declared nothing -- consumers fail closed
 * on an absent mapping.
 */
optional<reference_mapping> get_effective_reference_mapping( const database& d, asset_id_type asset );

/**
 * @return whether series @p series_idx of oracle @p o may feed a smartcoin whose own
 * mapping is @p debt_mapping and whose backing asset's mapping is @p backing_mapping:
 * the series is declared, oracle.base is the debt reference and oracle.quote is the
 * backing reference.
 *
 * Pure over its arguments (mappings resolved by the caller via
 * get_effective_reference_mapping; an absent mapping means "no binding", never call here
 * with one). Shared by the bind-time check, the read-time re-check and the delete-time
 * prune rule so the three can never disagree about what "valid" means.
 */
bool is_smartcoin_binding_valid( const oracle_object& o, uint16_t series_idx,
                                 const reference_mapping& debt_mapping,
                                 const reference_mapping& backing_mapping );

/**
 * @return whether an explicit {oracle, series, expiry} binding is past its consensus
 * expiry at @p head_block_num: the binding is present and the head block number is
 * strictly past its expiry height. An absent binding (legacy price_oracle_id or no
 * binding at all) is never expired -- the legacy path has no expiry and executes its
 * historical code unchanged.
 *
 * Pure over its arguments, like is_smartcoin_binding_valid. Shared by the read-time
 * re-check (db_update), the delete-time live scan and the F5 prune rule so the three
 * can never disagree about what "expired" means. Heights compare as exact integers;
 * no wall-clock, no time conversion.
 */
bool is_price_oracle_binding_expired( const optional<price_oracle>& binding,
                                      uint32_t head_block_num );

/**
 * @return whether series @p series_idx of oracle @p o may feed a futures-style market on
 * underlying reference @p underlying collateralized in an asset mapped by
 * @p collateral_mapping: the series is declared, oracle.base is the underlying and
 * oracle.quote is the collateral's reference. Contract size counts in smallest units of
 * the underlying reference asset, so no on-chain token for the underlying is needed.
 *
 * Validity only in this stage: there is no futures market object and no matching-engine
 * consumption yet. Pure over its arguments, like is_smartcoin_binding_valid.
 */
bool is_futures_binding_valid( const oracle_object& o, uint16_t series_idx,
                               reference_asset_id_type underlying,
                               const reference_mapping& collateral_mapping );

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
