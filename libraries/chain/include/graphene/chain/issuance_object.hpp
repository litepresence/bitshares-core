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
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/db/generic_index.hpp>

namespace graphene { namespace chain {

/**
 * @brief One issuance reserve per vault-backed pair (BSIP-1 section 4).
 * @ingroup object
 * @ingroup protocol
 *
 * The bonded backing behind senior stable: BTS deposits accumulate here,
 * stable supply (face) is the liability they secure, and the FXR junior
 * supply ledger prices dilution without a consensus feed. Created lazily
 * by the first mint for the pair (H2c pairs carry no new state and read
 * no new code paths); at most one record per pair ever exists. Bounded
 * state: per-account FXR lives in normal asset balances of the pinned
 * FXR token (transferable through existing machinery, no new index, no
 * unbounded map on this record); this object carries only pair-level
 * totals. Per-account stable likewise lives in asset balances; the
 * stable_supply here is the issuance-side mirror the rmin gate reads.
 */
class reserve_object : public abstract_object<reserve_object, protocol_ids, reserve_object_type>
{
   public:
      asset_id_type  pair;             ///< Senior stable UIA; immutable, unique
      asset_id_type  fxr_asset;        ///< Junior token UIA; pinned at creation, immutable
      share_type     bts_balance;      ///< BTS locked in the reserve (incl. fee slices)
      share_type     stable_supply;    ///< Face stable issued against this reserve
      share_type     fxr_supply;       ///< Junior supply ledger (dilution accounting mirror)
      uint32_t       last_ratio_bps = 0; ///< Coverage snapshot in bps (saturating, face terms)
      uint32_t       snapshot_block = 0; ///< Head block number the snapshot was taken at
      share_type     door_used_bts;    ///< BTS door conversions consumed this block
      uint32_t       door_block = 0;   ///< Head block number the door counter belongs to
};

struct by_reserve_pair; ///< reserves by pair (unique)

/**
* @ingroup object_index
*/
using reserve_multi_index_type = multi_index_container<
   reserve_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_reserve_pair>,
         member< reserve_object, asset_id_type, &reserve_object::pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using reserve_index = generic_index<reserve_object, reserve_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reserve_object )

FC_REFLECT_TYPENAME( graphene::chain::reserve_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reserve_object )
