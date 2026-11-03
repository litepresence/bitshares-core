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
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/db/generic_index.hpp>

namespace graphene { namespace chain {

/**
 * @brief One 90-day BTC seasoning clock per vault-backed pair (BSIP-1
 * section 5 staging: coverage >= 2.0 / >= 1.0 for 90 days with an
 * independent verifier before USD issuance).
 * @ingroup object
 * @ingroup protocol
 *
 * Created once at the gateway-leg activation for the pair (inside
 * `vault_register` apply, same atomic step as the vault); creation refuses
 * duplicates, so at most one record per pair ever exists. The maintenance
 * sweep (`process_h2_seasoning`) folds each sweep's coverages into the
 * running full-window minimums and recomputes `complete` from head-block
 * time every sweep -- never latched, so a post-complete breach clears the
 * flag by resetting the window it measures.
 */
class seasoning_record_object : public abstract_object<seasoning_record_object, protocol_ids, seasoning_object_type>
{
   public:
      asset_id_type  pair;             ///< Seasoned pair; immutable, unique
      time_point_sec genesis_time;     ///< Record creation (gateway-leg activation); immutable
      time_point_sec window_start;     ///< Continuous-hold window (re)start; head-block time only
      uint32_t       min_vault_bps = 0;  ///< Worst vault coverage since window_start (saturating bps)
      uint32_t       min_oracle_bps = 0; ///< Worst oracle coverage since window_start (saturating bps)
      bool           verifier_set = false; ///< Independent-verifier bit; once-only, never cleared
      account_id_type verifier;        ///< Recorded verifier identity; valid iff verifier_set
      bool           complete = false; ///< Recomputed every sweep; the future issuance gate reads it
      uint64_t       breach_count = 0; ///< Monotonic breaching-sweep count (AC-15c); never cleared
                                       ///< so a third party can reconstruct ungated days from
                                       ///< (breach_count, window_start, genesis_time) alone
};

struct by_seasoning_pair; ///< seasoning records by pair (unique)

/**
* @ingroup object_index
*/
using seasoning_record_multi_index_type = multi_index_container<
   seasoning_record_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_seasoning_pair>,
         member< seasoning_record_object, asset_id_type, &seasoning_record_object::pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using seasoning_record_index = generic_index<seasoning_record_object, seasoning_record_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::seasoning_record_object )

FC_REFLECT_TYPENAME( graphene::chain::seasoning_record_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::seasoning_record_object )
