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

#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/types.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

class database;

   /// Promotion ring bound (mirrors the H1 guard-queue bound). Shared: the
   /// price promotion path and the foreign transaction promotion path both
   /// write the guard's promotion log.
   constexpr size_t H2E_PROMOTION_LOG_CAP = 16;

using graphene::protocol::h2_tripwire_sample;
using graphene::protocol::price_oracle;

/**
 * @brief One observed promotion: the hardened OSM record behind an H2 read.
 * @ingroup object
 * @ingroup protocol
 *
 * The H1 delay queue does not record how many live producers backed a sample
 * when it promoted. This ring does: liveness-at-promotion is checked at read
 * time against the oracle's minimum, so a value that ripened under quorum
 * can never be consumed after the set thins. The grid anchor binds the record
 * to the absolute time grid (never the maintenance interval), and the delay
 * binds it to the committee delay in force: a delay reconfiguration
 * invalidates old records fail-closed instead of smuggling them through.
 */
struct h2_promotion_record
{
   time_point_sec promote_time;   ///< consumed_value_time of the promotion
   uint16_t       producer_count = 0; ///< current_value_producer_count observed
   uint32_t       anchor = 0;      ///< h2_osm_bucket_anchor(promote_time, delay)
   uint32_t       delay_sec = 0;   ///< committee delay the anchor was computed under

   void validate()const
   { FC_ASSERT( producer_count > 0, "Promotion records require a live producer" ); }
};

/**
 * @brief Separate per-oracle consumption-guard state (inventory OQ-39:
 * separate object, never oracle growth).
 * @ingroup object
 * @ingroup protocol
 *
 * Holds the fallback-series reference (single backup, owner-set), the
 * hardened promotion ring, and the per-interval promotion rate counter.
 * Created lazily per oracle (first bond lock or first publish observation),
 * so H1 oracles carry no new state and read no new code paths.
 */
class guard_state_object : public abstract_object<guard_state_object, protocol_ids, guard_state_object_type>
{
   public:
      oracle_id_type             oracle;   ///< Guarded oracle; immutable
      optional<price_oracle>     fallback; ///< Single backup series; empty = halt-on-stale
      vector<h2_promotion_record> promotion_log; ///< Newest last, capped at 16
      time_point_sec             last_promo_time;   ///< Change-detection anchor
      vector<protocol::oracle_value> last_promo_values; ///< Change-detection anchor
      time_point_sec             rate_window_start; ///< Interval-anchored window
      uint32_t                   promotion_count = 0; ///< Promotions this window
      bool                       consumption_hold = false; ///< Set past the limit
      /// The FOREIGN transaction promotion log (H3). Separate from the price
      /// log on purpose: the two paths have different value types, and a
      /// foreign publish must never evict a price promotion record (that
      /// would destroy the H2 bonded price leg's promotion proof and fail
      /// that leg closed). Newest last, capped at 16.
      vector<h2_promotion_record> foreign_promotion_log;
};

struct by_guard_oracle;  ///< guard states by oracle (unique)

/**
* @ingroup object_index
*/
using guard_state_multi_index_type = multi_index_container<
   guard_state_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_guard_oracle>,
         member< guard_state_object, oracle_id_type, &guard_state_object::oracle >
      >
   >
>;

/**
* @ingroup object_index
*/
using guard_state_index = generic_index<guard_state_object, guard_state_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::guard_state_object )

FC_REFLECT_TYPENAME( graphene::chain::guard_state_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::guard_state_object )

// Shared read helpers (definitions in oracle_substrate.cpp).
namespace graphene { namespace chain {
   const guard_state_object* h2_find_guard( const database& d, oracle_id_type oid );
   bool h2_oracle_has_bonded_live_set( const database& d, const oracle_object& oracle,
                                       time_point_sec now );
   bool h2_oracle_has_any_bond( const database& d, const oracle_object& oracle );
} }
