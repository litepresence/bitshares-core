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

using graphene::protocol::oracle_options;
using graphene::protocol::oracle_aggregation_method;
using graphene::protocol::oracle_series;
using graphene::protocol::oracle_value;

/**
 *  @brief A named price series between two reference assets, published to by a set of
 *  producers and referenced by id.
 *  @ingroup object
 *  @ingroup protocol
 *
 *  Unlike a legacy price feed, an oracle is not an attribute of an asset. It exists in its
 *  own right so that several consumers can reference the same series, and so that a price
 *  that is not the settlement price of any particular smartcoin has somewhere to live.
 *  Pricing in reference assets rather than on-chain asset ids is what makes sharing
 *  possible: HONEST.USD and COMMITTEE.USD can both read one USD/BTS oracle.
 *
 *  See ORACLE-DESIGN.md for the reasoning behind the aggregation and outlier rules.
 */
class oracle_object : public abstract_object<oracle_object, protocol_ids, oracle_object_type>
{
   public:
      account_id_type owner;          ///< Creator and administrator
      string          name;           ///< Unique, e.g. "BTC.USD"
      string          description;

      /// What a published price means, as reference assets. Immutable once created:
      /// consumers reference an oracle by id and would have no way to notice that what it
      /// measures had changed.
      reference_asset_id_type base;
      reference_asset_id_type quote;

      /// The ordered series list, fixed at creation. Every publish carries exactly one
      /// value per entry, in order; aggregation runs per series over the same producers.
      vector<oracle_series> series;

      oracle_options  options;

      /// Latest submission per producer: one value per declared series, in order.
      /// Bounded by options.producers. (H1-FINAL-01: "bounded by
      /// options.producers" is now CODE, not a comment -- update_current_value
      /// prunes rows for producers no longer in the set, mirroring the
      /// reputation prune, so rotation churn cannot grow this map.)
      flat_map<account_id_type, pair<time_point_sec, vector<oracle_value>>> submissions;

      /// Recent aggregates, oldest first, capped at GRAPHENE_ORACLE_MAX_HISTORY entries
      /// each holding one value per series. Recorded from the moment the oracle exists,
      /// because history cannot be reconstructed later.
      vector<pair<time_point_sec, vector<oracle_value>>> history;

      /**
       * The current aggregate, or absent when there is no usable value. One value per
       * declared series, in order.
       *
       * Absent rather than an empty vector on purpose. An empty vector reads as "no
       * series" in several code paths, and a consumer that mistakes "no data" for a
       * usable aggregate fails in the most expensive possible direction. An absent
       * optional cannot be misread.
       */
      optional<vector<oracle_value>>  current_value;
      time_point_sec   current_value_time;

      /// Number of live submissions behind @ref current_value, for API visibility into why an
      /// oracle is reporting nothing.
      uint16_t         current_value_producer_count = 0;

       /**
        * Market-issued assets whose settlement price comes from this oracle.
        *
        * Maintained by the asset_update_bitasset evaluator rather than derived by scanning, for
        * two reasons: publishing must refresh every bound asset's feed, and doing that by walking
        * all bitassets on every publish would put work proportional to the whole chain's asset
        * count into an operation designed to be sent every few seconds. It also makes the
        * "refuse to delete an oracle something depends on" check O(1).
        *
        * Capped at GRAPHENE_ORACLE_MAX_SUBSCRIBERS so the work a single publish can trigger is
        * bounded.
        */
       flat_set<asset_id_type> subscribers;

       // ---- Track A guards (new-pairs-only) ----
       //
       // current_value above is the RAW aggregate: computed immediately, transparent, and
       // exactly what it was before this change. The guarded value below is what
       // oracle-bound consumers actually read. Legacy feed paths never touch any of
       // these fields. All appended after subscribers: pre-existing field positions are
       // unchanged.

       /**
        * The guarded value bound consumers read: the raw aggregate after the OSM-style
        * delay AND the per-interval rate limit. Absent while nothing ripe is available,
        * while frozen, or on quorum loss -- every one of those fails closed downstream.
        * One value per declared series, in order, like current_value.
        */
       optional<vector<oracle_value>> consumed_value;
       /// When the consumed value's raw sample was formed (not when promoted). Read-time
       /// liveness (value_lifetime_sec) counts from here, so a delayed value cannot
       /// outlive the data it came from.
       time_point_sec consumed_value_time;

       /**
        * Delay queue: timestamped raw samples awaiting the guard delay, oldest first.
        * Capped at GRAPHENE_ORACLE_GUARD_MAX_PENDING with time-bucketed sampling, so a
        * full queue always spans the configured delay whatever the publish rate (the
        * same bucketing argument as the history ring: per-publish appends would make the
        * span a function of publish frequency).
        */
       vector<pair<time_point_sec, vector<oracle_value>>> pending_queue;

       /// Set while the last promotion was held by the rate limit. Cleared on the next
       /// in-band promotion or at the next maintenance-interval boundary.
       bool rate_limited = false;
       /// Holds counted in the current maintenance interval. Reset to 0 at each
       /// interval boundary (and on every successful promotion).
       uint32_t guard_hits = 0;
       /// head_block_time / maintenance_interval_sec at the last reset. Integer
       /// division on head-block time only: no floats, no wall-clock.
       uint64_t guard_epoch = 0;

       /**
        * Per-producer liveness/deviation history. Bounded by the producer set
        * (GRAPHENE_ORACLE_MAX_PRODUCERS): no open-ended growth. Counts only -- never
        * read by any economic logic in this stage.
        */
       flat_map<account_id_type, protocol::oracle_producer_reputation> reputation;

       // ---- H2b dispute bookkeeping (appended-last, never inserted) ----
       //
       // Dormant until an H2 dispute names the oracle, so H1 paths are
       // byte-identical: nothing here is read outside dispute evaluation and
       // the expiry sweep, both hardfork-gated.
       /// Open disputes (concurrency source of truth).
       uint16_t open_disputes = 0;
       /// Last dispute open (24h cooldown anchor).
       time_point_sec last_dispute_time;

      /// H1-FINAL-02 (carried from H1-08): the rate limiter's
      /// reference that no reset path can destroy. Written at every confirmed
      /// promotion, never cleared: a transient quorum gap or a defensive early
      /// return cannot remove the guard's baseline, so the re-entry promotion is
      /// still move-checked against the pre-gap reference. Read fallback: when
      /// absent (fresh oracle), the comparison falls back to consumed_value (the
      /// pre-existing shape).
      optional<vector<oracle_value>>  last_good_value;
      optional<time_point_sec>        last_good_time;
       /// Accrued 15% forfeit shares, swept by the H2d reward pool.
       share_type forfeit_pool_balance;

       /**
        * GOV-R9-02: head-block time at which @ref open_disputes last
        * transitioned to 0 -- the anchor for the committee unfreeze time-lock
        * (`GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC`). Written only at the
        * transition, never cleared, so it only ever moves forward with chain
        * time. Unset (epoch) means no dispute has ever cleared: the unfreeze
        * has no anchor and refuses rather than guessing one.
        */
       time_point_sec dispute_cleared_time;

      /// @return whether a submission made at @p published is still live at @p now
      bool is_submission_live( time_point_sec published, time_point_sec now )const
      {
         return published != time_point_sec()
                && ( now - published ).to_seconds() < int64_t( options.value_lifetime_sec );
      }

      /**
       * @return whether @ref current_value is still within its lifetime at @p now.
       *
       * Freshness has to be a READ-time question, not a write-time one. current_value is only
       * recomputed when a producer publishes, so an oracle whose producers all stop simply
       * keeps its last value for ever: there is no sweep that would notice. Consumers that ask
       * only `current_value.valid()` therefore go on using a price that expired long ago, and
       * value_lifetime_sec silently means nothing.
       */
      bool is_value_live( time_point_sec now )const
      {
         return current_value.valid() && is_submission_live( current_value_time, now );
      }

       /**
        * Recomputes @ref current_value from @ref submissions and, for median_over_window, from
        * @ref history, and appends to the history ring.
        *
        * Deterministic by construction: it only ever selects one of the observed values, never
        * computes a new one, so there is no rounding or overflow that could differ between
        * nodes. Aggregation runs per series over the SAME producer set, which is what keeps
        * bid <= ask true after aggregation (see ORACLE-DESIGN.md "Series"). @p now must be
        * the head block time.
        *
        * Then runs the Track A guards: samples the raw aggregate into the bounded delay
        * queue and promotes the latest ripe sample to @ref consumed_value, subject to the
        * freeze flag (no promotion while frozen) and the per-interval rate limit
        * (GRAPHENE_ORACLE_GUARD_MAX_MOVE_PPM; holds last-good + flag, never jumps).
        * @p delay_sec is the committee-owned guard delay;
        * @p maintenance_interval_sec bounds the rate-limit counter's interval. Both are
        * head-block-time-derived values passed by the caller (the object has no db).
        */
       void update_current_value( time_point_sec now, uint32_t delay_sec,
                                  uint32_t maintenance_interval_sec );

   private:
      /// Track A guard promotion (delay queue + freeze + rate limit). Called at the end
      /// of update_current_value; see the .cpp for the argument contract.
      void update_guarded_value( time_point_sec now, uint32_t delay_sec,
                                 uint32_t maintenance_interval_sec );
   public:
};

struct by_oracle_name;   ///< unique, and how humans address an oracle
struct by_owner;         ///< for API
struct by_reference_pair;///< for API

/**
* @ingroup object_index
*/
using oracle_multi_index_type = multi_index_container<
   oracle_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_oracle_name>,
         member< oracle_object, string, &oracle_object::name >
      >,
      ordered_unique< tag<by_owner>,
         composite_key< oracle_object,
            member< oracle_object, account_id_type, &oracle_object::owner >,
            member< object, object_id_type, &object::id >
         >
      >,
      ordered_unique< tag<by_reference_pair>,
         composite_key< oracle_object,
            member< oracle_object, reference_asset_id_type, &oracle_object::base >,
            member< oracle_object, reference_asset_id_type, &oracle_object::quote >,
            member< object, object_id_type, &object::id >
         >
      >
   >
>;

/**
* @ingroup object_index
*/
using oracle_index = generic_index<oracle_object, oracle_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::oracle_object )

FC_REFLECT_TYPENAME( graphene::chain::oracle_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::oracle_object )
