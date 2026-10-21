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
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

   /// Promotion ring bound (mirrors the H1 guard-queue bound). Shared: the
   /// price promotion path and the foreign transaction promotion path both
   /// write the guard's promotion log.
   constexpr size_t H2E_PROMOTION_LOG_CAP = 16;

using graphene::protocol::h2_tripwire_sample;
using graphene::protocol::price_oracle;

/**
 * @brief Per-oracle liveness reward pool: swept 15% forfeits paying bonded
 * live producers pro-rata at maintenance.
 * @ingroup object
 * @ingroup protocol
 *
 * Funded by the maintenance sweep from the oracle's own forfeit accrual and
 * from the forfeit accruals of vaults canonically bound to this oracle (the
 * 15% pool leg of the 80/15/finder split). Unbound vaults' accruals wait on
 * their vaults until a binding pins them: pool money never crosses pairs.
 * Payouts are pure redistribution of already-counted supply (the forfeit
 * split removed only the burn leg from current_supply), so the pool balance
 * stays supply-visible in the fixture audit exactly like the accrual shells
 * it drains. Rounding DOWN against payees; dust accrues for later windows.
 */
class reward_pool_object : public abstract_object<reward_pool_object, protocol_ids, reward_pool_object_type>
{
   public:
      oracle_id_type oracle;            ///< Owning oracle; immutable
      share_type     balance;           ///< Swept forfeits awaiting payout; supply-visible
      share_type     paid_lifetime;     ///< Cumulative payouts (API visibility)
      uint16_t       routing_oracle_bps = 0;  ///< 5000 proposal: oracle leg
      uint16_t       routing_vault_bps = 0;   ///< 3000 proposal: vault leg (issuance engine)
      uint16_t       routing_reserve_bps = 0; ///< 2000 proposal: reserve leg (issuance engine)
      time_point_sec last_payout;       ///< Last sweep that processed this pool
      /**
       * X-03 joint-cap merge contract (H2 side, bounded scope): per-sweep
       * recorded H2 diversion in bps on the shared 10000-bps denominator.
       * The H2 reward sweep writes routing_oracle_bps here each sweep; the
       * G1 merge reads this field and asserts
       * parity_bps + h2_diversion_bps <= 7000
       * (GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS) on one shared denominator in
       * both routers. H2 asserts its half locally
       * (h2_diversion_bps <= cap); the G1-side sum assert lands with the
       * merge, not here. No cross-branch writes: this field is H2-written,
       * G1-read. Appended-last, never inserted.
       */
      uint16_t       h2_diversion_bps = 0;
};

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
};

/**
 * @brief One tripwire window: bounded sample storage with provenance.
 * @ingroup object
 * @ingroup protocol
 *
 * Windows rotate at maintenance: the sweep evaluates older+newer, shifts
 * newer into older, and opens a fresh newer. A window is VALID only with at
 * least GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW of bond-side volume; the pair is
 * multi-pool only with two distinct pools across both windows. Pools on pairs
 * without a vault never record (H1-exclusion is structural: no vault, no
 * state, no median contribution).
 */
struct h2_tripwire_window
{
   time_point_sec                 start;
   vector<h2_tripwire_sample>     samples; ///< Oldest first, FIFO-capped at 64
   uint64_t                       total_volume = 0; ///< Bond-side volume sum
   flat_set<liquidity_pool_id_type> pools; ///< Distinct contributing pools

   void validate()const
   { FC_ASSERT( samples.size() <= GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES, "Window overflow" ); }
};

/**
 * @brief Per-pair market-vs-feed tripwire with the halt ladder.
 * @ingroup object
 * @ingroup protocol
 *
 * The feed leg is the pair's BOUND oracle series-0 value (binding
 * convention: bond-per-pair); unbound pairs have no feed leg and never
 * evaluate, however full their windows. Breach escalates atomically
 * door+debt on first breach (X-05: no block observes door-closed/debt-open),
 * then redemptions on the next breach (max 3, idempotent);
 * clean evaluations build the reopen streak (2 clears). Paused evaluations
 * (invalid windows or missing feed) hold the stage and reset the streak:
 * reopen needs two CONSECUTIVE clean windows.
 */
class tripwire_state_object : public abstract_object<tripwire_state_object, protocol_ids, tripwire_state_object_type>
{
   public:
      asset_id_type      pair;              ///< Vault-backed pair; immutable
      h2_tripwire_window win_old;           ///< Older of the two windows
      h2_tripwire_window win_new;           ///< Newer of the two windows
      uint8_t            halt_stage = 0;    ///< GRAPHENE_H2E_TRIPWIRE_STAGE_*
      uint8_t            clean_streak = 0;  ///< Consecutive clean evaluations
      bool               redemptions_halted = false; ///< Stage-3 latch
};

/**
 * @brief System-wide Recovery state over the explicit collateral scope.
 * @ingroup object
 * @ingroup protocol
 *
 * Singleton (at most one): collateral = unseized bonds of live vaults;
 * debt = live outstanding. Terminal wind-down books are out of scope by
 * design (OQ-43): segregated remainders are earmarked for their own
 * claimants and must never suspend other pairs' growth (fault containment).
 * Below 15000 bps new debt (vault_register) is refused; exits (wind-down
 * claims) stay open. Zero debt is healthy, never Recovery: there is nothing
 * to suspend.
 */
class recovery_state_object : public abstract_object<recovery_state_object, protocol_ids, recovery_state_object_type>
{
   public:
      uint32_t       trigger_bps = 0; ///< 15000 proposal
      bool           new_debt_suspended = false;
      time_point_sec entered_at;
      share_type     last_collateral; ///< Scope totals at the last evaluation
      share_type     last_debt;
};

struct by_pool_oracle;   ///< reward pools by oracle (unique)
struct by_guard_oracle;  ///< guard states by oracle (unique)
struct by_tripwire_pair; ///< tripwire states by pair (unique)

/**
* @ingroup object_index
*/
using reward_pool_multi_index_type = multi_index_container<
   reward_pool_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_pool_oracle>,
         member< reward_pool_object, oracle_id_type, &reward_pool_object::oracle >
      >
   >
>;

/**
* @ingroup object_index
*/
using reward_pool_index = generic_index<reward_pool_object, reward_pool_multi_index_type>;

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

/**
* @ingroup object_index
*/
using tripwire_multi_index_type = multi_index_container<
   tripwire_state_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_tripwire_pair>,
         member< tripwire_state_object, asset_id_type, &tripwire_state_object::pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using tripwire_index = generic_index<tripwire_state_object, tripwire_multi_index_type>;

/**
* @ingroup object_index
*/
using recovery_state_multi_index_type = multi_index_container<
   recovery_state_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;

/**
* @ingroup object_index
*/
using recovery_state_index = generic_index<recovery_state_object, recovery_state_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reward_pool_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::guard_state_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::tripwire_state_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::recovery_state_object )

FC_REFLECT_TYPENAME( graphene::chain::reward_pool_object )
FC_REFLECT_TYPENAME( graphene::chain::guard_state_object )
FC_REFLECT_TYPENAME( graphene::chain::tripwire_state_object )
FC_REFLECT_TYPENAME( graphene::chain::recovery_state_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reward_pool_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::guard_state_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::tripwire_state_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::recovery_state_object )
