/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once

#include <graphene/protocol/stealth.hpp>
#include <graphene/chain/types.hpp>

#include <graphene/db/generic_index.hpp>

#include <fc/crypto/sha256.hpp>
#include <fc/crypto/elliptic.hpp>

namespace graphene { namespace chain {

/**
 * @brief Spent key image (nullifier). One entry per stealth spend per
 * proof version. Double-spend = same image twice = rejected at insert.
 * @ingroup object
 *
 * Bounded: entries are created only by spends and never deleted except
 * with the balance set they guard; both version sets are enforced during
 * the dual-verify window, V1 frozen (spend-only-via-turnstile) at sunset.
 */
class stealth_nullifier_object : public graphene::db::abstract_object<stealth_nullifier_object,
                                          implementation_ids, impl_stealth_nullifier_object_type>
{
   public:
      fc::sha256      key_image; ///< sha256 of the 33B compressed image point
      uint8_t         proof_version = 0;
      fc::time_point_sec created;
};

struct by_nullifier_image;

using stealth_nullifier_multi_idx = multi_index_container<
   stealth_nullifier_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_nullifier_image>,
         member<stealth_nullifier_object, fc::sha256, &stealth_nullifier_object::key_image> >
   >
>;
using stealth_nullifier_index = generic_index<stealth_nullifier_object, stealth_nullifier_multi_idx>;

/**
 * @brief Per-interval alarm snapshot (BSIP-2 §1-§2, G1c).
 * @ingroup object
 *
 * Recomputed every maintenance interval by stealth_parity_maintenance from
 * consensus state only (no floats, no wall-clock: head-block time and
 * integer ratios). Queryable like any implementation object (get_object on
 * the stealth status singleton). Alarms are block-speed signals; monthly
 * stats and quarterly reports remain the governance instruments.
 */
struct stealth_alarm_snapshot
{
   /// Known-spend-adjusted effective set per asset: unspent decoy-candidate
   /// blinded balances (spent-but-retained outputs are already excluded by
   /// the counter, grandfathered ones never counted).
   flat_map<asset_id_type, uint32_t> effective_set;
   /// Worst per-asset interval grant/route ratio, percent (100 when grants
   /// exist with no routed inflow; 0 when neither moved).
   uint32_t              burn_rate_pct = 0;
   bool                  burn_warn = false;     ///< worst >= 50% (proposal)
   bool                  burn_critical = false; ///< worst >= 80% (proposal)
   /// True when the youngest 100-block creation window holds more than 40%
   /// of the retained decoy-eligible pool: new rings WILL skew young, so
   /// availability (the pool floor) is about to bind harder. Heuristic over
   /// the bounded creation histogram (spent outputs stay retained as decoys,
   /// so the histogram counts created-eligible, not unspent — documented
   /// approximation; the floor gate, not this flag, enforces).
   bool                  decoy_skew_warn = false;
   /// True while any fresh committee freeze vote is live or blind ops are
   /// halted: exits through the transparent legs may crowd (BSIP-2 §1).
   bool                  mass_exit_warn = false;
   /// True when parity_share + recorded H2 diversion exceeds the 70% joint
   /// ceiling (BSIP-1 §7b): signal, not halt — governance must rebalance.
   bool                  joint_cap_breach = false;
};

/**
 * @brief A committee freeze vote (up to one live vote per member).
 * @ingroup object
 */
struct stealth_freeze_vote
{
   account_id_type       voter;
   bool                  freeze = true;
   fc::time_point_sec    voted_at;
};

/**
 * @brief Singleton consensus state for the stealth subsystem.
 * @ingroup object
 *
 * Created at chain init (genesis replay included). Activation timestamps
 * are RECORDED at the first post-STEALTH maintenance, never assumed:
 * v1_sunset/turnstile_g2 are activation + V1_LIFETIME, so the turnstile
 * date is known from activation day one (BSIP-2 §1).
 */
class stealth_status_object : public graphene::db::abstract_object<stealth_status_object,
                                          implementation_ids, impl_stealth_status_object_type>
{
   public:
      /// Fail-closed halt flag: while set, all blind ops (39/40/41/83/85)
      /// reject in do_evaluate. Set by the tripwire (auto) or the freeze
      /// quorum (manual backup); cleared by the resume quorum.
      bool                  blind_halted = false;
      /// Block number that fired the tripwire (0 = never / manual-only).
      uint32_t              tripwire_fire_block = 0;
      /// Per-block blind-op counter for the cap (block_num, count).
      uint32_t              blind_block_num = 0;
      uint32_t              blind_block_count = 0;
      /// Activation record (0 = pre-activation).
      fc::time_point_sec    stealth_activated_time;
      fc::time_point_sec    v1_sunset_time;
      fc::time_point_sec    turnstile_g2_time;
      /// Live freeze votes, one per member, bounded by committee size.
      /// flat_map is ORDERED (consensus law: no unordered_* anywhere).
      flat_map<account_id_type, stealth_freeze_vote> freeze_votes;
      /// Per-asset shadow of confidential_supply, maintained by the SAME
      /// evaluators that move blind value (post-STEALTH only) but updated
      /// through an independent code path from asset_dynamic_data_object.
      /// Reconciliation compares the two; any divergence (direct state edit
      /// or a future op that forgets a counter) fires the tripwire. Seeded
      /// from live confidential_supply values at activation (first
      /// post-STEALTH maintenance), so pre-fork history reconciles by
      /// construction. flat_map is ORDERED (consensus law).
      flat_map<asset_id_type, share_type> blinded_supply_shadow;
      /// Per-asset count of UNSPENT blinded balances carrying post-fork
      /// creation metadata (decoy candidates; age is ruled per-ring by the
      /// decoy policy, not here). Maintained on insert/spend by the blind
      /// evaluators, post-STEALTH only — this is the O(1) backing of
      /// stealth_pool_depth (no per-evaluate full-pool scan). Spent-but-
      /// retained ring inputs stay indexed as future decoys but do NOT
      /// count here (their real value is gone; the floor guards live
      /// value). Grandfathered (pre-fork, metadata absent) balances never
      /// count. Zero entries are removed; flat_map is ORDERED.
      flat_map<asset_id_type, uint32_t> unspent_blind_count;
      // --- G1c parity pool (BSIP-2 §2). All appended-last. ---
      /// Per-asset parity pool balances (fee-share inflow minus granted
      /// subsidies). Zero entries removed; ORDERED flat_map. Part of supply
      /// accounting (see verify_asset_supplies): inflow redirects the
      /// accumulated_fees increment, outflow credits accumulated_fees, so
      /// every movement preserves asset totals exactly.
      flat_map<asset_id_type, share_type> parity_pool;
      /// Per-block subsidized-op counter for the cap (block_num, count).
      uint32_t              parity_block_num = 0;
      uint32_t              parity_subsidized_count = 0;
      /// Review/report heartbeats (0 = never; seeded to activation on the
      /// first post-STEALTH maintenance). Missed counts are RECOMPUTED each
      /// maintenance as whole elapsed intervals (deterministic under replay
      /// and time jumps; no incremental state to corrupt).
      fc::time_point_sec    last_parity_review_time;
      fc::time_point_sec    last_set_report_time;
      uint32_t              missed_parity_reviews = 0;
      uint32_t              missed_set_reports = 0;
      /// True once two consecutive quarterly reports are missed: fee-share
      /// routing stops until a report is attested. The pool keeps paying
      /// until empty (halt is on funding, not on granted subsidies).
      bool                  parity_funding_halted = false;
      /// H2-side diversion on the shared joint denominator, basis points
      /// (0 until the hybrid program lands and its writer records it here).
      /// The joint ceiling is enforced as accounting + alarm, never as a
      /// market-fee throw (routing must not brick on H2's numbers).
      uint32_t              h2_diversion_bps = 0;
      /// Per-interval routed/granted flow per asset (reset every
      /// maintenance after the burn ratio is computed). Flow stats, not
      /// balances: never part of supply accounting. Zero entries removed.
      flat_map<asset_id_type, share_type> interval_routed;
      flat_map<asset_id_type, share_type> interval_granted;
      /// Decoy-eligible blind outputs created per 100-block window
      /// (window index = block_num / 100, global across assets). Pruned to
      /// the newest 301 windows every maintenance: bounded by construction.
      flat_map<uint32_t, uint32_t> blind_window_counts;
      /// Activation snapshot of the transfer_to_blind fee schedule
      /// (base + per-output): the TRUE pre-parity levels, captured once at
      /// the first post-STEALTH maintenance. Feeds the cost anchor's max()
      /// so committee cuts below activation levels open a subsidy gap while
      /// committee raises move the anchor with them.
      uint64_t              activation_k39_fee = 0;
      uint32_t              activation_k39_ppo = 0;
      /// Last computed alarm snapshot (see stealth_alarm_snapshot).
      stealth_alarm_snapshot alarms;
};

using stealth_status_multi_idx = multi_index_container<
   stealth_status_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;
using stealth_status_index = generic_index<stealth_status_object, stealth_status_multi_idx>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE(graphene::chain::stealth_nullifier_object)
MAP_OBJECT_ID_TO_TYPE(graphene::chain::stealth_status_object)

FC_REFLECT_TYPENAME( graphene::chain::stealth_nullifier_object )
FC_REFLECT_TYPENAME( graphene::chain::stealth_status_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::stealth_nullifier_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::stealth_status_object )

FC_REFLECT( graphene::chain::stealth_freeze_vote, (voter)(freeze)(voted_at) )
FC_REFLECT( graphene::chain::stealth_alarm_snapshot,
            (effective_set)(burn_rate_pct)(burn_warn)(burn_critical)
            (decoy_skew_warn)(mass_exit_warn)(joint_cap_breach) )
