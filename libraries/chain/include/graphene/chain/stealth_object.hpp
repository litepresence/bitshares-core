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
 * @brief Per-interval alarm snapshot (BSIP-2 §1-§2).
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
   /// Live-set effective depth per asset: metadata-bearing blinded balances
   /// currently indexed. Ring spends remove nothing (nullifier
   /// migration: nullified outputs stay indexed and decoy-eligible), so only
   /// consuming spends leave the set — the live pool the floor gate measures,
   /// exposed to wallets/UIs via database_api::get_stealth_effective_set.
   flat_map<asset_id_type, uint32_t> effective_set;
   /// Worst per-asset interval grant/route ratio, percent (100 when grants
   /// exist with no routed inflow; 0 when neither moved).
   uint32_t              burn_rate_pct = 0;
   bool                  burn_warn = false;     ///< worst >= 50% (proposal)
   bool                  burn_critical = false; ///< worst >= 80% (proposal)
   /// True when the youngest 100-block creation window holds more than 40%
   /// of the retained decoy-eligible pool: new rings WILL skew young, so
   /// availability (the pool floor) is about to bind harder. Heuristic over
   /// the bounded creation histogram (nullified outputs stay indexed and
   /// decoy-eligible, so the histogram counts created-eligible live balances
   /// — documented approximation; the floor gate, not this flag, enforces).
   bool                  decoy_skew_warn = false;
   /// True while any fresh committee freeze vote is live or blind ops are
   /// halted: exits through the transparent legs may crowd (BSIP-2 §1).
   bool                  mass_exit_warn = false;
   /// True while any asset's live decoy-candidate pool sits below
   /// GRAPHENE_STEALTH_POOL_WARN_DEPTH (22): availability is degrading
   /// toward the floor halt. ALARM ONLY — no consensus path asserts on it
   /// (never FC_ASSERT in any market, fee, or blind evaluation path).
   bool                  thin_pool_warn = false;
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
 * @brief A pending committee parity attestation (parity quorum).
 * @ingroup object
 *
 * Single-member attestations no longer move the clocks: a review/report is
 * recorded only when two DISTINCT members attest the same kind while both
 * attestations are fresh (see GRAPHENE_STEALTH_PARITY_*). One pending entry
 * per member (latest wins); stale entries are pruned on every attestation,
 * so state stays bounded by committee size.
 */
struct stealth_parity_vote
{
   account_id_type       voter;
   uint8_t               kind = 0; ///< REVIEW_PARITY or REVIEW_SET_REPORT
   fc::time_point_sec    voted_at;
};

/**
 * @brief One deposit event (spec 2026-10-11 §8): WHO deposited HOW MANY.
 * @ingroup object
 *
 * One op39 pushes exactly one event regardless of its output count, so the
 * window is bounded by events, never by outputs. Appended-last discipline
 * applies to the member order.
 */
struct stealth_deposit_event
{
   account_id_type       account;
   uint32_t              n = 0;
};

/**
 * @brief Bounded deposit-event window (spec 2026-10-11 §8).
 * @ingroup object
 *
 * The last W deposit events for one asset, as a ring buffer: each op39
 * writes position `head`, then `head = (head + 1) % W`, overwriting the
 * oldest when full (`count` saturates at W). `total_ever` is monotonic
 * telemetry only — never a concentration input. E_dep is computed on read
 * by exact aggregation over ≤1024 pairs (integers only); since A4 the op39
 * evaluator ALSO scans (subsidy classifier in do_evaluate/do_apply), uncharged.
 * Ring-created outputs are unattributable by construction and never enter
 * here — only op39 deposits (transparent `o.from`) do. flat_map ORDERED.
 */
struct stealth_depositor_window
{
   uint64_t                                total_ever = 0;
   uint32_t                                head = 0;
   uint32_t                                count = 0;
   flat_map<uint32_t, stealth_deposit_event> events; ///< positions 0..W-1
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
      /// Fail-closed halt flag: while set, all blind ops (39/40/41/104/106)
      /// reject in do_evaluate. Set by the freeze 3-quorum (manual backup);
      /// cleared by the resume 3-quorum with an empty diverged_assets set.
      /// The supply tripwire no longer flaps this flag (SUP-07): it
      /// records diverged_assets per asset instead.
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
      fc::time_point_sec    v2_sunset_time; ///< V2 sunset: forces migration to V3 (ViewKey channel)
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
      /// Per-asset count of LIVE blinded balances carrying post-fork
      /// creation metadata (decoy candidates; age is ruled per-ring by the
      /// decoy policy, not here). Maintained on insert/spend by the blind
      /// evaluators, post-STEALTH only — this is the O(1) backing of
      /// stealth_pool_depth (no per-evaluate full-pool scan). Under
      /// nullifier migration the counter has live-set semantics: every
      /// indexed metadata-bearing balance counts, including nullified ones
      /// (they stay decoy-eligible, so the set grows with usage). Ring
      /// spends add outputs and remove nothing; explicit spends (op41/op108)
      /// decrement. Despite the historical field name `unspent_blind_count`,
      /// this is the LIVE set (all metadata-bearing balances), not a strict
      /// unspent count. Retained for object reflection / API surface
      /// compatibility; not renamed to avoid breaking wire reflection.
      /// Grandfathered (pre-fork, metadata absent) balances never count.
      /// Zero entries are removed; flat_map is ORDERED.
      flat_map<asset_id_type, uint32_t> unspent_blind_count;
      /// Per-asset supply-divergence set (SUP-07): assets whose
      /// evaluator-maintained shadow disagrees with live
      /// confidential_supply. Blind ops of listed assets halt individually
      /// (per-asset scope — healthy assets keep moving); the committee
      /// resume quorum is refused while this set is non-empty. Entries heal
      /// automatically when reconciliation passes for that asset.
      /// flat_set is ORDERED (consensus law).
      flat_set<asset_id_type> diverged_assets;
      /// Pending single-member parity attestations awaiting a second
      /// distinct member for the same kind (parity quorum). One per
      /// member; pruned to fresh entries on every attestation. ORDERED.
      flat_map<account_id_type, stealth_parity_vote> pending_parity_votes;
      // --- parity pool (BSIP-2 §2). All appended-last. ---
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
      /// G2 op109 market-fee routed this interval (MG-04): the issuer-fee
      /// amount accumulated by g2_route_market_fee_to_parity, expressed as
      /// basis points on the shared joint-cap denominator at maintenance.
      /// Scalar, one shared denominator with parity + h2. Reset each interval
      /// after the joint-cap alarm is computed so it never grows unbounded.
      share_type            g2_routed_interval = share_type( 0 );
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
      /// Per-block blind verification-work counter for the F-01 work budget
      /// (block_num, used microsecond-model units). Appended-last (R9B);
      /// reset on block rollover exactly like blind_block_num/count above.
      uint32_t              blind_work_block_num = 0;
      uint32_t              blind_work_used_us = 0;
      /// Phase-1 instrumentation (spec 2026-10-11 §8): per-asset deposit
      /// concentration. Read by the Rule R subsidy classifier
      /// (stealth_op39_subsidy_count -> stealth_window_dominance via
      /// stealth_window_dominant): a depositor past the 1/16 dominance
      /// boundary has their deposit subsidy capped at 1 output. It does NOT
      /// permit or refuse the op itself — the fee subsidy is money, not a
      /// gate — but it is consensus-live through the fee schedule, not
      /// dead state. (G1-10: the old "STATE ONLY — nothing reads
      /// it" doc predated the A3/A4 effective-N wiring.) Appended-last;
      /// zero-initialized, so history reconciles by default. Sparse: entries
      /// exist only for assets with post-STEALTH deposits.
      /// flat_map is ORDERED.
      flat_map<asset_id_type, stealth_depositor_window> deposit_windows;
      /// SUP-R-10 (CDR-10/CDR-11): append-only per-asset grant/route
      /// flow totals. Appended from interval_routed/interval_granted at each
      /// stealth_parity_maintenance immediately before the interval_*.clear()
      /// — NEVER cleared. Bounded by the number of opted-in assets that have
      /// ever had parity flow (no open growth: entries only appear when a
      /// non-zero flow is first recorded). Makes the per-asset flow series
      /// retrievable from chain state (get_objects on 2.20.0), closing the
      /// E0-measurability gap. Appended-last for wire-format stability.
      flat_map<asset_id_type, share_type> cumulative_routed;
      flat_map<asset_id_type, share_type> cumulative_granted;
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
FC_REFLECT( graphene::chain::stealth_parity_vote, (voter)(kind)(voted_at) )
FC_REFLECT( graphene::chain::stealth_deposit_event, (account)(n) )
FC_REFLECT( graphene::chain::stealth_depositor_window, (total_ever)(head)(count)(events) )
FC_REFLECT( graphene::chain::stealth_alarm_snapshot,
            (effective_set)(burn_rate_pct)(burn_warn)(burn_critical)
            (decoy_skew_warn)(mass_exit_warn)(joint_cap_breach)
            (thin_pool_warn) )
