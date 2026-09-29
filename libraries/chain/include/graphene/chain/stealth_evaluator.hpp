/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/chain/stealth_object.hpp>
#include <graphene/chain/types.hpp>

namespace graphene { namespace chain {

class stealth_transfer_evaluator : public evaluator<stealth_transfer_evaluator>
{
   public:
      typedef stealth_transfer_operation operation_type;

      void_result do_evaluate( const stealth_transfer_operation& o );
      void_result do_apply( const stealth_transfer_operation& o );

      virtual void pay_fee() override;
};

class freeze_blind_evaluator : public evaluator<freeze_blind_evaluator>
{
   public:
      typedef freeze_blind_operation operation_type;

      void_result do_evaluate( const freeze_blind_operation& o );
      void_result do_apply( const freeze_blind_operation& o );
};

class turnstile_reproof_evaluator : public evaluator<turnstile_reproof_evaluator>
{
   public:
      typedef turnstile_reproof_operation operation_type;

      void_result do_evaluate( const turnstile_reproof_operation& o );
      void_result do_apply( const turnstile_reproof_operation& o );

      virtual void pay_fee() override;
};

class parity_review_evaluator : public evaluator<parity_review_evaluator>
{
   public:
      typedef parity_review_operation operation_type;

      void_result do_evaluate( const parity_review_operation& o );
      void_result do_apply( const parity_review_operation& o );
};

// ---------------------------------------------------------------------------
// Introspection + maintenance hooks (used by evaluators AND the test suite)
// ---------------------------------------------------------------------------

/// True while blind ops must fail closed (tripwire or freeze quorum).
bool stealth_blind_halted( const database& db );
/// Nonzero block that fired the tripwire (0 = never).
uint32_t stealth_tripwire_fire_block( const database& db );
/// Blind ops counted against the cap in the currently-pending block.
uint32_t stealth_blind_count_this_block( const database& db );
/// Unspent decoy-candidate blinded balances of an asset (O(1) cached
/// counter, maintained on insert/spend by the blind evaluators; see
/// stealth_pool_count_add). Spent-but-retained outputs do not count.
uint32_t stealth_pool_depth( const database& db, asset_id_type asset );
/// Vote freshness: voted_at within the 48h expiry at head-block time.
bool stealth_vote_fresh( fc::time_point_sec now, fc::time_point_sec voted_at );
/// V1 sunset / turnstile G2 recorded at activation (0 pre-activation).
fc::time_point_sec stealth_v1_sunset_time( const database& db );
fc::time_point_sec stealth_turnstile_g2_time( const database& db );

/**
 * Maintenance-interval reconciliation (Monero-2018 rule, BSIP-2 §1):
 * for every asset, the evaluator-maintained shadow of confidential_supply
 * must equal the live counter EXACTLY. Any divergence engages blind_halted
 * automatically and records the firing block.
 * Called from perform_chain_maintenance (post-STEALTH only) and tests.
 *
 * Honesty note (review Finding 2): this detects DIVERGENCE between two
 * counters moved by the same evaluators through independent code paths —
 * i.e. direct state edits touching one side, or a future op that moves
 * blind value while forgetting one counter. It does NOT detect
 * common-mode drift where both counters move together: a verifier bug
 * that mints value through the proper evaluator paths updates the live
 * counter AND the shadow identically, so no comparison of the two can see
 * it, by construction. The defense against that class is prevention, not
 * detection: the conservation kernel (ring-bound pseudo-outputs + excess
 * equation on every spend) and sound output range proofs, which make the
 * mint unconstructable rather than merely visible. No cheap consensus
 * improvement closes the common-mode gap — recounting balances cannot sum
 * hidden values — so the tripwire keeps its narrow, truthful scope.
 */
void stealth_reconcile_supplies( database& db );

/**
 * Records first-activation timestamps at the first post-STEALTH
 * maintenance (idempotent). Called from perform_chain_maintenance.
 */
void stealth_maybe_record_activation( database& db );

// ---------------------------------------------------------------------------
// G1c parity economics (BSIP-2 §2): pool, float-to-cost, reviews, alarms
// ---------------------------------------------------------------------------

/**
 * Cost anchor for one blind op in CORE units: max(activation snapshot of the
 * transfer_to_blind schedule, pinned upstream defaults, current schedule),
 * mapped onto n blind outputs (fee + n*price_per_output).
 * The committee owns fee LEVELS (it parity-prices blind ops by lowering
 * their schedules); consensus owns the SELECTION between the parity level
 * (the op's own schedule) and this anchor by pool state. That split is
 * what "floats by rule, not by surprise" means: no committee action happens
 * at float time, and the float level is computable from public inputs.
 */
share_type stealth_cost_anchor_core( const database& db, uint32_t n_blind_outputs );

/**
 * Discount actually granted, CORE units: max(0, anchor - parity), where
 * parity is the op's own scheduled fee. Zero when the committee never priced
 * below the anchor (no discount, no debit — the pool then only accumulates).
 */
share_type stealth_parity_gap_core( const database& db, uint32_t n_blind_outputs,
                                    share_type parity_core );

/**
 * True when a gap of gap_core (CORE units) payable in fee_asset can be
 * subsidized now: post-STEALTH, not halted, parity review current (6mo),
 * pool balance covers the gap converted to fee_asset units (round UP,
 * pool-favoring), and the per-block subsidy cap is not exhausted. Missed
 * quarterly reports do NOT gate subsidies — they halt funding (routing)
 * only; the pool keeps paying until empty. Pure check (evaluate +
 * apply paths); the cap increment happens in do_apply only.
 */
bool stealth_parity_available( const database& db, asset_id_type fee_asset,
                               share_type gap_core );

/**
 * Convert a CORE-denominated gap to fee_asset units, rounding UP (the pool
 * never under-debits). CORE identity when fee_asset is CORE. Uses the same
 * core_exchange_rate the fee path uses, inverted with 128-bit math —
 * integer only, no floats.
 */
share_type stealth_gap_to_asset( const database& db, asset_id_type fee_asset,
                                 share_type gap_core );

/**
 * Enforce the float rule in do_evaluate (post-STEALTH only, fee-economics
 * path only — skipped exactly when the fee-schedule check is skipped, i.e.
 * genesis/test/generator context where no fee is paid and no subsidy may be
 * consumed). When subsidized, the central schedule check already enforces
 * the parity level, so this only binds on the cost path:
 * core_fee_paid >= cost_anchor.
 */
void stealth_require_blind_fee( const database& db, share_type core_fee_paid,
                                bool fees_enforced, asset_id_type fee_asset,
                                uint32_t n_blind_outputs, share_type parity_core );

/**
 * Consume the subsidy in do_apply (same skip guard as the check): the op's
 * paid level decides the path — at/above the cost anchor it is a cost-path
 * op (no discount granted, nothing consumed, even if the pool could cover);
 * below it, it MUST have been a subsidized parity-path op (fail-closed
 * assert + debit the pool by the gap in fee_asset units, credit the SAME
 * amount to the fee asset's accumulated_fees for supply-neutrality, record
 * interval flow, consume one per-block subsidy unit). All-or-nothing:
 * partial gaps are never split (deterministic, no dust games).
 */
void stealth_consume_parity_subsidy( database& db, bool fees_enforced,
                                     asset_id_type fee_asset,
                                     uint32_t n_blind_outputs,
                                     share_type parity_core,
                                     share_type core_fee_paid );

/**
 * Fee-share routing (called from database::pay_market_fees, the single
 * choke point for market + settlement fees): post-STEALTH and while funding
 * is not halted, move inout_increment * PARITY_FEE_SHARE_BPS / 10000 into
 * parity_pool[recv_asset] (128-bit integer math) and reduce inout_increment
 * to the remainder for accumulated_fees. Totals preserved exactly.
 * Returns the routed amount (0 pre-fork, while halted, or on dust).
 */
share_type stealth_parity_route_fee( database& db, asset_id_type recv_asset,
                                     share_type& inout_increment );

/**
 * Joint-ceiling accounting (BSIP-1 §7b): pure function. The parity share and
 * the recorded H2-side diversion on the shared denominator must jointly fit
 * under 70%. Recorded, not thrown, at runtime (see alarms.joint_cap_breach):
 * routing must never brick market fees on H2's numbers.
 */
bool stealth_joint_fee_within_cap( uint32_t parity_share_bps, uint32_t h2_diversion_bps );

/**
 * Per-interval maintenance (called from perform_chain_maintenance,
 * post-STEALTH only): seed review heartbeats at activation; recompute missed
 * review/report counts as whole elapsed intervals; derive funding-halted;
 * compute the burn ratio per asset from interval flow and reset the flow;
 * prune the creation histogram (newest 301 windows); refresh the alarm
 * snapshot (effective set, burn flags, skew flag, mass-exit flag, joint flag).
 */
void stealth_parity_maintenance( database& db );

/**
 * Record a committee attestation (called by parity_review_evaluator):
 * kind 0 resets the parity-review clock, kind 1 resets the set-report clock
 * (clearing funding-halted). head-block time only.
 */
void stealth_record_parity_review( database& db, uint8_t kind );

/// Read the last computed alarm snapshot (queryable via the status object).
stealth_alarm_snapshot stealth_current_alarms( const database& db );

/// Post-STEALTH only (pre-fork no-op): count n newly created decoy-eligible
/// blind outputs in the current 100-block window (bounded histogram input).
void stealth_window_count_add( database& db, uint32_t n );

/**
 * Shared pre-check for every blind op (legacy 39/40/41 + new 83/85):
 * hardfork active, not halted, block budget not exhausted. Increments the
 * per-block counter. Must be called from do_evaluate (check) AND the
 * increment must happen in do_apply (evaluation is side-effect free for
 * the proposal path). Split accordingly:
 * - stealth_check_blind_gate: pure check (evaluate + apply paths)
 * - stealth_count_blind_op: counter increment (apply path only)
 */
void stealth_check_blind_gate( const database& db );
void stealth_count_blind_op( database& db );
/// Post-STEALTH only (pre-fork no-op): move the per-asset confidential-supply
/// shadow by the same delta applied to asset_dynamic_data_object.
void stealth_shadow_add( database& db, asset_id_type asset, share_type delta );
/**
 * Post-STEALTH only (pre-fork no-op): maintain the per-asset count of
 * unspent metadata-bearing blinded balances backing stealth_pool_depth.
 * Positive delta on creation of a balance WITH post-fork metadata;
 * negative delta on consumption of such a balance (callers check
 * created_block != 0 for explicitly-consumed balances, which may be
 * grandfathered). Stealth spends consume inputs.size() real balances
 * (every real ring member is metadata-bearing by consensus rule) and
 * create outputs.size() new ones. Bounded: zero entries are removed.
 */
void stealth_pool_count_add( database& db, asset_id_type asset, int32_t delta );
/**
 * Post-STEALTH range soundness for legacy blind outputs (closes the live
 * gap uniformly): every output carrying a proof MUST verify, and every
 * output MUST carry one (single-output proof-less blinds were a pre-fork
 * wallet behavior; post-fork they are rejected — wallets attach proofs).
 */
void stealth_require_sound_range_proofs( const database& db,
      const vector<protocol::blind_output>& outputs );

} } // graphene::chain
