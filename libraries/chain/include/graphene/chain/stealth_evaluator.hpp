/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once
#include <graphene/chain/evaluator.hpp>
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
