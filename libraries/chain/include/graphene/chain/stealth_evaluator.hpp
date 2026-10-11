/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/chain/liquidity_pool_evaluator.hpp>
#include <graphene/chain/stealth_object.hpp>
#include <graphene/chain/types.hpp>

namespace graphene { namespace chain {

/**
 * Blind-operation evaluators (BSIP-2, STEALTH hardfork leg).
 *
 * Junior-dev map: `stealth_transfer` is the private payment itself (ring +
 * Bulletproofs+, verified in consensus, not in wallets); the other three are
 * the safety rails — `freeze_blind` halts all blind ops on a 3-quorum within
 * 24h (zero-fee so the halt is always callable), `turnstile_reproof`
 * migrates V1 outputs to V2 range proofs before the V1 sunset, and
 * `parity_review` records committee attestations that keep fee-parity and
 * set-report clocks current (kind 0 = parity review, kind 1 = set report;
 * zero-fee so attestations are never taxed). Every blind op first passes
 * `stealth_check_blind_gate` (hardfork active, not halted, block budget left)
 * and increments the per-block counter in apply only. Rings are consensus
 * floor 16 (TARGET everywhere, thin or deep; pool halt below 11, warning
 * below 22), cap 32; nullified members stay decoy-eligible (the nullifier
 * set is keyed by sha256(image), uncomputable without the opening, so a
 * nullified decoy is indistinguishable from a live one);
 * decoys must be 24h old with skew guards.
 * Markets, margin, pools, settlement, vaults, and oracles stay transparent —
 * blindness never touches price discovery or coverage accounting.
 */

/**
 * Private spend (CLSAG-lineage ring + Bulletproofs+ range proof).
 * Proves in evaluate (ring verifies, proofs verify, excess balances,
 * nullifiers fresh, fee meets the parity/cost rule via
 * `stealth_require_blind_fee`); consumes nullifiers and the parity subsidy
 * in apply. See the AUDIT markers in `stealth_proof.hpp` for what is
 * verbatim crypto vs adapted — the named specialist audit owns that line.
 */
class stealth_transfer_evaluator : public evaluator<stealth_transfer_evaluator>
{
   public:
      typedef stealth_transfer_operation operation_type;

      void_result do_evaluate( const stealth_transfer_operation& o );
      void_result do_apply( const stealth_transfer_operation& o );

      virtual void pay_fee() override;
};

/**
 * Emergency blind halt (zero-fee).
 * Three-quorum within 24h freezes all blind ops (freeze wins ties); thaw
 * needs a second 3-quorum AND an empty supply-divergence set. Fail-closed
 * by default: expiry of votes without quorum leaves the freeze in place.
 * Callable by anyone — the zero fee exists so the halt can never be
 * priced out.
 */
class freeze_blind_evaluator : public evaluator<freeze_blind_evaluator>
{
   public:
      typedef freeze_blind_operation operation_type;

      void_result do_evaluate( const freeze_blind_operation& o );
      void_result do_apply( const freeze_blind_operation& o );
};

/**
 * V1 → V2 turnstile migration.
 * Re-proves a legacy blind output with a V2 range proof before the V1 sunset
 * timestamp; after sunset, V1 outputs spend ONLY through this turnstile.
 * One-way: there is no path back to V1.
 */
class turnstile_reproof_evaluator : public evaluator<turnstile_reproof_evaluator>
{
   public:
      typedef turnstile_reproof_operation operation_type;

      void_result do_evaluate( const turnstile_reproof_operation& o );
      void_result do_apply( const turnstile_reproof_operation& o );

      virtual void pay_fee() override;
};

/**
 * Committee attestation review (op 107, kind-gated, zero-fee).
 * Kind 0 resets the 6-month parity-review clock (missed review ⇒ blind fees
 * float to cost by rule); kind 1 resets the set-report clock (two missed
 * reports ⇒ parity funding halts until reporting resumes). Bad kinds fail
 * fast in evaluate, never late in the block.
 */
class parity_review_evaluator : public evaluator<parity_review_evaluator>
{
   public:
      typedef parity_review_operation operation_type;

      void_result do_evaluate( const parity_review_operation& o );
      void_result do_apply( const parity_review_operation& o );
};

/**
 * Explicit spend of blind balances (op 108, proof-first double-spend guard).
 * One operation, two legs: outputs non-empty => blind->blind (ring spend's
 * kernel); outputs empty => blind->transparent exit (op41's kernel). The
 * per-input gate ORDER is the security property: recovery-proof verification
 * (3a) BEFORE nullifier absence (3b) — the proof binds (b,v) to the
 * commitment AND both images, so fabricated images refuse at the proof, not
 * at the nullifier set. Both kernels run in do_evaluate, never validate()
 * (proposal-embedded ops bypass validate).
 */
class stealth_explicit_spend_evaluator : public evaluator<stealth_explicit_spend_evaluator>
{
   public:
      typedef stealth_explicit_spend_operation operation_type;

      void_result do_evaluate( const stealth_explicit_spend_operation& o );
      void_result do_apply( const stealth_explicit_spend_operation& o );

      virtual void pay_fee() override;
};

/**
 * Blind pool swap (op 109, G2; design 2026-10-10-stealth-pool-swaps-design).
 * 1-in/1-out replica of liquidity_pool_exchange through the shared pool-math
 * helper, with the six-link soundness chain (Schnorr value-pin → ring M-leg
 * → kernel → integer check → BP+ → nullifiers). Verification order in
 * do_evaluate is load-bearing EXCEPT for one documented data dependency:
 * the shared pool math (and the composite-F bound asserts) run BEFORE the
 * ring verification because G2RM binds the composite fee F — the ring
 * message cannot be built before F is computed and bounded. All fail-closed
 * asserts still precede acceptance, and proof-before-nullifier is preserved.
 * Fee routing (design §5): issuer market-fee shares land in
 * parity_pool[asset] (never accumulated_fees); the committee network_percent
 * cut still vests to COMMITTEE; registrar/referrer rewards are forfeited
 * (no identifiable taker). No real user balance is ever touched (TEMP leg).
 */
class stealth_pool_exchange_evaluator : public evaluator<stealth_pool_exchange_evaluator>
{
   public:
      typedef stealth_pool_exchange_operation operation_type;

      void_result do_evaluate( const stealth_pool_exchange_operation& o );
      void_result do_apply( const stealth_pool_exchange_operation& o );

      virtual void pay_fee() override;

   private:
      const liquidity_pool_object* _pool = nullptr;
      pool_exchange_amounts _amounts;
      int64_t _F = 0;
};

// ---------------------------------------------------------------------------
// Introspection + maintenance hooks (used by evaluators AND the test suite)
// ---------------------------------------------------------------------------

/// True while blind ops must fail closed (tripwire or freeze quorum).
bool stealth_blind_halted( const database& db );
/// True while an asset's blind ops must fail closed (supply divergence:
/// the asset is listed in diverged_assets until reconciliation passes).
bool stealth_asset_halted( const database& db, asset_id_type asset );
/// Nonzero block that fired the tripwire (0 = never).
uint32_t stealth_tripwire_fire_block( const database& db );
/// Blind ops counted against the cap in the currently-pending block.
uint32_t stealth_blind_count_this_block( const database& db );
/// Live decoy-candidate blinded balances of an asset (O(1) cached
/// counter, maintained on insert/spend by the blind evaluators; see
/// stealth_pool_count_add). Task 3 (nullifier migration): live-set
/// semantics — every indexed metadata-bearing balance counts, including
/// nullified ones (they stay decoy-eligible, so the set grows with usage).
/// Historical field name `unspent_blind_count` retained (object reflection
/// + API surface); the misnomer is documented, not renamed.
uint32_t stealth_pool_depth( const database& db, asset_id_type asset );
/// Vote freshness: voted_at within the 24h expiry at head-block time.
bool stealth_vote_fresh( fc::time_point_sec now, fc::time_point_sec voted_at );
/// V1 sunset / turnstile G2 recorded at activation (0 pre-activation).
fc::time_point_sec stealth_v1_sunset_time( const database& db );
fc::time_point_sec stealth_turnstile_g2_time( const database& db );

/**
 * Maintenance-interval reconciliation (Monero-2018 rule, BSIP-2 §1):
 * for every asset, the evaluator-maintained shadow of confidential_supply
 * must equal the live counter EXACTLY. Any divergence records the asset in
 * diverged_assets (per-asset halt scope, SUP-07 — NOT the global flag) and
 * records the firing block; entries heal when reconciliation passes.
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
 * Rule R (spec docs/superpowers/specs/2026-10-10-stealth-entropy-economics.md
 * §4): the output count the PARITY SUBSIDY gap may be computed on, as a pure
 * function of the op's effect on the live anonymity set D_a.
 *
 * THE MODEL IS THE CHAIN'S OWN LIVE-SET COUNTER, not the pre-Task-3 reading of
 * spec §1 in which every op consumes its inputs (EE-1b, review F-1):
 *   - RING spends consume NOTHING — the whole-ring spent write and its coupled
 *     `stealth_pool_count_add(...,-1)` were both retired
 *     (stealth_evaluator.cpp:770-772), so ΔD_a = +n_out for op40/op104/op106/
 *     op109 at any ring size. A consolidation-shaped m-in/m-out ring op grows
 *     the measured live set by m and keeps the full per-output component.
 *   - EXPLICIT spends DO consume (-spent_counted at
 *     confidential_evaluator.cpp:187 and stealth_evaluator.cpp:1968), so
 *     op41/op108 net n_out - n_in: net-positive keeps the full component,
 *     net <= 0 falls back to the base fee (n = 1), and op41 — which carries no
 *     outputs member at all — and op108's exit leg get 0.
 *   - op39 deposits keep the full component (+n, the only net source of value
 *     into the blind set); an unknown op fails closed at 0.
 *
 * SCOPE — this NEVER governs the fee floor. The floor is
 * `stealth_cost_anchor_core(db, n_blind_outputs)` and this classifier cannot
 * move it: callers hand that function the op's REAL n_blind_outputs, so Rule R
 * can cap a DISCOUNT but never a floor.
 *
 * NARROWING (EE3-M1). This used to read "... which no user's fee is computed
 * against differently after this function exists". True when written — op109
 * then called neither `stealth_require_blind_fee` nor
 * `stealth_consume_parity_subsidy` and had no float rule at all (`ee67fd75`) —
 * but no longer a universal: `bed7c6ef` put op109 inside the mechanism, so an
 * op109 fee is now computed against the anchor where before it was not. What
 * survives is the weaker and load-bearing claim: this classifier never GOVERNS
 * the floor. Callers hand `stealth_cost_anchor_core` the op's REAL
 * n_blind_outputs, so Rule R can only shrink the gap, never move the floor;
 * the anchor function itself is unmodified (byte-identical since `ee67fd75`,
 * tooling/verify_stealth_cost_anchor_unchanged.py). op109's floor is
 * `anchor(1)` — the same for every 1-in/1-out swap, because it passes the
 * literal 1 (stealth_evaluator.cpp:2210) and a ring of any size cannot change
 * it. That rule is intended, STEALTH-gated (:1401 skips pre-STEALTH), fails
 * closed (:1411 asserts below the floor), and is pinned by
 * poolswap_happy_path / poolswap_wrong_fee_fails.
 *
 * Callers MUST pass
 *     subsidy_n = min( n_blind_outputs, stealth_subsidy_output_count(op) )
 * so the cap can only SHRINK the gap; taking the classifier result directly
 * would let a call site's own (possibly larger) n leak back in.
 */
uint32_t stealth_subsidy_output_count( const protocol::operation& op );

/// Phase-2 A4 (spec 2026-10-11-phase2 §2): true iff the window is full and
/// acct's share of the windowed base strictly exceeds 1/ring_target.
/// Integer only, no db access (unit-testable without chain state).
bool stealth_window_dominant( const stealth_depositor_window& w,
                              account_id_type acct, uint32_t ring_target );
/// Discount output count for op39: 1 when dominant past a full window, else
/// the Rule R classifier result. Both op39 call sites use min(n, this).
uint32_t stealth_op39_subsidy_count( const database& db, asset_id_type asset,
                                     account_id_type depositor,
                                     const protocol::operation& op );

/**
 * Cost anchor for one blind op in CORE units: max(activation snapshot of the
 * transfer_to_blind schedule, pinned upstream defaults, current schedule),
 * mapped onto n blind outputs (fee + n*price_per_output).
 * The committee owns fee LEVELS (it parity-prices blind ops by lowering
 * their schedules); consensus owns the SELECTION between the parity level
 * (the op's own schedule) and this anchor by pool state. That split is
 * what "floats by rule, not by surprise" means: no committee action happens
 * at float time, and the float level is computable from public inputs.
 *
 * THE FLOOR. This is the unsubsidized required fee and Rule R must not move
 * it: callers pass the op's REAL n_blind_outputs here, never subsidy_n.
 */
share_type stealth_cost_anchor_core( const database& db, uint32_t n_blind_outputs );

/**
 * Discount actually granted, CORE units: max(0, anchor(min(n_blind_outputs,
 * subsidy_n)) - parity), where parity is the op's own scheduled fee. Zero
 * when the committee never priced below the anchor (no discount, no debit —
 * the pool then only accumulates). subsidy_n caps the gap at the base-fee
 * component for ops that do not grow the anonymity set; it can only shrink
 * the anchor leg, never raise it (see stealth_subsidy_output_count).
 */
share_type stealth_parity_gap_core( const database& db, uint32_t n_blind_outputs,
                                    share_type parity_core, uint32_t subsidy_n );

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
 * core_fee_paid >= cost_anchor. cost_anchor is computed from the REAL
 * n_blind_outputs (Rule R never lowers a user's floor); subsidy_n only caps
 * the DISCOUNT that would have been granted below it.
 */
void stealth_require_blind_fee( const database& db, share_type core_fee_paid,
                                bool fees_enforced, asset_id_type fee_asset,
                                uint32_t n_blind_outputs, share_type parity_core,
                                uint32_t subsidy_n );

/**
 * Consume the subsidy in do_apply (same skip guard as the check): the op's
 * paid level decides the path — at/above the cost anchor it is a cost-path
 * op (no discount granted, nothing consumed, even if the pool could cover);
 * below it, it MUST have been a subsidized parity-path op (fail-closed
 * assert + debit the pool by the gap in fee_asset units, credit the SAME
 * amount to the fee asset's accumulated_fees for supply-neutrality, record
 * interval flow, consume one per-block subsidy unit). All-or-nothing:
 * partial gaps are never split (deterministic, no dust games).
 *
 * The cost-path test uses the REAL n_blind_outputs, so an op that paid the
 * floor is never charged a debit it did not earn; only the gap leg is capped
 * by subsidy_n, and require/consume derive it identically.
 */
void stealth_consume_parity_subsidy( database& db, bool fees_enforced,
                                     asset_id_type fee_asset,
                                     uint32_t n_blind_outputs,
                                     share_type parity_core,
                                     share_type core_fee_paid,
                                     uint32_t subsidy_n );

/**
 * Fee-share routing (called from database::pay_market_fees, the single
 * choke point for market + settlement fees): post-STEALTH, while funding
 * is not halted, AND only when the fee asset's issuer opted in via
 * additional_asset_options.parity_fee_share_enabled (Task 7 legacy gate:
 * absent == false, so every legacy asset never diverts), move
 * inout_increment * PARITY_FEE_SHARE_BPS / 10000 into
 * parity_pool[recv_asset] (128-bit integer math) and reduce inout_increment
 * to the remainder for accumulated_fees. Totals preserved exactly.
 * Returns the routed amount (0 pre-fork, while halted, on dust, or when the
 * asset did not opt in — the increment is then untouched).
 *
 * Deliberately NOT called from pay_force_settle_fees: the BSIP-87 slice is
 * collateral-denominated revenue credited to the DEBT asset's
 * accumulated_collateral_fees, so routing it would mix denominations inside
 * one per-asset pool entry and break the pool's denomination identity
 * (subsidies pay out pool[fee_asset] in fee_asset units). The MARKET-fee leg
 * of a force-settlement still routes when the COLLATERAL asset opted in —
 * denomination-preserving, via this same function.
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
 * the attestation is stored as pending; the clocks move only when two
 * DISTINCT members have attested the same kind within the attest-expiry
 * window (Task 6 quorum). Kind 0 moves the 6-month parity-review clock,
 * kind 1 moves the set-report clock (clearing funding-halted).
 * head-block time only. Unknown kinds fail closed.
 */
void stealth_record_parity_review( database& db, uint8_t kind, account_id_type voter );

/// Read the last computed alarm snapshot (queryable via the status object).
stealth_alarm_snapshot stealth_current_alarms( const database& db );

/// Post-STEALTH only (pre-fork no-op): count n newly created decoy-eligible
/// blind outputs in the current 100-block window (bounded histogram input).
void stealth_window_count_add( database& db, uint32_t n );

/**
 * Shared pre-check for every blind op (legacy 39/40/41 + new 104/106):
 * hardfork active, not halted, block budget not exhausted. Increments the
 * per-block counter. Must be called from do_evaluate (check) AND the
 * increment must happen in do_apply (evaluation is side-effect free for
 * the proposal path). Split accordingly:
 * - stealth_check_blind_gate: pure check (evaluate + apply paths)
 * - stealth_count_blind_op: counter increment (apply path only)
 * The F-01 work budget (R9B) rides alongside with the same split:
 * - stealth_check_blind_work_gate(db, work_us): fail-closed FC_ASSERT when
 *   the pending block's accumulated work plus this op exceeds
 *   GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK; no-op pre-fork.
 * - stealth_count_blind_work(db, work_us): accumulate in do_apply only.
 * Per-op work comes from the pure calculators below (integer model units,
 * saturated — never throws, never wraps):
 * - stealth_work_for_stealth_transfer: 2 x ring.size() per input (dual
 *   verify) at WORK_US_PER_RING_MEMBER, plus per-output range proofs, plus
 *   the kernel allowance.
 * - stealth_work_for_range_proofs(n): n outputs x WORK_US_PER_RANGE_PROOF
 *   (legacy deposits / blind transfers / turnstile outputs; V1 charged at
 *   the BP+ rate — conservative over-count, see stealth.hpp).
 * transfer_from_blind carries no work calls: explicit spends verify no
 * cryptography (index + owner checks only), so its work is 0 by
 * construction; the count gate still binds it.
 */
void stealth_check_blind_gate( const database& db );
/// Per-asset leg of the blind gate (SUP-07): every blind op evaluator calls
/// this with its asset right after stealth_check_blind_gate. No-op pre-fork.
void stealth_check_asset_gate( const database& db, asset_id_type asset );
void stealth_count_blind_op( database& db );
/// F-01 work-budget gate (R9B): fail-closed when the pending block's used
/// work plus work_us exceeds GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK.
/// No-op pre-fork. Called from do_evaluate right after the count gate.
void stealth_check_blind_work_gate( const database& db, uint32_t work_us );
/// F-01 work-budget accumulator (R9B): add work_us to the pending block's
/// used work (rollover reset like the op counter). do_apply path only.
void stealth_count_blind_work( database& db, uint32_t work_us );
/// Work-model units consumed by one stealth_transfer op (R9B): dual-verify
/// ring cost plus per-output range proofs plus the kernel allowance.
/// Pure, saturated at 0xFFFFFFFF (a proposal-embedded op bypasses
/// validate(), so input/ring counts are unbounded at gate time — the gate
/// still fails closed, never wraps).
uint32_t stealth_work_for_stealth_transfer( const protocol::stealth_transfer_operation& o );
/// Work-model units for n range-proven blind outputs (R9B): deposits,
/// blind transfers, turnstile outputs. Pure, saturated.
uint32_t stealth_work_for_range_proofs( uint32_t n_outputs );
/// Work-model units consumed by one op108 explicit spend (R9B): conservation
/// kernel + per-input recovery proofs + per-output range proofs. Pure,
/// saturated. Called from do_evaluate (gate) and do_apply (accounting).
uint32_t stealth_work_for_explicit_spend( const protocol::stealth_explicit_spend_operation& o );
/// Work-model units consumed by one G2 stealth pool swap (1-in/1-out):
/// Schnorr-pin kernel allowance + dual-verified ring legs (both versions) +
/// 2x range allowance (output BP+ m=1 + conceptual pin cost) + pool-math
/// leg. Pure, saturated at 0xFFFFFFFF (a proposal-embedded op bypasses
/// validate(), so ring_size is unbounded at gate time — the gate still
/// fails closed, never wraps). Strictly exceeds stealth_work_for_stealth_
/// transfer for equal ring sizes (design §7). Called from do_evaluate
/// (gate) and do_apply (accounting) by the G2 evaluator (G2-2).
uint32_t stealth_work_for_pool_exchange( uint32_t ring_size );
/// Work-model units consumed by one op106 turnstile migration (Task 4): one
/// BP+ output + conservation kernel + recovery-proof kernel, always charged
/// (the R15 extension is mandatory on every path). Pure, constant. Called
/// from do_evaluate (gate) and do_apply (accounting) — one definition so the
/// two cannot drift.
uint32_t stealth_work_for_turnstile();
/// Nullifier identity: sha256 over the 33-byte key image (single definition
/// in stealth_evaluator.cpp; moved out of the anonymous namespace in Task 3
/// so the test suite links the exact production identity — never duplicated).
/// Takes vector<char>, NOT commitment_type; callers convert explicitly.
fc::sha256 nullifier_key( const std::vector<char>& image33 );
/// Verification-work units counted against the budget in the
/// currently-pending block (0 pre-fork or on rollover).
uint32_t stealth_blind_work_this_block( const database& db );
/// Post-STEALTH only (pre-fork no-op): move the per-asset confidential-supply
/// shadow by the same delta applied to asset_dynamic_data_object.
void stealth_shadow_add( database& db, asset_id_type asset, share_type delta );
/**
 * Post-STEALTH only (pre-fork no-op): maintain the per-asset count of
 * LIVE metadata-bearing blinded balances backing stealth_pool_depth.
 * Positive delta on creation of a balance WITH post-fork metadata;
 * negative delta on consumption of such a balance (callers check
 * created_block != 0 for explicitly-consumed balances, which may be
 * grandfathered). Task 3 (nullifier migration): ring spends remove nothing
 * from the index, so they add outputs.size() only — nullified outputs stay
 * indexed and decoy-eligible. Bounded: zero entries are removed.
 */
 void stealth_pool_count_add( database& db, asset_id_type asset, int32_t delta );
/// Phase-1 instrumentation (spec 2026-10-11 §8): ring-buffer push.
/// No-op pre-STEALTH. n >= 1 (call sites pass outputs.size(), validated ≥ 1).
void stealth_deposit_histogram_add( database& db, asset_id_type asset,
                                    account_id_type depositor, uint32_t n );
/// Total deposited outputs (monotonic telemetry). Never throws.
uint64_t stealth_deposited_outputs( const database& db, asset_id_type asset );
/// Effective depositor count E_dep = N_w^2/sumsq over the window, 0 when empty.
uint64_t stealth_effective_depositor_count( const database& db, asset_id_type asset );
/**
 * Post-STEALTH range soundness for legacy blind outputs (closes the live
 * gap uniformly): every output carrying a proof MUST verify, and every
 * output MUST carry one (single-output proof-less blinds were a pre-fork
 * wallet behavior; post-fork they are rejected — wallets attach proofs).
 */
void stealth_require_sound_range_proofs( const database& db,
      const vector<protocol::blind_output>& outputs );

} } // graphene::chain
