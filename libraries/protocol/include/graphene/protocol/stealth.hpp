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
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>
#include <graphene/protocol/authority.hpp>

namespace graphene { namespace protocol {

using fc::ecc::blind_factor_type;
using fc::ecc::commitment_type;
using fc::ecc::range_proof_type;

/**
 * @defgroup g1_stealth G1 stealth transfers (BSIP-2)
 * @brief Consensus parameters and operations for bonded-era private transfers.
 *
 * All numeric constants below are PROPOSALS per BSIP-2 §7b/Discussion: the
 * pre-G1 specialist audit may RAISE security minimums, never lower them;
 * auditor deadlock falls back to these floor values after 90 days.
 * @{
 */

/// Floor ring size: the smallest ring the VERIFIER accepts (wire/verifier
/// bound, kept for budget math and golden vectors). It is NOT the consensus
/// floor: Task 6 (R7 C-01) raised the consensus floor to TARGET (16) in all
/// non-halted states, deep or thin. MIN-11 is reserved for a future
/// governance-opened thin-pool emergency only (availability fallback when
/// the pool cannot form target-size rings); no consensus path accepts it
/// today, and opening it needs its own audit + hardfork gate, not silence.
constexpr uint32_t GRAPHENE_STEALTH_RING_MIN = 11;
/// Target ring size: wallets default here; budgets are measured here and up.
constexpr uint32_t GRAPHENE_STEALTH_RING_TARGET = 16;
/// Ceiling ring size: bounds verifier work per input (DoS cap, not privacy).
constexpr uint32_t GRAPHENE_STEALTH_RING_MAX = 32;

/// Per-block blind-operation budget shared by ops 39/40/41/104/106 (see G1a §4c:
/// 100 x ring-16 worst case ~= 690ms <= 750ms = 25% of the 3s interval).
/// Counts every blind op (legacy + stealth) so the budget is one number.
/// Reserved transparent/market space rides the same counter: when the budget
/// is exhausted the block simply carries no more blind ops. Parity-pool fee
/// subsidy and wallet defaults are G1c, explicitly NOT here.
constexpr uint32_t GRAPHENE_STEALTH_MAX_BLIND_TX_PER_BLOCK = 100;

/// Decoy eligibility: outputs younger than this are ineligible as decoys
/// (Sybil-poisoning cost: an attacker must park outputs for a full day
/// before they can flood anyone's rings). Proposal; auditors may raise.
constexpr uint32_t GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC = 86400;
/// Skew window for the age-distribution rule, in blocks (~5 minutes).
constexpr uint32_t GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS = 100;
/// Max share of one ring's decoys that may fall in a single skew window
/// (percent). Proposal: no 100-block window contributes more than 40%.
constexpr uint32_t GRAPHENE_STEALTH_DECOY_SKEW_MAX_PCT = 40;
/// Blind-pool floor: per-asset count of unspent decoy-candidate blind outputs
/// (post-fork creation metadata present; spent-but-retained outputs do NOT
/// count) below which blind SPENDS of that asset halt. Deposits are never
/// gated (they create decoys — gating them would deadlock bootstrapping).
/// Availability yields to privacy, explicitly (thin-pool rings are worse
/// than no rings: they mark the spender as one of few).
constexpr uint32_t GRAPHENE_STEALTH_BLIND_POOL_FLOOR = 11;
/// Thin-pool decoy tightening (R-04, proposal): while the per-asset unspent
/// pool is below this depth, rings must meet the TARGET size (16, not the
/// 11 floor) and no 100-block window may contribute more than 25% (not
/// 40%). Rationale: a $1 Sybil floods a thin pool cheaply (BSIP-2 admits
/// the attack); small rings over attacker-majority windows are markings,
/// not anonymity. Task 6 (R7 C-01) extended the TARGET floor to deep pools
/// as well: 16 is the consensus floor everywhere; the thin regime now only
/// tightens the skew ceiling, not the size.
/// Auditors may raise any of these; the pre-G1 audit owns the final values.
constexpr uint32_t GRAPHENE_STEALTH_THIN_POOL_DEPTH = 64;
constexpr uint32_t GRAPHENE_STEALTH_THIN_SKEW_MAX_PCT = 25;
/// Pool-depth warning level (Task 6): per-asset unspent depth below this
/// raises the thin_pool_warn alarm. ALARM ONLY — never a consensus gate
/// (no FC_ASSERT on any market, fee, or blind path reads it): availability
/// degrades visibly before the floor halts it.
constexpr uint32_t GRAPHENE_STEALTH_POOL_WARN_DEPTH = 22;

/// Proof versions. V1 = Borromean range proofs via the fc backend (legacy
/// proofs verify forever; no forced migration of existing blind balances).
/// V2 = Bulletproofs+ (G1 wire format, secp256k1 port of 2020-735).
constexpr uint8_t GRAPHENE_STEALTH_PROOF_V1 = 1;
constexpr uint8_t GRAPHENE_STEALTH_PROOF_V2 = 2;

/// Ring-scheme versions (Task 6 migration vehicle, R7 C-10). The proof
/// version above versions the RANGE proofs and nullifier domains; the ring
/// SCHEME (signature construction: member statement, response count,
/// message transcript) needs its own forward-migration slot, because a
/// future scheme break (or improvement) must be deployable without
/// re-versioning proofs. 1 = the genesis CLSAG-lineage 3-response scheme
/// (rb, rv, rd per member + pseudo-output binding, dual V1/V2 linkage).
/// Consensus accepts ONLY known schemes (fail-closed); a new scheme ships
/// as a new id + its own verifier + dual-verify/turnstile window, never as
/// a silent reinterpretation of old rings. No PQC scheme exists: this slot
/// is agility plumbing (BSIP-2 quantum note), not a PQC promise.
constexpr uint8_t GRAPHENE_STEALTH_RING_SCHEME_V1 = 1;

/// V1 lifetime after activation (proposal: 365 days). At sunset V1 spends
/// become spend-only-via-turnstile; turnstile G2 IS this date, fixed at
/// activation per BSIP-2 §1 (never "next hardfork TBD"). Dual-verify window
/// = [activation, sunset]: both nullifier sets enforced throughout.
constexpr uint32_t GRAPHENE_STEALTH_V1_LIFETIME_SEC = 31536000;

/// Committee freeze-backup quorum (Task 6: proposal): THREE distinct
/// committee-member votes required to (un)halt blind ops (was 2 — a 2-quorum
/// lets any two colluding members halt alone; 3 forces a wider conspiracy).
/// Named-operator role approximation: any elected member may vote; votes
/// expire after 24h (was 48h — shorter auto-expiry so stale intent cannot
/// linger into a later crisis; Task 6).
constexpr uint32_t GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED = 3;
constexpr uint32_t GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC = 86400;

/// Consensus seeds (embedded in code, test-vector pinned in the audit
/// report; any library with opaque parameters stays rejected per BSIP-2).
/// H (Pedersen value base) is NOT derived from these: it is the S2/Elements
/// H constant verbatim (see stealth_proof.cpp), because legacy fc
/// commitments must verify under it.
#define GRAPHENE_STEALTH_BP_SEED "BitShares-G1-BP-secp256k1-v1"
#define GRAPHENE_STEALTH_J1_SEED "BitShares-G1-J1-secp256k1-v1"
#define GRAPHENE_STEALTH_J2_SEED "BitShares-G1-J2-secp256k1-v1"

/**
 * @defgroup g1_stealth_parity G1 parity economics (BSIP-2 §2)
 * @brief Fee-parity pool, float-to-cost rule, review defaults, joint cap.
 *
 * All numeric constants below are PROPOSALS per BSIP-2 Discussion (and
 * BSIP-1 §7b for the joint cap): auditors may raise them, never lower them;
 * auditor deadlock falls back to these floor values after 90 days.
 * Consensus law: integer (basis-point/second) math only, no floats;
 * head-block time only; bounded state (per-asset maps prune zero entries).
 * @{
 */

/// Fixed share of each market/settlement fee routed to the per-asset parity
/// pool (basis points of the issuer-fee increment, 500 = 5%). Redirects —
/// never mints: accumulated_fees receives the remainder, so the fee totals
/// are preserved exactly. Enforced at the single choke point
/// (database::pay_market_fees, which also serves force-settlement).
constexpr uint32_t GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS = 500;
/// Per-block cap on SUBSIDIZED blind ops (proposal: 50). Tighter than the
/// blind-op budget (100), so a fully subsidized block still leaves reserved
/// space for transparent/market operations. Each subsidized op consumes one
/// unit; beyond the cap (or with an empty pool) blind fees float to cost.
constexpr uint32_t GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK = 50;
/// Parity attestation quorum (Task 6): TWO distinct committee members must
/// attest the same kind (review or set-report) for the clocks to move. A
/// single-member attestation is recorded as pending only — it never resets
/// a clock alone (a lone reporter could otherwise extend subsidies
/// indefinitely). Pending attestations expire after 24h (same freshness
/// philosophy as freeze votes).
constexpr uint32_t GRAPHENE_STEALTH_PARITY_QUORUM_REQUIRED = 2;
constexpr uint32_t GRAPHENE_STEALTH_PARITY_ATTEST_EXPIRY_SEC = 86400;
/// Parity-pricing review cadence (proposal: 6 months = 180 days). Past one
/// full interval with no recorded review, subsidies stop (cost-mode):
/// blind fees float to cost by rule, never by surprise. Recording is an
/// explicit committee attestation (parity_review_operation), never silence.
constexpr uint32_t GRAPHENE_STEALTH_PARITY_REVIEW_INTERVAL_SEC = 15552000;
/// Anonymity-set report cadence (proposal: quarterly = 90 days). Two
/// consecutive missed reports halt parity FUNDING (routing stops; the pool
/// keeps paying until empty) until reporting resumes.
constexpr uint32_t GRAPHENE_STEALTH_PARITY_REPORT_INTERVAL_SEC = 7776000;
/// Joint fee-diversion ceiling shared with the hybrid program (BSIP-1 §7b,
/// proposal: <=70% of conversion fees on one shared denominator, reviewed
/// yearly). The parity share above (5%) is statically below it; the running
/// H2-side diversion is recorded on-chain (stealth_status_object) so the
/// joint accounting is enforced here, not assumed.
constexpr uint32_t GRAPHENE_STEALTH_JOINT_FEE_CAP_BPS = 7000;
/// Burn-rate alarm thresholds on the per-interval grant/route ratio
/// (proposals): 50% warn, 80% critical. Alarms are block-speed signals;
/// monthly stats and quarterly reports remain the governance instruments.
constexpr uint32_t GRAPHENE_STEALTH_PARITY_BURN_WARN_PCT = 50;
constexpr uint32_t GRAPHENE_STEALTH_PARITY_BURN_CRITICAL_PCT = 80;
/// 100-block creation windows retained for the decoy-skew alarm (matches the
/// skew rule window; bounds the histogram: <= 301 entries, pruned oldest).
constexpr uint32_t GRAPHENE_STEALTH_SKEW_WINDOW_BLOCKS = 100;
constexpr uint32_t GRAPHENE_STEALTH_SKEW_WINDOWS_KEPT = 301;

/// Pinned pre-parity blind-cost anchor (proposal): the upstream
/// transfer_to_blind defaults (base + per-output), kept as code constants so
/// the float-to-cost level never depends on committee silence. The live
/// anchor is max(snapshot at activation, pinned here, current schedule):
/// committee cuts below it open a subsidy gap; committee raises move the
/// anchor with them (no windfall subsidy on repricing); the central schedule
/// check always enforces current levels underneath.
constexpr uint64_t GRAPHENE_STEALTH_ANCHOR_BASE_FEE = 5 * GRAPHENE_BLOCKCHAIN_PRECISION;
constexpr uint32_t GRAPHENE_STEALTH_ANCHOR_PRICE_PER_OUTPUT = 5 * GRAPHENE_BLOCKCHAIN_PRECISION;

/// Attestation kinds for parity_review_operation.
constexpr uint8_t GRAPHENE_STEALTH_REVIEW_PARITY = 0;     ///< 6-month parity-pricing review
constexpr uint8_t GRAPHENE_STEALTH_REVIEW_SET_REPORT = 1; ///< quarterly anonymity-set report

/** @} endgroup g1_stealth_parity */

/** @} endgroup g1_stealth */

/**
 * @brief One linkable-ring spend authorization (G1 ring scheme).
 * @ingroup g1_stealth
 *
 * The ring lists decoy-eligible blind-output commitments; the prover knows
 * the Pedersen opening (blind, value) of exactly one member but the proof
 * hides which. Authorization is knowledge-of-opening: no per-input account
 * authority is declared, so observers learn only the candidate set.
 * Double-spend protection is the key image: I = b*J1 + v*J2 for the spent
 * opening, domain-separated per proof version (J1/J2 differ per version).
 * The same opening spent twice yields the same image and is rejected.
 *
 * Conservation kernel (pseudo-output pattern): each input carries a
 * pseudo-output commitment P = b'*G + v*H committing to the SAME value as
 * the real spent member under a fresh blind b'. The ring signature binds P
 * to the ring (per-member M equation over D_i = P - Q_i; forging an
 * inflated P requires log_G(H)), and the consensus excess equation
 * sum(P) - sum(outputs) - fee*H == excess*G proves balance without
 * revealing which member is real. Pseudos are ephemeral kernel inputs:
 * they are never indexed as balances.
 *
 * Wire note: decoy heights/times are NOT on the wire. The evaluator reads
 * creation metadata from chain state (blinded_balance_object, appended
 * fields); wire-claimed metadata would be a malleability surface.
 *
 * Cross-version linkage (Task 5, M05/GC-07): the prover knows the opening
 * (b,v), so it authorizes under EVERY supported version at once. key_image /
 * ring_sig carry the op-version authorization; alt_key_image / alt_ring_sig
 * (appended-last) carry the same opening's authorization under the other
 * version, over the same ring/pseudo-output/outputs/fee (only the version
 * byte and image differ in the message). Consensus verifies BOTH signatures
 * and nullifies BOTH images: one opening can never be spent once per
 * version inside the dual-verify window. An unverified extra image would be
 * a lying-prover bypass (garbage alt never collides), so the second
 * signature is mandatory, not decorative.
 */
struct stealth_ring_input
{
   /// Ring of blind-output commitments (real + decoys), consensus size
   /// [16, 32] (TARGET floor everywhere, thin or deep; the [11, 32] verifier
   /// bound below still accepts 11-rings as pure crypto, reserved for a
   /// future governance-opened thin-pool emergency). All distinct, all
   /// currently UNSPENT (Task 6, R7 C-02: spent flags are chain-visible, so
   /// a spent member could never be the real input — admitting one would
   /// shrink the plausible set to the unspent remainder). Order is
   /// consensus-significant (it is the signature's member order).
   vector<commitment_type> ring;
   /// Key image: 33-byte compressed secp256k1 point, unique per spent
   /// opening per version. Enforced in the nullifier set (both version sets
   /// during the dual-verify window).
   vector<char>            key_image;
   /// Ring signature: c_0 || (rb_0, rv_0, rd_0) ... || (rb_{n-1}, rv_{n-1},
   /// rd_{n-1}), 32-byte big-endian scalars, total 32 + 96*n bytes. The
   /// third response per member (rd) is the pseudo-output binding leg.
   vector<char>            ring_sig;
   /// Pseudo-output commitment (appended-last): same value as the real
   /// spent member, fresh blind. Bound to the ring by the signature's M
   /// equation; consumed by the excess equation. Never indexed.
   commitment_type         pseudo_output;
   /// Alternate-version key image (appended-last): the SAME opening's image
   /// under the other supported proof version (33 bytes). Nullified alongside
   /// key_image; bound by alt_ring_sig, never trusted unverified.
   vector<char>            alt_key_image;
   /// Alternate-version ring signature (appended-last): same ring, same
   /// pseudo-output, same outputs/fee, other version's message and image.
   /// Same size rule as ring_sig (32 + 96*n).
   vector<char>            alt_ring_sig;
   /// Ring-scheme version (appended-last migration vehicle, R7 C-10): the
   /// signature construction this ring authorizes under. Only
   /// GRAPHENE_STEALTH_RING_SCHEME_V1 exists; unknown schemes fail closed
   /// in validate() AND consensus (a future scheme needs its own id,
   /// verifier, and dual-verify/turnstile window — never silent
   /// reinterpretation). Wire-default 1 keeps existing constructions valid.
   uint8_t                 ring_scheme = GRAPHENE_STEALTH_RING_SCHEME_V1;
};

/**
 * @brief A new blinded output (works for both proof versions).
 * @ingroup g1_stealth
 */
struct stealth_blind_output
{
   commitment_type       commitment;
   /// V1: fc Borromean proof bytes. V2: G1 Bulletproofs+ blob
   /// (m || A || S || T1 || T2 || taux || mu || L/R pairs || a || b || t_hat).
   vector<char>          range_proof;
   authority             owner;
};

/**
 * @brief Ring-signed blind-to-blind transfer (new stealth path).
 * @ingroup g1_stealth
 *
 * Asset type stays VISIBLE (amount privacy, never asset privacy: per-asset
 * supply auditability is load-bearing for the whole program). Conservation
 * is a Mimblewimble-style kernel over the per-input pseudo-outputs:
 * sum(pseudo) - sum(outputs) - fee*H == excess*G, checked in consensus;
 * the excess scalar is sum(pseudo blinds) - sum(output blinds) mod n, and
 * each pseudo is bound to its ring's real input value by the ring
 * signature's M equation. Fee payer is TEMP (threshold-0 genesis
 * account: requires no signature); the fee itself is covered by the blind
 * surplus exactly like legacy blind_transfer, and paid via the FBA path.
 */
struct stealth_transfer_operation : public base_operation
{
   struct fee_params_t {
      uint64_t fee              = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
      uint32_t price_per_output = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
   };

   asset                          fee;
   asset_id_type                  asset_id; ///< visible asset type
   uint8_t                        proof_version = GRAPHENE_STEALTH_PROOF_V1;
   blind_factor_type              excess; ///< sum(in blinds) - sum(out blinds), mod n
   vector<stealth_ring_input>     inputs;
   vector<stealth_blind_output>   outputs;

   extensions_type                extensions; ///< appended-last; new fields go here

   account_id_type fee_payer()const { return GRAPHENE_TEMP_ACCOUNT; }
   void            validate()const;
   share_type      calculate_fee( const fee_params_t& k )const;
};

/**
 * @brief Committee backup halt switch for blind ops (BSIP-2 §1).
 * @ingroup g1_stealth
 *
 * The tripwire fires this automatically; the human backup is distinct
 * member votes reaching GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED (3) within
 * the 24h expiry. Freeze and resume are symmetric (same quorum both ways) so
 * no minority can hold the halt hostage and no small clique can halt alone.
 * Resume is additionally refused while any asset's supply-divergence set is
 * non-empty (per-asset halt scope heals asset-by-asset first).
 */
struct freeze_blind_operation : public base_operation
{
   // Zero default fee is deliberate (R7C fee floors): the halt switch must stay
   // callable in emergencies (halt path exists before the proofs do); abuse is
   // bounded because only seated committee members may call and each vote is a
   // 3-quorum/24h record. Committee may price it nonzero by vote at activation.
   struct fee_params_t { uint64_t fee = 0; };

   asset                 fee;
   account_id_type       voter; ///< must hold a committee_member_object
   bool                  freeze = true;
   string                reason;

   extensions_type       extensions; ///< appended-last

   account_id_type fee_payer()const { return voter; }
   void            validate()const;
};

/**
 * @brief Turnstile migration of a V1 blind balance to a newer proof version.
 * @ingroup g1_stealth
 *
 * The migration leg is transparent BY DESIGN (old commitment consumed in
 * the clear, new commitment created): a turnstile cannot unlink what it
 * migrates, it only re-proofs it under the surviving system. Available from
 * activation (early migration allowed); the ONLY V1-spend path past sunset.
 * Ownership follows the legacy model (owner authority signature) because
 * the spent output is explicit, not ring-hidden.
 */
struct turnstile_reproof_operation : public base_operation
{
   struct fee_params_t {
      uint64_t fee              = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
      uint32_t price_per_output = 5*GRAPHENE_BLOCKCHAIN_PRECISION;
   };

   asset                 fee;
   asset_id_type         asset_id; ///< visible asset type
   commitment_type       old_commitment; ///< V1 blind balance consumed
   authority             owner; ///< must match the balance owner
   blind_factor_type     old_blind; ///< revealed: conservation check needs it
   blind_factor_type     new_blind; ///< revealed: conservation check needs it
   stealth_blind_output  new_output;
   uint8_t               new_proof_version = GRAPHENE_STEALTH_PROOF_V2;

   extensions_type       extensions; ///< appended-last

   account_id_type fee_payer()const { return GRAPHENE_TEMP_ACCOUNT; }
   void            validate()const;
   share_type      calculate_fee( const fee_params_t& k )const;

   void            get_required_authorities( vector<authority>& a )const
   {
      a.push_back( owner );
   }
};

/**
 * @brief Committee attestation of a parity review or set report (BSIP-2 §2).
 * @ingroup g1_stealth_parity
 *
 * Two-member attestation (Task 6 quorum: any two DISTINCT elected committee
 * members attesting the same kind while both attestations are fresh): the
 * heartbeat only PERMITS parity to continue, so a false attestation buys
 * nothing but continued subsidies — unlike freeze_blind, which halts the
 * subsystem and therefore needs a 3-quorum. A lone attestation is recorded
 * as pending and moves no clock. Lying to governance is vote-punishable,
 * not consensus-punishable. Reviews (kind 0) reset the 6-month cost-mode
 * clock; set reports (kind 1) reset the missed-quarterly counter and resume
 * funding.
 */
struct parity_review_operation : public base_operation
{
   // Zero default fee is deliberate (R7C fee floors): attestations are
   // committee-only heartbeats that permit (never spend) subsidies; pricing
   // them would tax the reporting the system depends on. Committee may price
   // nonzero by vote at activation.
   struct fee_params_t { uint64_t fee = 0; };

   asset                 fee;
   account_id_type       voter; ///< must hold a committee_member_object
   uint8_t               kind = GRAPHENE_STEALTH_REVIEW_PARITY;
   string                note;

   extensions_type       extensions; ///< appended-last

   account_id_type fee_payer()const { return voter; }
   void            validate()const;
};

} } // graphene::protocol

FC_REFLECT( graphene::protocol::stealth_ring_input,
            (ring)(key_image)(ring_sig)(pseudo_output)(alt_key_image)(alt_ring_sig)
            (ring_scheme) )
FC_REFLECT( graphene::protocol::stealth_blind_output,
            (commitment)(range_proof)(owner) )
FC_REFLECT( graphene::protocol::stealth_transfer_operation,
            (fee)(asset_id)(proof_version)(excess)(inputs)(outputs)(extensions) )
FC_REFLECT( graphene::protocol::freeze_blind_operation,
            (fee)(voter)(freeze)(reason)(extensions) )
FC_REFLECT( graphene::protocol::turnstile_reproof_operation,
            (fee)(asset_id)(old_commitment)(owner)(old_blind)(new_blind)
            (new_output)(new_proof_version)(extensions) )
FC_REFLECT( graphene::protocol::parity_review_operation,
            (fee)(voter)(kind)(note)(extensions) )
FC_REFLECT( graphene::protocol::stealth_transfer_operation::fee_params_t, (fee)(price_per_output) )
FC_REFLECT( graphene::protocol::freeze_blind_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::turnstile_reproof_operation::fee_params_t, (fee)(price_per_output) )
FC_REFLECT( graphene::protocol::parity_review_operation::fee_params_t, (fee) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation )
