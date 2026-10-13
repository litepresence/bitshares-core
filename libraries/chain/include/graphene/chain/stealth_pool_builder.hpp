/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once

#include <graphene/protocol/stealth.hpp>

#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/sha256.hpp>

#include <cstdint>
#include <vector>

namespace graphene { namespace chain {

class database;
class liquidity_pool_object;

/**
 * Wallet-side G2 pool-swap sampler + op builder (BSIP-2, G2 design
 * 2026-10-10-stealth-pool-swaps-design §9).
 *
 * *** EVALUATORS MUST NEVER CALL THIS FILE'S PROVERS. *** This header's
 * sampler/builder are off-consensus wallet logic: they read chain state
 * (never write it) and call the proving library (stealth_prover.hpp,
 * non-deterministic by construction). Consensus verification of the
 * produced ops lives in stealth_evaluator.cpp. The builder runs the SAME
 * shared pool-math helper the evaluator runs
 * (calculate_pool_exchange_amounts) client-side so the exact-cover fee is
 * computed, never guessed.
 *
 * Integer law: no floats, no unordered_*, no wall-clock (head-block time
 * and head-block number from the database only).
 */

/**
 * A sampled decoy ring: `ring_size` distinct live commitments of one
 * asset, consensus-ordered (member order is the signature's member order),
 * with the real spent output at `real_index` (Fisher-Yates-shuffled into
 * the FULL ring under RAND_bytes, decoys and real together, so neither the
 * real's position nor the ring's member order carries the creation-window
 * structure the stratified set selection is built from — PRV-01).
 */
struct stealth_sampled_ring
{
   std::vector<fc::ecc::commitment_type> ring;
   size_t real_index = 0;
};

/**
 * Sample a G2-conformant ring around a known real output.
 *
 * Candidate rule (mirrors the evaluator membership loop exactly): live
 * blinded balance of `asset_id` carrying post-fork creation metadata
 * (created_block != 0 — grandfathered outputs are never decoy-eligible),
 * old enough for the decoy policy (24h min age, enforced again by the
 * final policy check) and for the wallet mix hold
 * (head_block − created_block >= min_mix_blocks, default 0 = off, same
 * rule as blind_receipt_mix_eligible; unknown-age (0) never eligible
 * under a hold — but created_block == 0 is already excluded above).
 *
 * The returned set always contains `real_commitment` (which must itself
 * satisfy the candidate rule — a too-young real input fails closed here,
 * never in consensus) plus ring_size−1 random distinct others, drawn
 * stratified over 100-block creation windows (anti-Sybil: one slot per
 * non-empty window per pass, never an output-proportional share) and then
 * Fisher-Yates-shuffled as a FULL ring under RAND_bytes so the emitted
 * member order is uniform and independent of that window structure (the
 * real position carries no signal — PRV-01). Thin-pool skew is honored by
 * verifying the final set with stealth_check_decoy_policy at this asset's
 * live depth (the same call the evaluator makes); skew failures resample
 * with fresh randomness (bounded attempts) and throw when the pool cannot
 * supply a conformant ring (availability yields to privacy).
 *
 * @param ring_size 16..32 (G2 TARGET floor; no thin-pool emergency leg).
 * @throws fc::exception when no conformant ring exists.
 */
stealth_sampled_ring stealth_sample_pool_ring( const database& db,
   const protocol::asset_id_type& asset_id,
   const fc::ecc::commitment_type& real_commitment,
   uint32_t min_mix_blocks = 0,
   uint32_t ring_size = 16 );

/**
 * The real input's opening (wallet secret state): which commitment is
 * really spent, its blind and value, and who receives the counter-asset
 * output.
 */
struct stealth_pool_swap_opening
{
   fc::ecc::commitment_type commitment;
   fc::sha256 blind;
   uint64_t value = 0;
   protocol::authority output_owner;
};

/**
 * Build (prove) a complete op109 stealth pool swap.
 *
 * EXACT-cover fee (binding link-4 constraint, non-negotiable): the tx fee
 * MUST equal amount_to_sell − maker_fee − pool_pays exactly. The builder
 * runs the shared pool-math helper client-side, sets fee to the computed
 * cover, and aborts client-side when:
 * - the cover is below the fee floor for the 1-output tx-fee leg, where
 *   the floor is max(the fee-schedule requirement,
 *   the G1c float rule: parity level when the parity pool covers the gap,
 *   else the cost anchor — stealth_cost_anchor_core /
 *   stealth_parity_available, n = 1), converted to the sold asset
 *   (round-up, pool-favoring). Below-floor covers are swaps consensus
 *   would refuse (schedule) or that violate the blind-fee float rule —
 *   small-slippage swaps on deep pools are the known UX casualty (see
 *   the G2-4 economics note in the task report); or
 * - min_to_receive is unmeetable (the shared helper throws
 *   liquidity_pool_exchange_unfillable_price — propagated as the abort).
 *
 * The opening's value MUST equal amount_to_sell (the value pin binds P
 * to the claimed amount and the ring binds P to the real input — a
 * mismatch is unprovable and fails closed here).
 *
 * No signature is attached: fee_payer is TEMP (threshold-0 genesis
 * account), so the op is complete as built ("assemble + sign" collapses
 * to assemble; the wallet broadcast path adds the tx envelope).
 */
protocol::stealth_pool_exchange_operation stealth_prove_pool_exchange(
   const database& db,
   const liquidity_pool_object& pool,
   const protocol::asset& amount_to_sell,
   const protocol::asset& min_to_receive,
   const stealth_pool_swap_opening& input_opening,
   uint8_t proof_version = protocol::GRAPHENE_STEALTH_PROOF_V2 );

} } // graphene::chain
