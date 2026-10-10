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

#include <graphene/protocol/stealth.hpp>
#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

/**
 * Wire-shape checks only (client-side, runs everywhere including
 * pre-hardfork relays). Consensus rules (rings, proofs, decoys, nullifiers)
 * live in the chain evaluators, hardfork-gated. validate() MUST NOT verify
 * cryptography: it runs on relays that may not have the EC context, and
 * consensus divergence between validate flavors would fork the network.
 * Every size bound here mirrors the verifier's bounds (same constants) or,
 * for V2 range proofs, stays deliberately looser (756 relay cap vs 592/658
 * exact verifier sizes). The relay direction is fixed: validate() never
 * REJECTS what the verifier ACCEPTS (valid transactions always relay); it
 * only pre-rejects a strict subset of what consensus rejects. Admitting a
 * blob consensus later rejects (e.g. a 593..756-byte V2 blob) is safe: the
 * evaluator fails closed on the exact size.
 */
void stealth_transfer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "unknown proof version" );
   FC_ASSERT( !inputs.empty() && inputs.size() <= 8,
              "input count out of bounds" );
   FC_ASSERT( !outputs.empty() && outputs.size() <= 8,
              "output count out of bounds" );
   for( const auto& in : inputs )
   {
      FC_ASSERT( in.ring.size() >= GRAPHENE_STEALTH_RING_MIN &&
                 in.ring.size() <= GRAPHENE_STEALTH_RING_MAX,
                 "ring size out of bounds" );
       FC_ASSERT( in.key_image.size() == 33, "key image must be 33 bytes" );
       FC_ASSERT( in.ring_sig.size() == 32 + 96 * in.ring.size(),
                  "ring signature size mismatch" );
       // Task 5 (M05/GC-07): the alternate-version linkage rides the same
       // size rules (relay-side early failure mirrors the consensus gate;
       // see the stealth_ring_input doc for why an unverified alt would be
       // a bypass — consensus verifies, never just parses).
       FC_ASSERT( in.alt_key_image.size() == 33, "alt key image must be 33 bytes" );
       FC_ASSERT( in.alt_ring_sig.size() == 32 + 96 * in.ring.size(),
                  "alt ring signature size mismatch" );
       // Task 6 (R7 C-10): the ring-scheme migration slot. Only the genesis
       // scheme exists; unknown schemes fail here (relay-side) AND in
       // consensus (proposal-embedded ops bypass validate — the evaluator
       // re-checks). A future scheme needs its own id, verifier, and
       // dual-verify/turnstile window, never silent reinterpretation.
       FC_ASSERT( in.ring_scheme == GRAPHENE_STEALTH_RING_SCHEME_V1,
                  "unknown ring scheme" );
      // distinct ring members (duplicate decoys shrink the real set).
      // O(n^2) with n <= 32 is bounded (<=1024 compares); the evaluator
      // re-checks (consensus rule; validate() is relay-side early failure).
      for( size_t i = 0; i < in.ring.size(); ++i )
         for( size_t j = i + 1; j < in.ring.size(); ++j )
            FC_ASSERT( in.ring[i] != in.ring[j], "duplicate ring member" );
   }
   for( const auto& out : outputs )
   {
      FC_ASSERT( !out.range_proof.empty(), "range proof required" );
      FC_ASSERT( out.range_proof.size() <= 8192, "range proof too large" );
      FC_ASSERT( !out.owner.is_impossible() );
   }
   if( proof_version == GRAPHENE_STEALTH_PROOF_V1 )
   {
      for( const auto& out : outputs )
         FC_ASSERT( out.range_proof.size() <= 4096, "V1 proof too large" );
   }
   else
   {
   // V2 G1 single-proof wire: 1 + 33*3 + 32*3 + rounds*66, rounds = 6
   // (m=1: 592 bytes) or 7 (m=2: 658 bytes). The 756 cap below stays a
   // loose relay-side upper bound only; the verifier enforces the exact
   // per-m size (stealth_bp_proof_size), never this cap.
      for( const auto& out : outputs )
         FC_ASSERT( out.range_proof.size() <= 756, "V2 proof too large" );
   }
}

share_type stealth_transfer_operation::calculate_fee( const fee_params_t& k )const
{
   return k.fee + outputs.size() * k.price_per_output;
}

void freeze_blind_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( voter != account_id_type(), "voter required" );
   FC_ASSERT( reason.size() <= 256, "reason too long" );
}

void turnstile_reproof_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( new_proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              new_proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "unknown proof version" );
   FC_ASSERT( !new_output.range_proof.empty(), "range proof required" );
   FC_ASSERT( new_output.range_proof.size() <= 8192, "range proof too large" );
   FC_ASSERT( !owner.is_impossible() );
   // A1 (mimo-2.6 re-audit): wire-level shape gate, mirroring the evaluator's
   // recovery-path checks (stealth_evaluator.cpp:917-922) so malformed
   // extensions are refused at validate() with identical pinned messages
   // instead of being type-dispatched further down the path. Size 0 stays
   // legal (plain turnstile; recovery is only required once the old
   // commitment is unknown at evaluation time).
   FC_ASSERT( extensions.size() <= 1, "Turnstile recovery takes one extension" );
   if( extensions.size() == 1 )
   {
      const auto& ext = *extensions.begin();
      // which()-guarded so a wrong type produces a clean FC_ASSERT with the
      // same wording get<> uses, never a raw static_variant throw.
      FC_ASSERT( ext.which() == 1,
                 "static_variant does not contain a value of type ${t}",
                 ("t", "turnstile_recovery_v2_extension") );
      FC_ASSERT( ext.get<turnstile_recovery_v2_extension>().recovery_proof.proof_bytes.size()
                    == 163,
                 "Turnstile recovery proof must be 163 bytes" );
   }
   // A2 (validate leg): the STORED owner (do_apply writes it to the migrated
   // blind balance) must be possible — same class of guard as the old-owner
   // check above, applied to the authority that will actually be persisted.
   FC_ASSERT( !new_output.owner.is_impossible(), "Migrated output owner is impossible" );
}

share_type turnstile_reproof_operation::calculate_fee( const fee_params_t& k )const
{
   return k.fee + k.price_per_output;
}

void parity_review_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( voter != account_id_type(), "voter required" );
   FC_ASSERT( kind == GRAPHENE_STEALTH_REVIEW_PARITY ||
              kind == GRAPHENE_STEALTH_REVIEW_SET_REPORT,
              "unknown review kind" );
   FC_ASSERT( note.size() <= 256, "note too long" );
}

void stealth_explicit_spend_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( fee.asset_id == asset_id, "fee asset must match asset_id" );
   FC_ASSERT( !inputs.empty(), "explicit spend needs at least one input" );
   FC_ASSERT( inputs.size() <= 8, "explicit spend input count out of bounds" );
   // No !outputs.empty() — the exit leg has zero outputs by design.
   // The ring pins the same bound (stealth.cpp:52); consensus law
   // bounds state per op.
   FC_ASSERT( outputs.size() <= 8, "explicit spend output count out of bounds" );
   FC_ASSERT( proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "unknown proof version" );
   for( const auto& in : inputs )
   {
      // Proof size is enforced by the verifier too (stealth_proof.cpp:655);
      // gate here so malformed input gets a clean message at validate().
      FC_ASSERT( in.recovery_proof.proof_bytes.size() == 163,
                 "Explicit spend recovery proof must be 163 bytes" );
      FC_ASSERT( !in.owner.is_impossible(), "explicit spend input owner is impossible" );
      // commitment_type is zero_initialized_array<unsigned char,33> and has
      // NO is_negative() (that lives on fc::bigint, not on the array).
      // Point validity is enforced later by the evaluator's point conversion
      // and the recovery-proof verification — no wire-layer check needed.
   }
   for( const auto& out : outputs )
   {
      FC_ASSERT( !out.range_proof.empty(), "range proof required" );
      FC_ASSERT( out.range_proof.size() <= 8192, "range proof too large" );
      FC_ASSERT( !out.owner.is_impossible(), "output owner is impossible" );
   }
   // Transparent exit (outputs empty) requires a destination AND a positive
   // public amount; the amount is necessarily revealed — adjust_balance writes
   // a public balance. Mirrors op41's validate() (confidential.cpp:72, `amount.amount > 0`).
   FC_ASSERT( !( outputs.empty() && to == account_id_type() ),
              "transparent exit requires a destination account" );
   if( outputs.empty() )
   {
      FC_ASSERT( amount.amount > 0, "transparent exit requires a positive amount" );
      FC_ASSERT( amount.asset_id == asset_id, "exit amount asset must match asset_id" );
   }
   // Blind->blind and blind->transparent are mutually exclusive by
   // construction; `to` and `amount` are ignored when outputs is non-empty.
}

share_type stealth_explicit_spend_operation::calculate_fee( const fee_params_t& k )const
{
   return k.fee + k.price_per_output * (uint64_t)outputs.size();
}

void stealth_pool_exchange_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( fee.asset_id == amount_to_sell.asset_id, "pool swap fee must be paid in the sold asset" );
   FC_ASSERT( amount_to_sell.amount > 0, "pool swap sell amount must be positive" );
   FC_ASSERT( min_to_receive.amount > 0, "pool swap slippage floor must be positive" );
   FC_ASSERT( proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "unknown proof version" );
   // 1-in/1-out is structural (single input/output fields, no vectors), so
   // no count bounds are needed here — unlike op104's 1..8 vectors.
   // Ring shape mirrors the op104 relay gate, but floored at TARGET (16):
   // G2 has no thin-pool emergency allowance (design §7: ring 16–32).
   FC_ASSERT( input.ring.size() >= GRAPHENE_STEALTH_RING_TARGET &&
              input.ring.size() <= GRAPHENE_STEALTH_RING_MAX,
              "ring size out of bounds" );
   FC_ASSERT( input.key_image.size() == 33, "key image must be 33 bytes" );
   FC_ASSERT( input.ring_sig.size() == 32 + 96 * input.ring.size(),
              "ring signature size mismatch" );
   FC_ASSERT( input.alt_key_image.size() == 33, "alt key image must be 33 bytes" );
   FC_ASSERT( input.alt_ring_sig.size() == 32 + 96 * input.ring.size(),
              "alt ring signature size mismatch" );
   FC_ASSERT( input.ring_scheme == GRAPHENE_STEALTH_RING_SCHEME_V1,
              "unknown ring scheme" );
   for( size_t i = 0; i < input.ring.size(); ++i )
      for( size_t j = i + 1; j < input.ring.size(); ++j )
         FC_ASSERT( input.ring[i] != input.ring[j], "duplicate ring member" );
   // Single V2 BP+ output (m=1): the exact 592-byte blob. G2 wires no V1
   // Borromean leg — the swap output is always a fresh BP+ commitment, so
   // the relay bound is exact, not the 756-byte loose cap.
   FC_ASSERT( output.range_proof.size() == 592, "pool swap output proof must be 592 bytes (BP+ m=1)" );
   FC_ASSERT( !output.owner.is_impossible(), "pool swap output owner is impossible" );
   // Schnorr value-pin (T ‖ s): 33B compressed point + 32B scalar = 65 bytes
   // (design §2/§3; the 64B text was corrected per the G2-2 brief).
   FC_ASSERT( value_pin.size() == 65, "pool swap value_pin must be 65 bytes" );
}

share_type stealth_pool_exchange_operation::calculate_fee( const fee_params_t& k )const
{
   // Mirror op104 (single blind output ⇒ ×1).
   return k.fee + k.price_per_output;
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation )
