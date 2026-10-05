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
 * Every size bound here mirrors the verifier's bounds exactly (same
 * constants) so malformed transactions fail early AND identically.
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
      // V2 G1 wire format: 1 + 33*4 + 32*2 + 7*66 + 32*3 = 756 max (m<=2).
      // Tighter per-m bounds are enforced by the verifier, not here.
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

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation )
