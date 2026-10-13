/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 *
 * Wallet-side G2 pool-swap sampler + op builder. See
 * stealth_pool_builder.hpp: off-consensus reads + proving; evaluators must
 * never call the provers (the builder runs the shared pool-math helper
 * client-side, which is pure reads — safe to share).
 */

#include <graphene/chain/stealth_pool_builder.hpp>
#include <graphene/chain/stealth_prover.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/confidential_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/chain/stealth_evaluator.hpp>
#include <graphene/chain/stealth_proof.hpp>

#include <graphene/protocol/stealth.hpp>

#include <openssl/rand.h>

#include <map>

namespace graphene { namespace chain {

namespace {

// Wallet mix-hold rule (same decision as
// graphene::wallet::blind_receipt_mix_eligible — restated here so the
// chain library does not include wallet headers; both are pinned by tests):
// hold 0 = off (everything eligible); otherwise eligible iff known age
// (created_block != 0, already enforced) AND
// head_block − created_block >= min_mix_blocks (no underflow: future
// blocks are ineligible).
bool mix_hold_eligible( uint32_t created_block, uint32_t head_block,
                        uint32_t min_mix_blocks )
{
   if( min_mix_blocks == 0 )
      return true;
   if( created_block == 0 || created_block > head_block )
      return false;
   return ( head_block - created_block ) >= min_mix_blocks;
}

// Fisher-Yates shuffle under RAND_bytes (wallet-side randomness is
// required here — deterministic order would tag the real position).
// False on RNG failure (fail-closed: no weakly-shuffled rings).
bool shuffle_indices( std::vector<size_t>& v )
{
   for( size_t i = v.size(); i > 1; --i )
   {
      uint32_t r = 0;
      if( RAND_bytes( (unsigned char*)&r, sizeof( r ) ) != 1 )
         return false;
      size_t j = (size_t)( r % i );
      std::swap( v[i-1], v[j] );
   }
   return true;
}

uint32_t rand_below( uint32_t n, bool& ok )
{
   uint32_t r = 0;
   ok = ( RAND_bytes( (unsigned char*)&r, sizeof( r ) ) == 1 );
   if( !ok ) return 0;
   return (uint32_t)( r % n );
}

} // anonymous namespace

stealth_sampled_ring stealth_sample_pool_ring( const database& db,
   const protocol::asset_id_type& asset_id,
   const fc::ecc::commitment_type& real_commitment,
   uint32_t min_mix_blocks,
   uint32_t ring_size )
{
   using protocol::GRAPHENE_STEALTH_RING_TARGET;
   using protocol::GRAPHENE_STEALTH_RING_MAX;
   using protocol::GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC;
   FC_ASSERT( ring_size >= GRAPHENE_STEALTH_RING_TARGET &&
              ring_size <= GRAPHENE_STEALTH_RING_MAX,
              "G2 ring size must be 16..32 (no thin-pool emergency leg)" );

   const uint32_t head_block = db.head_block_num();
   const fc::time_point_sec head_time = db.head_block_time();
   const auto& idx = db.get_index_type<blinded_balance_index>().indices();

   // Candidate rule mirrors the evaluator membership loop: indexed,
   // asset match, metadata-bearing. Spent-flagged outputs are excluded
   // (wallet-conservative: consensus still accepts them as decoys under
   // nullifier semantics, but visibly-consumed handles add less cover
   // and can never be the real input of a wallet spend).
   struct cand
   {
      fc::ecc::commitment_type c;
      uint32_t blk = 0;
      fc::time_point_sec t;
   };
   std::vector<cand> others;
   bool real_eligible = false;
   cand real_c;
   for( const auto& o : idx )
   {
      if( o.asset_id != asset_id )
         continue;
      if( o.created_block == 0 )
         continue; // grandfathered: never decoy-eligible
      if( o.spent )
         continue;
      if( o.created_block > head_block )
         continue; // from the future (policy refuses; fail closed here)
      if( o.created_time > head_time )
         continue;
      uint32_t age = (uint32_t)( head_time.sec_since_epoch() -
                                 o.created_time.sec_since_epoch() );
      if( age < GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC )
         continue; // under the 24h min age (policy would refuse)
      if( !mix_hold_eligible( o.created_block, head_block, min_mix_blocks ) )
         continue;
      if( o.commitment == real_commitment )
      {
         real_eligible = true;
         real_c.c = o.commitment;
         real_c.blk = o.created_block;
         real_c.t = o.created_time;
      }
      else
         others.push_back( cand{ o.commitment, o.created_block, o.created_time } );
   }
   FC_ASSERT( real_eligible,
              "Real input is not a decoy-eligible blinded balance "
              "(wrong asset, too young, metadata absent, or mix hold)" );
   FC_ASSERT( others.size() + 1 >= ring_size,
              "Not enough decoy-eligible outputs for a ${n}-ring",
              ("n", ring_size) );

   // Live depth for the thin-vs-deep skew ceiling (same input the
   // evaluator passes — sampler and consensus agree by construction).
   const uint32_t depth = stealth_pool_depth( db, asset_id );

   // Resample loop: fresh shuffle per attempt (bounded; exhaustion throws
   // — availability yields to privacy, explicitly).
   std::vector<size_t> order( others.size() );
   for( size_t i = 0; i < order.size(); ++i ) order[i] = i;
   for( int attempt = 0; attempt < 32; ++attempt )
   {
      FC_ASSERT( shuffle_indices( order ), "Prover RNG failed" );
      std::vector<cand> picked;
      picked.reserve( ring_size );
      // Stratified draw (spec 2026-10-11-wallet §1): bucket the shuffled
      // candidates by creation window (created_block / 100 — the same grid
      // as blind_window_counts), then round-robin across non-empty buckets.
      // A single-window dust dump earns one slot per pass, not an
      // output-proportional share. WHICH candidates land in each bucket is
      // shuffle-derived, but this loop EMITS them bucket-by-bucket in
      // ascending map-KEY order — the pick set is anti-Sybil policy, the
      // emission order is a fingerprint until the final shuffle below
      // (PRV-01). The real input's own bucket stays eligible (excluding it
      // would shrink the set and mark which window lacks the real input).
      std::map<uint32_t, std::vector<size_t>> buckets;
      for( size_t k = 0; k < order.size(); ++k )
         buckets[ others[ order[k] ].blk / 100 ].push_back( order[k] );
      bool progress = true;
      while( picked.size() < (size_t)( ring_size - 1 ) && progress )
      {
         progress = false;
         for( auto& kv : buckets )
         {
            if( picked.size() >= (size_t)( ring_size - 1 ) )
               break;
            if( !kv.second.empty() )
            {
               picked.push_back( others[ kv.second.back() ] );
               kv.second.pop_back();
               progress = true;
            }
         }
      }
      FC_ASSERT( picked.size() == (size_t)( ring_size - 1 ),
                 "Stratified draw exhausted candidates" );
      // Real input at a random position (order is consensus-significant;
      // a fixed position would tag the real member).
      bool ok = false;
      uint32_t at = rand_below( ring_size, ok );
      FC_ASSERT( ok, "Prover RNG failed" );
      picked.insert( picked.begin() + at, real_c );

      // PRV-01 (round-9 Critical): the stratified draw above EMITS its
      // picks in ascending-key bucket order — std::map iterates by window
      // KEY, not by the shuffle of `order`, so `picked` is the canonical
      // interleaved round-robin (window A, B, C, A, B, C, ...) of the
      // decoy multiset, with the real only spliced in. Member order is
      // consensus-significant and on the wire, and every member's
      // created_block is public, so that order alone names the real:
      // removing the real's position always restores the canonical draw
      // order (same-window decoys next to it do too — windows are
      // interchangeable within a bucket), collapsing a 16-ring to the
      // 2..3 positions in that set. The stratified SET above is
      // deliberate anti-Sybil policy and is unchanged; only the final
      // EMISSION ORDER is re-randomized here — Fisher-Yates over the
      // ENTIRE ring (decoys + real) under RAND_bytes, so the real's
      // position is uniform and independent of the window structure.
      // Fail-closed, exactly like the shuffles above: a failed RNG never
      // yields a fingerprintable ring.
      {
         std::vector<size_t> ring_order( picked.size() );
         for( size_t i = 0; i < ring_order.size(); ++i )
            ring_order[i] = i;
         FC_ASSERT( shuffle_indices( ring_order ), "Prover RNG failed" );
         std::vector<cand> shuffled;
         shuffled.reserve( picked.size() );
         size_t new_at = 0;
         for( size_t j = 0; j < ring_order.size(); ++j )
         {
            shuffled.push_back( picked[ ring_order[j] ] );
            if( ring_order[j] == (size_t)at )
               new_at = j;
         }
         picked.swap( shuffled );
         at = (uint32_t)new_at;
      }

      std::vector<uint32_t> heights;
      std::vector<fc::time_point_sec> times;
      heights.reserve( ring_size );
      times.reserve( ring_size );
      for( const auto& m : picked )
      {
         heights.push_back( m.blk );
         times.push_back( m.t );
      }
      std::string perr;
      if( stealth_check_decoy_policy( heights, times, head_time, head_block,
                                      perr, depth ) )
      {
         stealth_sampled_ring out;
         out.ring.reserve( ring_size );
         for( const auto& m : picked ) out.ring.push_back( m.c );
         out.real_index = at;
         return out;
      }
   }
   FC_ASSERT( false,
              "Cannot sample a policy-conformant ring "
              "(thin-pool skew or age spread — availability yields to privacy)" );
   FC_ASSERT( false, "unreachable" ); // silences -Wreturn-type
   return stealth_sampled_ring();
}

protocol::stealth_pool_exchange_operation stealth_prove_pool_exchange(
   const database& db,
   const liquidity_pool_object& pool,
   const protocol::asset& amount_to_sell,
   const protocol::asset& min_to_receive,
   const stealth_pool_swap_opening& input_opening,
   uint8_t proof_version )
{
   using protocol::GRAPHENE_STEALTH_PROOF_V1;
   using protocol::GRAPHENE_STEALTH_PROOF_V2;
   FC_ASSERT( proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Unknown proof version" );
   const uint8_t alt_version = ( proof_version == GRAPHENE_STEALTH_PROOF_V1 )
      ? GRAPHENE_STEALTH_PROOF_V2 : GRAPHENE_STEALTH_PROOF_V1;
   const int64_t a = amount_to_sell.amount.value;
   const int64_t min_v = min_to_receive.amount.value;
   FC_ASSERT( a > 0, "Sell amount must be positive" );
   FC_ASSERT( min_v > 0, "Slippage floor must be positive" );
   FC_ASSERT( input_opening.value == (uint64_t)a,
              "Input opening value must equal amount_to_sell "
              "(the pin binds P to the claim, the ring binds P to the real "
              "input — a mismatch is unprovable)" );
   FC_ASSERT( ( amount_to_sell.asset_id == pool.asset_a &&
                min_to_receive.asset_id == pool.asset_b ) ||
              ( amount_to_sell.asset_id == pool.asset_b &&
                min_to_receive.asset_id == pool.asset_a ),
              "Swap assets must be the pool's pair" );

   // (1) Shared pool math, client-side (the SAME helper consensus runs —
   // two copies of a rounding rule would diverge). Throws
   // liquidity_pool_exchange_unfillable_price when min_to_receive is
   // unmeetable: that throw IS the client-side min abort (propagated,
   // never converted into a refused op).
   pool_exchange_amounts ex = calculate_pool_exchange_amounts(
      db, pool, amount_to_sell, min_to_receive );
   const int64_t f_maker = ex.maker_market_fee.amount.value;
   const int64_t f_taker = ex.taker_market_fee.amount.value;
   const int64_t pool_pays = ex.pool_pays.amount.value;

   // (2) EXACT cover (link-4 binding): fee = a − f_maker − pool_pays.
   // Never chosen, never rounded, never topped up.
   {
      fc::uint128_t a128( (uint64_t)a );
      fc::uint128_t sub( (uint64_t)f_maker );
      sub += fc::uint128_t( (uint64_t)pool_pays );
      FC_ASSERT( a128 >= sub,
                 "Slippage exceeds input (pool too thin for this size)" );
   }
   const int64_t cover = a - f_maker - pool_pays;

   // (3) Fee floor for the 1-output tx-fee leg: max(the fee-schedule
   // requirement, the G1c float rule — parity level when the parity pool
   // covers the gap, else the cost anchor), converted to the sold asset
   // rounding UP (pool-favoring). Below-floor covers abort here because
   // consensus would refuse them (schedule leg) or they would violate the
   // blind-fee float rule (anchor leg) — a builder that picked the fee
   // independently would produce refused ops.
   {
      protocol::stealth_pool_exchange_operation stub;
      const share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            protocol::operation( stub ) ).amount;
      const share_type anchor = stealth_cost_anchor_core( db, 1 );
      const share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      const share_type float_core = stealth_parity_available(
         db, amount_to_sell.asset_id, gap ) ? parity_core : anchor;
      const share_type sched_floor =
         stealth_gap_to_asset( db, amount_to_sell.asset_id, parity_core );
      const share_type float_floor =
         stealth_gap_to_asset( db, amount_to_sell.asset_id, float_core );
      const share_type floor = ( sched_floor > float_floor )
         ? sched_floor : float_floor;
      FC_ASSERT( cover >= floor.value,
                 "Slippage cover ${c} below fee floor ${f} for this size: "
                 "grow the swap or fund the parity pool "
                 "(minimum viable slippage per swap)",
                 ("c", cover)("f", floor.value) );
   }

   // (4) Composite fee + link-4 self-check (mirror of the evaluator's
   // asserts (9) + equality: the builder refuses its own arithmetic
   // before any proof exists).
   int64_t F = 0;
   int64_t v_out = 0;
   {
      fc::uint128_t F128( (uint64_t)f_maker );
      F128 += fc::uint128_t( (uint64_t)f_taker );
      F128 += fc::uint128_t( (uint64_t)cover );
      FC_ASSERT( F128 <= fc::uint128_t( (uint64_t)GRAPHENE_MAX_SHARE_SUPPLY ),
                 "Composite fee exceeds max supply" );
      FC_ASSERT( F128 <= fc::uint128_t( (uint64_t)a ),
                 "Composite fee exceeds sell amount" );
      F = (int64_t)F128;
      v_out = a - F;
      FC_ASSERT( v_out > 0, "Swap output must be positive" );
      FC_ASSERT( fc::uint128_t( (uint64_t)v_out ) ==
                 fc::uint128_t( (uint64_t)( pool_pays - f_taker ) ),
                 "Internal link-4 mismatch (builder arithmetic defect)" );
   }

   // (5) Ring around the real input (policy-conformant by construction).
   stealth_sampled_ring smp = stealth_sample_pool_ring(
      db, amount_to_sell.asset_id, input_opening.commitment );

   // (6) Fresh blinds + commitments (fc::ecc::blind uses the consensus
   // G/H bases — the same commitments the verifiers recompute).
   const fc::sha256 bP = stealth_sample_blind();
   const fc::sha256 bOut = stealth_sample_blind();
   const fc::ecc::commitment_type P = fc::ecc::blind( bP, (uint64_t)a );
   const fc::ecc::commitment_type Cout =
      fc::ecc::blind( bOut, (uint64_t)v_out );

   // (7) Schnorr value pin (P, a, pool).
   std::vector<char> T33;
   std::string s32;
   {
      std::string perr;
      FC_ASSERT( stealth_prove_value_pin( P, a,
         pool.get_id().instance.value, bP, T33, s32, perr ),
         "Value-pin prove failed: ${e} (abort — do not retry with tired blinds)",
         ("e", perr) );
   }

   // (8) Output range proof (BP+ m=1, exactly 592 bytes).
   protocol::stealth_blind_output sout;
   sout.commitment = Cout;
   sout.owner = input_opening.output_owner;
   {
      std::string perr;
      FC_ASSERT( stealth_prove_bp_plus_m1( Cout, bOut, (uint64_t)v_out,
                                           sout.range_proof, perr ),
         "Range prove failed: ${e} (abort — do not retry with tired blinds)",
         ("e", perr) );
   }

   // (9) Kernel scalar.
   const fc::sha256 excess = stealth_compute_pool_excess( bP, bOut );

   // (10) Dual ring proof over the bound G2RM messages. Dry run under
   // dummy messages first (G2RM binds the images, so they must be known
   // before the real messages exist), then prove for real. Same b_P:
   // pseudo must be stable across both calls.
   stealth_pool_ring_proof rproof;
   {
      const std::string dummy( 32, '\0' );
      stealth_pool_ring_proof dry;
      std::string perr;
      FC_ASSERT( stealth_prove_pool_ring( proof_version, alt_version,
         smp.ring, smp.real_index, input_opening.blind,
         (uint64_t)a, bP, dummy, dummy, dry, perr ),
         "Ring dry-run failed: ${e}", ("e", perr) );
      std::vector<fc::ecc::commitment_type> out_cs = { Cout };
      fc::sha256 mh = stealth_pool_message( proof_version,
         amount_to_sell.asset_id, pool.get_id().instance.value, a, min_v,
         dry.key_image, smp.ring, dry.pseudo_output, out_cs, F );
      fc::sha256 ma = stealth_pool_message( alt_version,
         amount_to_sell.asset_id, pool.get_id().instance.value, a, min_v,
         dry.alt_key_image, smp.ring, dry.pseudo_output, out_cs, F );
      std::string msg( (const char*)mh.data(), 32 );
      std::string msga( (const char*)ma.data(), 32 );
      FC_ASSERT( stealth_prove_pool_ring( proof_version, alt_version,
         smp.ring, smp.real_index, input_opening.blind,
         (uint64_t)a, bP, msg, msga, rproof, perr ),
         "Ring prove failed: ${e} (abort — do not retry with tired blinds)",
         ("e", perr) );
      FC_ASSERT( rproof.pseudo_output == dry.pseudo_output,
                 "Internal: pseudo unstable across prove calls" );
   }

   // (11) Assemble + self-validate (fail-closed: the builder never
   // returns a shape consensus would refuse at relay).
   protocol::stealth_pool_exchange_operation op;
   op.fee = protocol::asset( cover, amount_to_sell.asset_id );
   op.pool = pool.get_id();
   op.amount_to_sell = amount_to_sell;
   op.min_to_receive = min_to_receive;
   op.proof_version = proof_version;
   op.excess = excess;
   op.input.ring = smp.ring;
   op.input.key_image = rproof.key_image;
   op.input.ring_sig = rproof.ring_sig;
   op.input.pseudo_output = rproof.pseudo_output;
   op.input.alt_key_image = rproof.alt_key_image;
   op.input.alt_ring_sig = rproof.alt_ring_sig;
   op.input.ring_scheme = protocol::GRAPHENE_STEALTH_RING_SCHEME_V1;
   op.output = sout;
   op.value_pin.assign( T33.begin(), T33.end() );
   op.value_pin.insert( op.value_pin.end(), s32.begin(), s32.end() );
   op.validate();
   return op;
}

} } // graphene::chain
