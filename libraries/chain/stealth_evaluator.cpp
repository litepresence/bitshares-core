/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */

#include <graphene/chain/stealth_evaluator.hpp>
#include <graphene/chain/stealth_proof.hpp>
#include <graphene/chain/stealth_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/confidential_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>

#include <fc/crypto/elliptic.hpp>

#include <map>

namespace graphene { namespace chain {

using protocol::GRAPHENE_STEALTH_BLIND_POOL_FLOOR;
using protocol::GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC;
using protocol::GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC;
using protocol::GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED;
using protocol::GRAPHENE_STEALTH_MAX_BLIND_TX_PER_BLOCK;
using protocol::GRAPHENE_STEALTH_PROOF_V1;
using protocol::GRAPHENE_STEALTH_PROOF_V2;
using protocol::GRAPHENE_STEALTH_RING_MAX;
using protocol::GRAPHENE_STEALTH_RING_MIN;
using protocol::GRAPHENE_STEALTH_V1_LIFETIME_SEC;

namespace {

// Singleton accessor (read-only): nullptr when the index is empty
// (pre-genesis replay of old databases).
const stealth_status_object* find_stealth_status( const database& db )
{
   const auto& idx = db.get_index_type<stealth_status_index>().indices();
   if( idx.empty() )
      return nullptr;
   return &*idx.begin();
}

// Mutating accessor: create-on-demand for old databases replaying without
// the genesis-created singleton. Only called from apply/maintenance paths.
// Returns a const ref; callers mutate via db.modify (undo-safe).
const stealth_status_object& get_or_create_stealth_status( database& db )
{
   const auto& idx = db.get_index_type<stealth_status_index>().indices();
   if( idx.empty() )
      return db.create<stealth_status_object>( []( stealth_status_object& ) {} );
   return *idx.begin();
}

bool stealth_passed( const database& db )
{
   return HARDFORK_STEALTH_PASSED( db.head_block_time() );
}

fc::sha256 nullifier_key( const std::vector<char>& image33 )
{
   return fc::sha256::hash( image33.data(), image33.size() );
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

bool stealth_blind_halted( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return false;
   return s->blind_halted;
}

uint32_t stealth_tripwire_fire_block( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return 0;
   return s->tripwire_fire_block;
}

uint32_t stealth_blind_count_this_block( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return 0;
   if( s->blind_block_num != db.head_block_num() + 1 )
      return 0;
   return s->blind_block_count;
}

uint32_t stealth_pool_depth( const database& db, asset_id_type asset )
{
   // O(1) cached counter (review Finding 3): no per-evaluate full-pool
   // scan. Maintained on insert/spend by the blind evaluators.
   const auto* s = find_stealth_status( db );
   if( !s )
      return 0;
   auto itr = s->unspent_blind_count.find( asset );
   return ( itr == s->unspent_blind_count.end() ) ? 0 : itr->second;
}

bool stealth_vote_fresh( fc::time_point_sec now, fc::time_point_sec voted_at )
{
   if( voted_at > now )
      return false;
   uint32_t age = (uint32_t)( now.sec_since_epoch() - voted_at.sec_since_epoch() );
   return age <= GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC;
}

fc::time_point_sec stealth_v1_sunset_time( const database& db )
{
   if( !stealth_passed( db ) )
      return fc::time_point_sec();
   const auto* s = find_stealth_status( db );
   if( s && s->v1_sunset_time != fc::time_point_sec() )
      return s->v1_sunset_time;
   return fc::time_point_sec( HARDFORK_STEALTH_TIME.sec_since_epoch()
                              + GRAPHENE_STEALTH_V1_LIFETIME_SEC );
}

fc::time_point_sec stealth_turnstile_g2_time( const database& db )
{
   if( !stealth_passed( db ) )
      return fc::time_point_sec();
   const auto* s = find_stealth_status( db );
   if( s && s->turnstile_g2_time != fc::time_point_sec() )
      return s->turnstile_g2_time;
   return stealth_v1_sunset_time( db );
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

void stealth_maybe_record_activation( database& db )
{
   if( !stealth_passed( db ) )
      return;
   const auto& s = get_or_create_stealth_status( db );
   if( s.stealth_activated_time != fc::time_point_sec() )
      return; // idempotent: first post-STEALTH maintenance wins
   // Activation date is the scheduled hardfork time itself (deterministic on
   // every node, independent of when maintenance first runs after the fork).
   // The turnstile G2 date is therefore known from activation day one.
   fc::time_point_sec activated = HARDFORK_STEALTH_TIME;
   fc::time_point_sec sunset( activated.sec_since_epoch() + GRAPHENE_STEALTH_V1_LIFETIME_SEC );
   // Seed the per-asset shadow from live counters so pre-fork history
   // reconciles by construction.
   flat_map<asset_id_type, share_type> seed;
   const auto& assets = db.get_index_type<asset_index>().indices();
   for( const auto& a : assets )
   {
      const auto& dyn = a.dynamic_asset_data_id( db );
      if( dyn.confidential_supply.value != 0 )
         seed[ a.get_id() ] = dyn.confidential_supply;
   }
   db.modify( s, [&]( stealth_status_object& o ) {
      o.stealth_activated_time = activated;
      o.v1_sunset_time = sunset;
      o.turnstile_g2_time = sunset;
      o.blinded_supply_shadow = seed;
   } );
}

void stealth_reconcile_supplies( database& db )
{
   if( !stealth_passed( db ) )
      return;
   stealth_maybe_record_activation( db );
   // Monero-2018 rule: the independent shadow of confidential_supply must
   // match the live counter EXACTLY for every asset. Any divergence (direct
   // state edit or a future op that forgets a counter) engages blind_halted
   // automatically and records the firing block. Fail-closed: while halted,
   // every blind op rejects in do_evaluate.
   bool diverged = false;
   const auto& assets = db.get_index_type<asset_index>().indices();
   const auto* s = find_stealth_status( db );
   FC_ASSERT( s != nullptr );
   for( const auto& a : assets )
   {
      const auto& dyn = a.dynamic_asset_data_id( db );
      auto itr = s->blinded_supply_shadow.find( a.get_id() );
      share_type shadow = ( itr == s->blinded_supply_shadow.end() )
                          ? share_type( 0 ) : itr->second;
      if( shadow != dyn.confidential_supply )
      {
         diverged = true;
         break;
      }
   }
   if( diverged )
   {
      db.modify( *s, [&]( stealth_status_object& o ) {
         o.blind_halted = true;
         if( o.tripwire_fire_block == 0 )
            o.tripwire_fire_block = db.head_block_num();
      } );
   }
}

// ---------------------------------------------------------------------------
// Gate + range soundness shared by every blind op
// ---------------------------------------------------------------------------

void stealth_check_blind_gate( const database& db )
{
   if( !stealth_passed( db ) )
      return; // pre-fork: legacy behavior unchanged
   FC_ASSERT( !stealth_blind_halted( db ), "Blind operations are halted (tripwire or committee freeze)" );
   FC_ASSERT( stealth_blind_count_this_block( db ) < GRAPHENE_STEALTH_MAX_BLIND_TX_PER_BLOCK,
              "Per-block blind-operation budget exhausted" );
}

void stealth_count_blind_op( database& db )
{
   if( !stealth_passed( db ) )
      return;
   const auto& s = get_or_create_stealth_status( db );
   uint32_t pending = db.head_block_num() + 1;
   db.modify( s, [&]( stealth_status_object& o ) {
      if( o.blind_block_num != pending )
      {
         o.blind_block_num = pending;
         o.blind_block_count = 0;
      }
      ++o.blind_block_count;
   } );
}

void stealth_require_sound_range_proofs( const database& db,
      const vector<protocol::blind_output>& outputs )
{
   FC_ASSERT( stealth_passed( db ), "Range soundness gate requires STEALTH activation" );
   for( const auto& out : outputs )
   {
      FC_ASSERT( !out.range_proof.empty(), "Blind output must carry a range proof post-STEALTH" );
      uint64_t min_v = 0, max_v = 0;
      std::vector<char> proof( out.range_proof.begin(), out.range_proof.end() );
      FC_ASSERT( stealth_verify_range_v1( out.commitment, proof, min_v, max_v ),
                 "Blind output range proof does not verify" );
   }
}

/// Shadow bookkeeping: post-STEALTH only, same deltas as the confidential_supply
/// updates, through this independent code path. Reconciliation compares the two.
void stealth_shadow_add( database& db, asset_id_type asset, share_type delta )
{
   if( !stealth_passed( db ) )
      return;
   if( delta.value == 0 )
      return;
   const auto& s = get_or_create_stealth_status( db );
   db.modify( s, [&]( stealth_status_object& o ) {
      auto itr = o.blinded_supply_shadow.find( asset );
      if( itr == o.blinded_supply_shadow.end() )
         o.blinded_supply_shadow[ asset ] = delta;
      else
         itr->second += delta;
   } );
}

/// Pool-count bookkeeping: post-STEALTH only. Counts unspent
/// metadata-bearing balances per asset (decoy candidates for the floor).
void stealth_pool_count_add( database& db, asset_id_type asset, int32_t delta )
{
   if( !stealth_passed( db ) )
      return;
   if( delta == 0 )
      return;
   const auto& s = get_or_create_stealth_status( db );
   db.modify( s, [&]( stealth_status_object& o ) {
      auto itr = o.unspent_blind_count.find( asset );
      uint32_t cur = ( itr == o.unspent_blind_count.end() ) ? 0 : itr->second;
      if( delta < 0 )
      {
         uint32_t sub = (uint32_t)( -(int64_t)delta );
         FC_ASSERT( cur >= sub, "Blind pool counter underflow" );
         cur -= sub;
      }
      else
         cur += (uint32_t)delta;
      if( cur == 0 )
         o.unspent_blind_count.erase( asset );
      else
         o.unspent_blind_count[ asset ] = cur;
   } );
}

// ---------------------------------------------------------------------------
// stealth_transfer
// ---------------------------------------------------------------------------

void_result stealth_transfer_evaluator::do_evaluate( const stealth_transfer_operation& o )
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Stealth transfers are not allowed until the stealth hardfork" );
   stealth_check_blind_gate( d );

   FC_ASSERT( o.fee.asset_id == o.asset_id, "Stealth transfer fee must be paid in the transferred asset" );
   FC_ASSERT( o.fee.amount >= 0 );
   FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Unknown proof version" );
   FC_ASSERT( !o.inputs.empty() && o.inputs.size() <= 8, "Input count out of bounds" );
   FC_ASSERT( !o.outputs.empty() && o.outputs.size() <= 8, "Output count out of bounds" );

   // V1 spends are spend-only-via-turnstile past sunset; only V2 rings survive.
   if( d.head_block_time() >= stealth_v1_sunset_time( d ) )
      FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
                 "V1 stealth spends are frozen past sunset (use turnstile re-proof)" );

   // Pool floor: ring spends need decoys; thin-pool rings mark the spender.
   FC_ASSERT( stealth_pool_depth( d, o.asset_id ) >= GRAPHENE_STEALTH_BLIND_POOL_FLOOR,
              "Blind pool below floor: stealth spends halted (availability yields to privacy)" );

   const auto& bbi = d.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   const auto& nul = d.get_index_type<stealth_nullifier_index>().indices().get<by_nullifier_image>();

   // Output commitments must be fresh; range proofs must verify under the op version.
   for( const auto& out : o.outputs )
   {
      FC_ASSERT( bbi.find( out.commitment ) == bbi.end(), "Stealth output commitment already exists" );
      for( const auto& a : out.owner.account_auths )
         a.first( d );
   }
   {
      std::string err;
      for( const auto& out : o.outputs )
      {
         if( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 )
         {
            uint64_t min_v = 0, max_v = 0;
            std::vector<char> proof( out.range_proof.begin(), out.range_proof.end() );
            FC_ASSERT( stealth_verify_range_v1( out.commitment, proof, min_v, max_v ),
                       "Stealth output V1 range proof does not verify: ${e}", ("e", err) );
         }
         else
         {
            std::vector<char> proof( out.range_proof.begin(), out.range_proof.end() );
            std::vector<fc::ecc::commitment_type> cs = { out.commitment };
            FC_ASSERT( stealth_verify_bp_plus( 1, proof, cs, err ),
                       "Stealth output V2 range proof does not verify: ${e}", ("e", err) );
         }
      }
   }

   // Rings: shape, membership, decoy policy, message, signature, nullifier.
   // Same key image twice in one op is a same-opening double spend.
   for( size_t a = 0; a < o.inputs.size(); ++a )
      for( size_t b = a + 1; b < o.inputs.size(); ++b )
         FC_ASSERT( o.inputs[a].key_image != o.inputs[b].key_image,
                    "Duplicate key image within operation" );
   std::vector<fc::ecc::commitment_type> out_cs;
   for( const auto& out : o.outputs )
      out_cs.push_back( out.commitment );

   for( const auto& in : o.inputs )
   {
      FC_ASSERT( in.ring.size() >= GRAPHENE_STEALTH_RING_MIN &&
                 in.ring.size() <= GRAPHENE_STEALTH_RING_MAX,
                 "Ring size out of bounds" );
      FC_ASSERT( in.key_image.size() == 33, "Key image must be 33 bytes" );
      FC_ASSERT( in.ring_sig.size() == 32 + 96 * in.ring.size(), "Ring signature size mismatch" );
      // Distinct members (bounded O(n^2), n <= 32).
      for( size_t i = 0; i < in.ring.size(); ++i )
         for( size_t j = i + 1; j < in.ring.size(); ++j )
            FC_ASSERT( in.ring[i] != in.ring[j], "Duplicate ring member" );
      // Every member must be a live blinded balance of this asset carrying
      // post-fork creation metadata. Grandfathered (pre-fork, metadata absent)
      // outputs are NEVER decoy-eligible and cannot hide in rings: they spend
      // explicitly or via turnstile only (availability yields to privacy).
      std::vector<uint32_t> heights;
      std::vector<fc::time_point_sec> times;
      heights.reserve( in.ring.size() );
      times.reserve( in.ring.size() );
      for( const auto& c : in.ring )
      {
         auto itr = bbi.find( c );
         FC_ASSERT( itr != bbi.end(), "Ring member is not a live blinded balance" );
         FC_ASSERT( itr->asset_id == o.asset_id, "Ring member asset mismatch" );
         FC_ASSERT( itr->created_block != 0, "Grandfathered outputs are not decoy-eligible" );
         heights.push_back( itr->created_block );
         times.push_back( itr->created_time );
      }
      {
         std::string err;
         FC_ASSERT( stealth_check_decoy_policy( heights, times, d.head_block_time(),
                                                d.head_block_num(), err ),
                    "Decoy policy violation: ${e}", ("e", err) );
      }
      // Double-spend: same image twice rejects at insert; check here for a
      // clean evaluate-time failure.
      FC_ASSERT( nul.find( nullifier_key( in.key_image ) ) == nul.end(),
                 "Key image already spent" );
      // Message bound to version/asset/image/ring/pseudo/outputs/fee
      // (single-sourced with provers via stealth_ring_message).
      std::vector<fc::ecc::commitment_type> ring_cs( in.ring.begin(), in.ring.end() );
      fc::sha256 m = stealth_ring_message( o.proof_version, o.asset_id, in.key_image,
                                           ring_cs, in.pseudo_output, out_cs, o.fee.amount );
      std::string msg( (const char*)m.data(), 32 );
      {
         std::string err;
         FC_ASSERT( stealth_verify_ring( o.proof_version, in, msg, err ),
                    "Ring signature does not verify: ${e}", ("e", err) );
      }
   }

   // Conservation kernel (Mimblewimble-style excess over pseudo-outputs):
   // sum(P) - sum(outputs) - fee*H == excess*G. Each pseudo P is bound to
   // its ring's real input value by the ring's M equation (verified above),
   // so the prover cannot inflate the kernel inputs; sound output range
   // proofs (verified above) rule out negative outputs. Together the two
   // legs make unbalanced ring spends unconstructable: any value surplus
   // or shortfall fails this equation. (G1b-2 left o.excess unwired with
   // an AUDIT-debt comment; the kernel is wired here, G1b-3 Finding 1.)
   {
      std::string err;
      std::vector<fc::ecc::commitment_type> pins;
      pins.reserve( o.inputs.size() );
      for( const auto& in : o.inputs )
         pins.push_back( in.pseudo_output );
      FC_ASSERT( stealth_verify_excess( pins, out_cs, o.fee.amount.value, o.excess, err ),
                 "Stealth conservation mismatch: ${e}", ("e", err) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result stealth_transfer_evaluator::do_apply( const stealth_transfer_operation& o )
{ try {
   // Fee rides the FBA-style path: credit TEMP first (the blind surplus covers
   // it by conservation), the evaluator framework debits it after do_apply.
   db().adjust_balance( o.fee_payer(), o.fee );
   // Record nullifiers (double-spend set) and create the new blinded balances
   // with decoy metadata. The real spent inputs stay in the index (needed as
   // future decoys); re-spend is blocked by the nullifier set.
   for( const auto& in : o.inputs )
   {
      db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
         n.key_image = nullifier_key( in.key_image );
         n.proof_version = o.proof_version;
         n.created = db().head_block_time();
      } );
   }
   for( const auto& out : o.outputs )
   {
      db().create<blinded_balance_object>( [&]( blinded_balance_object& b ) {
         b.asset_id = o.asset_id;
         b.owner = out.owner;
         b.commitment = out.commitment;
         b.created_block = db().head_block_num() + 1;
         b.created_time = db().head_block_time();
      } );
   }
   // The blind pool pays the fee out; both counters move together.
   const auto& add = o.asset_id( db() ).dynamic_asset_data_id( db() );
   db().modify( add, [&]( asset_dynamic_data_object& obj ) {
      obj.confidential_supply -= o.fee.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   } );
   stealth_shadow_add( db(), o.asset_id, share_type( -o.fee.amount.value ) );
   // Pool floor counter: every real input was metadata-bearing (membership
   // rule), so inputs.size() balances leave the unspent set; the new
   // outputs (created with metadata below) join it.
   stealth_pool_count_add( db(), o.asset_id, -(int32_t)o.inputs.size() );
   stealth_pool_count_add( db(), o.asset_id, (int32_t)o.outputs.size() );
   stealth_count_blind_op( db() );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void stealth_transfer_evaluator::pay_fee()
{
   generic_evaluator::pay_fee();
}

// ---------------------------------------------------------------------------
// freeze_blind (committee backup halt; works while halted by design)
// ---------------------------------------------------------------------------

void_result freeze_blind_evaluator::do_evaluate( const freeze_blind_operation& o )
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Freeze-blind votes are not allowed until the stealth hardfork" );
   // Only elected committee members may vote.
   const auto& cidx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   FC_ASSERT( cidx.find( o.voter ) != cidx.end(), "Freeze-blind voter is not a committee member" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result freeze_blind_evaluator::do_apply( const freeze_blind_operation& o )
{ try {
   const auto& s = get_or_create_stealth_status( db() );
   fc::time_point_sec now = db().head_block_time();
   db().modify( s, [&]( stealth_status_object& st ) {
      // One live vote per member (latest wins); drop expired votes to bound state.
      flat_map<account_id_type, stealth_freeze_vote> kept;
      for( const auto& kv : st.freeze_votes )
         if( stealth_vote_fresh( now, kv.second.voted_at ) )
            kept[ kv.first ] = kv.second;
      stealth_freeze_vote v;
      v.voter = o.voter;
      v.freeze = o.freeze;
      v.voted_at = now;
      kept[ o.voter ] = v;
      st.freeze_votes = kept;
      // Symmetric quorum both ways; freeze wins ties (fail-closed).
      uint32_t n_freeze = 0, n_resume = 0;
      for( const auto& kv : kept )
         ( kv.second.freeze ? n_freeze : n_resume )++;
      if( n_freeze >= GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED )
         st.blind_halted = true;
      else if( n_resume >= GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED )
         st.blind_halted = false;
   } );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

// ---------------------------------------------------------------------------
// turnstile_reproof (transparent migration leg, conservation-checkable)
// ---------------------------------------------------------------------------

void_result turnstile_reproof_evaluator::do_evaluate( const turnstile_reproof_operation& o )
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Turnstile re-proofs are not allowed until the stealth hardfork" );
   stealth_check_blind_gate( d );

   FC_ASSERT( o.fee.asset_id == o.asset_id, "Turnstile fee must be paid in the migrated asset" );
   FC_ASSERT( o.fee.amount >= 0 );
   FC_ASSERT( o.new_proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Turnstile migrates to V2 (the surviving system)" );
   FC_ASSERT( !o.new_output.range_proof.empty(), "Migrated output must carry a range proof" );
   for( const auto& a : o.owner.account_auths )
      a.first( d );

   // The spent balance must exist with a matching owner.
   const auto& bbi = d.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto itr = bbi.find( o.old_commitment );
   FC_ASSERT( itr != bbi.end(), "Turnstile old commitment is not a live blinded balance" );
   FC_ASSERT( itr->asset_id == o.asset_id, "Turnstile asset mismatch" );
   FC_ASSERT( itr->owner == o.owner, "Turnstile owner mismatch" );
   FC_ASSERT( bbi.find( o.new_output.commitment ) == bbi.end(),
              "Turnstile new commitment already exists" );

   // Conservation over the transparent leg: the blinds are revealed, so
   // C_old - C_new - fee*H must equal (b_old - b_new)*G. This binds the hidden
   // values: any new-value inflation (or fee shortfall) fails the equation.
   {
      // Excess scalar e = b_old - b_new (mod n), from the revealed blinds.
      fc::sha256 e_raw;
      {
         // 256-bit modular subtraction on the blind preimages.
         unsigned char a[32], b[32], e[32];
         std::copy( (const char*)o.old_blind.data(), (const char*)o.old_blind.data() + 32, (char*)a );
         std::copy( (const char*)o.new_blind.data(), (const char*)o.new_blind.data() + 32, (char*)b );
         // e = a - b mod n (secp256k1 order); implemented without OpenSSL
         // BIGNUMs to keep this TU free of direct crypto plumbing (the actual
         // EC check lives in stealth_verify_excess).
         static const unsigned char N[32] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
         auto ge = []( const unsigned char* x, const unsigned char* y ) {
            for( int i = 0; i < 32; ++i )
               if( x[i] != y[i] ) return x[i] > y[i];
            return true;
         };
         unsigned char t[32];
         int borrow = 0;
         if( ge( a, b ) )
         {
            for( int i = 31; i >= 0; --i )
            {
               int d = (int)a[i] - (int)b[i] - borrow;
               borrow = ( d < 0 ) ? 1 : 0;
               t[i] = (unsigned char)( d & 0xFF );
            }
            std::copy( t, t + 32, (char*)e );
         }
         else
         {
            // e = N - (b - a)
            for( int i = 31; i >= 0; --i )
            {
               int d = (int)b[i] - (int)a[i] - borrow;
               borrow = ( d < 0 ) ? 1 : 0;
               t[i] = (unsigned char)( d & 0xFF );
            }
            int c = 0;
            for( int i = 31; i >= 0; --i )
            {
               int d = (int)N[i] - (int)t[i] - c;
               c = ( d < 0 ) ? 1 : 0;
               e[i] = (unsigned char)( d & 0xFF );
            }
         }
         std::copy( (char*)e, (char*)e + 32, (char*)e_raw.data() );
      }
      std::string err;
      std::vector<fc::ecc::commitment_type> ins = { o.old_commitment };
      std::vector<fc::ecc::commitment_type> outs = { o.new_output.commitment };
      FC_ASSERT( stealth_verify_excess( ins, outs, o.fee.amount.value, e_raw, err ),
                 "Turnstile conservation mismatch: ${e}", ("e", err) );
   }

   // The new output's range proof must verify under its version.
   {
      std::string err;
      std::vector<char> proof( o.new_output.range_proof.begin(), o.new_output.range_proof.end() );
      std::vector<fc::ecc::commitment_type> cs = { o.new_output.commitment };
      if( o.new_proof_version == GRAPHENE_STEALTH_PROOF_V1 )
      {
         uint64_t min_v = 0, max_v = 0;
         FC_ASSERT( stealth_verify_range_v1( o.new_output.commitment, proof, min_v, max_v ),
                    "Turnstile V1 range proof does not verify" );
      }
      else
      {
         FC_ASSERT( stealth_verify_bp_plus( 1, proof, cs, err ),
                    "Turnstile V2 range proof does not verify: ${e}", ("e", err) );
      }
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result turnstile_reproof_evaluator::do_apply( const turnstile_reproof_operation& o )
{ try {
   db().adjust_balance( o.fee_payer(), o.fee );
   // Consume the old balance, create the migrated one (post-fork metadata:
   // migrated outputs are first-class decoy candidates once aged).
   const auto& bbi = db().get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto itr = bbi.find( o.old_commitment );
   FC_ASSERT( itr != bbi.end() );
   const bool had_metadata = ( itr->created_block != 0 );
   db().remove( *itr );
   db().create<blinded_balance_object>( [&]( blinded_balance_object& b ) {
      b.asset_id = o.asset_id;
      b.owner = o.new_output.owner;
      b.commitment = o.new_output.commitment;
      b.created_block = db().head_block_num() + 1;
      b.created_time = db().head_block_time();
   } );
   const auto& add = o.asset_id( db() ).dynamic_asset_data_id( db() );
   db().modify( add, [&]( asset_dynamic_data_object& obj ) {
      obj.confidential_supply -= o.fee.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   } );
   stealth_shadow_add( db(), o.asset_id, share_type( -o.fee.amount.value ) );
   // Pool floor counter: the consumed balance leaves the unspent set only
   // if it was counted (grandfathered balances never were); the migrated
   // output always joins it.
   if( had_metadata )
      stealth_pool_count_add( db(), o.asset_id, -1 );
   stealth_pool_count_add( db(), o.asset_id, 1 );
   stealth_count_blind_op( db() );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void turnstile_reproof_evaluator::pay_fee()
{
   generic_evaluator::pay_fee();
}

} } // graphene::chain
