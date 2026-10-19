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
#include <graphene/chain/liquidity_pool_object.hpp>

#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>

#include <fc/crypto/elliptic.hpp>
#include <fc/uint128.hpp>

#include <algorithm>
#include <map>

namespace graphene { namespace chain {

using protocol::GRAPHENE_STEALTH_BLIND_POOL_FLOOR;
using protocol::GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC;
using protocol::GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC;
using protocol::GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED;
using protocol::GRAPHENE_STEALTH_JOINT_FEE_CAP_BPS;
using protocol::GRAPHENE_STEALTH_MAX_BLIND_TX_PER_BLOCK;
using protocol::GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK;
using protocol::GRAPHENE_STEALTH_WORK_US_PER_KERNEL;
using protocol::GRAPHENE_STEALTH_WORK_US_PER_POOL_MATH;
using protocol::GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;
using protocol::GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER;
using protocol::GRAPHENE_STEALTH_PARITY_BURN_CRITICAL_PCT;
using protocol::GRAPHENE_STEALTH_PARITY_BURN_WARN_PCT;
using protocol::GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS;
using protocol::GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK;
using protocol::GRAPHENE_STEALTH_PARITY_ATTEST_EXPIRY_SEC;
using protocol::GRAPHENE_STEALTH_PARITY_QUORUM_REQUIRED;
using protocol::GRAPHENE_STEALTH_PARITY_REPORT_INTERVAL_SEC;
using protocol::GRAPHENE_STEALTH_PARITY_REVIEW_INTERVAL_SEC;
using protocol::GRAPHENE_STEALTH_POOL_WARN_DEPTH;
using protocol::GRAPHENE_STEALTH_PROOF_V1;
using protocol::GRAPHENE_STEALTH_PROOF_V2;
using protocol::GRAPHENE_STEALTH_REVIEW_PARITY;
using protocol::GRAPHENE_STEALTH_REVIEW_SET_REPORT;
using protocol::GRAPHENE_STEALTH_RING_MAX;
using protocol::GRAPHENE_STEALTH_RING_MIN;
using protocol::GRAPHENE_STEALTH_RING_TARGET;
using protocol::GRAPHENE_STEALTH_SKEW_WINDOW_BLOCKS;
using protocol::GRAPHENE_STEALTH_SKEW_WINDOWS_KEPT;
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

// legacy coexistence (BSIP-2 §2, GP-01/GP-02): the parity fee-share
// routes ONLY for assets whose issuer opted in via
// additional_asset_options.parity_fee_share_enabled (appended-last, absent ==
// false). Every legacy asset (bit*, HONEST.*, gateway UIAs, CORE) is absent-
// flagged, so post-fork fills on non-opted assets leave parity_pool
// untouched and credit 100% of the increment to accumulated_fees — by
// construction, not by convention. Read-only options lookup: deterministic,
// no floats, no time, no state change.
bool parity_fee_share_opted_in( const database& db, asset_id_type recv_asset )
{
   const auto& opt = recv_asset( db ).options.extensions.value.parity_fee_share_enabled;
   return opt.valid() && *opt;
}

} // anonymous namespace

// Exported to the test suite via stealth_evaluator.hpp (): the single
// definition of the nullifier identity — tests must link this, never
// duplicate the sha256 hash.
fc::sha256 nullifier_key( const std::vector<char>& image33 )
{
   // AUDIT: nullifier identity IS sha256(image) — double-spend detection
   // reduces to sha256 second-preimage resistance; any image truncation or
   // domain change here breaks cross-path linkage silently.
   return fc::sha256::hash( image33.data(), image33.size() );
}

// AGI-04: THE V1<->V2 linkage, single definition (declared in
// stealth_evaluator.hpp). Replaces the four historical inline ternaries
// (op40 evaluate/apply, op109 evaluate/apply) so they cannot drift; the
// op108 absolute tagging agrees by construction (its key_image_v1 field is
// always the V1-domain image — tagged GRAPHENE_STEALTH_PROOF_V1 directly,
// same mapping). Unknown versions link to V1: exact historical ternary
// semantics, unreachable in practice because the op version assert above
// each linkage refuses the op before the alt leg runs.
uint8_t stealth_alt_proof_version( uint8_t proof_version )
{
   return ( proof_version == protocol::GRAPHENE_STEALTH_PROOF_V1 )
          ? protocol::GRAPHENE_STEALTH_PROOF_V2
          : protocol::GRAPHENE_STEALTH_PROOF_V1;
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

bool stealth_blind_halted( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return false;
   return s->blind_halted;
}

/// Per-asset halt scope (SUP-07): true while the asset's supply
/// shadow diverges from live confidential_supply. Healthy assets keep
/// moving while a diverged asset's blind ops fail closed.
bool stealth_asset_halted( const database& db, asset_id_type asset )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return false;
   return s->diverged_assets.find( asset ) != s->diverged_assets.end();
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
   // disposition (audit "recorded but no gate"): turnstile_g2_time IS
   // v1_sunset_time by construction (recorded equal at activation, :186, and
   // pinned equal by turnstile_migration). There is no separate G2 event to
   // gate — the V1-spend freeze on every leg (op104 :344-346, legacy sunset
   // gates) IS the enforcement of this date. A distinct gate here would be
   // dead code asserting the same instant twice; if a future G2 phase needs
   // its own trigger, add the gate with it, not before.
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
   // snapshot the transfer_to_blind fee schedule once — the true
   // pre-parity levels feeding the cost anchor's max().
   const auto& k39 = db.current_fee_schedule()
      .get<protocol::transfer_to_blind_operation>();
   db.modify( s, [&]( stealth_status_object& o ) {
      o.stealth_activated_time = activated;
      o.v1_sunset_time = sunset;
      o.turnstile_g2_time = sunset;
      o.blinded_supply_shadow = seed;
      o.activation_k39_fee = k39.fee;
      o.activation_k39_ppo = k39.price_per_output;
   } );
}

void stealth_reconcile_supplies( database& db )
{
   if( !stealth_passed( db ) )
      return;
   stealth_maybe_record_activation( db );
   // Monero-2018 rule, per-asset scope (SUP-07): the independent
   // shadow of confidential_supply must match the live counter EXACTLY for
   // every asset. A diverged asset is recorded in diverged_assets (instead
   // of flapping the global blind_halted flag): blind ops OF THAT ASSET
   // halt individually, healthy assets keep moving, and the committee
   // resume quorum is refused while the set is non-empty. Entries heal
   // automatically when reconciliation passes for that asset (no vote
   // needed to clear honest bookkeeping); the global halt stays a
   // committee-only action. Fail-closed: while listed, every blind op of
   // that asset rejects in do_evaluate.
   //
   // SCOPE (GC-08 qualification): this is a COUNTER-level tripwire
   // only. It compares the per-asset confidential_supply counter against its
   // shadow — both move on the same fee/amount deltas in the same evaluators.
   // It provably CANNOT see value-level forgery that preserves the counters:
   // a cross-version double-spend (GC-07, closed by the dual-image linkage)
   // moves both counters by fees only, and a same-asset conservation break
   // inside a valid-looking kernel is a proof-soundness matter, not a counter
   // matter. Operators must not assume this halt detects value forgery;
   // value soundness rests on the ring/BP+/excess verifiers plus the
   // pre-G1 specialist audit, with this tripwire as the accounting backstop.
   const auto& assets = db.get_index_type<asset_index>().indices();
   const auto* s = find_stealth_status( db );
   FC_ASSERT( s != nullptr );
   flat_set<asset_id_type> still_diverged;
   for( const auto& a : assets )
   {
      const auto& dyn = a.dynamic_asset_data_id( db );
      auto itr = s->blinded_supply_shadow.find( a.get_id() );
      share_type shadow = ( itr == s->blinded_supply_shadow.end() )
                          ? share_type( 0 ) : itr->second;
      if( shadow != dyn.confidential_supply )
         still_diverged.insert( a.get_id() );
   }
   // The recomputed set REPLACES the old one: assets are never deleted, so
   // the iteration above covers every live asset, and a healed asset drops
   // out by construction (no separate clear path to forget).
   if( still_diverged != s->diverged_assets )
   {
      db.modify( *s, [&]( stealth_status_object& o ) {
         o.diverged_assets = still_diverged;
         if( !still_diverged.empty() && o.tripwire_fire_block == 0 )
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

/// Per-asset leg of the blind gate (SUP-07): called by every blind
/// op evaluator with the op's asset right after stealth_check_blind_gate.
/// Deposits are NOT exempt (a diverged asset's books are untrusted until
/// reconciliation passes for it — fail-closed both directions).
void stealth_check_asset_gate( const database& db, asset_id_type asset )
{
   if( !stealth_passed( db ) )
      return;
   FC_ASSERT( !stealth_asset_halted( db, asset ),
              "Blind operations of this asset are halted (supply divergence — see diverged_assets)" );
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

// ---------------------------------------------------------------------------
// F-01 verification-work budget (R9B): model-unit accounting, integer only
// ---------------------------------------------------------------------------

uint32_t stealth_work_for_stealth_transfer( const protocol::stealth_transfer_operation& o )
{
   // 64-bit accumulation with saturation: the gate runs before the
   // input/output-count asserts, and a proposal-embedded op bypasses
   // validate(), so counts are unbounded here — saturate, never wrap, and
   // the gate fails closed on the saturated value.
   uint64_t w = GRAPHENE_STEALTH_WORK_US_PER_KERNEL;
   for( const auto& in : o.inputs )
      w += (uint64_t)2 * in.ring.size() * GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER;
   w += (uint64_t)o.outputs.size() * GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;
   if( w > 0xFFFFFFFFu )
      return 0xFFFFFFFFu;
   return (uint32_t)w;
}

uint32_t stealth_work_for_range_proofs( uint32_t n_outputs )
{
   uint64_t w = (uint64_t)n_outputs * GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;
   if( w > 0xFFFFFFFFu )
      return 0xFFFFFFFFu;
   return (uint32_t)w;
}

uint32_t stealth_work_for_explicit_spend( const protocol::stealth_explicit_spend_operation& o )
{
   // 64-bit accumulation with saturation, mirroring
   // stealth_work_for_stealth_transfer (:338-351): this gate runs BEFORE the
   // input/output-count asserts and a proposal-embedded op bypasses validate(),
   // so counts are unbounded at gate time — saturate, never wrap.
   uint64_t w = GRAPHENE_STEALTH_WORK_US_PER_KERNEL;            // conservation kernel
   w += (uint64_t)o.inputs.size() * GRAPHENE_STEALTH_WORK_US_PER_KERNEL;  // per-input recovery proof
   w += (uint64_t)o.outputs.size() * GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;
   if( w > 0xFFFFFFFFu ) return 0xFFFFFFFFu;
   return (uint32_t)w;
}

uint32_t stealth_work_for_pool_exchange( uint32_t ring_size )
{
   // 64-bit accumulation with saturation, mirroring
   // stealth_work_for_stealth_transfer (:338-351): the gate runs before any
   // ring-size assert and a proposal-embedded op bypasses validate(), so
   // ring_size is unbounded at gate time — saturate, never wrap, and the
   // gate fails closed on the saturated value. Single 1-in/1-out G2 swap
   // leg: dual-verified ring (both version legs), TWO kernel allowances —
   // the Schnorr value-pin (do_evaluate step 7) AND the conservation kernel
   // verify_excess (step 10's blind->blind leg runs BOTH; NC-14: the model
   // had been charging one while the evaluator verified two), 2x range
   // allowance (output BP+ m=1 + conceptual pin cost), pool-math leg.
   uint64_t w = 2u * GRAPHENE_STEALTH_WORK_US_PER_KERNEL;                         // value-pin + conservation kernels
   w += (uint64_t)2 * ring_size * GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER;      // dual-verify ring
   w += (uint64_t)2 * GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;                  // output BP+ + pin cost
   w += GRAPHENE_STEALTH_WORK_US_PER_POOL_MATH;                                  // constant-product math
   if( w > 0xFFFFFFFFu ) return 0xFFFFFFFFu;
   return (uint32_t)w;
}

uint32_t stealth_work_for_turnstile()
{
   // (nullifier migration): one BP+ output + the conservation kernel
   // + the recovery-proof kernel, always. The recovery unit was conditional
   // on !o.extensions.empty() while the extension was optional; with the
   // turnstile proving on every path it is unconditionally charged. Fixed
   // shape (1-in/1-out), so the sum is constant — no saturation logic needed.
   return stealth_work_for_range_proofs( 1 )
        + GRAPHENE_STEALTH_WORK_US_PER_KERNEL
        + GRAPHENE_STEALTH_WORK_US_PER_KERNEL; // R15 recovery proof (mandatory)
}

uint32_t stealth_blind_work_this_block( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return 0;
   if( s->blind_work_block_num != db.head_block_num() + 1 )
      return 0;
   return s->blind_work_used_us;
}

void stealth_check_blind_work_gate( const database& db, uint32_t work_us )
{
   if( !stealth_passed( db ) )
      return; // pre-fork: legacy behavior unchanged
   // 64-bit sum: used stays <= budget by the apply invariant below, and
   // work_us is saturated above — no wrap on any input.
   uint64_t projected = (uint64_t)stealth_blind_work_this_block( db ) + work_us;
   FC_ASSERT( projected <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK,
              "Per-block blind verification-work budget exhausted" );
}

void stealth_count_blind_work( database& db, uint32_t work_us )
{
   if( !stealth_passed( db ) )
      return;
   const auto& s = get_or_create_stealth_status( db );
   uint32_t pending = db.head_block_num() + 1;
   db.modify( s, [&]( stealth_status_object& o ) {
      if( o.blind_work_block_num != pending )
      {
         o.blind_work_block_num = pending;
         o.blind_work_used_us = 0;
      }
      // No wrap: do_apply follows a do_evaluate that passed the gate for
      // this same op, so used + work_us <= budget here by construction.
      // Saturate defensively anyway (never throws in apply).
      uint64_t next = (uint64_t)o.blind_work_used_us + work_us;
      o.blind_work_used_us = ( next > 0xFFFFFFFFu ) ? 0xFFFFFFFFu : (uint32_t)next;
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
      // F-05 (R9A): the claimed range is checked, never ignored. min_value
      // is pinned to 0 (every honest prover — wallet 49-bit mantissa, tests —
      // signs min_value=0); nonzero minima fail closed here. No max_value
      // FLOOR is asserted: narrow proofs are sound (small values prove narrow
      // ranges by construction under min_bits=0), so a floor would reject
      // legitimate small-value outputs. The operative CEILING [0,2^50) is
      // enforced by the 4096-byte cap inside the verifier (50-bit = 4005B,
      // last admissible, ADDENDUM A6); see stealth_proof.hpp:160-161.
      FC_ASSERT( min_v == 0, "V1 range proof must claim min_value 0" );
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

/// Pool-count bookkeeping: post-STEALTH only. Counts LIVE
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

/// Phase-1 instrumentation (spec 2026-10-11 §8): ring-buffer push of one
/// deposit event. Post-STEALTH only (same guard posture as the adjacent
/// count-add); grandfathered pre-fork creates never count.
void stealth_deposit_histogram_add( database& db, asset_id_type asset,
                                    account_id_type depositor, uint32_t n )
{
   if( !HARDFORK_STEALTH_PASSED( db.head_block_time() ) )
      return; // grandfathered pre-fork creates never count
   FC_ASSERT( n >= 1, "Deposit window needs a positive output count" );
   const auto& s = get_or_create_stealth_status( db );
   db.modify( s, [&]( stealth_status_object& o ) {
      auto& w = o.deposit_windows[ asset ];
      w.total_ever += n;
      FC_ASSERT( w.total_ever <= (uint64_t)GRAPHENE_MAX_SHARE_SUPPLY,
                 "Deposit window total overflow" );
      stealth_deposit_event ev;
      ev.account = depositor;
      ev.n = n;
      w.events[ w.head ] = ev;
      w.head = ( w.head + 1 ) % protocol::GRAPHENE_STEALTH_DEPOSITOR_WINDOW;
      if( w.count < protocol::GRAPHENE_STEALTH_DEPOSITOR_WINDOW )
         ++w.count;
   } );
}

uint64_t stealth_deposited_outputs( const database& db, asset_id_type asset )
{
   const auto* s = find_stealth_status( db );
   if( !s )
      return 0;
   auto it = s->deposit_windows.find( asset );
   return ( it == s->deposit_windows.end() ) ? 0 : it->second.total_ever;
}

uint64_t stealth_effective_depositor_count( const database& db, asset_id_type asset )
{
   const auto* s = find_stealth_status( db );
   if( !s )
      return 0;
   auto it = s->deposit_windows.find( asset );
   if( it == s->deposit_windows.end() || it->second.count == 0 )
      return 0;
   // Exact aggregation over the window. Local flat_map (ORDERED, deterministic);
   // O(W) scan is acceptable: Phase 1 gates nothing on this path (tests, wallet, API).
   flat_map<account_id_type, uint64_t> acc;
   for( const auto& kv : it->second.events )
      acc[ kv.second.account ] += kv.second.n;
   // fc::uint128_t per this file's discipline (cf. stealth_parity_maintenance
   // :1575-1578); same arithmetic as the brief's __uint128_t form.
   fc::uint128_t base = 0, sumsq = 0;
   for( const auto& kv : acc )
   {
      base += kv.second;
      sumsq += fc::uint128_t( kv.second ) * kv.second;
   }
   return (uint64_t)( ( base * base ) / sumsq ); // sumsq > 0: counts >= 1
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
   // F-01 (R9B): the count gate above reserves market space; this second
   // gate bounds verification work (dual ring verifies + BP+ outputs).
   // Runs before the input/output-count asserts, so the calculator takes a
   // wire-shaped op and saturates (fail-closed, never wraps).
   stealth_check_blind_work_gate( d, stealth_work_for_stealth_transfer( o ) );
   stealth_check_asset_gate( d, o.asset_id );

   FC_ASSERT( o.fee.asset_id == o.asset_id, "Stealth transfer fee must be paid in the transferred asset" );
   FC_ASSERT( o.fee.amount >= 0 );
   FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Unknown proof version" );
   // parity float rule (BSIP-2 §2): pool-empty / cap-hit /
   // review-missed floats the required fee to the cost anchor. Skipped
   // exactly when the fee-schedule check is skipped (no fee paid, no subsidy
   // consumed — same context as genesis/test/generator paths). Rule R (EE-1b):
   // a ring spend consumes nothing from the live set (:769-771), so ΔD_a is
   // +n_out and the full per-output component is always available here.
   stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                             o.fee.asset_id, (uint32_t)o.outputs.size(),
                             calculate_fee_for_operation( operation( o ) ),
                             std::min( (uint32_t)o.outputs.size(),
                                stealth_subsidy_output_count( operation( o ) ) ) );
   FC_ASSERT( !o.inputs.empty() && o.inputs.size() <= 8, "Input count out of bounds" );
   FC_ASSERT( !o.outputs.empty() && o.outputs.size() <= 8, "Output count out of bounds" );

   // V1 spends are spend-only-via-turnstile past sunset; only V2 rings survive.
   if( d.head_block_time() >= stealth_v1_sunset_time( d ) )
      FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
                 "V1 stealth spends are frozen past sunset (use turnstile re-proof)" );

   // Pool floor: ring spends need decoys; thin-pool rings mark the spender.
   FC_ASSERT( stealth_pool_depth( d, o.asset_id ) >= GRAPHENE_STEALTH_BLIND_POOL_FLOOR,
              "Blind pool below floor: stealth spends halted (availability yields to privacy)" );

   // (M05/GC-07): exactly two proof versions exist; every spend
   // authorizes under both (dual-verify window [activation, sunset]). The
   // key image is version-domain (I = b*J1_v + v*J2_v, J bases differ per
   // version), so one opening yields two distinct nullifiers — both must be
   // checked AND recorded, or the opening spends once per version. A future
   // V3 must extend this mapping and the linkage below (fail-closed:
   // unknown versions are already rejected with the op version above).
   const uint8_t alt_version = stealth_alt_proof_version( o.proof_version );

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
            // F-05 (R9A): same claimed-range pin as the legacy path above —
            // min_value==0 fail-closed; no max_value floor (narrow proofs are
            // sound; the ceiling [0,2^50) rides the verifier's 4096-byte cap).
            FC_ASSERT( min_v == 0, "V1 range proof must claim min_value 0" );
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
   // Any key image twice in one op (main or alternate leg, same or across
   // inputs) is a same-opening double spend. Bounded: inputs <= 8, so at
   // most 16 images and 120 pairwise compares.
   {
      std::vector<std::vector<char>> all_images;
      all_images.reserve( 2 * o.inputs.size() );
      for( const auto& in : o.inputs )
      {
         all_images.push_back( in.key_image );
         all_images.push_back( in.alt_key_image );
      }
      for( size_t a = 0; a < all_images.size(); ++a )
         for( size_t b = a + 1; b < all_images.size(); ++b )
            FC_ASSERT( all_images[a] != all_images[b],
                       "Duplicate key image within operation" );
   }
   std::vector<fc::ecc::commitment_type> out_cs;
   for( const auto& out : o.outputs )
      out_cs.push_back( out.commitment );

   for( const auto& in : o.inputs )
   {
      FC_ASSERT( in.ring.size() >= GRAPHENE_STEALTH_RING_MIN &&
                 in.ring.size() <= GRAPHENE_STEALTH_RING_MAX,
                 "Ring size out of bounds" );
      // (R7 C-10): ring-scheme migration slot. Only the genesis
      // scheme verifies here; unknown schemes fail closed (validate() is
      // relay-side only — proposal-embedded ops bypass it).
      FC_ASSERT( in.ring_scheme == protocol::GRAPHENE_STEALTH_RING_SCHEME_V1,
                 "Unknown ring scheme" );
      FC_ASSERT( in.key_image.size() == 33, "Key image must be 33 bytes" );
      FC_ASSERT( in.ring_sig.size() == 32 + 96 * in.ring.size(), "Ring signature size mismatch" );
      // Consensus mirror of the relay-side alt shape checks (validate() is
      // bypassed by proposal-embedded ops; sizes must gate here too).
      FC_ASSERT( in.alt_key_image.size() == 33, "Alt key image must be 33 bytes" );
      FC_ASSERT( in.alt_ring_sig.size() == 32 + 96 * in.ring.size(),
                 "Alt ring signature size mismatch" );
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
         // DELETED (nullifier migration). The spent flag is retired;
         // nullified outputs are decoy-eligible again — the set grows with
         // use (C-02's rationale evaporated; images unlinkable; §8.2).
         heights.push_back( itr->created_block );
         times.push_back( itr->created_time );
      }
      {
         std::string err;
         // R-04: the caller owns the pool-depth context the pure policy
         // function lacks — pass this asset's unspent depth so thin pools
         // (< 64) enforce target-size rings with the tighter skew ceiling.
         FC_ASSERT( stealth_check_decoy_policy( heights, times, d.head_block_time(),
                                                d.head_block_num(), err,
                                                stealth_pool_depth( d, o.asset_id ) ),
                    "Decoy policy violation: ${e}", ("e", err) );
      }
      // Double-spend: same image twice rejects at insert; check here for a
      // clean evaluate-time failure. BOTH version legs are checked: the
      // opening was nullified under both by its first spend.
      FC_ASSERT( nul.find( nullifier_key( in.key_image ) ) == nul.end(),
                 "Key image already spent" );
      FC_ASSERT( nul.find( nullifier_key( in.alt_key_image ) ) == nul.end(),
                 "Alternate key image already spent" );
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
      // Alternate-version linkage: the SAME opening authorized under the
      // other version (same ring, same pseudo-output — P is version-
      // independent — same outputs/fee). Verified with the UNMODIFIED ring
      // verifier, so no new crypto enters consensus: an unverified alt image
      // would let a lying prover supply garbage that never collides and
      // spend once per version. The alt message is rebuilt here from chain
      // and op fields (single-sourced), never trusted from the wire.
      {
         protocol::stealth_ring_input alt_in;
         alt_in.ring = in.ring;
         alt_in.key_image = in.alt_key_image;
         alt_in.ring_sig = in.alt_ring_sig;
         alt_in.pseudo_output = in.pseudo_output;
         fc::sha256 ma = stealth_ring_message( alt_version, o.asset_id, in.alt_key_image,
                                               ring_cs, in.pseudo_output, out_cs,
                                               o.fee.amount );
         std::string msg_alt( (const char*)ma.data(), 32 );
         std::string err;
         FC_ASSERT( stealth_verify_ring( alt_version, alt_in, msg_alt, err ),
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
   // with decoy metadata. (nullifier migration): the real spent
   // inputs stay in the index AND stay decoy-eligible — re-spend is blocked
   // by the nullifier set alone. Griefing by decoy-inclusion is impossible:
   // a ring spend nullifies only the real input's images (a decoy's opening
   // is unknown to the spender), so the decoy owner spends normally.
   // (M05/GC-07): BOTH version legs are nullified (the opening was
   // authorized under both; either leg alone would leave the other spendable).
   const uint8_t alt_version = stealth_alt_proof_version( o.proof_version );
   for( const auto& in : o.inputs )
   {
      db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
         n.key_image = nullifier_key( in.key_image );
         n.proof_version = o.proof_version;
         n.created = db().head_block_time();
      } );
      db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
         n.key_image = nullifier_key( in.alt_key_image );
         n.proof_version = alt_version;
         n.created = db().head_block_time();
      } );
   }
     // (nullifier migration): the whole-ring spent write is retired
      // (griefing section above). A ring spend removes nothing from the
      // index, so it must not reduce the live count either — only the new
      // outputs join it below.
      // DELETED: for every ring member: db().modify( *itr,
      //   []( blinded_balance_object& b ) { b.spent = true; } );
      // DELETED: the coupled stealth_pool_count_add( db(), o.asset_id, -1 ).
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
   // Pool floor counter (live-set semantics): the ring removes
   // nothing from the index, so only the new outputs join the count.
   stealth_pool_count_add( db(), o.asset_id, (int32_t)o.outputs.size() );
   // settle the parity subsidy (pool debit + issuer credit + cap unit),
   // and count the new outputs in the skew histogram window.
   stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                   o.fee.asset_id, (uint32_t)o.outputs.size(),
                                   calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                   std::min( (uint32_t)o.outputs.size(),
                                      stealth_subsidy_output_count( operation( o ) ) ) );
   stealth_window_count_add( db(), (uint32_t)o.outputs.size() );
   stealth_count_blind_op( db() );
   stealth_count_blind_work( db(), stealth_work_for_stealth_transfer( o ) );
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
   const auto member_itr = cidx.find( o.voter );
   FC_ASSERT( member_itr != cidx.end(), "Freeze-blind voter is not a committee member" );
   // GOV-R9-01: committee_member_create is permissionless (op-29, LTM only)
   // and registry rows are never pruned, so registry membership alone is a
   // sybil door into the halt. The stake-elected set is the gate; this check
   // is additive and fail-closed -- the lookup above still identifies the
   // committee_member_object.
   {
      const auto& elected = d.get_global_properties().active_committee_members;
      FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
                 "Freeze-blind voter is registered but not on the elected committee" );
   }
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
      {
         // (SUP-07): the resume quorum is refused while any asset's
         // supply divergence is unresolved — the per-asset halt scope heals
         // asset-by-asset through reconciliation first. The votes stay
         // recorded (they are fresh); a later resume attempt after healing
         // clears without re-voting.
         if( st.diverged_assets.empty() )
            st.blind_halted = false;
      }
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
    // F-01 (R9B): one BP+ output plus the conservation kernel (same excess
    // verifier as a spend, charged the flat kernel allowance).
    // R15 (Step 2): recovery verification adds two batched multiexps
    // (~kernel-class work: measured kernel 471us vs 2048us allowance, so the
    // base allowance's headroom is borderline). the R15 extension is
    // mandatory on every path, so the recovery kernel unit is always charged
    // via the single shared definition below — the do_evaluate gate and the
    // do_apply accounting call the same function and cannot drift (fail-closed
    // direction; no new constant, no wire change).
    stealth_check_blind_work_gate( d, stealth_work_for_turnstile() );
   stealth_check_asset_gate( d, o.asset_id );

   FC_ASSERT( o.fee.asset_id == o.asset_id, "Turnstile fee must be paid in the migrated asset" );
   FC_ASSERT( o.fee.amount >= 0 );
   FC_ASSERT( o.new_proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Turnstile migrates to V2 (the surviving system)" );
   // parity float rule (one new blind output; same skip guard).
   // Rule R: turnstile is circulation (ΔD_a = 0) -> base fee only (n = 1),
   // which is the literal already passed here.
   stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                             o.fee.asset_id, 1,
                             calculate_fee_for_operation( operation( o ) ),
                             std::min( 1u, stealth_subsidy_output_count( operation( o ) ) ) );
   FC_ASSERT( !o.new_output.range_proof.empty(), "Migrated output must carry a range proof" );
   for( const auto& a : o.owner.account_auths )
      a.first( d );
   // A2 (mimo-2.6 re-audit): the STORED migrated owner must resolve too —
   // do_apply writes b.owner = o.new_output.owner, so an unresolvable
   // account reference would brick the output's spend path. Same loop every
   // other blind-output path runs (confidential_evaluator.cpp:46-47; the
   // outputs loop at stealth_evaluator.cpp:518-524). Divergence from
   // o.owner is legitimate (owner-controlled re-key; the OLD authority
   // signed the op), so this validates the new owner in isolation — it is
   // never forced equal to the old one.
   for( const auto& a : o.new_output.owner.account_auths )
      a.first( d );

   // The spent balance must exist with a matching owner.
   const auto& bbi = d.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto itr = bbi.find( o.old_commitment );
   FC_ASSERT( itr != bbi.end(), "Turnstile old commitment is not a live blinded balance" );
   FC_ASSERT( itr->asset_id == o.asset_id, "Turnstile asset mismatch" );
   FC_ASSERT( itr->owner == o.owner, "Turnstile owner mismatch" );
    // R15B-01: cheap new-commitment uniqueness precedes the expensive
    // recovery-proof verification (message identical; refusal order only).
    FC_ASSERT( bbi.find( o.new_output.commitment ) == bbi.end(),
                "Turnstile new commitment already exists" );
    // (nullifier migration): the R15 extension is mandatory on every
    // path. The deleted no-extension branch's only guard was the retired
    // whole-ring spent flag (stopped writing it), so a really-spent
    // output could re-migrate with no proof. op106 is new on this branch
    // (operations.hpp:170), so requiring the extension is replay-safe.
    // The representation proof binds (I1,I2) to old_commitment's opening
    // (F08B-01 class: nothing submitter-supplied is trusted), then the BOUND
    // images are nullifier-checked fail-closed (either present -> refuse).
    // The size assert below is the guard: an extension-less turnstile refuses
    // here with the same text validate() pins (stealth.cpp:132).
    FC_ASSERT( o.extensions.size() == 1, "Turnstile recovery takes one extension" );
    const auto& ext = o.extensions.begin()->get<protocol::turnstile_recovery_v2_extension>();
    // Task-2 note: 163B layout A_C(33)||A_1(33)||A_2(33)||s_b(32)||s_v(32).
    // The verifier re-checks this; the gate pins it for a clean error.
    FC_ASSERT( ext.recovery_proof.proof_bytes.size() == 163,
               "Turnstile recovery proof must be 163 bytes" );
    std::string perr;
    FC_ASSERT( stealth_verify_recovery_proof( o.old_commitment, ext.key_image_v1,
               ext.key_image_v2, ext.recovery_proof.proof_bytes,
               o.asset_id.instance.value, perr ),
               "Turnstile recovery proof does not verify: ${e}", ("e", perr) );
    const auto& nul = d.get_index_type<stealth_nullifier_index>().indices().get<by_nullifier_image>();
    const std::vector<char> r15_i1( ext.key_image_v1.begin(), ext.key_image_v1.end() );
    const std::vector<char> r15_i2( ext.key_image_v2.begin(), ext.key_image_v2.end() );
    FC_ASSERT( nul.find( nullifier_key( r15_i1 ) ) == nul.end(),
               "Turnstile recovery refused: V1 image nullified (really spent)" );
    FC_ASSERT( nul.find( nullifier_key( r15_i2 ) ) == nul.end(),
               "Turnstile recovery refused: V2 image nullified (really spent)" );
   // (R15B-01: the new-commitment uniqueness check now runs above, before
   // the recovery-proof verification.)

   // Conservation over the transparent leg: the blinds are revealed, so
   // C_old - C_new - fee*H must equal (b_old - b_new)*G. This binds the hidden
   // values: any new-value inflation (or fee shortfall) fails the equation.
   {
       // Excess scalar e = b_old - b_new (mod n), from the revealed blinds.
       // AUDIT: this hand-rolled 256-bit modular subtraction must equal the
       // excess the kernel checks exactly; a borrow/carry error here mints
       // or burns value while conservation still passes.
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
         // F-05 (R9A): same claimed-range pin — min_value==0 fail-closed;
         // no max_value floor (narrow proofs are sound; ceiling [0,2^50)
         // rides the verifier's 4096-byte cap).
         FC_ASSERT( min_v == 0, "V1 range proof must claim min_value 0" );
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
   // (nullifier migration, reverts the earlier spent-flag-conditional decrement): the counter measures
   // the LIVE metadata-bearing set, so every consumed metadata-bearing
   // balance leaves it exactly once — unconditionally on had_metadata. The
   // reverted guard (had_metadata && !was_spent) was correct under unspent
   // semantics (a griefed balance had already left at ring-spend time) and
   // is wrong under live semantics (it never left — same drift, inverted).
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
   // Pool floor counter: the consumed balance leaves the live set only if
   // it was counted (grandfathered balances never were); the migrated
   // output always joins it.
   if( had_metadata )
      stealth_pool_count_add( db(), o.asset_id, -1 );
   stealth_pool_count_add( db(), o.asset_id, 1 );
   // parity subsidy settlement + skew histogram (one new output).
   stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                   o.fee.asset_id, 1,
                                   calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                   std::min( 1u, stealth_subsidy_output_count( operation( o ) ) ) );
    stealth_window_count_add( db(), 1 );
    stealth_count_blind_op( db() );
    // mirror the do_evaluate work gate exactly — one shared
    // definition (stealth_work_for_turnstile) so gate and accounting stay
    // in sync.
    stealth_count_blind_work( db(), stealth_work_for_turnstile() );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void turnstile_reproof_evaluator::pay_fee()
{
   generic_evaluator::pay_fee();
}

// ---------------------------------------------------------------------------
// parity economics (BSIP-2 §2)
// ---------------------------------------------------------------------------

namespace {

uint32_t elapsed_intervals( fc::time_point_sec now, fc::time_point_sec since,
                            uint32_t interval_sec )
{
   if( interval_sec == 0 || now <= since )
      return 0;
   uint64_t elapsed = (uint64_t)now.sec_since_epoch() - (uint64_t)since.sec_since_epoch();
   uint64_t n = elapsed / interval_sec;
   return ( n > (uint64_t)0xFFFFFFFFu ) ? 0xFFFFFFFFu : (uint32_t)n;
}

uint32_t parity_subsidized_this_block( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s ) return 0;
   if( s->parity_block_num != db.head_block_num() + 1 )
      return 0;
   return s->parity_subsidized_count;
}

/// Live missed-report count (head-block time only; maintenance persists it).
uint32_t live_missed_reports( const database& db, const stealth_status_object& s )
{
   if( s.last_set_report_time == fc::time_point_sec() )
      return 0; // seeded at activation before any check can run
   return elapsed_intervals( db.head_block_time(), s.last_set_report_time,
                             GRAPHENE_STEALTH_PARITY_REPORT_INTERVAL_SEC );
}

bool live_review_current( const database& db, const stealth_status_object& s )
{
   if( s.last_parity_review_time == fc::time_point_sec() )
      return true; // seeded at activation; only false after a real interval
   return elapsed_intervals( db.head_block_time(), s.last_parity_review_time,
                             GRAPHENE_STEALTH_PARITY_REVIEW_INTERVAL_SEC ) == 0;
}

} // anonymous namespace

namespace {

/// Rule R classifier body (spec 2026-10-10-stealth-entropy-economics §4).
/// Lives at namespace scope because fc::static_variant visits need a
/// result_type and a real (non-local) class. Pure: no db, no state, integer only.
///
/// MODEL (EE-1b, review F-1). This classifies by the live-set effect ΔD_a the
/// chain's OWN counter actually measures — i.e. what each evaluator passes to
/// stealth_pool_count_add — NOT the pre-Task-3 reading of spec §1 in which every
/// op consumes its inputs. The two differ, and the difference is the whole
/// point:
///
///   RING spends consume NOTHING. The Task-3 nullifier migration retired the
///   whole-ring spent write together with its coupled counter decrement
///   (stealth_evaluator.cpp:770-772: "// DELETED: the coupled
///   stealth_pool_count_add( db(), o.asset_id, -1 )."). Ring members therefore
///   stay decoy-eligible by design and ΔD_a = +n_out, whatever the ring size.
///   op104 :792 is the coded witness — `pool_count_add(... outputs.size())` and
///   nothing else. A consolidation-shaped 8-in/8-out ring op therefore GROWS
///   the measured live set by 8, so it must not be capped at 1.
///
///   EXPLICIT spends really do consume: `-spent_counted` at
///   confidential_evaluator.cpp:187 (op41) and stealth_evaluator.cpp:1968
///   (op108), so ΔD_a = n_out - n_in there.
///
/// Reading the counter — not the pre-Task-3 intent — is what keeps the money
/// following the product. It RAISES the cap for consolidation-shaped ring ops
/// relative to the pre-EE-1b classifier, which under-rewarded exactly the ops
/// that grow D_a: the opposite of Rule R's purpose. It is safe because it
/// never moves the FLOOR: both floor legs (stealth_require_blind_fee and
/// stealth_consume_parity_subsidy) keep receiving the op's REAL
/// n_blind_outputs, and stealth_cost_anchor_core is untouched.
struct subsidy_rule_visitor
{
   typedef uint32_t result_type;

   /// Shared shape for the ops that really do consume their inputs: net growth
   /// keeps the full per-output component, circulation falls back to the base
   /// fee. Ring spends pass n_in = 0 because they consume nothing, which makes
   /// this one helper express both models (ring ops reduce to plain n_out).
   static uint32_t net_rule( uint32_t n_out, uint32_t n_in )
   {
      if( n_out > n_in )
         return n_out;                 // net growth: full component
      return n_out < 1u ? 0u : 1u;     // circulation: base fee only
   }

   /// op39 transfer_to_blind (deposit): ΔD_a = +n, the only net source of
   /// value into the blind set — full per-output component preserved.
   uint32_t operator()( const protocol::transfer_to_blind_operation& o ) const
   {
      return (uint32_t)o.outputs.size();
   }

   /// op41 transfer_from_blind (exit): an EXPLICIT spend, so net_rule with the
   /// op's real inputs; but the op carries NO blind outputs member at all, so
   /// n_out is 0 and the circulation branch collapses to 0 — preserving the
   /// literal `0` the call site has always passed
   /// (confidential_evaluator.cpp:159/:190).
   uint32_t operator()( const protocol::transfer_from_blind_operation& o ) const
   {
      return net_rule( 0u, (uint32_t)o.inputs.size() );
   }

   /// op40 blind_transfer: a RING spend — consumes nothing (:769-771), so
   /// ΔD_a = +n_out and inputs are deliberately NOT consulted.
   uint32_t operator()( const protocol::blind_transfer_operation& o ) const
   {
      return net_rule( (uint32_t)o.outputs.size(), 0u );
   }

   /// op104 stealth_transfer: same RING model, same counter site (:791).
   uint32_t operator()( const protocol::stealth_transfer_operation& o ) const
   {
      return net_rule( (uint32_t)o.outputs.size(), 0u );
   }

   /// op106 turnstile_reproof: exactly one migrated output (singular member),
   /// and its counter nets zero (-1/+1 at :1069-1071). n_out = 1 is the same
   /// answer under either model.
   uint32_t operator()( const protocol::turnstile_reproof_operation& ) const
   {
      return 1;
   }

   /// op108 stealth_explicit_spend: an EXPLICIT spend — it DOES consume its
   /// metadata-bearing inputs (-spent_counted, :1924), so this is the one
   /// non-ring op that uses net_rule with real inputs. net > 0 is real live-set
   /// growth and keeps the full component; net <= 0 is circulation and falls
   /// back to the base fee (the intentional conservatism of review F-2 — do
   /// not widen it to full subsidy); the exit leg has no outputs at all -> 0.
   uint32_t operator()( const protocol::stealth_explicit_spend_operation& o ) const
   {
      return net_rule( (uint32_t)o.outputs.size(), (uint32_t)o.inputs.size() );
   }

   /// op109 stealth_pool_exchange: a RING spend (the input is ring membership,
   /// so nothing is removed — :2317-2319 adds only the counter-asset output),
   /// 1-in/1-out BY SOUNDNESS (singular input/output members, not vectors), so
   /// n_out = 1 and the circulation result is 1 either way.
   uint32_t operator()( const protocol::stealth_pool_exchange_operation& ) const
   {
      return 1;
   }

   /// Every other op fails CLOSED: no subsidy, never a grant.
   template<typename Op>
   uint32_t operator()( const Op& ) const { return 0; }
};

} // anonymous namespace

uint32_t stealth_subsidy_output_count( const protocol::operation& op )
{
   // Rule R selects the output count the SUBSIDY gap may be computed on by
   // the op's effect on the live anonymity set D_a (spec §1 table) — NOT by
   // its being a blind op (finding F-01). Since EE-1b that effect is read off
   // the chain's own live-set counter (see subsidy_rule_visitor's MODEL note:
   // ring spends consume nothing at :769-771, explicit spends do at :1924),
   // not off the pre-Task-3 "every op consumes its inputs" assumption. The
   // caller still passes min(n_blind_outputs, result); this never raises a
   // call site's own n and never touches stealth_cost_anchor_core, so no
   // user's fee floor moves.
   subsidy_rule_visitor v;
   return op.visit( v );
}

bool stealth_window_dominant( const stealth_depositor_window& w,
                              account_id_type acct, uint32_t ring_target )
{
   if( w.count < protocol::GRAPHENE_STEALTH_DEPOSITOR_WINDOW )
      return false; // cold window: inclusion beats discipline (spec §9)
   flat_map<account_id_type, uint64_t> acc; // ORDERED, deterministic
   for( const auto& kv : w.events )
      acc[ kv.second.account ] += kv.second.n;
   uint64_t base = 0;
   for( const auto& kv : acc )
      base += kv.second;
   const auto it = acc.find( acct );
   const uint64_t mine = ( it == acc.end() ) ? 0 : it->second;
   return fc::uint128_t( mine ) * ring_target > base; // strict: exactly 1/16 → false
}

uint32_t stealth_op39_subsidy_count( const database& db, asset_id_type asset,
                                     account_id_type depositor,
                                     const protocol::operation& op )
{
   const uint32_t cls = stealth_subsidy_output_count( op );
   const auto* s = find_stealth_status( db );
   if( !s )
      return cls;
   const auto it = s->deposit_windows.find( asset );
   if( it == s->deposit_windows.end() )
      return cls;
   if( stealth_window_dominant( it->second, depositor,
                                protocol::GRAPHENE_STEALTH_RING_TARGET ) )
      return 1u;
   return cls;
}

share_type stealth_cost_anchor_core( const database& db, uint32_t n_blind_outputs )
{
   // G3-01: the current-schedule leg is derived through
   // fee_schedule.calculate_fee on a synthetic transfer_to_blind leg with
   // the same output count, so the committee scale factor applies here
   // exactly as it does to parity_core (which reaches the float rule via
   // calculate_fee_for_operation). Reading raw k39.fee/ppo ignored scale
   // and let the two legs diverge under repricing. The pinned and snapshot
   // legs stay unscaled by design: they are historical/constant floors on
   // the anchor, while live scale moves current + parity together; max()
   // keeps the higher. (Snapshot edge: a non-100% scale AT activation is
   // not captured in the stored raw params, understating the floor — the
   // fail-closed direction for subsidies.)
   protocol::transfer_to_blind_operation synth;
   synth.outputs.resize( n_blind_outputs );
   share_type current_leg =
      db.current_fee_schedule().calculate_fee( protocol::operation( synth ) ).amount;
   fc::uint128_t current( current_leg.value );
   fc::uint128_t pinned( protocol::GRAPHENE_STEALTH_ANCHOR_BASE_FEE );
   pinned += fc::uint128_t( protocol::GRAPHENE_STEALTH_ANCHOR_PRICE_PER_OUTPUT )
             * n_blind_outputs;
   fc::uint128_t anchored = current;
   if( pinned > anchored )
      anchored = pinned;
   // Activation snapshot of the same schedule (0 when the schedule was
   // zeroed at activation, e.g. test genesis — then pinned/current govern).
   const auto* s = find_stealth_status( db );
   if( s != nullptr )
   {
      fc::uint128_t snap( s->activation_k39_fee );
      snap += fc::uint128_t( s->activation_k39_ppo ) * n_blind_outputs;
      if( snap > anchored )
         anchored = snap;
   }
   FC_ASSERT( anchored <= GRAPHENE_MAX_SHARE_SUPPLY, "Stealth cost anchor overflow" );
   return share_type( static_cast<int64_t>( anchored ) );
}

share_type stealth_cost_floor_core( const database& db, uint32_t n_blind_outputs )
{
   // Pinned constant leg (historical floor, unmoved by any fee vote).
   fc::uint128_t floored( protocol::GRAPHENE_STEALTH_ANCHOR_BASE_FEE );
   floored += fc::uint128_t( protocol::GRAPHENE_STEALTH_ANCHOR_PRICE_PER_OUTPUT )
              * n_blind_outputs;
   // Activation snapshot leg (history, not live politics).
   const auto* s = find_stealth_status( db );
   if( s != nullptr )
   {
      fc::uint128_t snap( s->activation_k39_fee );
      snap += fc::uint128_t( s->activation_k39_ppo ) * n_blind_outputs;
      if( snap > floored )
         floored = snap;
   }
   FC_ASSERT( floored <= GRAPHENE_MAX_SHARE_SUPPLY, "Stealth cost floor overflow" );
   return share_type( static_cast<int64_t>( floored ) );
}

share_type stealth_parity_gap_core( const database& db, uint32_t n_blind_outputs,
                                    share_type parity_core, uint32_t subsidy_n )
{
   // Rule R: the DISCOUNT is capped at subsidy_n outputs; the FLOOR (below,
   // and in require/consume) keeps the op's real n_blind_outputs. min() makes
   // the cap monotonic — subsidy_n above n is a no-op, never a raise.
   const uint32_t n = ( subsidy_n < n_blind_outputs ) ? subsidy_n : n_blind_outputs;
   share_type cost = stealth_cost_anchor_core( db, n );
   if( cost <= parity_core )
      return share_type( 0 );
   return cost - parity_core;
}

share_type stealth_gap_to_asset( const database& db, asset_id_type fee_asset,
                                 share_type gap_core )
{
   // G4-01: negative gaps fail closed here (defense-in-depth). Production
   // callers (stealth_parity_available, stealth_consume_parity_subsidy) check
   // gap_core <= 0 first, so this fires only on direct/future misuse — but
   // the CORE fast path below would otherwise return a negative amount
   // ungated, while the UIA path wraps to uint64 and trips the overflow
   // assert. One explicit gate keeps both legs fail-closed identically.
   FC_ASSERT( gap_core.value >= 0, "Stealth gap conversion needs a non-negative gap" );
   if( gap_core.value == 0 )
      return share_type( 0 );
   if( fee_asset == asset_id_type() )
      return gap_core;
   const auto& cer = fee_asset( db ).options.core_exchange_rate;
   // G4-01: price::validate checks both CER legs at issue/update time, but
   // consensus must not trust stored state — a zero base converts every gap
   // to 0 (free subsidy: the pool is never debited). The quote leg was
   // already gated; the base leg was not. Both pinned here.
   FC_ASSERT( cer.base.amount.value > 0, "Stealth gap conversion needs a valid CER" );
   FC_ASSERT( cer.quote.amount.value > 0, "Stealth gap conversion needs a valid CER" );
   // X = ceil(gap_core * base / quote): the pool never under-debits.
   // Integer only (no floats); 128-bit headroom for supply-scale amounts.
   // Scale note: this conversion is scale-independent (CER, not fee scale).
   // The fee-scale snapshot edge lives in stealth_cost_anchor_core above: the
   // activation snapshot stores RAW k39 fee/ppo, so a non-100% scale AT
   // activation understates the snapshot floor. Fail-closed direction (a
   // lower anchor shrinks gaps/subsidies, never inflates them); live scale
   // moves current + parity together (scale-together: 100% -> parity 500000 /
   // anchor 600000 / gap 100000; 200% -> 1000000 / 1200000 / 200000).
   fc::uint128_t r( (uint64_t)gap_core.value );
   r *= (uint64_t)cer.base.amount.value;
   r += (uint64_t)cer.quote.amount.value - 1;
   r /= (uint64_t)cer.quote.amount.value;
   FC_ASSERT( r <= GRAPHENE_MAX_SHARE_SUPPLY, "Stealth gap conversion overflow" );
   return share_type( static_cast<int64_t>( r ) );
}

bool stealth_parity_available( const database& db, asset_id_type fee_asset,
                               share_type gap_core )
{
   if( !stealth_passed( db ) )
      return false;
   if( gap_core.value <= 0 )
      return false; // no discount granted: nothing to subsidize
   const auto* s = find_stealth_status( db );
   if( !s )
      return false;
   if( s->blind_halted )
      return false;
    // R-05 + G3-03: 80% burn-critical halts NEW subsidies
    // by rule — was signal-only, so a drain proceeded while the alarm
    // watched. Existing grants keep paying until empty; only new subsidy
    // availability gates here.
    //
    // G3-03 lag window (honest scope): burn_critical is recomputed ONLY in
    // stealth_parity_maintenance from the per-interval routed/granted flow
    // (snapshot semantics between maintenances). Inside one interval the
    // drain proceeds unhalted at up to
    // GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK (50) subsidized ops
    // per block — the per-block cap, not this flag, bounds the intra-window
    // burn. The flag then refuses new subsidies until a later maintenance
    // recomputes worst below 80% (auto-clear with fresh routed/granted
    // flow); the cost-anchor path always clears, so the halt never bricks
    // blind traffic, only its subsidy.
    if( s->alarms.burn_critical )
       return false;
   if( !live_review_current( db, *s ) )
      return false; // missed 6-month review: cost-mode by rule
   // Missed quarterly reports halt FUNDING (routing) only — the pool keeps
   // paying until empty (BSIP-2 §2). Subsidies must NOT gate on reports:
   // otherwise a funded pool could never serve its purpose while reporting
   // lapses, and no single-member parity review could re-arm it. The
   // funding halt lives in stealth_parity_route_fee + parity_funding_halted.
   if( parity_subsidized_this_block( db ) >= GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK )
      return false;
   share_type gap_asset = stealth_gap_to_asset( db, fee_asset, gap_core );
   auto itr = s->parity_pool.find( fee_asset );
   share_type balance = ( itr == s->parity_pool.end() ) ? share_type( 0 ) : itr->second;
   return balance >= gap_asset;
}

void stealth_require_blind_fee( const database& db, share_type core_fee_paid,
                                bool fees_enforced, asset_id_type fee_asset,
                                uint32_t n_blind_outputs, share_type parity_core,
                                uint32_t subsidy_n )
{
   if( !stealth_passed( db ) || !fees_enforced )
      return;
   share_type gap = stealth_parity_gap_core( db, n_blind_outputs, parity_core,
                                             subsidy_n );
   if( stealth_parity_available( db, fee_asset, gap ) )
      return; // subsidized: the central schedule check enforces parity level
   // Pool-empty / cap-hit / review-missed: blind fees float to cost.
   // Deterministic rule from the public schedule — no committee action here.
   // NOTE the REAL n_blind_outputs: Rule R caps the discount, never the floor.
   share_type cost = stealth_cost_floor_core( db, n_blind_outputs );
   FC_ASSERT( core_fee_paid >= cost,
              "Blind fee below cost level (parity pool cannot subsidize: "
              "pool empty, subsidy cap hit, or review/report missed)" );
}

void stealth_consume_parity_subsidy( database& db, bool fees_enforced,
                                     asset_id_type fee_asset,
                                     uint32_t n_blind_outputs,
                                     share_type parity_core,
                                     share_type core_fee_paid,
                                     uint32_t subsidy_n )
{
   if( !stealth_passed( db ) || !fees_enforced )
      return;
   // Same (n_blind_outputs, subsidy_n) derivation as do_evaluate's require, so
   // the debit can never exceed what the require admitted (mirror exactly;
   // a drained pool still fails closed on the availability assert below).
   share_type gap = stealth_parity_gap_core( db, n_blind_outputs, parity_core,
                                             subsidy_n );
   if( gap.value <= 0 )
      return;
   // Real n_blind_outputs: an op that paid the full anchor is never debited.
   share_type cost = stealth_cost_floor_core( db, n_blind_outputs );
   if( core_fee_paid >= cost )
      return; // cost path: user paid the anchor level, no discount granted
   // Parity path: the discount MUST be covered now (fail-closed: a cap unit
   // filled between do_evaluate and do_apply turns this into a throw —
   // the op underpaid the cost level it now falls under).
   FC_ASSERT( stealth_parity_available( db, fee_asset, gap ),
              "Parity subsidy no longer available at apply time" );
   share_type gap_asset = stealth_gap_to_asset( db, fee_asset, gap );
   const auto& dyn = fee_asset( db ).dynamic_asset_data_id( db );
   db.modify( dyn, [&]( asset_dynamic_data_object& o ) {
      o.accumulated_fees += gap_asset;
   } );
   const auto& s = get_or_create_stealth_status( db );
   uint32_t pending = db.head_block_num() + 1;
   db.modify( s, [&]( stealth_status_object& o ) {
      auto itr = o.parity_pool.find( fee_asset );
      FC_ASSERT( itr != o.parity_pool.end() && itr->second >= gap_asset,
                 "Parity pool underflow at apply time" );
      itr->second -= gap_asset;
      if( itr->second == share_type( 0 ) )
         o.parity_pool.erase( fee_asset );
      auto gitr = o.interval_granted.find( fee_asset );
      if( gitr == o.interval_granted.end() )
         o.interval_granted[ fee_asset ] = gap_asset;
      else
         gitr->second += gap_asset;
      if( o.parity_block_num != pending )
      {
         o.parity_block_num = pending;
         o.parity_subsidized_count = 0;
      }
      ++o.parity_subsidized_count;
   } );
}

share_type stealth_parity_route_fee( database& db, asset_id_type recv_asset,
                                     share_type& inout_increment )
{
   if( !stealth_passed( db ) )
      return share_type( 0 );
   if( inout_increment.value <= 0 )
      return share_type( 0 );
   // legacy gate (GP-01/GP-02): no opt-in, no diversion, ever. The
   // increment is untouched, so the caller credits 100% to accumulated_fees.
   // Checked before any state access: legacy assets never dirty undo state.
   if( !parity_fee_share_opted_in( db, recv_asset ) )
      return share_type( 0 );
   // The routed share of any single fee trivially fits the joint ceiling at
   // the proposal share (500bps << 7000bps); the assert pins that bound so a
   // future constant change that breaks it fails loudly, not silently.
   {
      fc::uint128_t cap_bound( (uint64_t)inout_increment.value );
      cap_bound *= GRAPHENE_STEALTH_JOINT_FEE_CAP_BPS;
      cap_bound /= 10000;
      fc::uint128_t share( (uint64_t)inout_increment.value );
      share *= GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS;
      share /= 10000;
      FC_ASSERT( share <= cap_bound, "Parity fee share exceeds joint ceiling" );
   }
   const auto& s = get_or_create_stealth_status( db );
   if( live_missed_reports( db, s ) >= 2 )
      return share_type( 0 ); // funding halted until reporting resumes
   fc::uint128_t r( (uint64_t)inout_increment.value );
   r *= GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS;
   r /= 10000;
   FC_ASSERT( r <= GRAPHENE_MAX_SHARE_SUPPLY );
   share_type routed( static_cast<int64_t>( r ) );
   if( routed.value == 0 )
      return routed; // dust: don't dirty undo state
   db.modify( s, [&]( stealth_status_object& o ) {
      auto itr = o.parity_pool.find( recv_asset );
      if( itr == o.parity_pool.end() )
         o.parity_pool[ recv_asset ] = routed;
      else
         itr->second += routed;
      auto ritr = o.interval_routed.find( recv_asset );
      if( ritr == o.interval_routed.end() )
         o.interval_routed[ recv_asset ] = routed;
      else
         ritr->second += routed;
   } );
   inout_increment -= routed;
   return routed;
}

bool stealth_joint_fee_within_cap( uint32_t parity_share_bps, uint32_t h2_diversion_bps )
{
   uint64_t joint = (uint64_t)parity_share_bps + (uint64_t)h2_diversion_bps;
   return joint <= (uint64_t)GRAPHENE_STEALTH_JOINT_FEE_CAP_BPS;
}

void stealth_window_count_add( database& db, uint32_t n )
{
   if( !stealth_passed( db ) || n == 0 )
      return;
   const auto& s = get_or_create_stealth_status( db );
   uint32_t window = ( db.head_block_num() + 1 ) / GRAPHENE_STEALTH_SKEW_WINDOW_BLOCKS;
   db.modify( s, [&]( stealth_status_object& o ) {
      auto itr = o.blind_window_counts.find( window );
      if( itr == o.blind_window_counts.end() )
         o.blind_window_counts[ window ] = n;
      else
         itr->second += n;
   } );
}

void stealth_parity_maintenance( database& db )
{
   if( !stealth_passed( db ) )
      return;
   stealth_maybe_record_activation( db );
   const auto& s = get_or_create_stealth_status( db );
   fc::time_point_sec now = db.head_block_time();
   fc::time_point_sec activated = ( s.stealth_activated_time == fc::time_point_sec() )
      ? HARDFORK_STEALTH_TIME : s.stealth_activated_time;
   db.modify( s, [&]( stealth_status_object& o ) {
      if( o.last_parity_review_time == fc::time_point_sec() )
         o.last_parity_review_time = activated;
      if( o.last_set_report_time == fc::time_point_sec() )
         o.last_set_report_time = activated;
      // Missed counts recomputed as whole elapsed intervals (replay-safe).
      o.missed_parity_reviews = elapsed_intervals( now, o.last_parity_review_time,
            GRAPHENE_STEALTH_PARITY_REVIEW_INTERVAL_SEC );
      o.missed_set_reports = elapsed_intervals( now, o.last_set_report_time,
            GRAPHENE_STEALTH_PARITY_REPORT_INTERVAL_SEC );
      o.parity_funding_halted = ( o.missed_set_reports >= 2 );
      // Burn ratio: worst per-asset interval grant/route percent.
      uint32_t worst = 0;
      for( const auto& kv : o.interval_granted )
      {
         share_type granted = kv.second;
         if( granted.value <= 0 )
            continue;
         auto ritr = o.interval_routed.find( kv.first );
         share_type routed = ( ritr == o.interval_routed.end() )
                             ? share_type( 0 ) : ritr->second;
         uint32_t pct;
         if( routed.value <= 0 )
            pct = 100;
         else
         {
            fc::uint128_t p( (uint64_t)granted.value );
            p *= 100;
            p /= (uint64_t)routed.value;
            pct = ( p > 0xFFFFFFFFu ) ? 0xFFFFFFFFu : (uint32_t)p;
         }
         if( pct > worst )
            worst = pct;
      }
      // SUP-R-10 (CDR-10/CDR-11): append the per-interval flow to
      // the cumulative counters BEFORE clearing. Never cleared: the flow
      // series is now retrievable from chain state (get_objects), closing
      // the E0-measurability gap. Zero entries are not written (sparse).
      for( const auto& kv : o.interval_routed )
      {
         if( kv.second.value == 0 )
            continue;
         auto citr = o.cumulative_routed.find( kv.first );
         if( citr == o.cumulative_routed.end() )
            o.cumulative_routed[ kv.first ] = kv.second;
         else
            citr->second += kv.second;
      }
      for( const auto& kv : o.interval_granted )
      {
         if( kv.second.value == 0 )
            continue;
         auto citr = o.cumulative_granted.find( kv.first );
         if( citr == o.cumulative_granted.end() )
            o.cumulative_granted[ kv.first ] = kv.second;
         else
            citr->second += kv.second;
      }
      o.interval_routed.clear();
      o.interval_granted.clear();
      o.alarms.burn_rate_pct = worst;
      o.alarms.burn_warn = ( worst >= GRAPHENE_STEALTH_PARITY_BURN_WARN_PCT );
      o.alarms.burn_critical = ( worst >= GRAPHENE_STEALTH_PARITY_BURN_CRITICAL_PCT );
      // Skew: prune to the newest 301 windows, then compare the youngest
      // window's share against the 40% tolerance (integer math, no floats).
      uint32_t cur = db.head_block_num() / GRAPHENE_STEALTH_SKEW_WINDOW_BLOCKS;
      while( o.blind_window_counts.size() > GRAPHENE_STEALTH_SKEW_WINDOWS_KEPT )
         o.blind_window_counts.erase( o.blind_window_counts.begin() );
      uint64_t total = 0;
      for( const auto& kv : o.blind_window_counts )
         total += kv.second;
      uint64_t young = 0;
      {
         auto yitr = o.blind_window_counts.find( cur );
         if( yitr != o.blind_window_counts.end() )
            young = yitr->second;
      }
      o.alarms.decoy_skew_warn = ( total > 0 && young * 100 > total * 40 );
      // Effective set: live copy of the decoy-candidate counters.
      o.alarms.effective_set = o.unspent_blind_count;
      // Thin-pool warning (): any asset below the warn depth arms it.
      // ALARM ONLY — nothing in consensus asserts on this flag (the pool
      // floor gate, not this flag, halts; deposits are never gated by it).
      {
         bool thin_warn = false;
         for( const auto& kv : o.unspent_blind_count )
            if( kv.second < GRAPHENE_STEALTH_POOL_WARN_DEPTH )
            {
               thin_warn = true;
               break;
            }
         o.alarms.thin_pool_warn = thin_warn;
      }
      // Mass exit: halted, or any fresh freeze vote live (no mutation here).
      bool exit_warn = o.blind_halted;
      if( !exit_warn )
         for( const auto& kv : o.freeze_votes )
            if( stealth_vote_fresh( now, kv.second.voted_at ) )
            {
               exit_warn = true;
               break;
            }
      o.alarms.mass_exit_warn = exit_warn;
      // Joint ceiling: parity share + recorded H2 diversion on the shared
      // denominator. Signal only (routing must never brick on H2's numbers).
      o.alarms.joint_cap_breach = !stealth_joint_fee_within_cap(
            GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS, o.h2_diversion_bps );
   } );
}

void stealth_record_parity_review( database& db, uint8_t kind, account_id_type voter )
{
   // G3-04: unknown kinds must never be recorded as parity (the old
   // else-branch did exactly that, with only relay-side validate() gating).
   // Consensus asserts 0/1 here AND in parity_review_evaluator::do_apply so
   // a proposal-embedded op 107 with a bad kind fails closed at apply time.
   FC_ASSERT( kind == GRAPHENE_STEALTH_REVIEW_PARITY ||
               kind == GRAPHENE_STEALTH_REVIEW_SET_REPORT,
               "Unknown parity review kind" );
   if( !stealth_passed( db ) )
      return;
   const auto& s = get_or_create_stealth_status( db );
   fc::time_point_sec now = db.head_block_time();
   db.modify( s, [&]( stealth_status_object& o ) {
      // quorum: a lone attestation is recorded as PENDING only.
      // Prune stale pendings (bounded by committee size), record this one
      // (latest wins per member), then count DISTINCT fresh members for the
      // same kind — the clocks move only at quorum (2).
      flat_map<account_id_type, stealth_parity_vote> kept;
      for( const auto& kv : o.pending_parity_votes )
      {
         uint32_t age = ( now.sec_since_epoch() > kv.second.voted_at.sec_since_epoch() )
            ? (uint32_t)( now.sec_since_epoch() - kv.second.voted_at.sec_since_epoch() ) : 0;
         if( age <= GRAPHENE_STEALTH_PARITY_ATTEST_EXPIRY_SEC )
            kept[ kv.first ] = kv.second;
      }
      stealth_parity_vote v;
      v.voter = voter;
      v.kind = kind;
      v.voted_at = now;
      kept[ voter ] = v;
      o.pending_parity_votes = kept;
      uint32_t distinct = 0;
      for( const auto& kv : kept )
         if( kv.second.kind == kind )
            ++distinct;
      if( distinct < GRAPHENE_STEALTH_PARITY_QUORUM_REQUIRED )
         return; // single-member attestation: pending, clocks untouched
      // Quorum reached: move the clock, clear this kind's pendings (they
      // are spent — a third attestation starts a fresh pending, never a
      // free second quorum).
      if( kind == GRAPHENE_STEALTH_REVIEW_SET_REPORT )
      {
         o.last_set_report_time = now;
         o.missed_set_reports = 0;
         o.parity_funding_halted = false;
      }
      else
      {
         o.last_parity_review_time = now;
         o.missed_parity_reviews = 0;
      }
      flat_map<account_id_type, stealth_parity_vote> rest;
      for( const auto& kv : kept )
         if( kv.second.kind != kind )
            rest[ kv.first ] = kv.second;
      o.pending_parity_votes = rest;
   } );
}

stealth_alarm_snapshot stealth_current_alarms( const database& db )
{
   const auto* s = find_stealth_status( db );
   if( !s )
      return stealth_alarm_snapshot();
   return s->alarms;
}

// ---------------------------------------------------------------------------
// parity_review (committee heartbeat for reviews/reports; works while halted)
// ---------------------------------------------------------------------------

void_result parity_review_evaluator::do_evaluate( const parity_review_operation& o )
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Parity reviews are not allowed until the stealth hardfork" );
   // G4-02: kind gate in do_evaluate (mirrors do_apply below and the record
   // helper) so a bad kind fails fast at mempool/proposal-create instead of a
   // late block failure. validate() is relay-side only and proposal-embedded
   // ops bypass it; the consensus boundary must gate the kind itself.
   FC_ASSERT( o.kind == GRAPHENE_STEALTH_REVIEW_PARITY ||
              o.kind == GRAPHENE_STEALTH_REVIEW_SET_REPORT,
              "Unknown parity review kind" );
   const auto& cidx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = cidx.find( o.voter );
   FC_ASSERT( member_itr != cidx.end(), "Parity review voter is not a committee member" );
   // GOV-R9-01: a parity attestation moves the review clocks and permits (never
   // spends) subsidies, so a permissionless registry row must not be a
   // mandate. Only the elected set attests; additive and fail-closed, the
   // registry lookup above is retained.
   {
      const auto& elected = d.get_global_properties().active_committee_members;
      FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
                 "Parity review voter is registered but not on the elected committee" );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result parity_review_evaluator::do_apply( const parity_review_operation& o )
{ try {
   // G3-04: kind gate in consensus (validate() runs on relays and is not
   // the consensus boundary for proposal-embedded ops).
   FC_ASSERT( o.kind == GRAPHENE_STEALTH_REVIEW_PARITY ||
               o.kind == GRAPHENE_STEALTH_REVIEW_SET_REPORT,
               "Unknown parity review kind" );
   stealth_record_parity_review( db(), o.kind, o.voter );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

// ---------------------------------------------------------------------------
// stealth_explicit_spend (op108: proof-first double-spend guard, two legs)
// ---------------------------------------------------------------------------

void_result stealth_explicit_spend_evaluator::do_evaluate( const stealth_explicit_spend_operation& o )
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Explicit stealth spends are not allowed until the stealth hardfork" );
   stealth_check_blind_gate( d );
   // One kernel-class verification per input's recovery proof (163B, two
   // multiexps). Turnstile charges GRAPHENE_STEALTH_WORK_US_PER_KERNEL
   // per recovery proof at :870; op108 has up to 8 inputs, so charge per input.
   // Plus ONE base kernel unit for the conservation check itself (verify_sum
   // or stealth_verify_excess) — the ring's calculator includes this base
   // (stealth_evaluator.cpp:331-344 starts at GRAPHENE_STEALTH_WORK_US_PER_KERNEL) and
   // omitting it undercharges the blind->blind leg's excess verification.
   // Use the shared calculator so the gate and the accounting cannot drift;
   // it saturates like stealth_work_for_stealth_transfer (see Step 3a).
   stealth_check_blind_work_gate( d, stealth_work_for_explicit_spend( o ) );
   stealth_check_asset_gate( d, o.fee.asset_id );

   // validate() is relay-side only and proposal-embedded ops bypass it, so the
   // evaluator re-asserts everything it depends on. Ring does the same at
   // stealth_evaluator.cpp:479-497.
   FC_ASSERT( o.fee.asset_id == o.asset_id, "Explicit spend fee must be paid in the spent asset" );
   FC_ASSERT( o.fee.amount >= 0, "Explicit spend fee cannot be negative" );
   FC_ASSERT( !o.inputs.empty(), "Explicit spend needs at least one input" );
   FC_ASSERT( o.inputs.size() <= 8, "Explicit spend input count out of bounds" );
   // Proposal-bypass re-assert of the output bound (ring :491-492).
   // No !empty — the exit leg is zero outputs by construction.
   FC_ASSERT( o.outputs.size() <= 8, "Explicit spend output count out of bounds" );
   FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Unknown proof version" );
   // parity float rule — every other blind op calls this in do_evaluate
   // (ring :488, turnstile :879, op41 :145, op40 :225, op39 :63). Without it
   // op108 bypasses the fee-parity floor while still calling
    // stealth_consume_parity_subsidy in do_apply — a half-wired parity rule.
   // Rule R (EE-1b): op108 is an EXPLICIT spend, so it DOES consume its
   // metadata-bearing inputs — net > 0 (a real split) keeps the full
   // per-output component, net <= 0 falls back to the base fee, and the exit
   // leg has no outputs at all (no subsidy).
    stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                              o.fee.asset_id, (uint32_t)o.outputs.size(),
                              calculate_fee_for_operation( operation( o ) ),
                              std::min( (uint32_t)o.outputs.size(),
                                 stealth_subsidy_output_count( operation( o ) ) ) );

   // V1 sunset, mirroring the ring at :495-497. Without this a V1 op108 past
   // sunset would mint fresh V1-range-proven outputs, defeating the sunset.
   if( d.head_block_time() >= stealth_v1_sunset_time( d ) )
      FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
                 "V1 explicit spends are frozen past sunset (use turnstile re-proof)" );

   const auto& bbi = d.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   const auto& nul = d.get_index_type<stealth_nullifier_index>().indices().get<by_nullifier_image>();

   // Outputs must be fresh and range-proven under the op version.
   // Shared error string mirrors the ring path (stealth_evaluator.cpp:525):
   // the V1 branch must NOT reference an `e` that only exists in the else-arm.
   {
      std::string err;
      for( const auto& out : o.outputs )
      {
         FC_ASSERT( bbi.find( out.commitment ) == bbi.end(), "Stealth output commitment already exists" );
         for( const auto& a : out.owner.account_auths ) a.first( d );
         if( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 )
         {
            uint64_t min_v = 0, max_v = 0;
            std::vector<char> proof( out.range_proof.begin(), out.range_proof.end() );
            FC_ASSERT( stealth_verify_range_v1( out.commitment, proof, min_v, max_v ),
                       "V1 range proof does not verify", ("min_v", min_v) );
            FC_ASSERT( min_v == 0, "V1 range proof must claim min_value 0" );
         }
         else
         {
            std::vector<char> proof( out.range_proof.begin(), out.range_proof.end() );
            std::vector<fc::ecc::commitment_type> cs = { out.commitment };
            FC_ASSERT( stealth_verify_bp_plus( 1, proof, cs, err ),
                       "V2 range proof does not verify: ${e}", ("e", err) );
         }
      }
   }

   // ---- PER-INPUT GATES. ORDER IS THE SECURITY PROPERTY. ----
   for( const auto& in : o.inputs )
   {
      auto itr = bbi.find( in.commitment );
      FC_ASSERT( itr != bbi.end(), "Explicit spend: commitment not a live blind balance" );
      FC_ASSERT( itr->asset_id == o.asset_id, "Explicit spend: input asset mismatch" );
      FC_ASSERT( itr->owner == in.owner, "Explicit spend: input owner mismatch" );

      // (3a) PROOF FIRST. Establishes the supplied images ARE this
      // commitment's opening. Skipping or reordering this step is a double
      // spend — see design spec §3.2a.
      std::string rerr;
      FC_ASSERT( stealth_verify_recovery_proof( in.commitment, in.key_image_v1,
                 in.key_image_v2, in.recovery_proof.proof_bytes,
                 o.asset_id.instance.value, rerr ),
                 "Explicit spend recovery proof does not verify: ${e}", ("e", rerr) );

      // (3b) THEN nullifier absence, both version legs. nullifier_key takes
      // const std::vector<char>& (:100-106); commitment_type is
      // zero_initialized_array<unsigned char,33> and does NOT implicitly
      // convert. Convert explicitly, mirroring the turnstile at :929-930.
      {
         const std::vector<char> i1( in.key_image_v1.begin(), in.key_image_v1.end() );
         const std::vector<char> i2( in.key_image_v2.begin(), in.key_image_v2.end() );
         FC_ASSERT( nul.find( nullifier_key( i1 ) ) == nul.end(),
                    "Explicit spend refused: V1 image nullified (really spent)" );
         FC_ASSERT( nul.find( nullifier_key( i2 ) ) == nul.end(),
                    "Explicit spend refused: V2 image nullified (really spent)" );
      }
   }

   // Duplicate commitment within one op would double-remove an index entry.
   for( size_t a = 0; a < o.inputs.size(); ++a )
      for( size_t b = a + 1; b < o.inputs.size(); ++b )
         FC_ASSERT( o.inputs[a].commitment != o.inputs[b].commitment,
                    "Duplicate commitment within explicit spend" );

   // Conservation — TWO KERNELS, one per leg. The transparent exit CANNOT use
   // stealth_verify_excess (it rejects an empty outs vector at
   // stealth_proof.cpp:760 and the exit has no output commitment by
   // construction), so it uses op41's verify_sum against
   // blind(excess, fee + amount) — confidential.cpp:80-89.
   {
      std::vector<fc::ecc::commitment_type> in_cs;
      in_cs.reserve( o.inputs.size() );
      for( const auto& in : o.inputs )
         in_cs.push_back( in.commitment );

      if( o.outputs.empty() )
      {
         // Transparent exit. op41's kernel: the public amount is committed on
         // the output side together with the fee. verify_sum, NOT
         // stealth_verify_excess — the latter rejects an empty outs vector
         // (stealth_proof.cpp:760) and this leg has none by construction.
         FC_ASSERT( o.to != account_id_type(), "transparent exit needs a destination" );
         // validate() checks these too, but proposals bypass validate — re-assert.
         FC_ASSERT( o.amount.asset_id == o.asset_id, "exit amount asset must match asset_id" );
         FC_ASSERT( o.amount.amount > 0, "transparent exit requires a positive amount" );
         std::vector<fc::ecc::commitment_type> out_cs;
         out_cs.push_back( fc::ecc::blind( o.excess,
                                           o.fee.amount.value + o.amount.amount.value ) );
         FC_ASSERT( fc::ecc::verify_sum( in_cs, out_cs, 0 ),
                    "Explicit spend conservation mismatch (exit leg)" );
      }
      else
      {
         // Blind->blind. The ring spend's kernel:
         // sum(C_in) - sum(C_out) - fee*H == excess*G (stealth_evaluator.cpp:680).
         std::string err;
         std::vector<fc::ecc::commitment_type> out_cs;
         out_cs.reserve( o.outputs.size() );
         for( const auto& out : o.outputs )
            out_cs.push_back( out.commitment );
         FC_ASSERT( stealth_verify_excess( in_cs, out_cs, o.fee.amount.value, o.excess, err ),
                    "Stealth conservation mismatch: ${e}", ("e", err) );
      }
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result stealth_explicit_spend_evaluator::do_apply( const stealth_explicit_spend_operation& o )
{ try {
   db().adjust_balance( o.fee_payer(), o.fee );
   const auto& bbi = db().get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   int32_t spent_counted = 0;
   for( const auto& in : o.inputs )
   {
      auto itr = bbi.find( in.commitment );
      GRAPHENE_ASSERT( itr != bbi.end(), blind_transfer_unknown_commitment, "", ("commitment", in.commitment) );
      if( itr->created_block != 0 ) ++spent_counted;

      // Record BOTH version images. The image fields are VERSION-NAMED:
      // key_image_v1 is always the V1-domain image, key_image_v2 always the
      // V2-domain image (the recovery proof binds I1/I2 to those exact
      // domain bases). Tag each nullifier with its OWN version, NOT with
      // o.proof_version — an op with proof_version==V2 still has a V1 image
      // in key_image_v1. The ring path tags with o.proof_version because
      // its key_image/alt_key_image fields are RELATIVE (primary/alternate);
      // op108's fields are absolute. AGI-04: this absolute tagging
      // IS the stealth_alt_proof_version mapping — key_image_v1 is the
      // V1-domain image (tag V1), key_image_v2 the V2-domain image (tag V2);
      // a future V3 must extend the helper AND this pair together.
      // nullifier_key needs the explicit vector<char> conversion
      // (commitment_type does not convert).
      {
         const std::vector<char> i1( in.key_image_v1.begin(), in.key_image_v1.end() );
         const std::vector<char> i2( in.key_image_v2.begin(), in.key_image_v2.end() );
         db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
            n.key_image = nullifier_key( i1 );
            n.proof_version = GRAPHENE_STEALTH_PROOF_V1;
            n.created = db().head_block_time();
         } );
         db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
            n.key_image = nullifier_key( i2 );
            n.proof_version = GRAPHENE_STEALTH_PROOF_V2;
            n.created = db().head_block_time();
         } );
      }
      db().remove( *itr );
   }

   // New outputs are always post-fork: do_evaluate already refused pre-hardfork,
   // so created_block/created_time are unconditional (same as the ring path).
   for( const auto& out : o.outputs )
      db().create<blinded_balance_object>( [&]( blinded_balance_object& obj ) {
         obj.asset_id = o.asset_id; obj.owner = out.owner;
         obj.commitment = out.commitment;
         obj.created_block = db().head_block_num() + 1;
         obj.created_time  = db().head_block_time();
      } );

   // Transparent exit: credit the PUBLIC amount. The value is already proven to
   // equal sum(in) - fee by the verify_sum kernel in do_evaluate, so there is
   // no "amount from conservation" to recompute here — o.amount IS that value.
   // Mirrors op41's confidential_evaluator.cpp:154-155.
   share_type exited = 0;
   if( o.outputs.empty() )
   {
      db().adjust_balance( o.to, o.amount );
      exited = o.amount.amount;
   }

   const auto& add = o.asset_id(db()).dynamic_asset_data_id(db());
   db().modify( add, [&]( asset_dynamic_data_object& obj ) {
      // Exit leg leaves the blind pool entirely: amount AND fee.
      // op41: confidential_supply -= o.amount.amount + o.fee.amount (:169).
      obj.confidential_supply -= ( exited + o.fee.amount );
      FC_ASSERT( obj.confidential_supply >= 0 );
   } );
   stealth_shadow_add( db(), o.fee.asset_id, share_type( -( exited + o.fee.amount ).value ) );
   // Pool counter: -metadata-bearing inputs removed, +outputs created.
   // Mirrors confidential_evaluator.cpp:266-267.
   stealth_pool_count_add( db(), o.asset_id, -spent_counted );
   stealth_pool_count_add( db(), o.asset_id, (int32_t)o.outputs.size() );
stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                    o.fee.asset_id, (uint32_t)o.outputs.size(),
                                    calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                    std::min( (uint32_t)o.outputs.size(),
                                       stealth_subsidy_output_count( operation( o ) ) ) );
   stealth_window_count_add( db(), (uint32_t)o.outputs.size() );
   stealth_count_blind_op( db() );
   // SAME calculator as do_evaluate — one definition, so gate and accounting
   // cannot drift (the ring's precedent; the turnstile duplicates it inline at
   // :1077-1081, which is why this op does not).
   stealth_count_blind_work( db(), stealth_work_for_explicit_spend( o ) );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void stealth_explicit_spend_evaluator::pay_fee()
{
   generic_evaluator::pay_fee();
}

// ---------------------------------------------------------------------------
// stealth_pool_exchange (op109, G2: blind pool swap, 1-in/1-out)
// ---------------------------------------------------------------------------

namespace {

/// G2 market-fee routing (design §5): the issuer market-fee share of one
/// pool-swap leg lands in parity_pool[recv_asset] (transparent singleton
/// map, never an account balance — fundable with zero linkage); the
/// committee network_percent cut still vests to COMMITTEE when nonzero;
/// registrar/referrer rewards are forfeited (no identifiable taker, so no
/// referral to reward). Unlike stealth_parity_route_fee this is NOT a 5%
/// share behind an opt-in gate: the G2 fee path is defined as 100% parity
/// routing (MG-04: it does not count toward the parity+h2 joint cap).
/// Totals preserved exactly: parity increment + network cut == fee_amount.
///
/// EE-3fix: the block below mirrors stealth_parity_route_fee's shape exactly,
/// including the interval_routed upsert. Without it a G2-only-funded asset
/// credits the pool but leaves the burn-rate DENOMINATOR at zero, so the first
/// grant reads as 100% burn, arms burn_critical and halts every later subsidy
/// (BSIP-2 §2's alarm must measure routed fee inflow, not funding method).
/// Only what actually lands in the pool is registered — the network cut above
/// vests to COMMITTEE and is not routed inflow, so it is not registered here.
void g2_route_market_fee_to_parity( database& db, asset_id_type recv_asset,
                                    share_type fee_amount )
{
   if( fee_amount.value <= 0 )
      return;
   share_type issuer_fee = fee_amount;
   const uint16_t network_percent =
      db.get_global_properties().parameters.get_market_fee_network_percent();
   if( network_percent > 0 )
   {
      fc::uint128_t cut( (uint64_t)issuer_fee.value );
      cut *= network_percent;
      cut /= GRAPHENE_100_PERCENT;
      FC_ASSERT( cut <= fc::uint128_t( (uint64_t)issuer_fee.value ),
                 "Fee shared to the network shouldn't be greater than total market fee" );
      const share_type net( static_cast<int64_t>( cut ) );
      if( net.value > 0 )
      {
         db.deposit_market_fee_vesting_balance( GRAPHENE_COMMITTEE_ACCOUNT,
                                                asset( net, recv_asset ) );
         issuer_fee -= net;
      }
   }
   if( issuer_fee.value <= 0 )
      return;
   const auto& st = get_or_create_stealth_status( db );
   db.modify( st, [&]( stealth_status_object& o ) {
      auto itr = o.parity_pool.find( recv_asset );
      if( itr == o.parity_pool.end() )
         o.parity_pool[ recv_asset ] = issuer_fee;
      else
         itr->second += issuer_fee;
      auto ritr = o.interval_routed.find( recv_asset );
      if( ritr == o.interval_routed.end() )
         o.interval_routed[ recv_asset ] = issuer_fee;
      else
         ritr->second += issuer_fee;
   } );
}

} // namespace

void_result stealth_pool_exchange_evaluator::do_evaluate( const stealth_pool_exchange_operation& o )
{ try {
   const database& d = db();
   // (1) Fork gate.
   FC_ASSERT( HARDFORK_STEALTH_PASSED( d.head_block_time() ),
              "Stealth pool swaps are not allowed until the stealth hardfork" );
   // (2) Blind gate (count).
   stealth_check_blind_gate( d );
   // (3) Work gate: a swap costs ring + 2xBP + TWO kernels (value-pin AND
   // conservation verify_excess — both verified below; NC-14) + pool math,
   // strictly more than :331. Runs before the ring-size asserts, so the
   // calculator takes a wire-shaped op and saturates (fail-closed, never
   // wraps).
   stealth_check_blind_work_gate( d,
      stealth_work_for_pool_exchange( (uint32_t)o.input.ring.size() ) );
   // (4) Asset gates (A AND B): per-asset supply-divergence halts bind both
   // legs (a diverged asset's books are untrusted in either direction).
   stealth_check_asset_gate( d, o.amount_to_sell.asset_id );
   stealth_check_asset_gate( d, o.min_to_receive.asset_id );

   // (5) Pool/shape/field bounds. validate() is relay-side only and
   // proposal-embedded ops bypass it, so the evaluator re-asserts everything
   // it depends on (op108 :1600-1612 discipline).
   FC_ASSERT( o.fee.asset_id == o.amount_to_sell.asset_id,
              "Stealth pool swap fee must be paid in the sold asset" );
   FC_ASSERT( o.fee.amount >= 0, "Stealth pool swap fee cannot be negative" );
   FC_ASSERT( o.amount_to_sell.amount > 0, "Stealth pool swap sell amount must be positive" );
   FC_ASSERT( o.min_to_receive.amount > 0, "Stealth pool swap slippage floor must be positive" );
   FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V1 ||
              o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
              "Unknown proof version" );
   FC_ASSERT( o.value_pin.size() == 65, "Stealth pool swap value_pin must be 65 bytes" );
   FC_ASSERT( o.output.range_proof.size() == 592,
              "Stealth pool swap output proof must be 592 bytes (BP+ m=1)" );
   // V1 sunset, mirroring the ring at :529-532. Without this a V1 op109 past
   // sunset would mint fresh V1-domain-nullified outputs, defeating the sunset.
   if( d.head_block_time() >= stealth_v1_sunset_time( d ) )
      FC_ASSERT( o.proof_version == GRAPHENE_STEALTH_PROOF_V2,
                 "V1 stealth pool swaps are frozen past sunset (use turnstile re-proof)" );

   _pool = &o.pool(d);
   FC_ASSERT( _pool->balance_a > 0 && _pool->balance_b > 0, "The pool has not been initialized" );
   FC_ASSERT(    ( o.amount_to_sell.asset_id == _pool->asset_a
                && o.min_to_receive.asset_id == _pool->asset_b )
              || ( o.amount_to_sell.asset_id == _pool->asset_b
                && o.min_to_receive.asset_id == _pool->asset_a ),
              "Asset type mismatch" );

   // Pool floor on the INPUT asset: ring spends need decoys; thin-pool rings
   // mark the spender (availability yields to privacy, explicitly).
   FC_ASSERT( stealth_pool_depth( d, o.amount_to_sell.asset_id ) >= GRAPHENE_STEALTH_BLIND_POOL_FLOOR,
              "Blind pool below floor: stealth spends halted (availability yields to privacy)" );

   // (6) Ring shape + decoy policy. G2 floors at TARGET (16): no thin-pool
   // emergency allowance (validate() already pins 16–32 at relay).
   const auto& in = o.input;
   FC_ASSERT( in.ring.size() >= GRAPHENE_STEALTH_RING_TARGET &&
              in.ring.size() <= GRAPHENE_STEALTH_RING_MAX,
              "Ring size out of bounds" );
   FC_ASSERT( in.ring_scheme == protocol::GRAPHENE_STEALTH_RING_SCHEME_V1,
              "Unknown ring scheme" );
   FC_ASSERT( in.key_image.size() == 33, "Key image must be 33 bytes" );
   FC_ASSERT( in.ring_sig.size() == 32 + 96 * in.ring.size(), "Ring signature size mismatch" );
   FC_ASSERT( in.alt_key_image.size() == 33, "Alt key image must be 33 bytes" );
   FC_ASSERT( in.alt_ring_sig.size() == 32 + 96 * in.ring.size(),
              "Alt ring signature size mismatch" );
   FC_ASSERT( in.key_image != in.alt_key_image, "Duplicate key image within operation" );
   for( size_t i = 0; i < in.ring.size(); ++i )
      for( size_t j = i + 1; j < in.ring.size(); ++j )
         FC_ASSERT( in.ring[i] != in.ring[j], "Duplicate ring member" );

   const auto& bbi = d.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   const auto& nul = d.get_index_type<stealth_nullifier_index>().indices().get<by_nullifier_image>();

   // Output commitment must be fresh; owner must resolve (checked now so a
   // garbage owner fails before any crypto verifies).
   FC_ASSERT( bbi.find( o.output.commitment ) == bbi.end(),
              "Stealth output commitment already exists" );
   for( const auto& a : o.output.owner.account_auths ) a.first( d );

   // Every member must be a live blinded balance of the INPUT asset carrying
   // post-fork creation metadata (grandfathered outputs are never decoys).
   // Nullified members stay eligible (nullifier set alone blocks re-spend).
   std::vector<uint32_t> heights;
   std::vector<fc::time_point_sec> times;
   heights.reserve( in.ring.size() );
   times.reserve( in.ring.size() );
   for( const auto& c : in.ring )
   {
      auto itr = bbi.find( c );
      FC_ASSERT( itr != bbi.end(), "Ring member is not a live blinded balance" );
      FC_ASSERT( itr->asset_id == o.amount_to_sell.asset_id, "Ring member asset mismatch" );
      FC_ASSERT( itr->created_block != 0, "Grandfathered outputs are not decoy-eligible" );
      heights.push_back( itr->created_block );
      times.push_back( itr->created_time );
   }
   {
      std::string err;
      FC_ASSERT( stealth_check_decoy_policy( heights, times, d.head_block_time(),
                                             d.head_block_num(), err,
                                             stealth_pool_depth( d, o.amount_to_sell.asset_id ) ),
                 "Decoy policy violation: ${e}", ("e", err) );
   }

   // (7) Schnorr value-pin (design §3 link 1; proof Lemma 1): binds the
   // pseudo-output to amount_to_sell. value_pin is T(33) ‖ s(32).
   {
      const std::vector<char> T_bytes( o.value_pin.begin(), o.value_pin.begin() + 33 );
      const std::string s_bytes( o.value_pin.begin() + 33, o.value_pin.end() );
      std::string err;
      FC_ASSERT( stealth_verify_value_pin( in.pseudo_output, o.amount_to_sell.amount.value,
                                           o.pool.instance.value, T_bytes, s_bytes, err ),
                 "Stealth pool swap value-pin does not verify: ${e}", ("e", err) );
   }

   // (8) Shared pool math + min_to_receive. ORDER NOTE (deviation from the
   // brief's listed order, forced by a data dependency): G2RM binds the
   // composite fee F, so F must be computed — and bounded — BEFORE the ring
   // message below can be built. Pool math is a pure public function with no
   // state effects; every fail-closed assert still precedes acceptance and
   // proof-before-nullifier is preserved.
   _amounts = calculate_pool_exchange_amounts( d, *_pool, o.amount_to_sell, o.min_to_receive );

   // (9) Composite-F asserts (proof §6: 128-bit sum, 0 ≤ F ≤ MAX, F ≤ a;
   // each term independently bound so fee mass cannot shift components).
   // F fits int64_t by construction: each term is ≥ 0 and the sum is capped
   // before the kernel's unsigned BN_set_word path (design §3, :768 note).
   FC_ASSERT( _amounts.maker_market_fee.amount >= 0, "Maker market fee cannot be negative" );
   FC_ASSERT( _amounts.taker_market_fee.amount >= 0, "Taker market fee cannot be negative" );
   {
      fc::uint128_t F128( 0 );
      // share_type is signed; the ≥0 asserts above make each cast exact.
      F128 += fc::uint128_t( (uint64_t)_amounts.maker_market_fee.amount.value );
      F128 += fc::uint128_t( (uint64_t)_amounts.taker_market_fee.amount.value );
      F128 += fc::uint128_t( (uint64_t)o.fee.amount.value );
      FC_ASSERT( F128 <= fc::uint128_t( (uint64_t)GRAPHENE_MAX_SHARE_SUPPLY ),
                 "Stealth pool swap composite fee exceeds max supply" );
      FC_ASSERT( F128 <= fc::uint128_t( (uint64_t)o.amount_to_sell.amount.value ),
                 "Stealth pool swap composite fee exceeds sell amount" );
      _F = (int64_t)F128;
   }

    // Link 4 (design §3): the kernel pins v_out = a − F; the helper pins
    // account_receives = pool_pays − f_taker. Nothing equates them unless we do.
    // 128-bit, FC_ASSERT (never GRAPHENE_ASSERT).
    fc::uint128_t link4_lhs( (uint64_t)( o.amount_to_sell.amount.value - _F ) ); // F ≤ amount already asserted
    fc::uint128_t link4_rhs( (uint64_t)( _amounts.pool_pays.amount.value - _amounts.taker_market_fee.amount.value ) );
    FC_ASSERT( link4_lhs == link4_rhs, "Fee must exactly cover slippage: amount − F == pool_pays − taker_fee" );

   // (9b) parity float rule + Rule R (spec
   // 2026-10-10-stealth-entropy-economics §4, finding F-02). Placement is
   // load-bearing twice over: it follows the pool math so F is final, and it
   // precedes acceptance (the ring message, nullifier, proof and kernel
   // asserts below all refuse), mirroring design §7's order. Rule R admits
   // op109 on the CIRCULATION rule — a swap is set-neutral (rotates D_A to
   // D_B, 1-in/1-out by soundness) so only the base-fee component of the gap
   // is granted; the floor is anchor(1), unchanged for any user.
   stealth_require_blind_fee( d, core_fee_paid, !trx_state->skip_fee_schedule_check,
                              o.fee.asset_id, 1,
                              calculate_fee_for_operation( operation( o ) ),
                              std::min( 1u, stealth_subsidy_output_count( operation( o ) ) ) );

   // (10) Ring signature + alt leg over G2RM (binds version, input asset,
   // pool, claimed value, slippage floor, image, ring, pseudo, outputs, F).
   const uint8_t alt_version = stealth_alt_proof_version( o.proof_version );
   std::vector<fc::ecc::commitment_type> ring_cs( in.ring.begin(), in.ring.end() );
   std::vector<fc::ecc::commitment_type> out_cs = { o.output.commitment };
   {
      fc::sha256 m = stealth_pool_message( o.proof_version, o.amount_to_sell.asset_id,
         o.pool.instance.value, o.amount_to_sell.amount.value, o.min_to_receive.amount.value,
         in.key_image, ring_cs, in.pseudo_output, out_cs, _F );
      std::string msg( (const char*)m.data(), 32 );
      std::string err;
      FC_ASSERT( stealth_verify_ring( o.proof_version, in, msg, err ),
                 "Ring signature does not verify: ${e}", ("e", err) );
   }
   {
      protocol::stealth_ring_input alt_in;
      alt_in.ring = in.ring;
      alt_in.key_image = in.alt_key_image;
      alt_in.ring_sig = in.alt_ring_sig;
      alt_in.pseudo_output = in.pseudo_output;
      fc::sha256 ma = stealth_pool_message( alt_version, o.amount_to_sell.asset_id,
         o.pool.instance.value, o.amount_to_sell.amount.value, o.min_to_receive.amount.value,
         in.alt_key_image, ring_cs, in.pseudo_output, out_cs, _F );
      std::string msg_alt( (const char*)ma.data(), 32 );
      std::string err;
      FC_ASSERT( stealth_verify_ring( alt_version, alt_in, msg_alt, err ),
                 "Ring signature does not verify: ${e}", ("e", err) );
   }

   // (11) Nullifier absence, both legs (proof-before-nullifier, op108
   // stealth_evaluator.cpp:1832-1846 discipline: the pin + ring proofs above
   // established the images ARE this opening before the set is consulted).
   FC_ASSERT( nul.find( nullifier_key( in.key_image ) ) == nul.end(),
              "Key image already spent" );
   FC_ASSERT( nul.find( nullifier_key( in.alt_key_image ) ) == nul.end(),
              "Alternate key image already spent" );

   // (12) BP+ range (m=1 enforced): v_out ∈ [0,2^64); transitively enforces
   // F ≤ amount_to_sell alongside (9).
   {
      std::string err;
      std::vector<char> proof( o.output.range_proof.begin(), o.output.range_proof.end() );
      FC_ASSERT( stealth_verify_bp_plus( 1, proof, out_cs, err ),
                 "Stealth pool swap output range proof does not verify: ${e}", ("e", err) );
   }

   // (13) Conservation kernel (proof Lemma 3): v_out = amount_to_sell − F.
   // With (9) this pins the output to pool_pays − f_taker (Lemma 4).
   {
      std::string err;
      FC_ASSERT( stealth_verify_excess( { in.pseudo_output }, out_cs, _F, o.excess, err ),
                 "Stealth conservation mismatch: ${e}", ("e", err) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void_result stealth_pool_exchange_evaluator::do_apply( const stealth_pool_exchange_operation& o )
{ try {
   // Fee rides the FBA-style path: credit TEMP first (the blind surplus covers
   // it by conservation), the evaluator framework debits it after do_apply.
   db().adjust_balance( o.fee_payer(), o.fee );

   // Pool reserve mutation — byte-identical to
   // liquidity_pool_exchange_evaluator::do_apply (:461-473), including the
   // virtual_value ≥ old and positivity asserts.
   const auto old_virtual_value = _pool->virtual_value;
   if( o.amount_to_sell.asset_id == _pool->asset_a )
   {
      db().modify( *_pool, [this]( liquidity_pool_object& lpo ){
         lpo.balance_a += _amounts.pool_receives.amount;
         lpo.balance_b -= _amounts.pool_pays.amount;
         lpo.update_virtual_value();
      });
   }
   else
   {
      db().modify( *_pool, [this]( liquidity_pool_object& lpo ){
         lpo.balance_b += _amounts.pool_receives.amount;
         lpo.balance_a -= _amounts.pool_pays.amount;
         lpo.update_virtual_value();
      });
   }

   FC_ASSERT( _pool->balance_a > 0 && _pool->balance_b > 0, "Internal error" );
   FC_ASSERT( _pool->virtual_value >= old_virtual_value, "Internal error" );

   // Market-fee routing (design §5): issuer shares → parity_pool (never
   // accumulated_fees); committee network_percent cut vests to COMMITTEE iff
   // nonzero; registrar/referrer rewards forfeited (no identifiable taker).
   g2_route_market_fee_to_parity( db(), o.amount_to_sell.asset_id, _amounts.maker_market_fee.amount );
   g2_route_market_fee_to_parity( db(), o.min_to_receive.asset_id, _amounts.taker_market_fee.amount );

    // parity subsidy settlement (Rule R, F-02). Sits beside the market-fee
    // routing because that is where the pool's funds come from — op109 now
    // draws on parity_pool under the same availability assert every other
    // blind op uses. The (n, subsidy_n) pair mirrors the do_evaluate require
    // at (9b) EXACTLY, so the debit can never exceed what require admitted;
    // if the pool drained in between, the availability assert in consume
    // fires closed and the block is rejected.
    stealth_consume_parity_subsidy( db(), !trx_state->skip_fee_schedule_check,
                                    o.fee.asset_id, 1,
                                    calculate_fee_for_operation( operation( o ) ), core_fee_paid,
                                    std::min( 1u, stealth_subsidy_output_count( operation( o ) ) ) );

   // Nullifiers, both version legs (relative tags, ring-path discipline:
   // key_image rides o.proof_version, alt rides the other version).
   const uint8_t alt_version = stealth_alt_proof_version( o.proof_version );
   db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
      n.key_image = nullifier_key( o.input.key_image );
      n.proof_version = o.proof_version;
      n.created = db().head_block_time();
   } );
   db().create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
      n.key_image = nullifier_key( o.input.alt_key_image );
      n.proof_version = alt_version;
      n.created = db().head_block_time();
   } );

   // New blinded balance is the COUNTER-asset (B): input was asset A.
   // Post-fork creation metadata (decoy-eligible from tomorrow, never today).
   db().create<blinded_balance_object>( [&]( blinded_balance_object& b ) {
      b.asset_id = o.min_to_receive.asset_id;
      b.owner = o.output.owner;
      b.commitment = o.output.commitment;
      b.created_block = db().head_block_num() + 1;
      b.created_time = db().head_block_time();
   } );

   // Blind supply: asset A releases the input principal PLUS the tx-fee
   // value, asset B absorbs the kernel-pinned output value. The fee leg
   // needs the extra term: the kernel subtracts F (including f_tx) from the
   // counter-asset output while the framework credits f_tx to TEMP (then
   // debits it) and to accumulated_fees/pending via convert/pay — that +f_tx
   // in A-books pairs with an extra −f_tx here, exactly like G1's
   // confidential_supply −= fee (which pairs its own TEMP/pending legs).
   // Without it every swap mints f_tx of supply (caught by
   // verify_asset_supplies in tests). account_receives == pool_pays − f_taker
   // == v_out (proof Lemma 4), so both counters move exactly with the kernel.
   const asset_id_type asset_a = o.amount_to_sell.asset_id;
   const asset_id_type asset_b = o.min_to_receive.asset_id;
   const share_type burn_a = o.amount_to_sell.amount + o.fee.amount;
   FC_ASSERT( burn_a >= o.amount_to_sell.amount, "Stealth pool swap supply burn overflow" );
   const auto& add_a = asset_a(db()).dynamic_asset_data_id(db());
   db().modify( add_a, [&]( asset_dynamic_data_object& obj ) {
      obj.confidential_supply -= burn_a;
      FC_ASSERT( obj.confidential_supply >= 0 );
   } );
   stealth_shadow_add( db(), asset_a, share_type( -burn_a.value ) );
   const auto& add_b = asset_b(db()).dynamic_asset_data_id(db());
   db().modify( add_b, [&]( asset_dynamic_data_object& obj ) {
      obj.confidential_supply += _amounts.account_receives.amount;
      FC_ASSERT( obj.confidential_supply >= 0 );
   } );
   stealth_shadow_add( db(), asset_b, share_type( _amounts.account_receives.amount.value ) );

   // Pool counter (live-set semantics): the ring removes nothing, so
   // only the new counter-asset output joins the decoy set.
   stealth_pool_count_add( db(), asset_b, 1 );
   stealth_window_count_add( db(), 1 );
   stealth_count_blind_op( db() );
   stealth_count_blind_work( db(),
      stealth_work_for_pool_exchange( (uint32_t)o.input.ring.size() ) );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (o) ) }

void stealth_pool_exchange_evaluator::pay_fee()
{
   generic_evaluator::pay_fee();
}

} } // graphene::chain
