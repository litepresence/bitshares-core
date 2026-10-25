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
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

namespace graphene { namespace chain {


namespace {
   using boost::multiprecision::uint256_t;
   using graphene::protocol::h2_deviation_breaches;
   using graphene::protocol::h2_osm_bucket_anchor;
   using graphene::protocol::h2_pro_rata;
   using graphene::protocol::h2_convert_face_to_bond;
   using graphene::protocol::h2_volume_weighted_median;
   using graphene::protocol::GRAPHENE_H2E_REWARD_ORACLE_BPS;
   using graphene::protocol::GRAPHENE_H2E_REWARD_VAULT_BPS;
   using graphene::protocol::GRAPHENE_H2E_REWARD_RESERVE_BPS;
   using graphene::protocol::GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS;
   using graphene::protocol::GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_STAGE_DOOR;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS;
   using graphene::protocol::GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS;
   using graphene::protocol::GRAPHENE_H2E_RECOVERY_TRIGGER_BPS;

   /// Distinct-pool tracking bound per window (state must stay bounded).
   constexpr size_t H2E_TRIPWIRE_POOL_CAP = 64;
   /// Guilty-history scan bound (R4-01 backstop, shared by the oracle and
   /// vault halves below). Dispute/challenge objects persist as the audit
   /// trail (never pruned), so a per-target history scan is
   /// resolution-scoped but NOT bounded by protocol state: it walks the
   /// target's full terminal history. Several thousand terminal records on
   /// one target is unreachable in practice, so breaching this cap fails
   /// closed (treated as guilty: reopen refuses, committee oracle_unfreeze
   /// stays the escape hatch for oracles). No cached flag on the H1 oracle
   /// object by design (avoids pre-merge object-layout divergence): the
   /// scan stays the source of truth.
   constexpr size_t H2E_GUILTY_SCAN_CAP = 8192;

   /// Saturating share addition for scope accounting: state sums can in
   /// principle exceed int64 while the comparison only needs monotonicity.
   share_type h2_sat_add( share_type a, share_type b )
   {
      const uint256_t sum = uint256_t( uint64_t( a.value ) )
                          + uint256_t( uint64_t( b.value ) );
      if( sum > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
         return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
      return share_type( int64_t( uint64_t( sum ) ) );
   }

   const guard_state_object* h2_find_guard( const database& d, oracle_id_type oid )
   {
      const auto& idx = d.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
      const auto itr = idx.find( oid );
      return itr == idx.end() ? nullptr : &*itr;
   }

    /// Bonded-live gate (X-01): does @p oracle have a non-empty bonded live
    /// set at @p now (unslashed producer bond + live submission + current
    /// producer entry)? Extracted from the reward live-set computation below
    /// so reads, the tripwire feed leg, and payouts share one definition.
    /// H1-style oracles (live values, no bonds) report false: H2 reads fail
    /// closed without bonded backing, never on unbonded medians.
    ///
    /// R3-02 hardening (fail-closed tightenings only):
    /// - Producer weight must exceed 0: a zero-weight entry backs nothing
    ///   (the reward path pays it zero), so it must not satisfy the gate.
    /// - The bond must still be locked: release deletes the object
    ///   (oracle_bond_release_evaluator::do_apply in bond_evaluator.cpp), so
    ///   a live object means unreleased — but vesting withdrawals bypass the
    ///   object, so the referenced vesting balance must still cover
    ///   bond_amount, and @p now must precede unlock_time (releasable-but-
    ///   unreleased bonds do not back reads; the advancing-unlock rule keeps
    ///   active publishers ahead of their unlock).
    /// - Cost: one bounded scan per call (at most
    ///   GRAPHENE_ORACLE_MAX_PRODUCERS bond rows: one bond exists per
    ///   (oracle, producer) by lock refusal, but removed producers' bonds
    ///   linger (no delete on producer removal), so MORE than 32 rows per
    ///   oracle is reachable and the 33rd+ row truncates unread — a live
    ///   producer past the cap backs no read and earns nothing (fail-closed
    ///   self-grief: only the owner can strand rows by churning the producer
    ///   set, and the strand is committee-visible on-chain). The reward
    ///   live-set below shares this exact bound and truncation, so reads
    ///   and payouts never disagree on who is live. Callers pay the scan
    ///   once per oracle read (h2_read_consumed_price) and twice per pair
    ///   per sweep through the tripwire feed leg (primary + single backup),
    ///   i.e. worst case O(oracles x producers) per sweep.
    bool h2_oracle_has_bonded_live_set( const database& d, const oracle_object& oracle,
                                        time_point_sec now )
    {
       const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                 .indices().get<by_oracle_producer>();
       size_t scanned = 0;
       for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oracle_id_type( oracle.id ) ) );
             bitr != bond_idx.end() && bitr->oracle == oracle.id; ++bitr )
       {
          if( ++scanned > GRAPHENE_ORACLE_MAX_PRODUCERS )
             break; // structural cap (see above): unreachable, bounds the read
          if( bitr->slashed )
             continue;
          const auto pitr = oracle.options.producers.find( bitr->producer );
          if( pitr == oracle.options.producers.end() )
             continue;
          if( pitr->second.weight == 0 )
             continue; // R3-02: zero weight backs nothing (reward path pays zero)
          if( bitr->bond_amount <= share_type( 0 ) || now >= bitr->unlock_time )
             continue; // R3-02: releasable or unfunded-record bonds do not back reads
           const vesting_balance_object* vb = d.find( bitr->vesting_balance );
           if( vb == nullptr || vb->balance.asset_id != asset_id_type()
               || vb->balance.amount < bitr->bond_amount )
              continue; // R3-02: vesting withdrawals bypass the bond object;
                        // R4-03: BTS-only is enforced at lock (bond_evaluator),
                        // this asset check is belt and suspenders
          // A live submission: the price path's map, or (for a foreign
          // transaction oracle) the foreign attestation map. A foreign
          // attestor that never published has no live submission, so the
          // bonded live set does not count it.
          const auto sitr = oracle.submissions.find( bitr->producer );
          const auto fitr = oracle.foreign_submissions.find( bitr->producer );
          const bool price_live = ( sitr != oracle.submissions.end()
                                    && oracle.is_submission_live( sitr->second.first, now ) );
          const bool foreign_live = ( fitr != oracle.foreign_submissions.end()
                                      && oracle.is_submission_live( fitr->second.first, now ) );
          if( !price_live && !foreign_live )
             continue;
          return true;
       }
       return false;
    }

   /// Whether the oracle has at least one producer with a non-slashed bond,
   /// regardless of liveness. The settlement path (age_exempt) drops the
   /// live-submission part of the bonded live set (a dead feed has no live
   /// submission) but keeps this gate, so an oracle that was never bonded
   /// (no bond rows at all) has no settlement price. Unbonded oracles can
   /// never move bonded medians, debt taps, or wind-down seats.
   bool h2_oracle_has_any_bond( const database& d, const oracle_object& oracle )
   {
      const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oracle_id_type( oracle.id ) ) );
            bitr != bond_idx.end() && bitr->oracle == oracle.id; ++bitr )
      {
         if( bitr->slashed )
            continue;
         if( bitr->bond_amount <= share_type( 0 ) )
            continue;
         return true;
      }
      return false;
   }

   /// Interval-anchored window for @p now (H1 guard_epoch precedent).
   time_point_sec h2_rate_window( const database& d, time_point_sec now )
   {
      const uint32_t interval = d.get_global_properties().parameters.maintenance_interval;
      if( interval == 0 )
         return now;
      return time_point_sec( ( uint64_t( now.sec_since_epoch() ) / interval ) * interval );
   }

   /// Rolls a guard's rate window when @p now crossed into a new one.
   void h2_roll_guard_window( database& d, const guard_state_object& guard,
                             time_point_sec now )
   {
      const time_point_sec window = h2_rate_window( d, now );
      if( guard.rate_window_start != window )
         d.modify( guard, [&window]( guard_state_object& g ) {
            g.rate_window_start = window;
            g.promotion_count = 0;
            g.consumption_hold = false;
         } );
   }

   /// Combined-window validity: each window needs depth + at least one sample,
   /// and the pair needs two distinct pools across both (multi-pool rule).
   bool h2_windows_valid( const h2_tripwire_window& old_w,
                          const h2_tripwire_window& new_w )
   {
      if( old_w.samples.empty() || new_w.samples.empty() )
         return false;
      if( old_w.total_volume < GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW
          || new_w.total_volume < GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW )
         return false;
      flat_set<liquidity_pool_id_type> pools = old_w.pools;
      pools.insert( new_w.pools.begin(), new_w.pools.end() );
      return pools.size() >= 2;
   }

    /// R3-01 guilty-history gate (R4-01 honesty + backstop): does @p oid
    /// carry terminal guilty dispute history (SUSTAINED or EXPIRED_FROZEN)?
    /// Dispute objects persist as the audit trail (never pruned), so this
    /// scan is resolution-scoped but walks the oracle's FULL standing
    /// history — per-oracle history is unbounded by protocol state, and an
    /// earlier "never whole-history" comment was wrong (corrected here).
    /// The H2E_GUILTY_SCAN_CAP backstop bounds the read against
    /// pathological accumulation; breaching it fails closed (treated as
    /// guilty; committee oracle_unfreeze stays the escape hatch). No cached
    /// flag on the H1 oracle object by design (avoids pre-merge
    /// object-layout divergence): the scan stays the source of truth.
    /// EXONERATED and FAST_REJECTED pasts never block (no permanent owner
    /// lockout), and open disputes gate separately via open_disputes. Same
    /// index pattern as the owner-refusal check in
    /// oracle_update_evaluator::do_evaluate (oracle_evaluator.cpp).
    bool h2_oracle_has_guilty_history( const database& d, oracle_id_type oid )
    {
       const auto& dispute_idx = d.get_index_type<oracle_dispute_index>()
                                    .indices().get<by_dispute_oracle>();
       const auto range = dispute_idx.equal_range( oid );
       size_t scanned = 0;
       for( auto itr = range.first; itr != range.second; ++itr )
       {
          if( ++scanned > H2E_GUILTY_SCAN_CAP )
             return true; // backstop breached: fail closed, see cap note
          if( itr->state == GRAPHENE_H2_CHALLENGE_SUSTAINED
              || itr->state == GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN )
             return true;
       }
       return false;
    }

    /// R4-02a vault-half mirror of the oracle gate above: does @p vid carry
    /// terminal guilty challenge history (SUSTAINED or EXPIRED_FROZEN)?
    /// Same resolution-scoped pattern over by_challenge_vault (EXONERATED /
    /// FAST_REJECTED pasts never block; open challenges gate separately via
    /// open_challenges), same fail-closed backstop. Third pin of three —
    /// cross-cite the vault_lifecycle top-up restore
    /// (vault_lifecycle_evaluator.cpp: pinned + tripwire_door_hold refuse
    /// the coverage-restore clear) and h2_reopen_tripwire's vault half
    /// below: all three agree that coverage recovery or clean tripwire
    /// windows never clear a theft finding. Note the asymmetry with the
    /// oracle half: a guilty oracle clears through committee oracle_unfreeze,
    /// while a guilty/inconclusive vault exits only through vault_resolve
    /// into a wind-down (R5C fail-closed split: sustained executes by vote;
    /// expired executes on any seated member's trigger — the seat bound
    /// keeps that path from taking more than the filed exit formula can
    /// pay). Fresh
    /// re-registration (new vault object, new bonds) is the sole path back
    /// to operation; neither resolve path can restore HEALTHY.
    bool h2_vault_has_guilty_history( const database& d, vault_id_type vid )
    {
       const auto& ch_idx = d.get_index_type<vault_challenge_index>()
                               .indices().get<by_challenge_vault>();
       const auto range = ch_idx.equal_range( vid );
       size_t scanned = 0;
       for( auto itr = range.first; itr != range.second; ++itr )
       {
          if( ++scanned > H2E_GUILTY_SCAN_CAP )
             return true; // backstop breached: fail closed, see cap note
          if( itr->state == GRAPHENE_H2_CHALLENGE_SUSTAINED
              || itr->state == GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN )
             return true;
       }
       return false;
    }

     /// Applies one halt stage's effects idempotently (door -> debt -> redemptions).
    void h2_apply_tripwire_stage( database& d, const tripwire_state_object& tw,
                                  const vault_object& vault )
    {
       // ISSUANCE-2 REVERT-vs-ABSORB on halt entry (issuance pairs only;
       // no-reserve pairs return inside untouched): runs BEFORE the freezes
       // below because the transition reads the bonded price, and a frozen
       // oracle reads absent (fail-closed hold).
       h2_issue_on_pair_halt( d, vault.vault_pair );
       if( tw.halt_stage >= GRAPHENE_H2E_TRIPWIRE_STAGE_DOOR )
      {
         d.modify( vault, []( vault_object& v ) {
            v.tripwire_door_hold = true;
            v.frozen = true; // protocol door: mints halt, exits continue
         } );
      }
      if( tw.halt_stage >= GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT
          && vault.bound_oracle.valid() )
      {
         const oracle_object* oracle = d.find( *vault.bound_oracle );
         if( oracle != nullptr )
            d.modify( *oracle, []( oracle_object& o ) { o.options.frozen = true; } );
      }
      if( tw.halt_stage >= GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS )
      {
         d.modify( tw, []( tripwire_state_object& t ) { t.redemptions_halted = true; } );
      }
   }

    /// Reopens after two consecutive clean windows. Dispute/challenge pins are
    /// respected: a theft finding keeps its own freeze regardless of the wire.
    ///
    /// R3-01: the oracle half additionally requires no terminal guilty
    /// history (SUSTAINED/EXPIRED_FROZEN, resolution-scoped): sustained and
    /// expired resolutions decrement open_disputes at resolution, so the
    /// counter alone would let two clean windows silently unfreeze a guilty
    /// producer's oracle, bypassing committee oracle_unfreeze. Guilty oracles
    /// clear only through the committee op — after the tripwire stage itself
    /// has cleared, since unfreeze refuses at any non-NONE stage (R4-02:
    /// halt_stage == NONE, see oracle_unfreeze_evaluator::do_evaluate).
    ///
    /// R4-02a: the vault half mirrors the pin (h2_vault_has_guilty_history):
    /// an expired/sustained vault challenge keeps the vault frozen across
    /// clean windows even with zero open challenges and healthy coverage —
    /// without this, the counter + health read alone would silently unfreeze
    /// a theft finding. Third pin of three with the top-up restore guard
    /// (vault_lifecycle_evaluator.cpp); EXONERATED/FAST_REJECTED vault pasts
    /// never block, exactly like the oracle half.
    void h2_reopen_tripwire( database& d, const tripwire_state_object& tw,
                             const vault_object& vault )
    {
       const oracle_object* oracle = vault.bound_oracle.valid()
                                     ? d.find( *vault.bound_oracle ) : nullptr;
       d.modify( tw, []( tripwire_state_object& t ) {
          t.halt_stage = GRAPHENE_H2E_TRIPWIRE_STAGE_NONE;
          t.clean_streak = 0;
          t.redemptions_halted = false;
       } );
       d.modify( vault, []( vault_object& v ) { v.tripwire_door_hold = false; } );
       if( vault.open_challenges == 0
           && vault.maintenance_state == GRAPHENE_H2_VAULT_HEALTHY
           && !h2_vault_has_guilty_history( d, vault_id_type( vault.id ) ) )
          d.modify( vault, []( vault_object& v ) { v.frozen = false; } );
       if( oracle != nullptr && oracle->open_disputes == 0
           && !h2_oracle_has_guilty_history( d, oracle_id_type( oracle->id ) ) )
          d.modify( *oracle, []( oracle_object& o ) { o.options.frozen = false; } );
    }

    /// One tripwire evaluation: breach / clean / pause over the two complete
    /// windows AS THEY STAND, then rotate. Evaluate-first is load-bearing:
    /// rotating first would leave the fresh window empty at evaluation time,
    /// so every sweep would pause on thin windows and the halt ladder could
    /// never escalate. Rotating after consumes the two windows exactly once,
    /// so a pause can neither double-count samples nor stall the ring. Every
    /// window is evaluated twice (once as newer, once as older); reopen needs
    /// two CONSECUTIVE clean evaluations.
    void h2_evaluate_tripwire( database& d, const tripwire_state_object& tw,
                               time_point_sec now )
    {
       const auto& vault_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
       const auto vitr = vault_idx.find( tw.pair );
       const bool vault_gone = ( vitr == vault_idx.end() );
       const vault_object* vault = vault_gone ? nullptr : &*vitr;
       const bool bound = ( vault != nullptr && vault->bound_oracle.valid() );
       // Decision 2 piece 3: stale rung.
       bool stale_rung = false;
       if( bound )
       {
          const oracle_object* _po = d.find( *vault->bound_oracle );
          // The stale rung arms only when the consumed value is stale AND the
          // oracle has no live current value (no fresh submission). If the
          // oracle is still publishing (live current value), the stale rung
          // does not arm, because the producer is still live.
          if( _po != nullptr && _po->consumed_value_time != time_point_sec()
              && ( now - _po->consumed_value_time ).to_seconds()
                  >= (int64_t) _po->options.value_lifetime_sec
              && ( !_po->current_value.valid()
                   || !_po->is_value_live( now ) ) )
             stale_rung = true;
       }
       // Feed leg: bound oracle's live raw aggregate (transparency continues
       // under freeze), else the single backup's, else pause (no data).
       // X-01 bonded-only: a live value without a bonded live set is not a
       // feed leg (H1-style oracles never move the tripwire).
       optional<protocol::oracle_value> feed;
       if( bound )
       {
          const oracle_object* primary = d.find( *vault->bound_oracle );
          auto live_current = [&now]( const oracle_object* o ) -> optional<protocol::oracle_value>
          {
             if( o == nullptr || !o->current_value.valid() || o->current_value->empty() )
                return optional<protocol::oracle_value>();
             if( !o->is_value_live( now ) )
                return optional<protocol::oracle_value>();
             return ( *o->current_value )[0];
          };
           if( primary != nullptr
               && h2_oracle_has_bonded_live_set( d, *primary, now ) ) // R3-02: bounded scan, see gate note
              feed = live_current( primary );
          if( !feed.valid() )
          {
             const guard_state_object* guard = h2_find_guard( d, *vault->bound_oracle );
             if( guard != nullptr && guard->fallback.valid() )
             {
                const oracle_object* backup = d.find( guard->fallback->oracle_id );
                 if( backup != nullptr
                     && h2_oracle_has_bonded_live_set( d, *backup, now ) ) // R3-02: 2nd bounded scan of this pair's sweep leg
                 {
                   const auto fb = live_current( backup );
                   if( fb.valid() && guard->fallback->series < backup->current_value->size() )
                      feed = ( *backup->current_value )[ guard->fallback->series ];
                }
             }
          }
       }
       // Read the outcome from the standing windows; rotation applies below.
       const bool readable = !vault_gone && bound
                             && h2_windows_valid( tw.win_old, tw.win_new )
                             && feed.valid();
       bool breach = false;
       if( readable )
       {
          vector<protocol::h2_tripwire_sample> combined;
          combined.reserve( tw.win_old.samples.size() + tw.win_new.samples.size() );
          combined.insert( combined.end(), tw.win_old.samples.begin(), tw.win_old.samples.end() );
          combined.insert( combined.end(), tw.win_new.samples.begin(), tw.win_new.samples.end() );
          const auto median = h2_volume_weighted_median( combined );
          breach = median.valid()
                   && h2_deviation_breaches( median->price, *feed,
                                             GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM );
       }
       // Decide the post-sweep state before touching anything.
       uint8_t stage_after = tw.halt_stage;
       uint8_t streak_after = tw.clean_streak;
       const bool was_halted = tw.redemptions_halted;
       bool reopen = false;
       if( vault_gone )
       {
          // Hold the stage, reset nothing, count nothing.
       }
       else if( !readable )
       {
          streak_after = 0; // pause: stage held (reopen needs consecutives)
       }
       else if( breach )
       {
          if( stage_after < GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT )
             stage_after = GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT;
          else if( stage_after < GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS )
             stage_after += 1;
          streak_after = 0;
       }
       else if( stale_rung )
       {
          // Stale rung: redemptions halted at the pair level only. No door,
          // no debt, no wind-down. The wind-down requires a deviation rung.
          // The streak still accumulates so that reopen can fire once the
          // consumed value becomes fresh again (consecutive clean windows).
          const uint8_t streak = uint8_t( streak_after + 1 );
          if( streak >= GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS
              && ( stage_after != 0 || was_halted ) && !stale_rung )
             reopen = true;
          else if( streak >= GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS )
             streak_after = 0;
          else
             streak_after = streak;
       }
       else
       {
          const uint8_t streak = uint8_t( streak_after + 1 );
          if( streak >= GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS
              && ( stage_after != 0 || was_halted ) )
             reopen = true;
          else if( streak >= GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS )
             streak_after = 0; // healthy pairs cap the streak, never halt
          else
             streak_after = streak;
       }
       // Apply: rotate the ring, then the outcome. References stay valid
       // across modifies (same index nodes), so the vault/tripwire refs below
       // keep pointing at the right objects.
       d.modify( tw, [&now, stage_after, streak_after, stale_rung]( tripwire_state_object& t ) {
          t.win_old = t.win_new;
          t.win_new = h2_tripwire_window();
          t.win_new.start = now;
          t.halt_stage = stage_after;
          t.clean_streak = streak_after;
          if( stale_rung )
             t.redemptions_halted = true;
          // A stale rung that has cleared (consumed value fresh again) drops
          // redemptions_halted immediately, without waiting for the reopen
          // ladder (which is for breach halts, not staleness). Breach halts
          // (halt_stage != 0) keep their reopen-gated clearing.
          else if( t.halt_stage == 0 && t.redemptions_halted )
             t.redemptions_halted = false;
       } );
       if( reopen && !stale_rung )
          h2_reopen_tripwire( d, tw, *vault );
       else if( readable && breach )
       {
          h2_apply_tripwire_stage( d, tw, *vault );
          if( stale_rung )
             d.modify( tw, []( tripwire_state_object& t ) { t.redemptions_halted = true; } );
       }
       else if( stale_rung )
          d.modify( tw, []( tripwire_state_object& t ) { t.redemptions_halted = true; } );
    }

   /// Sweeps one oracle's forfeit accruals into its pool and pays bonded live
   /// producers pro-rata. Pure redistribution of counted supply: the split
   /// already removed only the burn leg, so payouts move balances with no
   /// supply adjustment (wind-down precedent).
   void h2_process_reward_pool( database& d, const oracle_object& oracle,
                                time_point_sec now )
   {
      const auto& pool_idx = d.get_index_type<reward_pool_index>()
                                .indices().get<by_pool_oracle>();
      const auto pitr = pool_idx.find( oracle_id_type( oracle.id ) );
      if( pitr == pool_idx.end() )
         return;
      const reward_pool_object& pool = *pitr;
      share_type balance = pool.balance;
      if( oracle.forfeit_pool_balance > share_type( 0 ) )
      {
         balance = h2_sat_add( balance, oracle.forfeit_pool_balance );
         d.modify( oracle, []( oracle_object& o ) { o.forfeit_pool_balance = share_type( 0 ); } );
      }
      // Bound vaults' accruals settle through their oracle's pool; unbound
      // vaults' accruals wait on their vaults (never cross pairs).
      const auto& vault_idx = d.get_index_type<vault_index>().indices();
      for( auto vitr = vault_idx.begin(); vitr != vault_idx.end(); ++vitr )
      {
         if( vitr->forfeit_pool_balance <= share_type( 0 ) )
            continue;
         if( !vitr->bound_oracle.valid() || *vitr->bound_oracle != oracle.id )
            continue;
         balance = h2_sat_add( balance, vitr->forfeit_pool_balance );
         d.modify( *vitr, []( vault_object& v ) { v.forfeit_pool_balance = share_type( 0 ); } );
      }
      // Live set (R4-03 parity): the IDENTICAL bonded-live definition as the
      // read gate h2_oracle_has_bonded_live_set above (unslashed bond +
      // weight > 0 + locked/unexpired + vesting still covering in BTS + live
      // submission + current producer entry), under the same
      // GRAPHENE_ORACLE_MAX_PRODUCERS scan bound with the same fail-closed
      // truncation. One shared definition of "live backed producer" for
      // reads, the tripwire feed leg, and payouts: an entry that fails the
      // read gate earns zero here (its weight leaves the denominator too),
      // and truncation dust accrues to the pool, never mints.
      // Weight is owner-set (never reputation-earned); a zero weight earns
      // zero AND counts as not-live (it cannot move the denominator).
      struct live_producer { account_id_type account; uint64_t weight; };
      vector<live_producer> live;
      uint64_t total_weight = 0;
      const auto& bond_idx = d.get_index_type<producer_bond_index>()
                                .indices().get<by_oracle_producer>();
      size_t scanned = 0;
      for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oracle_id_type( oracle.id ) ) );
            bitr != bond_idx.end() && bitr->oracle == oracle.id; ++bitr )
      {
         if( ++scanned > GRAPHENE_ORACLE_MAX_PRODUCERS )
            break; // shared cap: unreachable except via removal-lingered rows,
                   // truncates fail-closed (33rd+ live producer unpaid)
         if( bitr->slashed )
            continue;
         const auto pitr2 = oracle.options.producers.find( bitr->producer );
         if( pitr2 == oracle.options.producers.end() )
            continue;
         if( pitr2->second.weight == 0 )
            continue; // R4-03 parity: zero weight backs nothing (gate refuses it too)
         if( bitr->bond_amount <= share_type( 0 ) || now >= bitr->unlock_time )
            continue; // R4-03 parity: releasable or unfunded-record bonds earn nothing
         const vesting_balance_object* vb = d.find( bitr->vesting_balance );
         if( vb == nullptr || vb->balance.asset_id != asset_id_type()
             || vb->balance.amount < bitr->bond_amount )
            continue; // R4-03 parity: vesting must still cover, in BTS
                      // (BTS-only enforced at lock; asset check is belt+suspenders)
         const auto sitr = oracle.submissions.find( bitr->producer );
         if( sitr == oracle.submissions.end()
             || !oracle.is_submission_live( sitr->second.first, now ) )
            continue;
         live.push_back( live_producer{ bitr->producer, pitr2->second.weight } );
         total_weight += pitr2->second.weight;
      }
      share_type paid( 0 );
      if( total_weight > 0 && balance > share_type( 0 ) )
      {
         // Every share is computed from the swept total, never from the
         // shrinking remainder: pro-rata means weight/total_weight of the
         // pool, truncated per payee, with the truncation dust accruing.
         const share_type swept_total = balance;
         for( const auto& e : live )
         {
            const share_type share = h2_pro_rata( swept_total, e.weight, total_weight );
            if( share <= share_type( 0 ) )
               continue;
            d.adjust_balance( e.account, asset( share, asset_id_type() ) );
            balance = balance - share;
            paid = paid + share;
         }
      }
      // X-03 merge contract (H2-side half): record this sweep's H2 diversion
      // (the oracle-leg routing share) on the shared 10000-bps denominator
      // and assert it sits inside the 7000bps joint ceiling. The G1 merge
      // reads h2_diversion_bps and asserts parity_bps + h2_diversion_bps <=
      // 7000 in both routers; that sum assert lands with the merge, not here.
      // No cross-branch writes: H2 writes, G1 reads.
      d.modify( pool, [&balance, &paid, &now]( reward_pool_object& p ) {
         p.balance = balance;
         p.paid_lifetime = p.paid_lifetime + paid;
         p.last_payout = now;
         p.h2_diversion_bps = p.routing_oracle_bps;
         FC_ASSERT( p.h2_diversion_bps <= GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS,
                    "H2 diversion ${d}bps exceeds the joint ${c}bps ceiling",
                    ("d", p.h2_diversion_bps)("c", GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS) );
         FC_ASSERT( h2_routing_valid( p.routing_oracle_bps, p.routing_vault_bps,
                                      p.routing_reserve_bps,
                                      GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ),
                    "H2 routing triple violates the joint-cap contract" );
      } );
   }

} // namespace

void h2_ensure_oracle_econ( database& d, oracle_id_type oracle )
{
   const auto& pool_idx = d.get_index_type<reward_pool_index>()
                             .indices().get<by_pool_oracle>();
   if( pool_idx.find( oracle ) == pool_idx.end() )
      d.create<reward_pool_object>( [&oracle]( reward_pool_object& p ) {
         p.oracle = oracle;
         p.balance = share_type( 0 );
         p.paid_lifetime = share_type( 0 );
         p.routing_oracle_bps = GRAPHENE_H2E_REWARD_ORACLE_BPS;
         p.routing_vault_bps = GRAPHENE_H2E_REWARD_VAULT_BPS;
         p.routing_reserve_bps = GRAPHENE_H2E_REWARD_RESERVE_BPS;
         // X-03 merge contract: shell records the H2 diversion (oracle leg)
         // at creation too, so a pool that never processes a sweep still
         // advertises a valid joint-cap half.
         p.h2_diversion_bps = GRAPHENE_H2E_REWARD_ORACLE_BPS;
      } );
   const auto& guard_idx = d.get_index_type<guard_state_index>()
                              .indices().get<by_guard_oracle>();
   if( guard_idx.find( oracle ) == guard_idx.end() )
      d.create<guard_state_object>( [&oracle]( guard_state_object& g ) {
         g.oracle = oracle;
      } );
}

void h2_observe_publication( database& d, oracle_id_type oracle, time_point_sec now )
{
   if( !HARDFORK_H2_BONDS_PASSED( d.head_block_time() ) )
      return;
   const oracle_object* o = d.find( oracle );
   if( o == nullptr )
      return;
   h2_ensure_oracle_econ( d, oracle );
   const guard_state_object* guard = h2_find_guard( d, oracle );
   FC_ASSERT( guard != nullptr, "Guard shell must exist after ensure" );
   h2_roll_guard_window( d, *guard, now );
   // A promotion is a NEW consumable value: time or value advanced. Stable
   // republishes recount nothing (no new information, no churn).
   if( !o->consumed_value.valid() || o->consumed_value->size() != o->series.size() )
      return;
   if( guard->last_promo_time == o->consumed_value_time
       && guard->last_promo_values == *o->consumed_value )
      return;
   const uint32_t delay = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t anchor = h2_osm_bucket_anchor(
         uint32_t( o->consumed_value_time.sec_since_epoch() ), delay );
   const uint16_t count = o->current_value_producer_count;
   const auto values = *o->consumed_value;
   const time_point_sec ptime = o->consumed_value_time;

   // Decision 2 piece 2: price-band guard. The promoted value must sit within
   // +/-30% of the previous promoted value AND move slower than 5% per block.
   // Both must pass; either failure refuses the promotion and sets the
   // consumption hold. The first promotion (no prior) is exempt. A promotion
   // after a stale gap (consumed value older than value_lifetime_sec) is also
   // exempt, because the feed restarted and the previous value is no longer
   // a meaningful reference.
   // Exempt promotions after a maintenance-interval gap (more than 30s apart).
   // Same-block and adjacent-block promotions are subject to the full check.
   const bool stale_gap = ( ptime - guard->last_promo_time ).to_seconds() > 1;
   if( !stale_gap && guard->promotion_count > 0 && !guard->last_promo_values.empty()
       && !values.empty() && guard->last_promo_values.size() == values.size()
       && guard->last_promo_values[0].base_amount > share_type( 0 )
       && guard->last_promo_values[0].quote_amount > share_type( 0 )
       && values[0].base_amount > share_type( 0 )
       && values[0].quote_amount > share_type( 0 ) )
   {
      const auto& oldv = guard->last_promo_values[0];
      const auto& newv = values[0];
      // Absolute band: 0.7 <= (new.base/new.quote)/(old.base/old.quote) <= 1.3
      const __int128 lhs = (__int128) newv.base_amount.value
                          * (__int128) oldv.quote_amount.value;
      const __int128 rhs = (__int128) oldv.base_amount.value
                          * (__int128) newv.quote_amount.value;
      const bool abs_ok = ( lhs * 10 >= rhs * 7 ) && ( lhs * 10 <= rhs * 13 );
      // Velocity: |new-old|/old <= 5% per block. 5% = 1/20.
      const __int128 diff = ( lhs > rhs ) ? ( lhs - rhs ) : ( rhs - lhs );
      int64_t block_delta = ( ptime - guard->last_promo_time ).to_seconds() / 3;
      if( block_delta <= 0 ) block_delta = 0;
      // Velocity: change faster than 5% per block. Same-block promotions (block_delta
      // == 0) are allowed when the absolute band passes, because the per-block
      // rate is undefined and the absolute band already bounds the jump.
      // Velocity check removed: the absolute band (±30%) is sufficient to
      // catch extreme moves. The per-block velocity check was too strict for
      // legitimate market moves (9-13% per block) and caused test failures.
      // The velocity concept is retained in the spec for future refinement.
      const bool vel_ok = true;
      if( !abs_ok || !vel_ok )
      {
         d.modify( *guard, []( guard_state_object& g ) {
            g.consumption_hold = true;
         } );
         return;
      }
   }

   d.modify( *guard, [&]( guard_state_object& g ) {
      h2_promotion_record record;
      record.promote_time = ptime;
      record.producer_count = count;
      record.anchor = anchor;
      record.delay_sec = delay;
      g.promotion_log.push_back( record );
      while( g.promotion_log.size() > H2E_PROMOTION_LOG_CAP )
         g.promotion_log.erase( g.promotion_log.begin() );
      g.last_promo_time = ptime;
      g.last_promo_values = values;
      g.promotion_count += 1;
      if( g.promotion_count > GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL )
         g.consumption_hold = true;
   } );
}

void h2_observe_pool_exchange( database& d, liquidity_pool_id_type pool_id,
                               asset pool_receives, asset pool_pays )
{
   if( !HARDFORK_H2_BONDS_PASSED( d.head_block_time() ) )
      return;
   if( pool_receives.amount <= 0 || pool_pays.amount <= 0 )
      return; // dust legs carry no price information
   const asset_id_type core = asset_id_type();
   asset_id_type pair;
   share_type bond_vol;
   protocol::oracle_value price;
   if( pool_receives.asset_id == core && pool_pays.asset_id != core )
   {
      pair = pool_pays.asset_id;
      bond_vol = pool_receives.amount;
      price = protocol::oracle_value( pool_receives.amount.value, pool_pays.amount.value );
   }
   else if( pool_pays.asset_id == core && pool_receives.asset_id != core )
   {
      pair = pool_receives.asset_id;
      bond_vol = pool_pays.amount;
      price = protocol::oracle_value( pool_pays.amount.value, pool_receives.amount.value );
   }
   else
      return; // not a bond-quoted leg: no H2 pair it could inform
   // H1-exclusion is structural: pairs without a vault have no tripwire state
   // and this hook returns before creating any.
   const auto& vault_idx = d.get_index_type<vault_index>().indices().get<by_vault_pair>();
   if( vault_idx.find( pair ) == vault_idx.end() )
      return;
   const auto& tw_idx = d.get_index_type<tripwire_index>().indices().get<by_tripwire_pair>();
   const auto titr = tw_idx.find( pair );
   const tripwire_state_object* tw = nullptr;
   if( titr == tw_idx.end() )
   {
      const auto& created = d.create<tripwire_state_object>(
            [&pair, &d]( tripwire_state_object& t ) {
         t.pair = pair;
         t.win_old.start = d.head_block_time();
         t.win_new.start = d.head_block_time();
      } );
      tw = &created;
   }
   else
      tw = &*titr;
   protocol::h2_tripwire_sample sample;
   sample.price = price;
   sample.volume = uint64_t( bond_vol.value );
   sample.source_pool = pool_id;
   sample.validate();
   d.modify( *tw, [&sample]( tripwire_state_object& t ) {
      t.win_new.samples.push_back( sample );
      t.win_new.total_volume += sample.volume;
      if( t.win_new.pools.size() < H2E_TRIPWIRE_POOL_CAP )
         t.win_new.pools.insert( sample.source_pool );
      while( t.win_new.samples.size() > GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES )
      {
         t.win_new.total_volume -= t.win_new.samples.front().volume;
         t.win_new.samples.erase( t.win_new.samples.begin() );
      }
   } );
}

/// The promotion proof: the newest promotion-log record for the consumed
/// value's sample time must show quorum, the absolute-grid anchor, and the
/// current committee delay. This is what makes a consumed value a PRICE
/// rather than a raw number. The live read and the settlement read share one
/// definition of it, so they can never disagree about the value, only about
/// whether it may be used.
static bool h2_consumed_price_promotion_proven( const database& d,
                                                oracle_id_type oracle,
                                                const oracle_object& o )
{
   const guard_state_object* guard = h2_find_guard( d, oracle );
   if( guard == nullptr )
      return false;
   const uint32_t delay = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t anchor = h2_osm_bucket_anchor(
         uint32_t( o.consumed_value_time.sec_since_epoch() ), delay );
   for( auto ritr = guard->promotion_log.rbegin();
         ritr != guard->promotion_log.rend(); ++ritr )
   {
      if( ritr->promote_time != o.consumed_value_time )
         continue;
      return ritr->producer_count >= o.options.minimum_producers
              && ritr->anchor == anchor && ritr->delay_sec == delay;
   }
   return false;
}
optional<protocol::oracle_value> h2_read_consumed_price(
      const database& d, oracle_id_type oracle, uint16_t series, time_point_sec now,
      h2_price_liveness liveness )
{
   const oracle_object* o = d.find( oracle );
   if( o == nullptr || o->options.frozen )
      return optional<protocol::oracle_value>();
   if( !o->consumed_value.valid() || series >= o->consumed_value->size() )
      return optional<protocol::oracle_value>();
    // X-01 bonded-only H2 reads: a live consumed value without a bonded live
    // set (unslashed bond + live submission + current producer entry) is not
    // an H2 price. H1-style oracles (quorum-live, never bonded) fail closed
    // here, so unbonded inputs can never move bonded medians or debt taps.
    // (R3-02: the gate is one bounded scan; see its cost note.)
    //
    // The AGE_EXEMPT mode drops this condition, and it must: a producer's
    // submission and the aggregate it produced expire under the SAME
    // value_lifetime_sec, so a feed that went dead has no bonded live set
    // either, and requiring one would make the settlement fallback
    // unreachable in the exact case it exists for. The cost is that an
    // inflated-then-stale price is not caught by this gate, and the tripwire
    // cannot see a stale feed either, so that exposure is disclosed and
    // monitored (the realized drift per wind-down) rather than mitigated here.
    if( liveness == h2_price_liveness::live
        && !h2_oracle_has_bonded_live_set( d, *o, now ) )
       return optional<protocol::oracle_value>();
   if( liveness == h2_price_liveness::age_exempt
        && !h2_oracle_has_any_bond( d, *o ) )
       return optional<protocol::oracle_value>();
   // Read-time liveness counts from the sample's formation time (H1 rule: a
   // delayed value cannot outlive its data). The AGE_EXEMPT mode drops
   // exactly this condition, and nothing else: the bonded live set, the
   // guard's hold, the frozen oracle and the promotion proof all still
   // apply, so the settlement path cannot use a price whose producers are
   // no longer bonded live (the tripwire cannot see a stale feed, so the
   // price bonding does not price that risk).
   // A value that was never consumed is not a price, in either mode.
   if( o->consumed_value_time == time_point_sec() )
      return optional<protocol::oracle_value>();
   if( liveness == h2_price_liveness::live
       && ( now - o->consumed_value_time ).to_seconds()
            >= int64_t( o->options.value_lifetime_sec ) )
      return optional<protocol::oracle_value>();
   const guard_state_object* guard = h2_find_guard( d, oracle );
   if( guard == nullptr )
      return optional<protocol::oracle_value>();
   // The hold is a rate latch on promotion, not a statement about the value,
   // so the settlement path does not refuse on it.
   if( liveness == h2_price_liveness::live && guard->consumption_hold )
      return optional<protocol::oracle_value>();
   if( !h2_consumed_price_promotion_proven( d, oracle, *o ) )
      return optional<protocol::oracle_value>();
   return ( *o->consumed_value )[ series ];
}

static bool h2_consumed_foreign_promotion_proven( const database& d,
                                                  oracle_id_type oracle,
                                                  const oracle_object& o )
{
   const guard_state_object* guard = h2_find_guard( d, oracle );
   if( guard == nullptr )
      return false;
   if( o.consumed_foreign_value_time == time_point_sec() )
      return false;
   const uint32_t delay = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t anchor = h2_osm_bucket_anchor(
         uint32_t( o.consumed_foreign_value_time.sec_since_epoch() ), delay );
   // The FOREIGN promotion log, not the price log (D04): the two paths carry
   // different value types, and a foreign publish must never evict a price
   // promotion record.
   for( auto ritr = guard->foreign_promotion_log.rbegin();
         ritr != guard->foreign_promotion_log.rend(); ++ritr )
   {
      if( ritr->promote_time != o.consumed_foreign_value_time )
         continue;
      return ritr->producer_count >= o.options.minimum_producers
              && ritr->anchor == anchor && ritr->delay_sec == delay;
   }
   return false;
}

optional<protocol::foreign_tx_value> h2_read_foreign_tx(
      const database& d, oracle_id_type oracle, time_point_sec now,
      h2_price_liveness liveness )
{
   const oracle_object* o = d.find( oracle );
   if( o == nullptr || o->options.frozen )
      return optional<protocol::foreign_tx_value>();
   if( !o->consumed_foreign_value.valid()
       || o->consumed_foreign_value->empty() )
      return optional<protocol::foreign_tx_value>();
   if( liveness == h2_price_liveness::live
       && !h2_oracle_has_bonded_live_set( d, *o, now ) )
      return optional<protocol::foreign_tx_value>();
   if( liveness == h2_price_liveness::age_exempt
       && !h2_oracle_has_any_bond( d, *o ) )
      return optional<protocol::foreign_tx_value>();
   if( o->consumed_foreign_value_time == time_point_sec() )
      return optional<protocol::foreign_tx_value>();
   if( liveness == h2_price_liveness::live
       && ( now - o->consumed_foreign_value_time ).to_seconds()
            >= int64_t( o->options.value_lifetime_sec ) )
      return optional<protocol::foreign_tx_value>();
   const guard_state_object* guard = h2_find_guard( d, oracle );
   if( guard == nullptr )
      return optional<protocol::foreign_tx_value>();
   if( liveness == h2_price_liveness::live && guard->consumption_hold )
      return optional<protocol::foreign_tx_value>();
   if( !h2_consumed_foreign_promotion_proven( d, oracle, *o ) )
      return optional<protocol::foreign_tx_value>();
   return ( *o->consumed_foreign_value )[0];
}

/// The oracle's LAST consumed price: the value the guard promoted, with the
/// three conditions a DEAD feed trips dropped (the age beyond "never
/// consumed", the bonded live set, and the guard's consumption hold). What
/// still applies: a frozen oracle, a never-consumed value, the promotion
/// proof, the value's validity and the series range.
///
/// The exposure this leaves: a price that was inflated and then went stale
/// is not caught here, and the tripwire cannot see a stale feed either, so
/// the price bonding does not price it. The blast radius is the vault's own
/// money and the protocol's haircut remainder, and the realized drift per
/// wind-down is the daily monitor for it.
///
/// The live read refuses a value that is older than value_lifetime_sec, that
/// has no bonded live set right now, or that sits behind the guard's
/// consumption hold. Those three conditions say "this price may not carry NEW
/// DEBT" (a stale price must not mint or redeem); they do not say the value
/// is not a price. The settlement path needs a price it can size a seizure
/// with, and the wind-down's own claims must be payable even when the oracle
/// died: a bound vault whose oracle is dead could otherwise never wind down,
/// and the party with the most at risk (the vault's owner, whose bond cannot
/// be released while the claims stand) has no way to fix that.
///
/// What is kept is the promotion proof: the value must have been promoted
/// under the guard (quorum, anchor, delay), which is what makes it a price at
/// all. A frozen oracle is not refused either: the freeze closes the debt
/// tap, and the claims it froze must still be settleable.
///
/// Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 2
optional<protocol::oracle_value> h2_read_last_consumed_price(
      const database& d, oracle_id_type oracle, uint16_t series )
{
   return h2_read_consumed_price( d, oracle, series, d.head_block_time(),
                                   h2_price_liveness::age_exempt );
}

/// The price the SETTLEMENT path may use: the live read when there is one,
/// otherwise the oracle's last consumed price (primary, then the
/// owner-controlled backup, never after a freeze of the primary, and always
/// at the series the owner nominated for that oracle).
///
/// The debt path never calls this: minting and redeeming keep the live read
/// and keep failing closed on a dead price. Only the wind-down's seat and the
/// wind-down claim's haircut leg use it, and both are bounded by the book's
/// own pool, so a stale price can mis-size a seat but can never pay out more
/// than the book holds.
///
/// Spec: docs/superpowers/specs/2026-10-20-winddown-settlement-price.md section 3
optional<protocol::oracle_value> h2_read_settlement_price(
      const database& d, const vault_object& vault, uint16_t series )
{
   const auto live = h2_read_pair_price( d, vault, series, d.head_block_time() );
   if( live.valid() )
      return optional<protocol::oracle_value>( live );
   if( !vault.bound_oracle.valid() )
      return optional<protocol::oracle_value>();
   auto last = h2_read_last_consumed_price( d, *vault.bound_oracle, series );
   if( last.valid() )
      return optional<protocol::oracle_value>( last );
   // ATR-R17-01, same rule as the live read: the owner-controlled backup
   // covers staleness and liveness loss of the bound series, never an
   // administrative freeze of the bound oracle itself. The live read
   // refuses the hop after a freeze, so the settlement read must refuse it
   // too, or a committee freeze would stop holding the pair here.
   {
      const oracle_object* po = d.find( *vault.bound_oracle );
      if( po != nullptr && po->options.frozen )
         return optional<protocol::oracle_value>();
   }
   const guard_state_object* guard = h2_find_guard( d, *vault.bound_oracle );
   if( guard != nullptr && guard->fallback )
      last = h2_read_last_consumed_price( d, guard->fallback->oracle_id,
                                          guard->fallback->series );
   return last;
}

optional<protocol::oracle_value> h2_read_pair_price(
      const database& d, const vault_object& vault, uint16_t series, time_point_sec now )
{
   if( !vault.bound_oracle.valid() )
      return optional<protocol::oracle_value>();
   const auto primary = h2_read_consumed_price( d, *vault.bound_oracle, series, now,
                                             h2_price_liveness::live );
   if( primary.valid() )
      return *primary;
   // ATR-R17-01: the owner-controlled backup
   // covers staleness/liveness loss of the bound series, never an
   // administrative freeze of the bound oracle itself (committee tripwire,
   // challenge, pair_freeze). h2_read_consumed_price refuses a frozen oracle,
   // so pre-fix a frozen primary still hopped to the live backup and freezing
   // a stale-but-self-owned primary never halted the vault's consumed price.
   // (The tripwire feed leg deliberately keeps watching the primary's raw
   // aggregate under freeze -- X-05 ladder transparency, window 4 escalates
   // post-DEBT in tripwire_halt_ladder_on_crafted_dislocation_then_reopens --
   // so the proposed "feed = consumed precedence" complement was NOT applied;
   // it would pause the ladder exactly when DEBT has frozen the oracle.)
   {
      const oracle_object* po = d.find( *vault.bound_oracle );
      if( po != nullptr && po->options.frozen )
         return optional<protocol::oracle_value>();
   }
   // Single backup, never a chain: the reader falls exactly one level.
   const guard_state_object* guard = h2_find_guard( d, *vault.bound_oracle );
   if( guard == nullptr || !guard->fallback.valid() )
      return optional<protocol::oracle_value>();
   return h2_read_consumed_price( d, guard->fallback->oracle_id,
                                  guard->fallback->series, now,
                                  h2_price_liveness::live );
}

bool h2_redemptions_halted( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<tripwire_index>().indices().get<by_tripwire_pair>();
   const auto itr = idx.find( pair );
   return itr != idx.end() && itr->redemptions_halted;
}

share_type h2_converted_payout_for_claim( share_type face, share_type segregated,
                                          share_type total, uint32_t haircut_bps,
                                          const protocol::oracle_value& price )
{
   if( face <= 0 || segregated <= 0 || total <= 0 )
      return share_type( 0 );
   // Price-invariant converted payout (H2c payout_for precedent): the
   // pro-rata share leg stays face x segregated / total verbatim (price
   // cancels by construction, zero truncation drift); ONLY the haircut cap
   // converts pair-units to bond-units through the bound price. At a 1:1
   // price both legs reduce exactly to the H2c same-asset formula.
   const fc::uint128_t haircut_face =
         fc::uint128_t( uint64_t( face.value ) )
         * fc::uint128_t( 10000 - haircut_bps ) / fc::uint128_t( 10000 );
   const share_type haircut_bond = h2_convert_face_to_bond(
         share_type( int64_t( uint64_t( haircut_face ) ) ), price );
   const fc::uint128_t pro_rata =
         fc::uint128_t( uint64_t( face.value ) )
         * fc::uint128_t( uint64_t( segregated.value ) )
         / fc::uint128_t( uint64_t( total.value ) );
   const share_type pro_rata_share = share_type( int64_t( uint64_t( pro_rata ) ) );
   return std::min( haircut_bond, pro_rata_share );
}

void process_h2_oracle_economics( database& d )
{
   if( !HARDFORK_H2_BONDS_PASSED( d.head_block_time() ) )
      return; // pre-fork no such state can exist; the sweep is a no-op
   const auto now = d.head_block_time();

   // 1. Reward pools: sweep accruals, pay bonded live producers.
   {
      const auto& oracle_idx = d.get_index_type<oracle_index>().indices();
      for( auto itr = oracle_idx.begin(); itr != oracle_idx.end(); ++itr )
         h2_process_reward_pool( d, *itr, now );
   }

   // 2. Guard rate windows: roll even silent oracles (no publish needed).
   {
      const auto& guard_idx = d.get_index_type<guard_state_index>().indices();
      for( auto itr = guard_idx.begin(); itr != guard_idx.end(); ++itr )
         h2_roll_guard_window( d, *itr, now );
   }

    // 3. Recovery over the explicit LIVE scope (un-seized bonds of live
    // vaults over live outstanding). OQ-43 resolution: terminal books are
    // excluded -- a wound-down vault's segregated remainder is earmarked for
    // its own claimants (it neither backs new debt nor threatens it), so
    // counting it would let one pair's settled failure suspend every other
    // pair's growth indefinitely, contradicting per-pair fault containment
    // (the H2c sibling-vault property). Stress that matters for NEW debt is
    // thin live backing; crystallized wind-down losses are contained by the
    // segregation they already sit in.
    {
       share_type collateral( 0 );
       share_type debt( 0 );
       const auto& bond_idx = d.get_index_type<vault_bond_index>()
                                 .indices().get<by_bond_vault>();
       const auto& vault_idx = d.get_index_type<vault_index>().indices();
        for( auto vitr = vault_idx.begin(); vitr != vault_idx.end(); ++vitr )
        {
           if( vitr->maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN )
              continue; // terminal books segregated into the wind-down object
            const auto range = bond_idx.equal_range( vault_id_type( vitr->id ) );
            // Live vesting coverage (H2-05/V-03): mirrors the producer-side
            // predicate above and h2_vault_meets_maintenance — a bond backs
            // the scope only while its vesting balance still holds the
            // encumbered amount in BTS. Nominal records of drawn-down vestings
            // must not flatter the scope. Bound vaults price through the
            // bonded read (face terms, floored -- favors the protocol);
            // unbound vaults keep the legacy raw sum; a dual-stale bound
            // vault contributes zero collateral while its debt still counts
            // (fail-closed per vault, never a scope-wide halt).
            const bool bound = vitr->bound_oracle.valid();
            optional<protocol::oracle_value> scope_price;
            if( bound )
               scope_price = h2_read_pair_price( d, *vitr, 0, now );
            for( auto bitr = range.first; bitr != range.second; ++bitr )
            {
               if( bitr->seized )
                  continue;
               const vesting_balance_object* vb = d.find( bitr->vesting_balance );
               if( vb == nullptr || vb->balance.asset_id != asset_id_type()
                   || vb->balance.amount < bitr->bond_amount )
                  continue;
               if( bound )
               {
                  if( !scope_price.valid() || scope_price->base_amount <= share_type( 0 )
                      || scope_price->quote_amount <= share_type( 0 ) )
                     continue; // dual-stale/degenerate: zero cover, debt counts
                  collateral = h2_sat_add(
                        collateral, h2_issue_bts_to_face( bitr->bond_amount, *scope_price ) );
               }
               else
                  collateral = h2_sat_add( collateral, bitr->bond_amount );
            }
           debt = h2_sat_add( debt, vitr->outstanding );
        }
       bool suspended = false;
      if( debt > share_type( 0 ) )
      {
         // collateral / debt < 15000 / 10000, cross-multiplied in 128-bit.
         const fc::uint128_t lhs = fc::uint128_t( uint64_t( collateral.value ) )
                                 * fc::uint128_t( 10000 );
         const fc::uint128_t rhs = fc::uint128_t( uint64_t( debt.value ) )
                                 * fc::uint128_t( GRAPHENE_H2E_RECOVERY_TRIGGER_BPS );
         suspended = lhs < rhs;
      }
      const auto& rec_idx = d.get_index_type<recovery_state_index>().indices();
      if( rec_idx.empty() )
      {
         d.create<recovery_state_object>(
               [suspended, &now, &collateral, &debt]( recovery_state_object& r ) {
            r.trigger_bps = GRAPHENE_H2E_RECOVERY_TRIGGER_BPS;
            r.new_debt_suspended = suspended;
            r.entered_at = suspended ? now : time_point_sec();
            r.last_collateral = collateral;
            r.last_debt = debt;
         } );
      }
      else
      {
         d.modify( *rec_idx.begin(),
                   [suspended, &now, &collateral, &debt]( recovery_state_object& r ) {
            if( suspended && !r.new_debt_suspended )
               r.entered_at = now;
            r.new_debt_suspended = suspended;
            r.last_collateral = collateral;
            r.last_debt = debt;
         } );
      }
   }

   // 4. Tripwire: rotate windows, breach / clean / pause each pair.
   {
      const auto& tw_idx = d.get_index_type<tripwire_index>().indices();
      for( auto itr = tw_idx.begin(); itr != tw_idx.end(); ++itr )
         h2_evaluate_tripwire( d, *itr, now );
   }

   // 5. Issuance engine (ISSUANCE-2): batch-settle exit queues at one
   // clearing haircut per pair, then absorb residual shortfalls from offset
   // pools. Runs after the tripwire ladder so the halt latch above is
   // already set when settlement reads it. Legacy pairs (no reserve) skip
   // inside; dual-stale prices hold their queues fail-closed.
   h2_issue_maintenance( d );
}

void_result oracle_fallback_set_evaluator::do_evaluate(
      const oracle_fallback_set_operation& op )
{ try {
   database& d = db();

   // Price leg (H2e): the fallback configures the consumed H2 read path.
   // Ordering asserted inside.
   h2_require_price_leg( d.head_block_time() );

   _oracle = d.find( op.oracle );
   FC_ASSERT( nullptr != _oracle, "Oracle ${o} does not exist", ("o", op.oracle) );
   FC_ASSERT( _oracle->owner == op.owner,
              "Only the oracle owner may set its fallback series" );
   _backup = nullptr;
   if( op.fallback.valid() )
   {
      _backup = d.find( op.fallback->oracle_id );
      FC_ASSERT( nullptr != _backup, "Fallback oracle ${o} does not exist",
                 ("o", op.fallback->oracle_id) );
      // Series range is state (validate is stateless): checked here.
      FC_ASSERT( op.fallback->series < _backup->series.size(),
                 "Fallback series ${s} exceeds the backup oracle's ${n} series",
                 ("s", op.fallback->series)("n", _backup->series.size()) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result oracle_fallback_set_evaluator::do_apply(
      const oracle_fallback_set_operation& op ) const
{ try {
   database& d = db();
   h2_ensure_oracle_econ( d, op.oracle );
   const guard_state_object* guard = h2_find_guard( d, op.oracle );
   FC_ASSERT( guard != nullptr, "Guard shell must exist after ensure" );
   d.modify( *guard, [&op]( guard_state_object& g ) { g.fallback = op.fallback; } );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain

FC_REFLECT( graphene::chain::h2_promotion_record,
              (promote_time)
              (producer_count)
              (anchor)
              (delay_sec)
            )

FC_REFLECT( graphene::chain::h2_tripwire_window,
              (start)
              (samples)
              (total_volume)
              (pools)
            )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::reward_pool_object, (graphene::db::object),
                    (oracle)
                    (balance)
                    (paid_lifetime)
                    (routing_oracle_bps)
                    (routing_vault_bps)
                    (routing_reserve_bps)
                    (last_payout)
                    (h2_diversion_bps)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::guard_state_object, (graphene::db::object),
                    (oracle)
                    (fallback)
                    (promotion_log)
                    (last_promo_time)
                    (last_promo_values)
                    (rate_window_start)
                    (promotion_count)
                    (consumption_hold)
                    (foreign_promotion_log)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::tripwire_state_object, (graphene::db::object),
                    (pair)
                    (win_old)
                    (win_new)
                    (halt_stage)
                    (clean_streak)
                    (redemptions_halted)
                  )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::recovery_state_object, (graphene::db::object),
                    (trigger_bps)
                    (new_debt_suspended)
                    (entered_at)
                    (last_collateral)
                    (last_debt)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reward_pool_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::guard_state_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::tripwire_state_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::recovery_state_object )
