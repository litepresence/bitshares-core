/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once

#include <graphene/protocol/stealth.hpp>
#include <graphene/chain/types.hpp>

#include <graphene/db/generic_index.hpp>

#include <fc/crypto/sha256.hpp>
#include <fc/crypto/elliptic.hpp>

namespace graphene { namespace chain {

/**
 * @brief Spent key image (nullifier). One entry per stealth spend per
 * proof version. Double-spend = same image twice = rejected at insert.
 * @ingroup object
 *
 * Bounded: entries are created only by spends and never deleted except
 * with the balance set they guard; both version sets are enforced during
 * the dual-verify window, V1 frozen (spend-only-via-turnstile) at sunset.
 */
class stealth_nullifier_object : public graphene::db::abstract_object<stealth_nullifier_object,
                                          implementation_ids, impl_stealth_nullifier_object_type>
{
   public:
      fc::sha256      key_image; ///< sha256 of the 33B compressed image point
      uint8_t         proof_version = 0;
      fc::time_point_sec created;
};

struct by_nullifier_image;

using stealth_nullifier_multi_idx = multi_index_container<
   stealth_nullifier_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_nullifier_image>,
         member<stealth_nullifier_object, fc::sha256, &stealth_nullifier_object::key_image> >
   >
>;
using stealth_nullifier_index = generic_index<stealth_nullifier_object, stealth_nullifier_multi_idx>;

/**
 * @brief A committee freeze vote (up to one live vote per member).
 * @ingroup object
 */
struct stealth_freeze_vote
{
   account_id_type       voter;
   bool                  freeze = true;
   fc::time_point_sec    voted_at;
};

/**
 * @brief Singleton consensus state for the stealth subsystem.
 * @ingroup object
 *
 * Created at chain init (genesis replay included). Activation timestamps
 * are RECORDED at the first post-STEALTH maintenance, never assumed:
 * v1_sunset/turnstile_g2 are activation + V1_LIFETIME, so the turnstile
 * date is known from activation day one (BSIP-2 §1).
 */
class stealth_status_object : public graphene::db::abstract_object<stealth_status_object,
                                          implementation_ids, impl_stealth_status_object_type>
{
   public:
      /// Fail-closed halt flag: while set, all blind ops (39/40/41/83/85)
      /// reject in do_evaluate. Set by the tripwire (auto) or the freeze
      /// quorum (manual backup); cleared by the resume quorum.
      bool                  blind_halted = false;
      /// Block number that fired the tripwire (0 = never / manual-only).
      uint32_t              tripwire_fire_block = 0;
      /// Per-block blind-op counter for the cap (block_num, count).
      uint32_t              blind_block_num = 0;
      uint32_t              blind_block_count = 0;
      /// Activation record (0 = pre-activation).
      fc::time_point_sec    stealth_activated_time;
      fc::time_point_sec    v1_sunset_time;
      fc::time_point_sec    turnstile_g2_time;
      /// Live freeze votes, one per member, bounded by committee size.
      /// flat_map is ORDERED (consensus law: no unordered_* anywhere).
      flat_map<account_id_type, stealth_freeze_vote> freeze_votes;
      /// Per-asset shadow of confidential_supply, maintained by the SAME
      /// evaluators that move blind value (post-STEALTH only) but updated
      /// through an independent code path from asset_dynamic_data_object.
      /// Reconciliation compares the two; any divergence (direct state edit
      /// or a future op that forgets a counter) fires the tripwire. Seeded
      /// from live confidential_supply values at activation (first
      /// post-STEALTH maintenance), so pre-fork history reconciles by
      /// construction. flat_map is ORDERED (consensus law).
      flat_map<asset_id_type, share_type> blinded_supply_shadow;
      /// Per-asset count of UNSPENT blinded balances carrying post-fork
      /// creation metadata (decoy candidates; age is ruled per-ring by the
      /// decoy policy, not here). Maintained on insert/spend by the blind
      /// evaluators, post-STEALTH only — this is the O(1) backing of
      /// stealth_pool_depth (no per-evaluate full-pool scan). Spent-but-
      /// retained ring inputs stay indexed as future decoys but do NOT
      /// count here (their real value is gone; the floor guards live
      /// value). Grandfathered (pre-fork, metadata absent) balances never
      /// count. Zero entries are removed; flat_map is ORDERED.
      flat_map<asset_id_type, uint32_t> unspent_blind_count;
};

using stealth_status_multi_idx = multi_index_container<
   stealth_status_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;
using stealth_status_index = generic_index<stealth_status_object, stealth_status_multi_idx>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE(graphene::chain::stealth_nullifier_object)
MAP_OBJECT_ID_TO_TYPE(graphene::chain::stealth_status_object)

FC_REFLECT_TYPENAME( graphene::chain::stealth_nullifier_object )
FC_REFLECT_TYPENAME( graphene::chain::stealth_status_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::stealth_nullifier_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::stealth_status_object )

FC_REFLECT( graphene::chain::stealth_freeze_vote, (voter)(freeze)(voted_at) )
