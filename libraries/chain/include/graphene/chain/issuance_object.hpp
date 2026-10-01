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

#include <graphene/chain/types.hpp>
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/db/generic_index.hpp>

namespace graphene { namespace chain {

/**
 * @brief One pending door output: an unvested redeem escrow + its burned face.
 * @ingroup object
 *
 * The vesting balance ID is the load-bearing record (brief: door conversions
 * create identifiable vesting records); owner + face_burned ride along so the
 * REVERT transition can undo the redeem exactly (BTS back to the reserve,
 * face back to the owner/supply/outstanding). Bounded: at most
 * GRAPHENE_H2_ISSUE_PENDING_VEST_CAP entries per reserve, pruned on mature.
 */
struct h2_pending_vesting
{
   vesting_balance_id_type owner_vesting; ///< Redeem escrow, immutable
   account_id_type         owner;         ///< Redeemer, immutable
   share_type              face_burned;   ///< Face to re-mint on REVERT, immutable

   void validate()const
   { FC_ASSERT( face_burned > 0, "Pending vestings record positive burned face" ); }
};

/**
 * @brief One queued batch exit: face burned at request, BTS paid at settle.
 * @ingroup object
 *
 * Bounded: at most GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT entries per
 * reserve and GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS of queued value.
 */
struct h2_exit_request
{
   account_id_type requester; ///< Exit owner, immutable
   share_type      face;      ///< Face burned at request, immutable, > 0
   uint32_t        block = 0; ///< Head block number of the request

   void validate()const
   { FC_ASSERT( face > 0, "Exit requests queue positive face" ); }
};

/**
 * @brief One issuance reserve per vault-backed pair (BSIP-1 section 4).
 * @ingroup object
 * @ingroup protocol
 *
 * The bonded backing behind senior stable: BTS deposits accumulate here,
 * stable supply (face) is the liability they secure, and the FXR junior
 * supply ledger prices dilution without a consensus feed. Created lazily
 * by the first mint for the pair (H2c pairs carry no new state and read
 * no new code paths); at most one record per pair ever exists. Bounded
 * state: per-account FXR lives in normal asset balances of the pinned
 * FXR token (transferable through existing machinery, no new index, no
 * unbounded map on this record); this object carries only pair-level
 * totals. Per-account stable likewise lives in asset balances; the
 * stable_supply here is the issuance-side mirror the rmin gate reads.
 *
 * ISSUANCE-2 appends (appended-last, never inserted): the soft-band
 * partition (exactly N_BANDS amounts per leg, summing to the totals), the
 * band anchor price, the bounded pending-vesting list (REVERT-vs-ABSORB),
 * the bounded batch-exit queue, and the uncovered-shortfall record.
 */
class reserve_object : public abstract_object<reserve_object, protocol_ids, reserve_object_type>
{
   public:
      asset_id_type  pair;             ///< Senior stable UIA; immutable, unique
      asset_id_type  fxr_asset;        ///< Junior token UIA; pinned at creation, immutable
      share_type     bts_balance;      ///< BTS locked in the reserve (incl. fee slices)
      share_type     stable_supply;    ///< Face stable issued against this reserve
      share_type     fxr_supply;       ///< Junior supply ledger (dilution accounting mirror)
      uint32_t       last_ratio_bps = 0; ///< Coverage snapshot in bps (saturating, face terms)
      uint32_t       snapshot_block = 0; ///< Head block number the snapshot was taken at
      share_type     door_used_bts;    ///< BTS door conversions consumed this block
      uint32_t       door_block = 0;   ///< Head block number the door counter belongs to
      // ---- ISSUANCE-2 soft bands (appended-last) ----
      /// Per-band BTS partition, exactly N_BANDS entries, sums to bts_balance.
      /// Bound: N_BANDS amounts, no open arrays (size invariant in code).
      vector<share_type> band_bts;
      /// Per-band face partition, exactly N_BANDS entries, sums to stable_supply.
      /// Bound: N_BANDS amounts, no open arrays (size invariant in code).
      vector<share_type> band_stable;
      /// Consumed price the bands are centered on (bond-per-pair binding
      /// convention); empty (0/0) means unanchored (pre-first-conversion).
      protocol::oracle_value band_anchor;
      uint32_t       band_block = 0;   ///< Head block number the anchor was set at
      // ---- ISSUANCE-2 REVERT-vs-ABSORB (appended-last) ----
      /// Unvested door outputs, oldest first. Bound: PENDING_VEST_CAP
      /// entries (redeems prune matured first, refuse past the cap).
      vector<h2_pending_vesting> pending_vestings;
      // ---- ISSUANCE-2 batch exits (appended-last) ----
      /// Open exit requests, oldest first. Bound: EXIT_QUEUE_MAX_COUNT
      /// entries and EXIT_QUEUE_MAX_BTS of queued value (both refuse).
      vector<h2_exit_request> exit_queue;
      /// Residual shortfall after the offset pool absorbed what it could
      /// (BTS units, overwritten each computation, 0 when covered). The
      /// remainder dilutes through the existing rmax junior path at claim
      /// time -- this record is the handoff, never a second ledger.
      share_type     uncovered_shortfall;
};

struct by_reserve_pair; ///< reserves by pair (unique)

/**
* @ingroup object_index
*/
using reserve_multi_index_type = multi_index_container<
   reserve_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_reserve_pair>,
         member< reserve_object, asset_id_type, &reserve_object::pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using reserve_index = generic_index<reserve_object, reserve_multi_index_type>;

/**
 * @brief One offset pool per issuance pair: the shock absorber (BSIP-1 §4).
 * @ingroup object
 * @ingroup protocol
 *
 * Created lazily by the first offset deposit for the pair; at most one
 * record per pair ever exists. balance is pool-owned BTS (supply-visible in
 * the fixture audit, reserve precedent). claims is the per-account ledger
 * {owner -> amount, available_after}: bounded at OFFSET_MAX_CLAIMANTS
 * entries (refuse past the cap), merged by owner, non-transferable by
 * construction (no operation but offset_claim names a claim, and it requires
 * the owner plus maturity). Absorbs haircut claims pro-rata by the same
 * factor as the balance (floored; absorbers take the first loss), so
 * sum(claims) <= balance holds by construction. The pool absorbs residual
 * shortfalls instantly when a position reads below 100% after bands (exact
 * predicate in h2_offset_should_absorb); the remainder is recorded on the
 * reserve as uncovered_shortfall for the rmax junior path.
 */
struct h2_offset_claim
{
   account_id_type owner;            ///< Claim owner, immutable
   share_type      amount;           ///< BTS owed, > 0
   time_point_sec  available_after;  ///< Head-block time + 7 days, immutable per deposit

   void validate()const
   { FC_ASSERT( amount > 0, "Offset claims record positive amounts" ); }
};

class offset_pool_object : public abstract_object<offset_pool_object, protocol_ids, offset_pool_object_type>
{
   public:
      asset_id_type            pair;    ///< Senior stable UIA; immutable, unique
      share_type               balance; ///< Pool-owned BTS awaiting absorb or claim
      /// Per-account claim ledger, oldest first. Bound:
      /// OFFSET_MAX_CLAIMANTS entries (refuse past the cap, merge by owner).
      vector<h2_offset_claim>  claims;
};

struct by_offset_pair; ///< offset pools by pair (unique)

/**
* @ingroup object_index
*/
using offset_pool_multi_index_type = multi_index_container<
   offset_pool_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_offset_pair>,
         member< offset_pool_object, asset_id_type, &offset_pool_object::pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using offset_pool_index = generic_index<offset_pool_object, offset_pool_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reserve_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::offset_pool_object )

FC_REFLECT_TYPENAME( graphene::chain::reserve_object )
FC_REFLECT_TYPENAME( graphene::chain::offset_pool_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reserve_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::offset_pool_object )
