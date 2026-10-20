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
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/db/generic_index.hpp>

#include <fc/uint128.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

/**
 * @brief Per-gateway fault containment: one failed vault's segregated bonds
 * paying its holders pro-rata, never another vault, never another pair's
 * reserve. This pair's own reserve backing IS swept into the book (the
 * reserve is the pair's pooled first-loss collateral), bounded by the seat.
 * @ingroup object
 * @ingroup protocol
 *
 * Created by the 150% maintenance hook (top-up expiry) or by vault_resolve
 * executing a sustained challenge. segregated_bond is the seat bound by what
 * the filed exit formula can pay (the reserve leg first, then the bonds, both
 * capped; a bond the bound never reaches keeps its vesting balance with its
 * owner), debited at creation, so the supply audit counts segregated_bond -
 * paid_total as escrowed (H2b precedent). total_claims is the outstanding at freeze (the claim
 * denominator). Redemptions continue into this object while the source vault
 * stays failed closed.
 */
class winddown_vault_object : public abstract_object<winddown_vault_object, protocol_ids, winddown_vault_object_type>
{
   public:
      asset_id_type pair;            ///< Failed pair; immutable
      vault_id_type source_vault;    ///< Failed vault; immutable
      share_type    segregated_bond; ///< Seized slice; the ONLY reimbursement source
      share_type    total_claims;    ///< Outstanding at freeze; the claim denominator
      share_type    claimed_total;   ///< Sum of accepted claim faces (<= total_claims)
      share_type    paid_total;      ///< Sum of payouts made (for the supply audit)
      share_type    senior_paid;     ///< Senior payouts (rmax baseline)
      share_type    junior_paid;     ///< Junior payouts (capped at rmax x senior_paid)
      uint32_t      haircut_bps = 0; ///< Last-good-minus-haircut, 1500 proposal
      uint8_t       state = 0;       ///< GRAPHENE_H2_WINDDOWN_*; complete at zero remainder

      /**
       * Payout math (declared, rounding DOWN against claimants): payout =
       * min(claim * (10000 - haircut) / 10000, claim * segregated / total),
       * every division truncating in 128-bit. Same-asset units in H2c; the
       * live price leg is H2d.
       */
      static share_type payout_for( share_type claim, share_type segregated,
                                    share_type total, uint32_t haircut_bps )
      {
         if( claim <= 0 || segregated <= 0 || total <= 0 )
            return share_type( 0 );
         const fc::uint128_t haircut_face =
               fc::uint128_t( uint64_t( claim.value ) )
               * fc::uint128_t( 10000 - haircut_bps ) / fc::uint128_t( 10000 );
         const fc::uint128_t pro_rata =
               fc::uint128_t( uint64_t( claim.value ) )
               * fc::uint128_t( uint64_t( segregated.value ) )
               / fc::uint128_t( uint64_t( total.value ) );
         const fc::uint128_t payout = std::min( haircut_face, pro_rata );
         return share_type( int64_t( uint64_t( payout ) ) );
      }
};

/**
 * @brief One-shot claim record: one per (winddown, claimant), doubling as the
 * double-claim guard.
 * @ingroup object
 * @ingroup protocol
 */
class winddown_claim_object : public abstract_object<winddown_claim_object, protocol_ids, winddown_claim_object_type>
{
   public:
      winddown_vault_id_type winddown;    ///< Parent wind-down; immutable
      account_id_type        claimant;    ///< Paid account; immutable
      uint8_t                tranche = 0; ///< Senior (0) or junior (1); immutable
      share_type             claim_amount;///< Accepted face; immutable
      share_type             payout;      ///< Paid out; immutable
};

struct by_winddown_vault;  ///< wind-downs by source vault
struct by_winddown_claimant; ///< claims by (winddown, claimant): the double-claim guard

/**
* @ingroup object_index
*/
using winddown_vault_multi_index_type = multi_index_container<
   winddown_vault_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_non_unique< tag<by_winddown_vault>,
         member< winddown_vault_object, vault_id_type, &winddown_vault_object::source_vault >
      >
   >
>;

/**
* @ingroup object_index
*/
using winddown_vault_index = generic_index<winddown_vault_object, winddown_vault_multi_index_type>;

/**
* @ingroup object_index
*/
using winddown_claim_multi_index_type = multi_index_container<
   winddown_claim_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_winddown_claimant>,
         composite_key< winddown_claim_object,
            member< winddown_claim_object, winddown_vault_id_type, &winddown_claim_object::winddown >,
            member< winddown_claim_object, account_id_type, &winddown_claim_object::claimant >
         >
      >
   >
>;

/**
* @ingroup object_index
*/
using winddown_claim_index = generic_index<winddown_claim_object, winddown_claim_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::winddown_vault_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::winddown_claim_object )

FC_REFLECT_TYPENAME( graphene::chain::winddown_vault_object )
FC_REFLECT_TYPENAME( graphene::chain::winddown_claim_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::winddown_vault_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::winddown_claim_object )
