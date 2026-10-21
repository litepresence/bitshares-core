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
#include <graphene/protocol/vault_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/db/generic_index.hpp>

#include <fc/uint128.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

using graphene::protocol::authority;

/**
 * @brief A threshold-authority vault set bound to one pair, with its terms.
 * @ingroup object
 * @ingroup protocol
 *
 * Mint authority sits with the vault authority, never an issuer key. Coverage
 * (bonds over outstanding) blocks mint below secure_ratio; the maintenance
 * state machine that acts on it arrives with vault lifecycle ops (H2c).
 */
/// One outstanding foreign redeem: the user who burned, the amount burned, the
/// foreign-chain address to unlock to, the SLA deadline, and whether the
/// unlock proof has arrived. The vault carries a bounded vector of these.
struct foreign_redeem_record
{
   account_id_type      redeemer;          ///< Who burned; the miss reimburses them
   share_type           amount = 0;        ///< Burned amount (foreign units)
   std::string          recipient;         ///< Foreign-chain address to unlock to
   protocol::foreign_tx_id deposit_id;    ///< The redeem's deposit id
   time_point_sec       sla_deadline;      ///< Missed-deadline freeze point (72h)
   bool                 unlocked = false;  ///< Unlock proof published
};

} } // graphene::chain

FC_REFLECT( graphene::chain::foreign_redeem_record,
            (redeemer)(amount)(recipient)(deposit_id)(sla_deadline)(unlocked) )

namespace graphene { namespace chain {

class vault_object : public abstract_object<vault_object, protocol_ids, vault_object_type>
{
   public:
      asset_id_type vault_pair;        ///< The vault-backed UIA this set secures; immutable
      authority     vault_authority;   ///< Threshold custody set; immutable except via rotate (H2c)
      share_type    min_bond;          ///< Committed raw lock floor, in bond_asset smallest units
      uint64_t      min_bond_usd_cents = 0; ///< USD-terms denomination record at lock
      asset_id_type bond_asset;        ///< BTS at genesis
      uint32_t      secure_ratio_bps = 0;   ///< Genesis-committed; raise-only via timelock (H2c)
      uint32_t      challenge_window_sec = 0;
      share_type    outstanding;      ///< Liabilities minted against this vault, smallest units
      bool          frozen = false;   ///< Fail-closed: while set, mint blocked
      // ---- H2b dispute bookkeeping (appended-last, never inserted) ----
      uint16_t      open_challenges = 0; ///< Open challenges (concurrency source of truth)
      time_point_sec last_challenge_time; ///< Last challenge open (24h cooldown anchor)
      share_type    forfeit_pool_balance; ///< Accrued 15% forfeit shares, swept by H2d
       // ---- H2c vault lifecycle (appended-last, never inserted) ----
       uint8_t       maintenance_state = 0; ///< GRAPHENE_H2_VAULT_* (healthy/topup/winddown)
       time_point_sec top_up_deadline;  ///< Head-block time: breach + 36h top-up window
       time_point_sec last_breach_time; ///< Head-block time the current breach was found
       // ---- H2d oracle economics (appended-last, never inserted) ----
       optional<oracle_id_type> bound_oracle; ///< Canonical pair<->oracle binding,
            ///< pinned by the first pair_freeze and enforced thereafter; empty
            ///< means the vault has no price leg (H2c behavior preserved)
       bool          tripwire_door_hold = false; ///< While set, the H2c sweep
            ///< must not clear frozen: the tripwire owns the door, not coverage
        // ---- H3 foreign backing asset (appended-last, never inserted) ----
        uint8_t       backing_chain = 0; ///< 0 = BitShares (H2 vault),
             ///< 1 = bitcoin, 2 = ethereum, 3 = solana
        std::string   backing_asset; ///< Foreign asset id string; empty = BitShares asset
        // ---- H3 committed exchange rate (appended-last, never inserted) ----
        // The rate the vault commits at registration and never changes: one
        // foreign-asset unit is worth backing_rate_num / backing_rate_den
        // bond-asset raw units. It converts a foreign outstanding into bond
        // terms for the coverage check and a foreign burn into a bond
        // reimbursement. A zero denominator means the vault has no rate
        // (an H2 vault, whose outstanding is already in bond terms).
        uint64_t      backing_rate_num = 0;
        uint64_t      backing_rate_den = 1;
        // ---- H3 foreign redeem SLA tracking (appended-last, never inserted) ----
        // One record per outstanding foreign redeem. Bounded: a vault can
        // carry at most GRAPHENE_H3_MAX_PENDING_REDEEMS outstanding redeems,
        // so the vector cannot grow without limit.
        std::vector<foreign_redeem_record> foreign_redeems;

      /// @return whether a mint of @p amount stays within the secure ratio
      bool mint_within_secure_ratio( share_type bonds, share_type new_outstanding )const
      {
         // Cross-multiplied integer compare, no division and no floats:
         // bonds / new_outstanding >= secure_ratio_bps / 10000.
         if( new_outstanding <= 0 )
            return true;
         if( bonds <= 0 )
            return false;
         const fc::uint128_t lhs = fc::uint128_t( bonds.value )
                                 * fc::uint128_t( 10000 );
         const fc::uint128_t rhs = fc::uint128_t( new_outstanding.value )
                                 * fc::uint128_t( secure_ratio_bps );
         return lhs >= rhs;
      }
};

/// @brief Convert a foreign-asset amount into bond-asset raw units at the
/// vault's committed rate. Integer math only, rounded DOWN against the
/// vault (never rounds in the vault's favor on a reimbursement). A zero
/// denominator means the vault has no committed rate, so the conversion is
/// undefined and the caller must refuse.
///
/// Spec: docs/superpowers/specs/2026-10-20-h3-bitcoin-accs-foreign-chain-vaults-design.md section 7
inline share_type h2_vault_convert_to_bond_terms( const vault_object& v,
                                                  share_type foreign_amount )
{
   if( v.backing_rate_den == 0 )
      return share_type( 0 );
   const fc::uint128_t scaled = fc::uint128_t( foreign_amount.value )
                              * fc::uint128_t( v.backing_rate_num );
   const fc::uint128_t out = scaled / fc::uint128_t( v.backing_rate_den );
   if( out > fc::uint128_t( GRAPHENE_MAX_SHARE_SUPPLY ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( out ) );
}

/// @brief Whether a vault is backed by a foreign chain asset (H3).
/// A vault is foreign-backed when its backing_chain is non-zero (0 = BitShares,
/// the degenerate H2 vault). Consensus law: select-don't-compute; this is a
/// pure field read.
inline bool h2_vault_is_foreign_backed( const vault_object& v )
{
   return v.backing_chain != 0;
}

struct by_vault_pair; ///< unique while live: one vault set per pair (H2a minimum)

/**
* @ingroup object_index
*/
using vault_multi_index_type = multi_index_container<
   vault_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_vault_pair>,
         member< vault_object, asset_id_type, &vault_object::vault_pair >
      >
   >
>;

/**
* @ingroup object_index
*/
using vault_index = generic_index<vault_object, vault_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::vault_object )

FC_REFLECT_TYPENAME( graphene::chain::vault_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::vault_object )
