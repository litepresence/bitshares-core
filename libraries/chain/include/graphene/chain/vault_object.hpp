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
