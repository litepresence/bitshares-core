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
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

/**
 * @brief A vesting-locked vault bond record. The locked funds live in the
 * referenced vesting balance (CDD policy); this object is the encumbrance.
 * @ingroup object
 * @ingroup protocol
 *
 * The vesting pointer is immutable: no update operation exists. Seizure and
 * wind-down accounting arrive with vault lifecycle ops (H2c); until then a
 * bond only locks and (via vault terms) unlocks.
 */
class vault_bond_object : public abstract_object<vault_bond_object, protocol_ids, vault_bond_object_type>
{
   public:
      vault_id_type           vault;            ///< Owning vault; immutable
      account_id_type         owner;            ///< Bond depositor; immutable
      vesting_balance_id_type vesting_balance;  ///< Immutable pointer at the locked funds
      share_type              bond_amount;      ///< Raw lock, equals the vault min_bond
      uint64_t                bond_usd_cents = 0; ///< USD-terms denomination record at lock
      time_point_sec          lock_time;        ///< Head-block time at lock
      uint32_t                unbond_delay_sec = 0; ///< max(challenge window, 7d)
      time_point_sec          unlock_time;      ///< lock_time + unbond_delay_sec
      bool                    seized = false;   ///< Set by wind-down execution (H2c)
};

/**
 * @brief A vesting-locked producer bond record securing one oracle.
 * @ingroup object
 * @ingroup protocol
 *
 * Flat min_bond, 7-day unbond, advancing unlock: each live publication pushes
 * unlock_time out, so an active producer can never drift into releasability
 * while still publishing. The only slash path is dispute loss (H2b).
 */
class producer_bond_object : public abstract_object<producer_bond_object, protocol_ids, producer_bond_object_type>
{
   public:
      oracle_id_type          oracle;           ///< The bonded oracle; immutable
      account_id_type         producer;         ///< Bonded producer; immutable
      vesting_balance_id_type vesting_balance;  ///< Immutable pointer at the locked funds
      share_type              bond_amount;      ///< Raw lock
      uint64_t                bond_usd_cents = 0; ///< USD-terms denomination record at lock
      time_point_sec          lock_time;        ///< Head-block time at lock
      time_point_sec          unlock_time;      ///< Advanced on each live publication
      uint16_t                bootstrap_weight = 0; ///< Decaying federated reputation (H2d decay)
      bool                    slashed = false;  ///< Only slash path is dispute loss (H2b)
};

struct by_bond_vault;      ///< vault bonds by owning vault
struct by_oracle_producer; ///< producer bonds, unique per (oracle, producer)
struct by_bond_unlock_time;///< producer bonds by unlock, for sweeps

/**
* @ingroup object_index
*/
using vault_bond_multi_index_type = multi_index_container<
   vault_bond_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_non_unique< tag<by_bond_vault>,
         member< vault_bond_object, vault_id_type, &vault_bond_object::vault >
      >
   >
>;

/**
* @ingroup object_index
*/
using vault_bond_index = generic_index<vault_bond_object, vault_bond_multi_index_type>;

/**
* @ingroup object_index
*/
using producer_bond_multi_index_type = multi_index_container<
   producer_bond_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_oracle_producer>,
         composite_key< producer_bond_object,
            member< producer_bond_object, oracle_id_type, &producer_bond_object::oracle >,
            member< producer_bond_object, account_id_type, &producer_bond_object::producer >
         >
      >,
      ordered_non_unique< tag<by_bond_unlock_time>,
         member< producer_bond_object, time_point_sec, &producer_bond_object::unlock_time >
      >
   >
>;

using producer_bond_index = generic_index<producer_bond_object, producer_bond_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::vault_bond_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::producer_bond_object )

FC_REFLECT_TYPENAME( graphene::chain::vault_bond_object )
FC_REFLECT_TYPENAME( graphene::chain::producer_bond_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::vault_bond_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::producer_bond_object )
