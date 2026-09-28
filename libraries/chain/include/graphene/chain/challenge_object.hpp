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
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

/**
 * @brief A bonded theft/failure challenge against one vault, with its vote record.
 * @ingroup object
 * @ingroup protocol
 *
 * Bonds escrow from the challenger's transparent balance at open (the object
 * records totals; funds move only through adjust_balance, never into a
 * separate account). Terminal states persist as the audit trail: H2c execution
 * reads sustained challenges, and the reward pool sweep (H2d) reads the
 * recorded pool shares.
 */
class vault_challenge_object : public abstract_object<vault_challenge_object, protocol_ids, vault_challenge_object_type>
{
   public:
      vault_id_type   vault;            ///< Target vault; immutable
      account_id_type challenger;       ///< Bond poster; immutable
      share_type      challenge_bond;   ///< Total escrowed by the challenger (one rung only)
      uint64_t        challenge_bond_usd_cents = 0; ///< USD-terms record at lock
      string          evidence_memo;    ///< Transparent evidence, 1..1000 chars; immutable
      time_point_sec  opened;           ///< Head-block time at open
      time_point_sec  deadline;         ///< opened + 48h vote window
      flat_map<account_id_type, uint8_t> votes; ///< Committee voter -> decision; one each
      uint8_t         state = 0;        ///< Lifecycle state (GRAPHENE_H2_CHALLENGE_*); terminal sticks
      account_id_type finder;           ///< Finder-fee recipient on forfeit (decisive voter)
      // ---- H2c execution (appended-last, never inserted) ----
      bool            executed = false; ///< Set by vault_resolve (sustained -> wind-down)
};

struct by_challenge_vault;   ///< challenges by target vault (concurrency source of truth lives on the vault)
struct by_challenge_deadline;///< challenges by vote deadline (expiry sweep)

/**
* @ingroup object_index
*/
using vault_challenge_multi_index_type = multi_index_container<
   vault_challenge_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_non_unique< tag<by_challenge_vault>,
         member< vault_challenge_object, vault_id_type, &vault_challenge_object::vault >
      >,
      ordered_non_unique< tag<by_challenge_deadline>,
         member< vault_challenge_object, time_point_sec, &vault_challenge_object::deadline >
      >
   >
>;

/**
* @ingroup object_index
*/
using vault_challenge_index = generic_index<vault_challenge_object, vault_challenge_multi_index_type>;

/**
 * @brief A bonded dispute against one retained oracle aggregate, with rounds and votes.
 * @ingroup object
 * @ingroup protocol
 *
 * Round 1 opens with the base bond; each escalation doubles the rung and opens
 * a fresh 48h window, capped at 3 rounds. Per-side totals (never per-round
 * vectors: resolution forfeits or returns whole sides) keep the object bounded.
 * The defender is the accused producer; their bond is marked slashed on
 * sustain, and seizure math arrives with wind-downs (H2c).
 */
class oracle_dispute_object : public abstract_object<oracle_dispute_object, protocol_ids, oracle_dispute_object_type>
{
   public:
      oracle_id_type  oracle;           ///< Target oracle; immutable
      account_id_type challenger;       ///< Round-1 bond poster; immutable
      account_id_type defender;         ///< Accused producer; immutable
      time_point_sec  accused_time;     ///< Retained history entry under dispute; immutable
      uint16_t        accused_series = 0; ///< Series index inside that entry; immutable
      uint8_t         round = 1;        ///< 1..3 (GRAPHENE_H2_DISPUTE_MAX_ROUNDS)
      share_type      challenger_bonds; ///< Total escrowed by the challenger across rounds
      share_type      defender_bonds;   ///< Total escrowed by the defender across rounds
      share_type      round1_bond;      ///< Immutable raw base: rung r costs base x 2^(r-1)
      uint64_t        round1_bond_usd_cents = 0; ///< Immutable USD-terms base for the ladder
      uint64_t        challenger_bonds_usd_cents = 0; ///< USD-terms sum of challenger rungs
      uint64_t        defender_bonds_usd_cents = 0;   ///< USD-terms sum of defender rungs
      string          evidence_memo;    ///< Transparent evidence, 1..1000 chars; immutable
      time_point_sec  opened;           ///< Head-block time at open
      time_point_sec  round_deadline;   ///< Current round's vote deadline (reset per escalation)
      flat_map<account_id_type, uint8_t> votes; ///< Committee voter -> decision; one each
      uint8_t         state = 0;        ///< Lifecycle state (GRAPHENE_H2_CHALLENGE_*); terminal sticks
      account_id_type finder;           ///< Finder-fee recipient on forfeit
};

struct by_dispute_oracle;    ///< disputes by target oracle
struct by_dispute_deadline;  ///< disputes by round deadline (expiry sweep)
struct by_dispute_defender;  ///< disputes by accused producer (bond-release gate)

/**
* @ingroup object_index
*/
using oracle_dispute_multi_index_type = multi_index_container<
   oracle_dispute_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_non_unique< tag<by_dispute_oracle>,
         member< oracle_dispute_object, oracle_id_type, &oracle_dispute_object::oracle >
      >,
      ordered_non_unique< tag<by_dispute_deadline>,
         member< oracle_dispute_object, time_point_sec, &oracle_dispute_object::round_deadline >
      >,
      ordered_non_unique< tag<by_dispute_defender>,
         member< oracle_dispute_object, account_id_type, &oracle_dispute_object::defender >
      >
   >
>;

/**
* @ingroup object_index
*/
using oracle_dispute_index = generic_index<oracle_dispute_object, oracle_dispute_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::vault_challenge_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::oracle_dispute_object )

FC_REFLECT_TYPENAME( graphene::chain::vault_challenge_object )
FC_REFLECT_TYPENAME( graphene::chain::oracle_dispute_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::vault_challenge_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::oracle_dispute_object )
