/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
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

#include <graphene/protocol/authority.hpp>
#include <graphene/protocol/types.hpp>

#include <graphene/db/generic_index.hpp>

#include <fc/crypto/elliptic.hpp>

namespace graphene { namespace chain {

/**
 * @class blinded_balance_object
 * @brief tracks a blinded balance commitment
 * @ingroup object
 * @ingroup protocol
 */
class blinded_balance_object : public graphene::db::abstract_object<blinded_balance_object,
                                         implementation_ids, impl_blinded_balance_object_type>
{
   public:
      fc::ecc::commitment_type                commitment;
      asset_id_type                           asset_id;
      authority                               owner;
      /// G1 (STEALTH hardfork): creation metadata for decoy-eligibility
      /// (BSIP-2 §1: 24h min age, 100-block skew windows). Appended last;
      /// pre-fork balances carry 0/epoch (treated as grandfathered:
      /// NEVER decoy-eligible, spendable only explicitly or via turnstile).
      uint32_t                                created_block = 0;
      fc::time_point_sec                      created_time;
      /// Task 3 (nullifier migration, BSIP-2): RETIRED cross-path guard.
      /// Ring spends no longer write this flag (decoy-inclusion griefing:
      /// nullified outputs stay decoy-eligible, re-spend is refused by the
      /// nullifier set alone). Post-fork stealth outputs spend ONLY via
      /// op108; the legacy explicit-spend legs (op40/op41) refuse them via
      /// the created_block == 0 gate, not this field. Grandfathered
      /// (pre-fork, created_block == 0) balances keep the legacy legs.
      /// Field RETAINED (never read post-fork except the turnstile
      /// no-extension branch until Task 4): removing it would break object
      /// reflection / wire format. Appended last; default false preserves
      /// pre-fork balances.
      bool                                    spent = false;
};

struct by_commitment;

/**
 * @ingroup object_index
 */
using blinded_balance_obj_multi_idx = multi_index_container<
   blinded_balance_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_commitment>,
         member<blinded_balance_object, commitment_type, &blinded_balance_object::commitment> >
   >
>;
using blinded_balance_index = generic_index<blinded_balance_object, blinded_balance_obj_multi_idx>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE(graphene::chain::blinded_balance_object)

FC_REFLECT_TYPENAME( graphene::chain::blinded_balance_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::blinded_balance_object )
