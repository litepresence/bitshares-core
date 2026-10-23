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
#include <graphene/protocol/accs_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/db/generic_index.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

#include <fc/uint128.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

using namespace graphene::db;
using graphene::protocol::authority;

/**
 * @brief ACCS gateway declaration: a foreign chain or subtoken gateway.
 * @ingroup object
 */
class accs_gateway_object : public abstract_object<accs_gateway_object, protocol_ids, accs_gateway_object_type>
{
   public:
      uint8_t     chain_id = 0;          ///< Foreign chain enum
      std::string foreign_asset_id;      ///< Empty = native asset
      account_id_type declared_by;       ///< Committee member
      uint32_t    declared_at = 0;       ///< Block number
      uint32_t    min_confirmations = 6; ///< Per-chain minimum
      bool        active = true;          ///< Committee can deactivate
};

/**
 * @brief ACCS orderbook: keyed by (base_asset, chain_id, foreign_asset_id).
 * @ingroup object
 */
class accs_orderbook_object : public abstract_object<accs_orderbook_object, protocol_ids, accs_orderbook_object_type>
{
   public:
      asset_id_type base_asset;          ///< BitShares asset being sold
      uint8_t       chain_id = 0;        ///< Foreign chain
      std::string   foreign_asset_id;    ///< Foreign token identifier
      std::vector<protocol::accs_offer_id_type> open_offers;    ///< Offer IDs in open state
      std::vector<protocol::accs_offer_id_type> matched_offers; ///< Offer IDs in matched state
      uint64_t      next_offer_id = 1;   ///< Monotonic counter
};

/**
 * @brief ACCS offer: Alice's escrowed offer to sell base for foreign crypto.
 * @ingroup object
 */
enum class accs_offer_state : uint8_t
{
   open = 0,
   matched = 1,
   fulfilled = 2,
   expired = 3,
   cancelled = 4
};

class accs_offer_object : public abstract_object<accs_offer_object, protocol_ids, accs_offer_object_type>
{
   public:
      uint64_t    offer_id = 0;          ///< Unique within orderbook
      object_id_type orderbook;           ///< Parent orderbook
      account_id_type seller;            ///< Alice
      asset_id_type base_asset;          ///< Asset being sold
      uint8_t     chain_id = 0;          ///< Foreign chain
      std::string foreign_asset_id;      ///< Foreign token identifier
      share_type  base_amount = 0;        ///< Amount of base asset offered
      share_type  foreign_amount = 0;     ///< Minimum foreign asset wanted
      std::string foreign_recipient;     ///< Alice's foreign-chain address
      share_type  escrow_balance = 0;     ///< Locked base asset
      uint8_t     state = 0;             ///< accs_offer_state
      uint32_t    expiry = 0;            ///< 0 = no expiry
      uint32_t    matched_at = 0;        ///< Block number when matched
      account_id_type matched_buyer;     ///< Bob (0 if unmatched)
      share_type  griefing_bond = 0;     ///< Bob's bond (0 if unmatched)
      uint32_t    sla_deadline = 0;      ///< Block number SLA deadline
      std::string expected_tx_hash;      ///< Foreign tx hash (set at fulfill)
      uint32_t    created_block = 0;     ///< Block number of creation
};

using accs_gateway_multi_index_type = multi_index_container<
   accs_gateway_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;
using accs_gateway_index = generic_index<accs_gateway_object, accs_gateway_multi_index_type>;

using accs_orderbook_multi_index_type = multi_index_container<
   accs_orderbook_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;
using accs_orderbook_index = generic_index<accs_orderbook_object, accs_orderbook_multi_index_type>;

using accs_offer_multi_index_type = multi_index_container<
   accs_offer_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
>;
using accs_offer_index = generic_index<accs_offer_object, accs_offer_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::accs_gateway_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::accs_orderbook_object )
MAP_OBJECT_ID_TO_TYPE( graphene::chain::accs_offer_object )

FC_REFLECT_TYPENAME( graphene::chain::accs_gateway_object )
FC_REFLECT_TYPENAME( graphene::chain::accs_orderbook_object )
FC_REFLECT_TYPENAME( graphene::chain::accs_offer_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::accs_gateway_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::accs_orderbook_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::accs_offer_object )


