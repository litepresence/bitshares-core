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
#include <graphene/chain/accs_object.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace chain {

} } // graphene::chain

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::accs_gateway_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::accs_orderbook_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::accs_offer_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::accs_consumed_tx_object )

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::accs_gateway_object, (graphene::db::object),
                    (chain_id)(foreign_asset_id)(foreign_asset_code)(oracle_id)(declared_by)(declared_at)
                    (min_confirmations)(active)(consumed_tx_count) )
FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::accs_orderbook_object, (graphene::db::object),
                    (base_asset)(chain_id)(foreign_asset_id)(open_offers)
                    (matched_offers)(next_offer_id) )
FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::accs_offer_object, (graphene::db::object),
                    (offer_id)(orderbook)(seller)(base_asset)(chain_id)
                    (foreign_asset_id)(base_amount)(foreign_amount)(foreign_recipient)
                    (escrow_balance)(state)(expiry)(matched_at)(matched_buyer)
                    (griefing_bond)(sla_deadline)(expected_tx_hash)(created_block) )
FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::accs_consumed_tx_object, (graphene::db::object),
                    (chain_id)(foreign_asset_id)(tx)(consumed_block) )
