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
#include <graphene/protocol/accs_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void accs_declare_gateway_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( chain_id < 256, "Invalid chain id" );
}

share_type accs_declare_gateway_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_deactivate_gateway_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( chain_id < 256, "Invalid chain id" );
}

share_type accs_deactivate_gateway_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_create_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( base_amount > 0, "Base amount must be positive" );
   FC_ASSERT( foreign_amount > 0, "Foreign amount must be positive" );
   FC_ASSERT( !foreign_recipient.empty(), "Foreign recipient must not be empty" );
   FC_ASSERT( foreign_recipient.size() <= 256, "Foreign recipient too long" );
   FC_ASSERT( chain_id < 256, "Invalid chain id" );
   FC_ASSERT( foreign_asset_id.size() <= 256, "Foreign asset id too long" );
}

share_type accs_create_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_cancel_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

share_type accs_cancel_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_match_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( griefing_bond > 0, "Griefing bond must be positive" );
}

share_type accs_match_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_fulfill_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount > 0, "Fulfillment amount must be positive" );
   FC_ASSERT( !foreign_tx_hash.empty(), "Foreign tx hash must not be empty" );
   FC_ASSERT( foreign_tx_hash.size() <= 256, "Foreign tx hash too long" );
}

share_type accs_fulfill_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_claim_griefing_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

share_type accs_claim_griefing_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation )