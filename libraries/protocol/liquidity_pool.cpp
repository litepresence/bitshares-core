/*
 * Copyright (c) 2020 Abit More, and contributors.
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
#include <graphene/protocol/liquidity_pool.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void liquidity_pool_create_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( asset_a < asset_b, "ID of the first asset should be smaller than ID of the second asset" );
   FC_ASSERT( asset_a != share_asset && asset_b != share_asset,
              "Share asset can not be the same as one of the assets in the pool" );
   FC_ASSERT( taker_fee_percent <= GRAPHENE_100_PERCENT, "Taker fee percent should not exceed 100%" );
   FC_ASSERT( withdrawal_fee_percent <= GRAPHENE_100_PERCENT, "Withdrawal fee percent should not exceed 100%" );

   // BSIP-7 AB pool parameter validation (mirrors do_evaluate).
   if( extensions.value.curve_type.valid() )
   {
      uint8_t _curve_type = *extensions.value.curve_type;
      FC_ASSERT( _curve_type == 0 || _curve_type == 2, "Unknown curve type" );
      if( _curve_type == 2 )
      {
         FC_ASSERT( extensions.value.ab_weight_num.valid() && *extensions.value.ab_weight_num > 0,
                    "AB pool requires positive weight numerator" );
         FC_ASSERT( extensions.value.ab_weight_den.valid() && *extensions.value.ab_weight_den > 0,
                    "AB pool requires positive weight denominator" );
         FC_ASSERT( *extensions.value.ab_weight_num < *extensions.value.ab_weight_den,
                    "AB pool weight must be in (0, 1)" );
         FC_ASSERT( extensions.value.ab_p_low.valid() && *extensions.value.ab_p_low > 0,
                    "AB pool requires a positive lower price bound" );
         FC_ASSERT( extensions.value.ab_p_high.valid() && *extensions.value.ab_p_high > *extensions.value.ab_p_low,
                    "AB pool requires P_low < P_high" );
      }
   }
}

void liquidity_pool_delete_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void liquidity_pool_update_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( taker_fee_percent.valid() || withdrawal_fee_percent.valid(), "Should update something" );
   if( taker_fee_percent.valid() )
      FC_ASSERT( *taker_fee_percent <= GRAPHENE_100_PERCENT, "Taker fee percent should not exceed 100%" );
   if( withdrawal_fee_percent.valid() )
      FC_ASSERT( 0 == *withdrawal_fee_percent, "Withdrawal fee percent can only be updated to zero" );
}

void liquidity_pool_deposit_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount_a.amount > 0 && amount_b.amount > 0, "Both amounts of the assets should be positive" );
   FC_ASSERT( amount_a.asset_id < amount_b.asset_id,
              "ID of the first asset should be smaller than ID of the second asset" );
}

void liquidity_pool_withdraw_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( share_amount.amount > 0, "Amount of the share asset should be positive" );
}

void liquidity_pool_exchange_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount_to_sell.amount > 0, "Amount to sell should be positive" );
   FC_ASSERT( min_to_receive.amount > 0, "Minimum amount to receive should be positive" );
   FC_ASSERT( amount_to_sell.asset_id != min_to_receive.asset_id,
             "ID of the two assets should not be the same" );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_create_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_delete_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_update_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_deposit_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_withdraw_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_exchange_operation::fee_params_t )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_create_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_delete_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_update_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_deposit_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_withdraw_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::liquidity_pool_exchange_operation )
