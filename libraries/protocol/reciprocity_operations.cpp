// SPDX-License-Identifier: MIT
#include <graphene/protocol/reciprocity_operations.hpp>

namespace graphene { namespace protocol {

void reciprocity_pool_create_operation::validate()const
{
   FC_ASSERT( assets.size() >= 2, "Pool must have at least 2 assets", ("code", 20) );
   FC_ASSERT( assets.size() <= MAX_TOKENS, "Pool exceeds max assets", ("code", 20) );
   FC_ASSERT( share_asset != asset_id_type(), "Zero share asset address", ("code", 8) );
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
}

void reciprocity_pool_swap_operation::validate()const
{
   FC_ASSERT( pool != reciprocity_pool_id_type(), "Zero pool address", ("code", 8) );
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
   FC_ASSERT( !amounts_to_sell.empty(), "Empty amounts_to_sell", ("code", 20) );
   FC_ASSERT( !min_to_receive.empty(), "Empty min_to_receive", ("code", 20) );
}

void reciprocity_pool_add_liquidity_operation::validate()const
{
   FC_ASSERT( pool != reciprocity_pool_id_type(), "Zero pool address", ("code", 8) );
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
   FC_ASSERT( !amounts.empty(), "Empty amounts", ("code", 20) );
   FC_ASSERT( amounts.size() <= MAX_TOKENS, "Amounts exceeds max assets", ("code", 20) );
}

void reciprocity_pool_remove_liquidity_operation::validate()const
{
   FC_ASSERT( pool != reciprocity_pool_id_type(), "Zero pool address", ("code", 8) );
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
   FC_ASSERT( share_amount.amount > 0, "Share amount must be positive", ("code", 30) );
}

void reciprocity_claim_founder_royalty_operation::validate()const
{
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
   FC_ASSERT( token != asset_id_type(), "Zero token address", ("code", 8) );
}

void reciprocity_claim_promoter_royalty_operation::validate()const
{
   FC_ASSERT( account != account_id_type(), "Zero account address", ("code", 8) );
   FC_ASSERT( token != asset_id_type(), "Zero token address", ("code", 8) );
}

}} // graphene::protocol

#include <fc/io/raw.hpp>

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_create_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_add_liquidity_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_remove_liquidity_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_swap_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_founder_royalty_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_promoter_royalty_operation::fee_params_t )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_create_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_add_liquidity_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_remove_liquidity_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_swap_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_founder_royalty_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_promoter_royalty_operation )

