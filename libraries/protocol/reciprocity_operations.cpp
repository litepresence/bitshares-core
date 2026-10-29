// SPDX-License-Identifier: MIT
#include <graphene/protocol/reciprocity_operations.hpp>
#include <graphene/protocol/reserved_bsip4_slots.hpp>

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

// Reserved BSIP-4 slots 78-117 (P4-01)
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_78_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_78_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_79_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_79_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_80_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_80_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_81_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_81_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_82_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_82_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_83_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_83_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_84_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_84_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_85_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_85_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_86_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_86_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_87_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_87_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_88_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_88_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_89_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_89_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_90_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_90_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_91_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_91_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_92_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_92_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_93_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_93_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_94_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_94_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_95_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_95_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_96_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_96_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_97_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_97_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_98_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_98_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_99_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_99_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_100_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_100_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_101_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_101_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_102_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_102_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_103_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_103_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_104_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_104_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_105_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_105_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_106_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_106_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_107_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_107_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_108_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_108_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_109_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_109_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_110_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_110_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_111_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_111_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_112_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_112_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_113_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_113_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_114_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_114_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_115_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_115_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_116_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_116_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_117_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_117_operation )

