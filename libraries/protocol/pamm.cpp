#include <graphene/protocol/pamm.hpp>
#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void pamm_create_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( fee_rate_bps <= 10000 );
   FC_ASSERT( delay_seconds > 0, "delay_seconds must be positive" );
   FC_ASSERT( min_tank_level >= 0, "min_tank_level must be non-negative" );
   FC_ASSERT( fee_pool_balance >= 0, "fee_pool_balance must be non-negative" );
}

void pamm_deposit_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( amount.amount > 0 );
   FC_ASSERT( amount.asset_id != asset_id_type(), "amount asset_id must be set" );
}

void pamm_withdraw_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( share_amount.amount > 0 );
   FC_ASSERT( share_amount.asset_id != asset_id_type(), "share_amount asset_id must be set" );
}

void pamm_snapshot_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( nav_den > 0 );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_create_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_deposit_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_withdraw_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_snapshot_operation::fee_params_t )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_create_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_deposit_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_withdraw_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_snapshot_operation )