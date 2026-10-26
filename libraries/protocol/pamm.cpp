#include <graphene/protocol/pamm.hpp>
#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void pamm_create_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( fee_rate_bps <= 10000 );
}

void pamm_deposit_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( amount.amount > 0 );
}

void pamm_withdraw_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0 );
   FC_ASSERT( share_amount.amount > 0 );
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