#include <graphene/protocol/bsip5_ops.hpp>
#include <fc/io/raw.hpp>

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_opt_in_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_opt_in_operation )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_payout_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_payout_operation )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rebate_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rebate_operation )
