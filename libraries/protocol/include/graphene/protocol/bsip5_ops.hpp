#pragma once
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>
#include <graphene/protocol/authority.hpp>

namespace graphene { namespace protocol {

   struct bsip5_claim_rewards_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::bsip5_claim_rewards_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip5_claim_rewards_operation, (fee)(account)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rewards_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rewards_operation )
