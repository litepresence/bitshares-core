#pragma once

#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>
#include <graphene/protocol/authority.hpp>

namespace graphene { namespace protocol {

   struct bsip4_pool_create_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 100000; };
      asset           fee;
      account_id_type creator;
      extensions_type extensions;
      account_id_type fee_payer() const { return creator; }
      void validate() const {}
   };

   struct bsip4_pool_deposit_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

   struct bsip4_pool_withdraw_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

   struct bsip4_pool_swap_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

   struct bsip4_claim_founder_fees_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

   struct bsip4_claim_promoter_fees_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::bsip4_pool_create_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip4_pool_deposit_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip4_pool_withdraw_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip4_pool_swap_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip4_claim_founder_fees_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip4_claim_promoter_fees_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::bsip4_pool_create_operation, (fee)(creator)(extensions) )
FC_REFLECT( graphene::protocol::bsip4_pool_deposit_operation, (fee)(account)(extensions) )
FC_REFLECT( graphene::protocol::bsip4_pool_withdraw_operation, (fee)(account)(extensions) )
FC_REFLECT( graphene::protocol::bsip4_pool_swap_operation, (fee)(account)(extensions) )
FC_REFLECT( graphene::protocol::bsip4_claim_founder_fees_operation, (fee)(account)(extensions) )
FC_REFLECT( graphene::protocol::bsip4_claim_promoter_fees_operation, (fee)(account)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_create_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_deposit_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_withdraw_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_swap_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_claim_founder_fees_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_claim_promoter_fees_operation::fee_params_t )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_create_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_deposit_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_withdraw_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_pool_swap_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_claim_founder_fees_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip4_claim_promoter_fees_operation )
