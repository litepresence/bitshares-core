#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/protocol/bsip4_ops.hpp>

namespace graphene { namespace chain {

   class bsip4_pool_create_evaluator : public evaluator<bsip4_pool_create_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_pool_create_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         object_id_type do_apply(const operation_type& o);
   };
   class bsip4_pool_deposit_evaluator : public evaluator<bsip4_pool_deposit_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_pool_deposit_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };
   class bsip4_pool_withdraw_evaluator : public evaluator<bsip4_pool_withdraw_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_pool_withdraw_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };
   class bsip4_pool_swap_evaluator : public evaluator<bsip4_pool_swap_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_pool_swap_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };
   class bsip4_claim_founder_fees_evaluator : public evaluator<bsip4_claim_founder_fees_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_claim_founder_fees_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };
   class bsip4_claim_promoter_fees_evaluator : public evaluator<bsip4_claim_promoter_fees_evaluator>
   {
      public:
         typedef graphene::protocol::bsip4_claim_promoter_fees_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };

} } // graphene::chain
