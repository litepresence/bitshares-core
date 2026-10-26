#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/protocol/bsip5_ops.hpp>

namespace graphene { namespace chain {

   class bsip5_opt_in_evaluator : public evaluator<bsip5_opt_in_evaluator>
   {
      public:
         typedef graphene::protocol::bsip5_opt_in_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };

   class bsip5_payout_evaluator : public evaluator<bsip5_payout_evaluator>
   {
      public:
         typedef graphene::protocol::bsip5_payout_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };

   class bsip5_claim_rebate_evaluator : public evaluator<bsip5_claim_rebate_evaluator>
   {
      public:
         typedef graphene::protocol::bsip5_claim_rebate_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };

} } // graphene::chain
