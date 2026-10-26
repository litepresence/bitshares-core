#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/protocol/bsip5_ops.hpp>

namespace graphene { namespace chain {

   class bsip5_claim_rewards_evaluator : public evaluator<bsip5_claim_rewards_evaluator>
   {
      public:
         typedef graphene::protocol::bsip5_claim_rewards_operation operation_type;
         void_result do_evaluate(const operation_type& o);
         void_result do_apply(const operation_type& o);
   };

} } // graphene::chain
