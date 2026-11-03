#pragma once
#include <graphene/chain/evaluator.hpp>
#include <graphene/chain/pamm_object.hpp>
#include <graphene/protocol/pamm.hpp>

namespace graphene { namespace chain {

class pamm_create_evaluator : public evaluator<pamm_create_evaluator>
{
   public:
      typedef pamm_create_operation operation_type;
      void_result do_evaluate(const pamm_create_operation& op);
      generic_operation_result do_apply(const pamm_create_operation& op);
      const pamm_pool_object* _pool = nullptr;
};

class pamm_deposit_evaluator : public evaluator<pamm_deposit_evaluator>
{
   public:
      typedef pamm_deposit_operation operation_type;
      void_result do_evaluate(const pamm_deposit_operation& op);
      generic_operation_result do_apply(const pamm_deposit_operation& op);
      const pamm_pool_object* _pool = nullptr;
};

class pamm_withdraw_evaluator : public evaluator<pamm_withdraw_evaluator>
{
   public:
      typedef pamm_withdraw_operation operation_type;
      void_result do_evaluate(const pamm_withdraw_operation& op);
      generic_operation_result do_apply(const pamm_withdraw_operation& op);
      const pamm_pool_object* _pool = nullptr;
};

class pamm_snapshot_evaluator : public evaluator<pamm_snapshot_evaluator>
{
   public:
      typedef pamm_snapshot_operation operation_type;
      void_result do_evaluate(const pamm_snapshot_operation& op);
      generic_operation_result do_apply(const pamm_snapshot_operation& op);
      const pamm_pool_object* _pool = nullptr;
};

} } // graphene::chain#pragma once
#include <graphene/chain/evaluator.hpp>
namespace graphene { namespace chain { class pamm_evaluator; }}
