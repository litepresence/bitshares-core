#include <graphene/chain/bsip4_evaluator.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/database.hpp>
#include <fc/exception/exception.hpp>

namespace graphene { namespace chain {

void_result bsip4_pool_create_evaluator::do_evaluate(const bsip4_pool_create_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
object_id_type bsip4_pool_create_evaluator::do_apply(const bsip4_pool_create_operation& o)
{
   return object_id_type();
}

void_result bsip4_pool_deposit_evaluator::do_evaluate(const bsip4_pool_deposit_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
void_result bsip4_pool_deposit_evaluator::do_apply(const bsip4_pool_deposit_operation& o)
{
   return void_result();
}

void_result bsip4_pool_withdraw_evaluator::do_evaluate(const bsip4_pool_withdraw_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
void_result bsip4_pool_withdraw_evaluator::do_apply(const bsip4_pool_withdraw_operation& o)
{
   return void_result();
}

void_result bsip4_pool_swap_evaluator::do_evaluate(const bsip4_pool_swap_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
void_result bsip4_pool_swap_evaluator::do_apply(const bsip4_pool_swap_operation& o)
{
   return void_result();
}

void_result bsip4_claim_founder_fees_evaluator::do_evaluate(const bsip4_claim_founder_fees_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
void_result bsip4_claim_founder_fees_evaluator::do_apply(const bsip4_claim_founder_fees_operation& o)
{
   return void_result();
}

void_result bsip4_claim_promoter_fees_evaluator::do_evaluate(const bsip4_claim_promoter_fees_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP4_PASSED( db().head_block_time() ),
              "BSIP-4 hardfork has not passed" );
   return void_result();
}
void_result bsip4_claim_promoter_fees_evaluator::do_apply(const bsip4_claim_promoter_fees_operation& o)
{
   return void_result();
}

} } // graphene::chain
