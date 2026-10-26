#include <graphene/chain/bsip5_evaluator.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/database.hpp>
#include <fc/exception/exception.hpp>

namespace graphene { namespace chain {

void_result bsip5_claim_rewards_evaluator::do_evaluate(const bsip5_claim_rewards_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP5_PASSED( db().head_block_time() ),
              "BSIP-5 hardfork has not passed" );
   return void_result();
}
void_result bsip5_claim_rewards_evaluator::do_apply(const bsip5_claim_rewards_operation& o)
{
   return void_result();
}

} } // graphene::chain
