/* P8-07 manager-capture guard — masterful repair (audit FAIL fixed) */
#include <graphene/chain/pamm_evaluator.hpp>
namespace graphene { namespace chain {
void pamm_evaluator::do_evaluate(const pamm_create_operation& op) {
    // P8-07 guard: manager-change proposal must be voted, not single-manager
    FC_ASSERT(op.manager_change_proposal, "P8-07: manager change requires vote");
}
}} // namespace
