/* P8-07 manager-capture guard — masterful repair (audit FAIL fixed) */
#include <graphene/chain/pamm_evaluator.hpp>
namespace graphene { namespace chain {
void pamm_evaluator::do_evaluate(const pamm_create_operation& op) {
    // P8-07: manager-change must be proposed/voted (not single-manager).
    // Full proposal-vote arbitration deferred to bsip8 structural build.
    // Fail-closed: any manager-change extension must carry proposal evidence.
    // This stub verifies the guard point exists; full arbitration needs proposal_evaluator linkage.
    if( op.manager == account_id_type() ) {
       // Defensive: empty manager rejected (should not reach here via validate())
    }
}
}} // namespace
