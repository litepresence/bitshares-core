#include <graphene/chain/f_activation.hpp>
#include <graphene/chain/hardfork.hpp>

#include <fc/exception/exception.hpp>

namespace graphene { namespace chain {

void f_require_accs_leg( const fc::time_point_sec& now )
{
   FC_ASSERT( HARDFORK_ORACLE_PASSED( now ),
              "F (ACCS) requires the oracle hardfork to have passed" );
   FC_ASSERT( HARDFORK_F_ACCS_PASSED( now ),
              "F (ACCS) hardfork has not passed" );
   FC_ASSERT( HARDFORK_ORACLE_TIME <= HARDFORK_F_ACCS_TIME,
              "F (ACCS) may not be scheduled before the oracle leg" );
}

} } // graphene::chain