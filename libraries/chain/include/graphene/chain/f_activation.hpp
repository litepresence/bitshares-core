#pragma once

#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/types.hpp>

#include <fc/time.hpp>

namespace graphene { namespace chain {

class database;

/// F (foreign chain / ACCS) activation gate: requires the oracle gate to have
/// passed first, and refuses an inverted schedule (F before oracle) fail-closed.
void f_require_accs_leg( const fc::time_point_sec& now );

} } // graphene::chain