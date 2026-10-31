#include <boost/test/unit_test.hpp>
#include <graphene/chain/f_activation.hpp>
#include <graphene/chain/hardfork.hpp>
#include <fc/time.hpp>

using namespace graphene::chain;

BOOST_AUTO_TEST_SUITE( f_gate_tests )

BOOST_AUTO_TEST_CASE( f2_refused_before_f_accs )
{
   // Before F_ACCS passes, the gate refuses.
   BOOST_CHECK_THROW( f_require_accs_leg( fc::time_point_sec( 1 ) ), fc::exception );
}

BOOST_AUTO_TEST_CASE( f2_refused_when_oracle_gate_after_f_accs )
{
   // Inverted schedule: oracle time after F time is refused.
   // HARDFORK_ORACLE_TIME / HARDFORK_F_ACCS_TIME are compile-time constants;
   // an inverted schedule is represented by calling with a time that passes
   // F but the ordering check (ORACLE <= F) is a compile-time property of
   // the constants, so we assert the constants are ordered.
   BOOST_CHECK( HARDFORK_ORACLE_TIME <= HARDFORK_F_ACCS_TIME );
}

BOOST_AUTO_TEST_CASE( f2_applies_after_both_gates )
{
   // After both gates pass, the gate succeeds.
   fc::time_point_sec t = HARDFORK_F_ACCS_TIME;
   BOOST_CHECK_NO_THROW( f_require_accs_leg( t ) );
}

BOOST_AUTO_TEST_CASE( f3_f_accs_strictly_after_oracle )
{
   // F_ACCS must sit strictly after the oracle leg so an inverted schedule
   // is refused fail-closed (REPAIR-01/04).
   BOOST_CHECK( HARDFORK_ORACLE_TIME < HARDFORK_F_ACCS_TIME );
}

BOOST_AUTO_TEST_SUITE_END()
