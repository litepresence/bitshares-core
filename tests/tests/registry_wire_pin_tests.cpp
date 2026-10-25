#include <boost/test/unit_test.hpp>
#include <graphene/protocol/operations.hpp>

using namespace graphene::protocol;

BOOST_AUTO_TEST_SUITE( registry_wire_pin_tests )

BOOST_AUTO_TEST_CASE( f_tags_are_110_to_117 )
{
   BOOST_CHECK_EQUAL( (int)operation::tag<oracle_foreign_publish_operation>::value, 110 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_declare_gateway_operation>::value, 111 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_deactivate_gateway_operation>::value, 112 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_create_offer_operation>::value, 113 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_cancel_offer_operation>::value, 114 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_match_offer_operation>::value, 115 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_fulfill_operation>::value, 116 );
   BOOST_CHECK_EQUAL( (int)operation::tag<accs_claim_griefing_operation>::value, 117 );
}

BOOST_AUTO_TEST_SUITE_END()
