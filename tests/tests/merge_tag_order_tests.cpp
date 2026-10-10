/*
 * Merge plumbing — per-tree G1 tag position test (Task 2, X-09 per-tree).
 *
 * The final H2R+G1R union lays operations out as one consecutive block:
 * H1 oracle ops at 78-82, H2 ops at 83-103, G1 stealth ops at 104-107.
 * This test pins the G1 leg of that layout inside the G1 tree: after the
 * Task 2 renumber (H2 protocol ops imported into this tree's typelist at
 * 83-103, G1 ops moved to 104-107) all four checks pass.
 *
 * RED state: before the renumber the G1 ops sit at 83-86 (colliding with
 * the H2 block), so every check below FAILS. That failure is the
 * collision evidence, not a regression.
 *
 * MERGE-TIME (final H2R+G1R union task — H2-side assertions live there,
 * not here): extend with the H2 leg pins plus the union
 * uniqueness/consecutiveness check, i.e. the brief's full Step 1 case:
 *
 *   BOOST_AUTO_TEST_CASE(tags_83_to_107_unique_consecutive) {
 *      BOOST_CHECK_EQUAL((int)operation::tag<vault_register_operation>::value, 83);
 *      BOOST_CHECK_EQUAL((int)operation::tag<stealth_transfer_operation>::value, 104);
 *      BOOST_CHECK_EQUAL((int)operation::tag<freeze_blind_operation>::value, 105);
 *      BOOST_CHECK_EQUAL((int)operation::tag<turnstile_reproof_operation>::value, 106);
 *      BOOST_CHECK_EQUAL((int)operation::tag<parity_review_operation>::value, 107);
 *      BOOST_CHECK_EQUAL((int)operation::tag<issuance_exit_request_operation>::value, 103);
 *   }
 *
 * (vault_register_operation == 83 and issuance_exit_request_operation == 103
 * are H2-tree assertions; they belong to the merge task that owns the
 * H2R+G1R union tree. This tree asserts only its own four G1 tags.)
 */
#include <boost/test/unit_test.hpp>

#include <graphene/protocol/operations.hpp>

using namespace graphene::protocol;

BOOST_AUTO_TEST_SUITE(merge_tag_order_tests)

BOOST_AUTO_TEST_CASE(tags_g1_104_to_107)
{
   // (C++14: tag<X>::value is constexpr-static; bind to a local first —
   // passing it straight into BOOST_CHECK_EQUAL odr-uses it via const-ref
   // and fails to link. Same pattern as g1_stealth_tests G4-06 pins.)
   const int tag104 = operation::tag<stealth_transfer_operation>::value;
   const int tag105 = operation::tag<freeze_blind_operation>::value;
   const int tag106 = operation::tag<turnstile_reproof_operation>::value;
   const int tag107 = operation::tag<parity_review_operation>::value;
   BOOST_CHECK_EQUAL( tag104, 104 );
   BOOST_CHECK_EQUAL( tag105, 105 );
   BOOST_CHECK_EQUAL( tag106, 106 );
   BOOST_CHECK_EQUAL( tag107, 107 );
}

// G2-2: op108 (explicit spend) + op109 (pool exchange) appended after the G1
// block, extending the consecutive stealth range to 104–109. Appended-last:
// every earlier tag is untouched by construction.
BOOST_AUTO_TEST_CASE(tags_g1_108_to_109)
{
   const int tag108 = operation::tag<stealth_explicit_spend_operation>::value;
   const int tag109 = operation::tag<stealth_pool_exchange_operation>::value;
   BOOST_CHECK_EQUAL( tag108, 108 );
   BOOST_CHECK_EQUAL( tag109, 109 );
}

BOOST_AUTO_TEST_SUITE_END()
