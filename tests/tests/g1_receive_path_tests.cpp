/*
 * RP2: wallet-layer receive-path helpers (pure fc crypto; no chain fixture).
 * Spec §4: docs/superpowers/specs/2026-10-12-g1-stealth-receive-path-design.md
 */
#include <boost/test/unit_test.hpp>

#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>
#include <graphene/wallet/stealth_receive.hpp>

#include <fc/crypto/digest.hpp>
#include <fc/io/raw.hpp>

using namespace graphene::protocol;
using namespace graphene::wallet;
using memo_data = graphene::protocol::stealth_confirmation::memo_data;

BOOST_AUTO_TEST_CASE( rp2_single_key_send_scan_round_trip )
{ try {
   auto address = fc::ecc::private_key::generate();
   auto otk     = fc::ecc::private_key::generate();
   const int64_t amt = 12345;
   auto blind = fc::sha256::hash( "rp2-single-blind", 15 );
   memo_data memo;
   memo.amount = asset( amt );
   memo.blinding_factor = blind;
   memo.commitment = fc::ecc::blind( blind, amt );

   // Degenerate: view == spend == address key.
   auto rec = build_recognition( otk, address.get_public_key(), address.get_public_key(), memo );
   BOOST_CHECK( rec.one_time_key == otk.get_public_key() );

   auto match = try_recognition_single_key( rec, address );
   BOOST_REQUIRE( match.valid() );
   BOOST_REQUIRE( match->has_auth );
   BOOST_CHECK( match->memo.amount.amount.value == amt );
   BOOST_CHECK( match->memo.commitment == memo.commitment );
   // auth_priv recomputes the on-chain owner key: auth_pub == address.child(sha256(secret)).
   auto secret = otk.get_shared_secret( address.get_public_key() );
   auto child  = fc::sha256::hash( secret );
   BOOST_CHECK( match->auth_priv.get_public_key()
                == address.get_public_key().child( child ) );
   BOOST_CHECK( verify_memo_commitment( match->memo ) );

   // Not ours: a different address fails.
   auto stranger = fc::ecc::private_key::generate();
   BOOST_CHECK( !try_recognition_single_key( rec, stranger ).valid() );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( rp2_dual_key_watch_only_tallies_without_spend_priv )
{ try {
   auto view  = fc::ecc::private_key::generate();
   auto spend = fc::ecc::private_key::generate();
   auto otk   = fc::ecc::private_key::generate();
   const int64_t amt = 777;
   auto blind = fc::sha256::hash( "rp2-dual-blind", 13 );
   memo_data memo;
   memo.amount = asset( amt );
   memo.blinding_factor = blind;
   memo.commitment = fc::ecc::blind( blind, amt );

   // Sender encrypts to ViewKey; AuthKey from SpendKey_pub.
   auto rec = build_recognition( otk, view.get_public_key(), spend.get_public_key(), memo );

   // Watch-only: view_priv + spend_pub — match succeeds, no auth_priv derived.
   auto wo = try_recognition( rec, view, spend.get_public_key() );
   BOOST_REQUIRE( wo.valid() ); // decrypt + tally path
   BOOST_CHECK( !wo->has_auth );
   BOOST_CHECK( wo->memo.amount.amount.value == amt );
   BOOST_CHECK( verify_memo_commitment( wo->memo ) );

   // Hot: full spend key derives auth_priv = spend_priv.child(sha256(shared)).
   auto hot = try_recognition( rec, view, spend.get_public_key(), spend );
   BOOST_REQUIRE( hot.valid() );
   BOOST_REQUIRE( hot->has_auth );
   auto secret = view.get_shared_secret( otk.get_public_key() );
   auto child  = fc::sha256::hash( secret );
   BOOST_CHECK( hot->auth_priv.get_public_key()
                == spend.get_public_key().child( child ) );

   // Wrong view key: no match.
   auto bad_view = fc::ecc::private_key::generate();
   BOOST_CHECK( !try_recognition( rec, bad_view, spend.get_public_key(), spend ).valid() );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( rp2_memo_tamper_fails_commitment_rederivation )
{ try {
   auto address = fc::ecc::private_key::generate();
   auto otk     = fc::ecc::private_key::generate();
   const int64_t amt = 42;
   auto blind = fc::sha256::hash( "rp2-tamper-blind", 16 );
   memo_data memo;
   memo.amount = asset( amt );
   memo.blinding_factor = blind;
   memo.commitment = fc::ecc::blind( blind, amt );
   auto rec = build_recognition( otk, address.get_public_key(), address.get_public_key(), memo );

   // Tamper: corrupt one ciphertext byte → decrypt garbage → re-derivation fails.
   auto rec_bad = rec;
   BOOST_REQUIRE( !rec_bad.encrypted_memo.empty() );
   rec_bad.encrypted_memo[0] ^= 0x01;
   auto m = try_recognition_single_key( rec_bad, address );
   // Either decrypt/unpack fails closed (no match), or a garbage memo fails verify.
   // try_recognition_single_key MUST NOT return a result whose verify passes on tampered data.
   if( m.valid() )
      BOOST_CHECK( !verify_memo_commitment( m->memo ) );
   // Mandatory check helper itself:
   memo_data bad = memo;
   bad.amount = asset( amt + 1 ); // opening no longer matches commitment
   BOOST_CHECK( !verify_memo_commitment( bad ) );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( rp2_deterministic_address_derivation_versioned_path )
{ try {
   auto a0 = derive_stealth_address_keys( "alpha bravo charlie", 0 );
   auto a1 = derive_stealth_address_keys( "alpha bravo charlie", 1 );
   auto b0 = derive_stealth_address_keys( "alpha bravo charlie", 0 );
   auto c0 = derive_stealth_address_keys( "different brainkey here", 0 );
   // Deterministic: same brainkey+index ⇒ same keys.
   BOOST_CHECK( a0.view_pub  == b0.view_pub );
   BOOST_CHECK( a0.spend_pub == b0.spend_pub );
   // Distinct indices / brainkeys diverge.
   BOOST_CHECK( a0.view_pub  != a1.view_pub );
   BOOST_CHECK( a0.spend_pub != a1.spend_pub );
   BOOST_CHECK( a0.view_pub  != c0.view_pub );
   // view != spend (dual-key property).
   BOOST_CHECK( a0.view_pub != a0.spend_pub );
   // Round-trip: derived keys complete a scan.
   auto otk = fc::ecc::private_key::generate();
   const int64_t amt = 10;
   auto blind = fc::sha256::hash( "rp2-det-blind", 13 );
   memo_data memo;
   memo.amount = asset( amt );
   memo.blinding_factor = blind;
   memo.commitment = fc::ecc::blind( blind, amt );
   auto rec = build_recognition( otk, a0.view_pub, a0.spend_pub, memo );
   auto m = try_recognition( rec, a0.view_priv, a0.spend_pub, a0.spend_priv );
   BOOST_REQUIRE( m.valid() );
} FC_CAPTURE_AND_RETHROW() }
