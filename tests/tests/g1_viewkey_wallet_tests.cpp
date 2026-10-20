/*
 * ViewKey ring-authorization gap — the WALLET half.
 *
 * Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-design.md section 2.1
 * Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
 *
 * The hole under test: the recognition memo carried an opening that was
 * DERIVED FROM THE VIEW KEY, so a private-view-key holder recovered it (from
 * the memo, which is encrypted to the view key by design) and could construct
 * a valid ring spend over the output. The wallet half closes it for the
 * new-output path (op39): the opening is derived from the SPEND key, the memo
 * ships no opening (the zero marker), a dual-key address is never silently
 * degraded to the single-key path, and a watch-only recognition is marked
 * tally-only and refused by every spend builder.
 *
 * The consensus half (the V3 spend-key proof on ring inputs) is a separate,
 * specialist-gated task; nothing here touches consensus code.
 */
#include <boost/test/unit_test.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/confidential_object.hpp>

#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>

#include <graphene/app/database_api.hpp>
#include <graphene/app/api.hpp>
#include <graphene/wallet/wallet.hpp>
#include <graphene/wallet/stealth_receive.hpp>

#include <fc/crypto/digest.hpp>
#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;
using namespace graphene::protocol;

BOOST_FIXTURE_TEST_SUITE( g1_viewkey_wallet_tests, database_fixture )

namespace {

/// The opening (Pedersen blind factor) of a stealth output, derived from one
/// side's private key and the other side's public key:
///   opening = H( H( ECDH(priv, pub) ) )
/// ECDH is symmetric, so the sender (otk private, spend public) and the
/// recipient (spend private, otk public) compute the SAME value.
fc::sha256 vk_opening( const fc::ecc::private_key& priv, const fc::ecc::public_key& pub )
{
   auto secret = priv.get_shared_secret( pub );
   auto child  = fc::sha256::hash( secret );
   return fc::sha256::hash( child );
}

/// True when the opening opens the commitment for `value`.
bool vk_opens( const fc::sha256& opening, int64_t value, const fc::ecc::commitment_type& commitment )
{
   auto c = fc::ecc::blind( opening, (uint64_t)value );
   return fc::ecc::verify_sum( { c }, { commitment }, 0 );
}

/// The zero marker: a memo that carries it holds NO opening at all.
bool vk_is_zero_marker( const fc::sha256& v )
{
   return v == fc::sha256();
}

} // namespace

// ---------------------------------------------------------------------------
// Test 1: a watch-only wallet cannot build a spend from a recognized output,
// and the refusal is the TALLY-ONLY MARKER, not an incidental path.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_watch_only_cannot_spend_recognized_output )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-hot-password" );
   W.unlock( "vk-hot-password" );
   for( const auto& f : { "vk-hot-test.json", "vk-watch-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-hot-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk alice brainkey words here";
   W.create_stealth_address( "alice-st", bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"alice-st","200"}}, false );
   BOOST_REQUIRE_EQUAL( confirm.trx.operations.size(), 1u );
   PUSH_TX( db, confirm.trx );
   generate_block();

   // The watch-only wallet holds the VIEW key only.
   graphene::wallet::wallet_data wdata2;
   wdata2.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api WO( wdata2, rapi );
   WO.set_password( "vk-watch-password" );
   WO.unlock( "vk-watch-password" );
   WO.set_wallet_filename( "vk-watch-test.json" );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );
   WO.import_stealth_view_key( "alice-wo", graphene::utilities::key_to_wif( keys.view_priv ),
                               public_key_type( keys.spend_pub ) );

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = WO.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 1u );
   BOOST_CHECK( fresh[0].amount.amount == core.amount( 20000000 ).amount );
   // The watch-only recognition is marked TALLY-ONLY explicitly (not merely
   // "an authority key happens to be missing").
   BOOST_CHECK( fresh[0].tally_only );

   // The watch-only wallet must refuse to build a spend, and the refusal must
   // name the tally-only marker (the explicit marker, not the incidental
   // absence of an authority key).
   std::string err;
   try { WO.transfer_from_blind( "alice-wo", "dan", "10", "1.3.0", false ); }
   catch( const fc::exception& e ) { err = e.to_detail_string(); }
   BOOST_REQUIRE( !err.empty() );
   BOOST_CHECK_MESSAGE( err.find( "tally-only" ) != std::string::npos, err );

   // Wallet-file compat: an old receipt (written before the marker existed)
   // loads with the marker OFF. Its watch-only receipts are still refused by
   // the empty-authority arm of blind_receipt_spendable.
   {
      graphene::wallet::blind_receipt r;
      fc::variant v;
      fc::to_variant( r, v, 20 );
      BOOST_CHECK_EQUAL( v.get_object()["tally_only"].as_bool(), false );
      fc::variant empty_obj = fc::variant( fc::variant_object() );
      graphene::wallet::blind_receipt back;
      fc::from_variant( empty_obj, back, 20 );
      BOOST_CHECK_EQUAL( back.tally_only, false );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 2: a spend-key wallet can build AND push the spend of the same
// recognized output, and the opening it spends with is the SPEND-derived one.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_spend_key_wallet_can_build_and_push_spend )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-hot2-password" );
   W.unlock( "vk-hot2-password" );
   for( const auto& f : { "vk-hot2-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-hot2-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk bob brainkey words here";
   W.create_stealth_address( "bob-st", bki, 0 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"bob-st","200"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 1u );
   // A hot (spend-key) recognition is NOT tally-only: it is spendable.
   BOOST_CHECK( !fresh[0].tally_only );

   // The receipt the hot wallet recorded must carry the SPEND-derived opening
   // (recomputed from the spend key), not a view-derived one.
   auto spend_opening = vk_opening( keys.spend_priv, fresh[0].conf.one_time_key );
   BOOST_CHECK( fresh[0].data.blinding_factor == spend_opening );
   BOOST_CHECK( vk_opens( fresh[0].data.blinding_factor,
                          fresh[0].amount.amount.value, fresh[0].data.commitment ) );

   auto spend = W.transfer_from_blind( "bob-st", "dan", "150", "1.3.0", false );
   BOOST_CHECK( !spend.trx.operations.empty() );
   PUSH_TX( db, spend.trx );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 3: a NEW output's memo carries NO usable opening. The view-key holder
// decrypts the memo, and the opening it can derive does NOT open the output.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_new_output_memo_carries_no_usable_opening )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-memo-password" );
   W.unlock( "vk-memo-password" );
   for( const auto& f : { "vk-memo-test.json", "vk-memo-watch.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-memo-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk carol brainkey words here";
   W.create_stealth_address( "carol-st", bki, 0 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"carol-st","200"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   // The watch-only holder decrypts the memo (through the chain scan) and
   // learns the amount and the commitment — and nothing else.
   graphene::wallet::wallet_data wdata2;
   wdata2.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api WO( wdata2, rapi );
   WO.set_password( "vk-memo-watch-password" );
   WO.unlock( "vk-memo-watch-password" );
   WO.set_wallet_filename( "vk-memo-watch.json" );
   WO.import_stealth_view_key( "carol-wo", graphene::utilities::key_to_wif( keys.view_priv ),
                               public_key_type( keys.spend_pub ) );

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = WO.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 1u );
   const auto& memo = fresh[0].data;

   // The memo carries NO opening: the zero marker.
   BOOST_CHECK( vk_is_zero_marker( memo.blinding_factor ) );
   BOOST_CHECK( graphene::wallet::memo_is_openingless( memo ) );

   // The opening the VIEW-key holder can derive does not open the output.
   auto view_opening = vk_opening( keys.view_priv, fresh[0].conf.one_time_key );
   BOOST_CHECK( !vk_opens( view_opening, memo.amount.amount.value, memo.commitment ) );

   // The SPEND-derived opening does open it — the holder of the spend key can.
   auto spend_opening = vk_opening( keys.spend_priv, fresh[0].conf.one_time_key );
   BOOST_CHECK( vk_opens( spend_opening, memo.amount.amount.value, memo.commitment ) );

   // The marker dispatch: an openingless memo's opening is recomputed from
   // the SPEND key, and a holder WITHOUT the spend key gets nothing at all
   // (the output stays closed to a view-key holder).
   {
      auto sel = graphene::wallet::select_opening( memo,
                                                   fc::optional<fc::ecc::private_key>( keys.spend_priv ),
                                                   fresh[0].conf.one_time_key );
      BOOST_REQUIRE( sel.valid() );
      BOOST_CHECK( *sel == spend_opening );
      auto wo_sel = graphene::wallet::select_opening( memo,
                                                       fc::optional<fc::ecc::private_key>(),
                                                       fresh[0].conf.one_time_key );
      BOOST_CHECK( !wo_sel.valid() );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 4: a LEGACY output (a memo with a nonzero marker) still opens from its
// memo. The legacy path is grandfathered: the memo carries the opening and
// the recipient reads it from there.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_legacy_output_still_opens_from_its_memo )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-legacy-password" );
   W.unlock( "vk-legacy-password" );
   for( const auto& f : { "vk-legacy-test.json", "vk-legacy-bob.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-legacy-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   // A legacy recipient: a plain (single-key) address, never dual-key. The
   // sender only needs the address key (labeled); the recipient's wallet
   // holds the private key.
   const std::string legacy_bk = "legacy bob brainkey words";
   auto bob = fc::ecc::private_key::regenerate( fc::sha256::hash( legacy_bk.c_str(), legacy_bk.size() ) );
   BOOST_CHECK( W.set_key_label( public_key_type( bob.get_public_key() ), "bob-legacy" ) );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"bob-legacy","200"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   // The sender's memo still carries the opening (the legacy marker is
   // nonzero) and it is the legacy view-derived one.
   const auto& out = confirm.outputs[0];
   BOOST_CHECK( !vk_is_zero_marker( out.decrypted_memo.blinding_factor ) );
   auto legacy_opening = vk_opening( bob, out.confirmation.one_time_key );
   BOOST_CHECK( out.decrypted_memo.blinding_factor == legacy_opening );

   // The recipient opens it from the memo.
   graphene::wallet::wallet_data bdata;
   bdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api BR( bdata, rapi );
   BR.set_password( "vk-bob-password" );
   BR.unlock( "vk-bob-password" );
   BR.set_wallet_filename( "vk-legacy-bob.json" );
   BR.create_blind_account( "bob-legacy", legacy_bk );

   auto receipt = BR.receive_blind_transfer( out.confirmation_receipt, "", "" );
   BOOST_CHECK( !vk_is_zero_marker( receipt.data.blinding_factor ) );
   BOOST_CHECK( receipt.data.blinding_factor == out.decrypted_memo.blinding_factor );
   BOOST_CHECK( vk_opens( receipt.data.blinding_factor,
                          receipt.amount.amount.value, receipt.data.commitment ) );

   // The marker dispatch: a LEGACY memo's opening is the memo's own value —
   // the holder does NOT recompute it from a spend key, even when it holds
   // one. The dispatch is what keeps grandfathered outputs openable.
   {
      auto sel = graphene::wallet::select_opening( receipt.data,
                                                   fc::optional<fc::ecc::private_key>( bob ),
                                                   out.confirmation.one_time_key );
      BOOST_REQUIRE( sel.valid() );
      BOOST_CHECK( *sel == receipt.data.blinding_factor );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 5: the new (spend-derived) derivation and the legacy (view-derived)
// derivation DIFFER, so the marker is real. A test that passes with either
// derivation proves nothing.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_new_and_legacy_derivations_differ )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-diff-password" );
   W.unlock( "vk-diff-password" );
   for( const auto& f : { "vk-diff-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-diff-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk dave brainkey words here";
   W.create_stealth_address( "dave-st", bki, 0 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"dave-st","200"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 1u );

   // The two derivations differ for the same one-time key.
   auto spend_opening = vk_opening( keys.spend_priv, fresh[0].conf.one_time_key );
   auto view_opening  = vk_opening( keys.view_priv,  fresh[0].conf.one_time_key );
   BOOST_CHECK( spend_opening != view_opening );

   // The shipped helper computes exactly those two values.
   BOOST_CHECK( graphene::wallet::derive_opening( keys.spend_priv, fresh[0].conf.one_time_key ) == spend_opening );
   BOOST_CHECK( graphene::wallet::derive_opening( keys.view_priv,  fresh[0].conf.one_time_key ) == view_opening );

   // And the output's actual opening is the spend-derived one, so the
   // view-derived opening does not open it.
   BOOST_CHECK( fresh[0].data.blinding_factor == spend_opening );
   BOOST_CHECK( fresh[0].data.blinding_factor != view_opening );
   BOOST_CHECK( !vk_opens( view_opening, fresh[0].amount.amount.value, fresh[0].data.commitment ) );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 6: the sender's dual-key address with an UNAVAILABLE spend key
// refuses the build instead of degrading to the single-key path (which would
// hand the opening to every view-key holder).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_dual_key_address_without_spend_key_refuses_the_build )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-refuse-password" );
   W.unlock( "vk-refuse-password" );
   for( const auto& f : { "vk-refuse-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-refuse-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   // The sender's address book holds the recipient as a dual-key address
   // whose spend key is unavailable (a view-key-only import).
   const std::string bki = "vk erin brainkey words here";
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );
   W.import_stealth_view_key( "erin-nospend", graphene::utilities::key_to_wif( keys.view_priv ),
                               public_key_type() );

   std::string err;
   try { W.transfer_to_blind( "dan", "1.3.0", {{"erin-nospend","200"}}, false ); }
   catch( const fc::exception& e ) { err = e.to_detail_string(); }
   BOOST_REQUIRE( !err.empty() );
   BOOST_CHECK_MESSAGE( err.find( "Dual-key address" ) != std::string::npos, err );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
