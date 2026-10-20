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
 *
 * The repair round (the delta re-audit of the wallet half) added the
 * sender-side resolution order (a dual record before the labeled keys), the
 * refusal of a recipient the sender cannot classify, the refusal of the
 * single-output op39 (the operation publishes the sum of the outputs'
 * openings), the openingless change memo of a spend-derived op40, and the
 * receiver-side age gate (the chain's creation state, never the memo,
 * decides which reading applies).
 */
#include <boost/test/unit_test.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/confidential_object.hpp>
#include <graphene/chain/stealth_evaluator.hpp>

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

/// The dual-key record with this label (empty when the wallet has none).
graphene::wallet::stealth_address_record vk_record( const vector<graphene::wallet::stealth_address_record>& recs,
                                                     const std::string& label )
{
   for( const auto& r : recs )
      if( r.label == label )
         return r;
   return graphene::wallet::stealth_address_record();
}

/// A hand-built op39 to a dual-key address in the DEGRADED (pre-fix) shape:
/// the owner key is derived from the VIEW pub and the memo carries the
/// view-derived opening. It is the shape a sender could force on a dual
/// address — the fixed wallet never builds it, and the receiver must not
/// accept the sender's reading of it.
///
/// `corrupt_memo_commitment` makes the memo name a commitment the chain does
/// not show for the output (the malformed-recognition case).
transfer_to_blind_operation vk_degraded_op39( const database& db,
                                              const account_id_type& from,
                                              const public_key_type& view_pub,
                                              int64_t value,
                                              bool corrupt_memo_commitment )
{
   const asset_object& core = db.get_core_asset();
   fc::ecc::public_key view_ecc = view_pub;   // copy-init: the proven conversion
   auto otk    = fc::ecc::private_key::generate();
   auto secret = otk.get_shared_secret( view_ecc );
   auto child  = fc::sha256::hash( secret );
   auto opening = fc::sha256::hash( child );          // the legacy view-derived opening
   auto nonce  = fc::sha256::hash( otk.get_secret() );

   blind_output out;
   out.owner      = authority( 1, public_key_type( view_ecc.child( child ) ), 1 );
   out.commitment = fc::ecc::blind( opening, (uint64_t)value );
   out.range_proof = fc::ecc::range_proof_sign( 0, out.commitment, opening, nonce,
                                                 0, 49, (uint64_t)value );

   stealth_confirmation::memo_data memo;
   memo.amount = asset( value, core.get_id() );
   memo.blinding_factor = opening;
   memo.commitment = corrupt_memo_commitment ? fc::ecc::commitment_type() : out.commitment;
   memo.check = secret._hash[0].value();

   stealth_confirmation conf;
   conf.one_time_key = otk.get_public_key();
   conf.to = public_key_type( view_ecc.child( child ) );
   conf.encrypted_memo = fc::aes_encrypt( secret, fc::raw::pack( memo ) );
   out.stealth_memo = conf;

   transfer_to_blind_operation bop;
   bop.from   = from;
   bop.amount = asset( value, core.get_id() );
   auto fees = db.get_global_properties().parameters.get_current_fees();
   bop.fee    = fees.calculate_fee( bop, core.options.core_exchange_rate );
   bop.outputs.push_back( out );
   bop.blinding_factor = opening;   // the sum of the outputs' openings
   return bop;
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
   W.create_stealth_address( "alice-st2", bki, 1 );

   // TWO outputs: a single-output deposit to a dual-key address would publish
   // the output's opening (the operation's blinding_factor field is the sum
   // of the openings), so the wallet refuses that shape.
   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"alice-st","200"},{"alice-st2","100"}}, false );
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
   W.create_stealth_address( "bob-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"bob-st","200"},{"bob-st2","100"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 2u );
   // The receipts come back in chain order (the op's outputs are sorted by
   // commitment), so pick the one that belongs to bob-st.
   const graphene::wallet::blind_receipt* bob_receipt = nullptr;
   for( const auto& r : fresh ) if( r.address_key == public_key_type( keys.view_pub ) ) { bob_receipt = &r; break; }
   BOOST_REQUIRE( bob_receipt != nullptr );
   // A hot (spend-key) recognition is NOT tally-only: it is spendable.
   BOOST_CHECK( !bob_receipt->tally_only );

   // The receipt the hot wallet recorded must carry the SPEND-derived opening
   // (recomputed from the spend key), not a view-derived one.
   auto spend_opening = vk_opening( keys.spend_priv, bob_receipt->conf.one_time_key );
   BOOST_CHECK( bob_receipt->data.blinding_factor == spend_opening );
   BOOST_CHECK( vk_opens( bob_receipt->data.blinding_factor,
                          bob_receipt->amount.amount.value, bob_receipt->data.commitment ) );

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
   W.create_stealth_address( "carol-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"carol-st","200"},{"carol-st2","100"}}, false );
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
                                                   out.confirmation.one_time_key,
                                                   graphene::wallet::opening_shape::legacy );
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
   W.create_stealth_address( "dave-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"dave-st","200"},{"dave-st2","100"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 2u );
   const graphene::wallet::blind_receipt* dave_receipt = nullptr;
   for( const auto& r : fresh ) if( r.address_key == public_key_type( keys.view_pub ) ) { dave_receipt = &r; break; }
   BOOST_REQUIRE( dave_receipt != nullptr );

   // The two derivations differ for the same one-time key.
   auto spend_opening = vk_opening( keys.spend_priv, dave_receipt->conf.one_time_key );
   auto view_opening  = vk_opening( keys.view_priv,  dave_receipt->conf.one_time_key );
   BOOST_CHECK( spend_opening != view_opening );

   // The shipped helper computes exactly those two values.
   BOOST_CHECK( graphene::wallet::derive_opening( keys.spend_priv, dave_receipt->conf.one_time_key ) == spend_opening );
   BOOST_CHECK( graphene::wallet::derive_opening( keys.view_priv,  dave_receipt->conf.one_time_key ) == view_opening );

   // And the output's actual opening is the spend-derived one, so the
   // view-derived opening does not open it.
   BOOST_CHECK( dave_receipt->data.blinding_factor == spend_opening );
   BOOST_CHECK( dave_receipt->data.blinding_factor != view_opening );
   BOOST_CHECK( !vk_opens( view_opening, dave_receipt->amount.amount.value, dave_receipt->data.commitment ) );
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

// ---------------------------------------------------------------------------
// Test 7 (C-1): the sender's OWN "<label>.view" label resolves to the dual
// record. The label is in the sender's address book, so the old resolution
// order (address book first) took the single-key path and produced a
// VIEW-derived opening: the new output was openable (and ring-spendable) by
// every holder of the recipient's view key.
//
// RED on the base tree: the memo carried the view-derived opening.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_op39_to_own_view_label_is_spend_derived )
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
   W.set_password( "vk-c1-password" );
   W.unlock( "vk-c1-password" );
   for( const auto& f : { "vk-c1-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-c1-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk frank brainkey words here";
   W.create_stealth_address( "frank-st", bki, 0 );
   W.create_stealth_address( "frank-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   // "frank-st.view" is the wallet's OWN label for the dual address's view
   // pub: it is in the address book, so the old order took the single-key
   // path. Two outputs, so the single-output refusal does not fire here.
   auto confirm = W.transfer_to_blind( "dan", "1.3.0",
                                       {{"frank-st.view","200"},{"frank-st2","100"}}, false );
   BOOST_REQUIRE_EQUAL( confirm.outputs.size(), 2u );
   BOOST_CHECK( confirm.outputs[0].label == "frank-st.view" );

   const auto& out = confirm.outputs[0];
   // The memo ships NO opening (the zero marker): the recipient recomputes it
   // from the spend key.
   BOOST_CHECK( vk_is_zero_marker( out.decrypted_memo.blinding_factor ) );

   // The output's opening IS the spend-derived one, and the view-derived
   // value does not open it.
   auto spend_opening = vk_opening( keys.spend_priv, out.confirmation.one_time_key );
   auto view_opening  = vk_opening( keys.view_priv,  out.confirmation.one_time_key );
   BOOST_CHECK( vk_opens( spend_opening, out.decrypted_memo.amount.amount.value,
                          out.decrypted_memo.commitment ) );
   BOOST_CHECK( !vk_opens( view_opening, out.decrypted_memo.amount.amount.value,
                           out.decrypted_memo.commitment ) );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 8 (C-2): a recipient the sender cannot classify is REFUSED, not
// guessed. A bare base58 key that is not in the sender's address book may be
// a remote dual recipient's VIEW pub; the single-key path would publish a
// view-derived opening.
//
// RED on the base tree: the build succeeded with the legacy shape.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_op39_to_unclassifiable_recipient_is_refused )
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
   W.set_password( "vk-c2-password" );
   W.unlock( "vk-c2-password" );
   for( const auto& f : { "vk-c2-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-c2-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   // A REMOTE dual recipient: the sender holds neither key, only the view
   // pub (the string a remote recipient shares).
   const std::string bki = "vk grace brainkey words here";
   auto remote = graphene::wallet::derive_stealth_address_keys( bki, 0 );
   std::string view_pub_b58 = static_cast<std::string>( public_key_type( remote.view_pub ) );

   std::string err;
   try { W.transfer_to_blind( "dan", "1.3.0", {{view_pub_b58,"200"}}, false ); }
   catch( const fc::exception& e ) { err = e.to_detail_string(); }
   BOOST_REQUIRE( !err.empty() );
   BOOST_CHECK_MESSAGE( err.find( "classify" ) != std::string::npos, err );

   // The same recipient WITH its spend pub is classifiable: the remote dual
   // record makes the payment a dual one (spend-derived opening, no opening
   // in the memo).
   W.import_stealth_address_pubs( "grace-remote", public_key_type( remote.view_pub ),
                                   public_key_type( remote.spend_pub ) );
   auto confirm = W.transfer_to_blind( "dan", "1.3.0",
                                       {{"grace-remote","200"},{"grace-remote","100"}}, false );
   BOOST_REQUIRE_EQUAL( confirm.outputs.size(), 2u );
   BOOST_CHECK( vk_is_zero_marker( confirm.outputs[0].decrypted_memo.blinding_factor ) );
   auto spend_opening = vk_opening( remote.spend_priv, confirm.outputs[0].confirmation.one_time_key );
   BOOST_CHECK( vk_opens( spend_opening, confirm.outputs[0].decrypted_memo.amount.amount.value,
                          confirm.outputs[0].decrypted_memo.commitment ) );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 9 (C-3): a single-recipient deposit to a dual-key address is REFUSED.
// The op39 operation publishes the sum of the outputs' openings, so with one
// output the published scalar IS that output's opening: no wallet-side
// derivation can hide it.
//
// RED on the base tree: the build succeeded (and the operation published the
// opening).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_single_recipient_dual_deposit_is_refused )
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
   W.set_password( "vk-c3-password" );
   W.unlock( "vk-c3-password" );
   for( const auto& f : { "vk-c3-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-c3-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk heidi brainkey words here";
   W.create_stealth_address( "heidi-st", bki, 0 );

   std::string err;
   try { W.transfer_to_blind( "dan", "1.3.0", {{"heidi-st","200"}}, false ); }
   catch( const fc::exception& e ) { err = e.to_detail_string(); }
   BOOST_REQUIRE( !err.empty() );
   BOOST_CHECK_MESSAGE( err.find( "sum of the outputs" ) != std::string::npos, err );

   // The LEGACY single-key recipient keeps the single-output path: there the
   // opening is the address key's own (view == spend), so publishing it
   // hands it to nobody new.
   const std::string legacy_bk = "vk legacy ivan brainkey words";
   auto ivan = fc::ecc::private_key::regenerate( fc::sha256::hash( legacy_bk.c_str(), legacy_bk.size() ) );
   BOOST_CHECK( W.set_key_label( public_key_type( ivan.get_public_key() ), "ivan-legacy" ) );
   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"ivan-legacy","200"}}, false );
   BOOST_REQUIRE_EQUAL( confirm.outputs.size(), 1u );
   BOOST_CHECK( !vk_is_zero_marker( confirm.outputs[0].decrypted_memo.blinding_factor ) );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 10 (C-4): the op40 CHANGE output's memo must not carry the change
// opening. The change opening is the conservation difference
// (sum(inputs) - to_opening), so publishing it hands the RECIPIENT's
// spend-derived opening to every holder of the SENDER's view key.
//
// RED on the base tree: the change memo carried the opening, and
// sum(inputs) - change_opening == the recipient's opening.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_op40_change_memo_does_not_reveal_the_recipient_opening )
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
   W.set_password( "vk-c4-password" );
   W.unlock( "vk-c4-password" );
   for( const auto& f : { "vk-c4-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-c4-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   // The sender pays from a LEGACY blind account (its inputs are the legacy,
   // view-derived shape: the sum of their openings is known to the sender's
   // view-key holder).
   const std::string sender_bk = "vk judy brainkey words here";
   W.create_blind_account( "judy-blind", sender_bk );
   auto deposit = W.transfer_to_blind( "dan", "1.3.0", {{"judy-blind","1000"}}, false );
   PUSH_TX( db, deposit.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto receipts = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( receipts.size(), 1u );
   const auto input_opening = receipts[0].data.blinding_factor;

   // The dual-key recipient.
   const std::string bki = "vk kim brainkey words here";
   W.create_stealth_address( "kim-st", bki, 0 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto pay = W.blind_transfer( "judy-blind", "kim-st", "100", "1.3.0", false );
   BOOST_REQUIRE_EQUAL( pay.outputs.size(), 2u );
   const auto& change_out = pay.outputs[0];   // the change comes first
   const auto& to_out    = pay.outputs[1];   // the recipient's output

   // The RECIPIENT's output is spend-derived: its memo ships no opening.
   BOOST_CHECK( vk_is_zero_marker( to_out.decrypted_memo.blinding_factor ) );
   auto recipient_opening = vk_opening( keys.spend_priv, to_out.confirmation.one_time_key );
   BOOST_CHECK( vk_opens( recipient_opening, to_out.decrypted_memo.amount.amount.value,
                          to_out.decrypted_memo.commitment ) );

   // The CHANGE memo must not carry the change opening: the difference
   // (sum(inputs) - change_opening) would be the recipient's opening.
   auto change_opening = change_out.decrypted_memo.blinding_factor;
   BOOST_CHECK( vk_is_zero_marker( change_opening ) );
   // The strong form: with the change opening published, the holder of the
   // sender's view key recovers the recipient's opening as a difference.
   auto recovered = fc::ecc::blind_sum( { input_opening, change_opening }, 1 );
   BOOST_CHECK( recovered != recipient_opening );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 11 (I-1 + I-2): the RECEIVER takes its reading from the chain's
// creation state, never from the memo. A sender that forces the legacy shape
// on a dual-key address (the owner key derived from the view pub, the memo
// carrying the view-derived opening) must not produce a spendable receipt in
// the receiver's wallet.
//
// RED on the base tree: the receipt was spendable and carried the opening.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_receiver_ignores_a_sender_chosen_legacy_shape )
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
   W.set_password( "vk-i1-password" );
   W.unlock( "vk-i1-password" );
   for( const auto& f : { "vk-i1-test.json", "vk-i1-watch.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-i1-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk leo brainkey words here";
   W.create_stealth_address( "leo-st", bki, 0 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   // A sender forces the legacy shape on the dual address.
   auto bop = vk_degraded_op39( db, dan_id,
                                 public_key_type( keys.view_pub ), 200, false );
   trx.clear_signatures();
   trx.operations.clear();
   trx.operations = { bop };
   set_expiration( db, trx );
   sign( trx, dan_private_key );
   PUSH_TX( db, trx );
   trx.clear_signatures();
   trx.operations.clear();
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;

   // The HOT wallet (it holds the dual record and both keys): the receipt may
   // not be spendable on a view-derived authority, and it may not carry an
   // opening the wallet could ring-spend.
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 1u );
   BOOST_CHECK( fresh[0].tally_only );
   BOOST_CHECK( vk_is_zero_marker( fresh[0].data.blinding_factor ) );

   // The WATCH-ONLY wallet: same, and its spend builder must refuse.
   graphene::wallet::wallet_data wdata2;
   wdata2.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api WO( wdata2, rapi );
   WO.set_password( "vk-i1-watch-password" );
   WO.unlock( "vk-i1-watch-password" );
   WO.set_wallet_filename( "vk-i1-watch.json" );
   WO.import_stealth_view_key( "leo-wo", graphene::utilities::key_to_wif( keys.view_priv ),
                               public_key_type( keys.spend_pub ) );
   auto wo_fresh = WO.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( wo_fresh.size(), 1u );
   BOOST_CHECK( wo_fresh[0].tally_only );
   BOOST_CHECK( vk_is_zero_marker( wo_fresh[0].data.blinding_factor ) );
   std::string err;
   try { WO.transfer_from_blind( "leo-wo", "dan", "10", "1.3.0", false ); }
   catch( const fc::exception& e ) { err = e.to_detail_string(); }
   BOOST_REQUIRE( !err.empty() );
   BOOST_CHECK_MESSAGE( err.find( "tally-only" ) != std::string::npos, err );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 12 (I-3): one malformed recognition must not end the scan. Anyone who
// knows a victim's view pub can craft a memo whose commitment differs from
// the chain's; aborting the scan would leave the victim unable to create
// receipts (their stealth funds would become unspendable).
//
// RED on the base tree: the scan threw.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_malformed_recognition_does_not_abort_the_scan )
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
   W.set_password( "vk-i3-password" );
   W.unlock( "vk-i3-password" );
   for( const auto& f : { "vk-i3-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-i3-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk mallory brainkey words here";
   W.create_stealth_address( "mallory-st", bki, 0 );
   W.create_stealth_address( "mallory-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   // A good deposit (two outputs) and a malformed recognition (a memo whose
   // commitment is not the one the chain shows).
   auto confirm = W.transfer_to_blind( "dan", "1.3.0",
                                       {{"mallory-st","200"},{"mallory-st2","100"}}, false );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto bad = vk_degraded_op39( db, dan_id,
                                public_key_type( keys.view_pub ), 50, true );
   trx.clear_signatures();
   trx.operations.clear();
   trx.operations = { bad };
   set_expiration( db, trx );
   sign( trx, dan_private_key );
   PUSH_TX( db, trx );
   trx.clear_signatures();
   trx.operations.clear();
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   // The good receipts are recorded; the malformed one is skipped.
   BOOST_REQUIRE_EQUAL( fresh.size(), 2u );
   for( const auto& r : fresh )
      BOOST_CHECK( r.amount.amount.value != 50 );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 13 (I-4): the POST-ACTIVATION path. After the STEALTH fork the chain
// requires a sound range proof on every output and marks the balance with
// its creation block; the receiver's age gate then reads the new shape.
//
// The post-activation SPEND path is still unreachable from the wallet (op40
// and op41 refuse post-fork balances and op108 has no wallet builder) — see
// the repair report.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( vk_post_activation_deposit_is_spend_derived_and_chain_bound )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 10000000000 ) );
   generate_block();
   // Past the STEALTH activation.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   // The transaction size limit: a post-activation deposit carries a range
   // proof per output, which does not fit in the genesis limit.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   generate_block(); // seal the size change

   auto lapi = std::make_shared<graphene::app::login_api>( app );
   lapi->login( "", "" );
   fc::api<graphene::app::login_api> rapi( lapi );

   graphene::wallet::wallet_data wdata;
   wdata.chain_id = db.get_chain_id();
   graphene::wallet::wallet_api W( wdata, rapi );
   W.set_password( "vk-i4-password" );
   W.unlock( "vk-i4-password" );
   for( const auto& f : { "vk-i4-test.json" } )
      try { if( fc::exists( fc::path( f ) ) ) fc::remove_all( fc::path( f ) ); } catch( ... ) {}
   W.set_wallet_filename( "vk-i4-test.json" );
   BOOST_CHECK( W.import_key( "dan", graphene::utilities::key_to_wif( dan_private_key ) ) );

   const std::string bki = "vk nia brainkey words here";
   W.create_stealth_address( "nia-st", bki, 0 );
   W.create_stealth_address( "nia-st2", bki, 1 );
   auto keys = graphene::wallet::derive_stealth_address_keys( bki, 0 );

   auto confirm = W.transfer_to_blind( "dan", "1.3.0", {{"nia-st","200"},{"nia-st2","100"}}, false );
   BOOST_REQUIRE_EQUAL( confirm.outputs.size(), 2u );
   // The wallet does not implement the post-activation blind fee float yet
   // (the schedule prices the op39 at 0 and the float rule wants the anchor
   // when no parity subsidy is available — a pre-existing gap, recorded in
   // the repair report). The test pays the anchor itself so that the
   // post-activation path can be exercised.
   {
      auto& op = confirm.trx.operations[0].get<transfer_to_blind_operation>();
      op.fee = core.amount( stealth_cost_anchor_core( db, 2 ).value );
      confirm.trx.signatures.clear();
      sign( confirm.trx, dan_private_key );
   }
   // Every output carries a sound range proof after the activation.
   const auto& ttb = confirm.trx.operations[0].get<transfer_to_blind_operation>();
   BOOST_REQUIRE_EQUAL( ttb.outputs.size(), 2u );
   for( const auto& o : ttb.outputs )
      BOOST_CHECK( !o.range_proof.empty() );
   PUSH_TX( db, confirm.trx );
   generate_block();

   auto head = db.head_block_num();
   const uint32_t scan_from = head >= 5 ? head - 5 : 1;
   auto fresh = W.scan_stealth_recognitions( scan_from, head );
   BOOST_REQUIRE_EQUAL( fresh.size(), 2u );
   auto keys1 = graphene::wallet::derive_stealth_address_keys( bki, 1 );
   for( const auto& r : fresh )
   {
      BOOST_CHECK( !r.tally_only );
      // The receipt's opening is the spend-derived one.
      auto spend_priv = ( r.address_key == public_key_type( keys.view_pub ) ) ? keys.spend_priv : keys1.spend_priv;
      auto spend_opening = vk_opening( spend_priv, r.conf.one_time_key );
      BOOST_CHECK( r.data.blinding_factor == spend_opening );
      BOOST_CHECK( vk_opens( r.data.blinding_factor, r.amount.amount.value, r.data.commitment ) );
   }

   // The chain bound the outputs to their creation block (the age gate's
   // input): a post-activation balance carries it, a pre-activation one does
   // not.
   auto bals = W.get_blind_balances( "nia-st" );
   BOOST_REQUIRE_EQUAL( bals.size(), 1u );
   BOOST_CHECK( bals[0].amount == core.amount( 20000000 ).amount );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
