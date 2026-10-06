/*
 * H2e activation gates: per-leg activation heights, gateway-before-price
 * ordering, H1-exclusion, and tag/wire pins for every H2 op and object.
 *
 * BSIP-1 section 6 stages H2 as gateway Track B before price Track B, with
 * activation heights as consensus-reject rules (gateway height < price height
 * enforced in evaluators, never a sequencing promise) and H1 pairs excluded
 * from bonded medians. This suite proves the mechanism:
 *
 * - Leg ordering: the configured gateway height strictly precedes the price
 *   height; inverted and equal pairs are refused by the ordering predicate.
 * - Pre-activation: one op per gate (gateway / shared primitives / price) is
 *   refused before any leg activates.
 * - Staging window: between the gateway and price heights bonded custody
 *   (vault_register) is admitted while price-judgment ops (vault_challenge,
 *   oracle_bond_lock) are still refused; at the price height the refusal
 *   lifts for the same challenge.
 * - H1-exclusion: market-issued pairs and H1-bound pairs are refused at
 *   vault_register; a plain UIA registers (control).
 * - Pins: operation tags 83-100 and protocol-space object IDs 1.25.x-1.37.x
 *   are pinned, with pack/unpack round-trips over the appended-field ops
 *   (rotate co_signers, wind-down claim, fallback set, hybrid mint/redeem).
 *
 * No new economics here: every value below reuses the H2a-H2d pilot basis
 * ($0.001/BTS, 1e6 raw units per USD cent).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/operations.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

/// H1-03 vacuity pin: pre-fork refusals must reach the hardfork gate, never
/// stop at the fee check. Callers set the exact fee on a funded CORE payer,
/// so the refusal text must name the H2 gate; deleting any gate turns these
/// red instead of silently green on insufficient_fee.
void h2g_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
{
   try { PUSH_TX( db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( "H2" ) != std::string::npos
            && ( e.to_string().find( "hardfork" ) != std::string::npos
              || e.to_string().find( "activation" ) != std::string::npos ),
            what << " refused off-gate (vacuous, not gate proof): " << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED pre-fork" );
}

} // namespace (gate-refusal helper)

namespace {

// Pilot basis inherited from H2a: 1e6 raw BTS units per USD cent.
constexpr int64_t H2G_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2G_VAULT_USD_CENTS = 1340000; // $13,400 proposal
constexpr uint64_t H2G_FLOOR_USD_CENTS = 83750;   // $837.50 challenge floor
const share_type H2G_VAULT_RAW =
      share_type( int64_t( H2G_VAULT_USD_CENTS ) * H2G_RAW_PER_USD_CENT );
const share_type H2G_ROUND1_RAW =
      share_type( int64_t( H2G_FLOOR_USD_CENTS ) * H2G_RAW_PER_USD_CENT );

void h2g_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_committee_member( account );
}

reference_asset_id_type h2g_create_reference(
      database_fixture& f, account_id_type creator, const fc::ecc::private_key& key,
      const string& symbol, uint8_t precision )
{
   reference_asset_create_operation op;
   op.creator     = creator;
   op.symbol      = symbol;
   op.precision   = precision;
   op.description = symbol + " reference asset";
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return reference_asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

oracle_id_type h2g_make_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      const string& name, reference_asset_id_type base, reference_asset_id_type quote )
{
   oracle_create_operation op;
   op.owner   = owner;
   op.name    = name;
   op.base    = base;
   op.quote   = quote;
   op.series  = { oracle_series( oracle_series_kind::mid,
                                 oracle_series_rounding::unspecified ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

/// Creates a plain UIA to serve as a vault pair candidate.
asset_id_type h2g_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol )
{
   asset_create_operation op;
   op.issuer      = issuer;
   op.symbol      = symbol;
   op.precision   = 5;
   op.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   // Placeholder CER (uia_tests pattern): validate only requires base and
   // quote differ; the pair asset is never traded in this suite.
   op.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_register_operation h2g_register_op(
      account_id_type registrar, asset_id_type pair, const authority& vault_auth )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = H2G_VAULT_RAW;
   op.min_bond_usd_cents   = H2G_VAULT_USD_CENTS;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000; // 200% proposal
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   return op;
}

vault_id_type h2g_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      asset_id_type pair, const authority& vault_auth )
{
   vault_register_operation op = h2g_register_op( registrar, pair, vault_auth );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_challenge_operation h2g_challenge_op(
      account_id_type challenger, vault_id_type vault )
{
   vault_challenge_operation op;
   op.challenger               = challenger;
   op.vault                    = vault;
   op.challenge_bond           = H2G_ROUND1_RAW;
   op.challenge_bond_usd_cents = H2G_FLOOR_USD_CENTS;
   op.evidence_memo            = "evidence:staging-window";
   return op;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_activation_tests, database_fixture )

/// BSIP-1 section 6 (E-03): the configured schedule reads BONDS < GATEWAY <
/// PRICE with distinct heights. Inversion (and equality) is refused by the
/// predicate every H2 gate helper asserts, so a mis-scheduled configuration
/// can never stage custody before judgment machinery or price judgment
/// before bonded custody. R3-04: the two-argument shim is removed, so even
/// this pin goes through the full three-leg form.
BOOST_AUTO_TEST_CASE( gateway_activation_precedes_price_by_rule )
{
   // Authoritative three-leg ordering (E-03: BONDS leg included).
   BOOST_CHECK( h2_legs_ordered( HARDFORK_H2_BONDS_TIME,
                                 HARDFORK_H2_GATEWAY_TIME,
                                 HARDFORK_H2_PRICE_TIME ) );
   // Gateway/price inversion and collapse refuse through the full form.
   BOOST_CHECK( !h2_legs_ordered( HARDFORK_H2_BONDS_TIME,
                                  HARDFORK_H2_PRICE_TIME,
                                  HARDFORK_H2_GATEWAY_TIME ) );
   BOOST_CHECK( !h2_legs_ordered( HARDFORK_H2_BONDS_TIME,
                                  HARDFORK_H2_GATEWAY_TIME,
                                  HARDFORK_H2_GATEWAY_TIME ) );
}

/// E-03 ordering matrix (R3-04 completed): every inversion or collapse of
/// BONDS<GATEWAY<PRICE is refused by the three-leg predicate, so all H2
/// gates fail closed together (never silently staged). Real heights cover
/// all six distinct permutations; synthetic times pin every equality shape
/// (first-two, last-two, first==last, all-equal) since B==P-style collapses
/// are inexpressible with the distinct configured heights.
BOOST_AUTO_TEST_CASE( h2_bonds_gateway_price_ordering_matrix )
{
   const auto B = HARDFORK_H2_BONDS_TIME;
   const auto G = HARDFORK_H2_GATEWAY_TIME;
   const auto P = HARDFORK_H2_PRICE_TIME;
   // Distinct heights pinned: BONDS(2029-11-01) < GATEWAY(2029-12-01) < PRICE(2030-01-01).
   BOOST_CHECK( B < G );
   BOOST_CHECK( G < P );
   BOOST_CHECK( h2_legs_ordered( B, G, P ) );
   // All five inversions refuse, including the R3-04 additions (G,P,B) and
   // (P,B,G).
   BOOST_CHECK( !h2_legs_ordered( G, B, P ) );
   BOOST_CHECK( !h2_legs_ordered( B, P, G ) );
   BOOST_CHECK( !h2_legs_ordered( P, G, B ) );
   BOOST_CHECK( !h2_legs_ordered( G, P, B ) );
   BOOST_CHECK( !h2_legs_ordered( P, B, G ) );
   // Collapses over real heights refuse.
   BOOST_CHECK( !h2_legs_ordered( B, B, P ) );
   BOOST_CHECK( !h2_legs_ordered( B, G, G ) );
   BOOST_CHECK( !h2_legs_ordered( B, B, B ) );
   BOOST_CHECK( !h2_legs_ordered( G, G, P ) );
   BOOST_CHECK( !h2_legs_ordered( G, G, G ) );
   BOOST_CHECK( !h2_legs_ordered( P, P, P ) );
   BOOST_CHECK( !h2_legs_ordered( B, B, G ) );
   BOOST_CHECK( !h2_legs_ordered( G, P, P ) );
   // Synthetic strictness pins (x<y && y<z, exactly): every equality shape
   // refuses — B==P<G (t1,t2,t1), B==P>G (t1,t0,t1), B<G==P (t0,t1,t1) and
   // the G<P collapse variants (t0,t0,t1), (t1,t1,t2) — as do first==last
   // straddles and the all-equal point.
   const auto t0 = fc::time_point_sec( 1000000 );
   const auto t1 = fc::time_point_sec( 2000000 );
   const auto t2 = fc::time_point_sec( 3000000 );
   BOOST_CHECK( h2_legs_ordered( t0, t1, t2 ) );
   BOOST_CHECK( !h2_legs_ordered( t1, t2, t1 ) ); // B==P<G shape
   BOOST_CHECK( !h2_legs_ordered( t1, t0, t1 ) ); // B==P>G shape
   BOOST_CHECK( !h2_legs_ordered( t0, t1, t1 ) ); // B<G==P shape
   BOOST_CHECK( !h2_legs_ordered( t0, t0, t1 ) ); // B==G<P shape
   BOOST_CHECK( !h2_legs_ordered( t1, t1, t2 ) ); // G<P collapse variant
   BOOST_CHECK( !h2_legs_ordered( t1, t2, t2 ) ); // G<P collapse variant
   BOOST_CHECK( !h2_legs_ordered( t0, t2, t0 ) ); // first==last straddle
   BOOST_CHECK( !h2_legs_ordered( t2, t0, t2 ) ); // first==last straddle
   BOOST_CHECK( !h2_legs_ordered( t1, t1, t1 ) ); // all-equal
}

/// One op per gate is refused before any leg activates: vault_register
/// (gateway leg), vault_challenge (shared primitives), oracle_bond_lock and
/// oracle_fallback_set (price leg).
BOOST_AUTO_TEST_CASE( all_three_gates_refuse_before_activation )
{ try {
   ACTORS( (alice) );
   fund( alice );

   {
      vault_register_operation rop =
            h2g_register_op( alice_id, asset_id_type(), authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2g_require_gate_refusal( db, tx, "vault_register pre-activation" );
   }

   {
      vault_challenge_operation cop;
      cop.challenger               = alice_id;
      cop.vault                    = vault_id_type( 0 );
      cop.challenge_bond           = share_type( 1000000 );
      cop.challenge_bond_usd_cents = H2G_FLOOR_USD_CENTS;
      cop.evidence_memo            = "evidence:pre-activation";
      signed_transaction tx;
      tx.operations.push_back( cop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2g_require_gate_refusal( db, tx, "vault_challenge pre-activation" );
   }

   {
      oracle_bond_lock_operation lop;
      lop.producer        = alice_id;
      lop.oracle          = oracle_id_type( 0 );
      lop.vesting_balance = vesting_balance_id_type( 0 );
      lop.bond_amount     = share_type( 1000000 );
      lop.bond_usd_cents  = GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS;
      signed_transaction tx;
      tx.operations.push_back( lop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2g_require_gate_refusal( db, tx, "oracle_bond_lock pre-activation" );
   }

   {
      oracle_fallback_set_operation fop;
      fop.owner  = alice_id;
      fop.oracle = oracle_id_type( 0 );
      signed_transaction tx;
      tx.operations.push_back( fop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2g_require_gate_refusal( db, tx, "oracle_fallback_set pre-activation" );
   }
} FC_LOG_AND_RETHROW() }

/// Between the gateway and price heights bonded custody is admitted while
/// price judgment is still refused; shared primitives are already live
/// (E-03: BONDS < GATEWAY, so challenge machinery precedes custody and the
/// Dec 2029 unchallengeable window is closed). At the price height the
/// price-leg refusal lifts.
BOOST_AUTO_TEST_CASE( gateway_window_admits_custody_not_price )
{ try {
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000000LL ) );
   fund( bob, asset( 100000000000LL ) );
   h2g_make_committee_member( *this, alice );

   // Gateway leg live (and BONDS already passed): custody registers.
   const asset_id_type pair = h2g_create_uia( *this, alice_id, alice_private_key, "GATE" );
   const vault_id_type vid = h2g_register_vault(
         *this, alice_id, alice_private_key, pair, authority( 1, alice_id, 1 ) );
   BOOST_CHECK( vid( db ).vault_pair == pair );

   // Shared primitives already live in the gateway window (E-03): the same
   // challenge posts here (it was refused pre-BONDS, admitted since BONDS).
   {
      vault_challenge_operation cop = h2g_challenge_op( bob_id, vid );
      signed_transaction tx;
      tx.operations.push_back( cop );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      const vault_challenge_id_type cid = vault_challenge_id_type {
         PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };
      BOOST_CHECK( vid( db ).open_challenges == 1 );
      BOOST_CHECK( cid( db ).vault == vid );
   }

   // Price leg still dark: producer bonding is refused in the window.
   {
      oracle_bond_lock_operation lop;
      lop.producer        = bob_id;
      lop.oracle          = oracle_id_type( 0 );
      lop.vesting_balance = vesting_balance_id_type( 0 );
      lop.bond_amount     = share_type( 1000000 );
      lop.bond_usd_cents  = GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS;
      signed_transaction tx;
      tx.operations.push_back( lop );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // At the price height the price-leg refusal lifts (fallback set admits).
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   {
      // The gateway-window challenge above already proved primitives live;
      // here the price leg admits bond locks (existence-checked: unknown
      // oracle still refused, but the gate itself no longer fires first).
      // A well-formed fallback set on a fresh oracle posts.
      const auto bts_ref = h2g_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
      const auto usd_ref = h2g_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
      const oracle_id_type oid =
            h2g_make_oracle( *this, alice_id, alice_private_key, "GATE.USD", bts_ref, usd_ref );
      oracle_fallback_set_operation fop;
      fop.owner  = alice_id;
      fop.oracle = oid;
      signed_transaction tx;
      tx.operations.push_back( fop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
} FC_LOG_AND_RETHROW() }

/// E-03: gateway pre-BONDS refuses vault_register (challenge machinery must
/// be live first). Direct gate-level proof: the gateway helper asserts BONDS
/// passed, so a time before BONDS refuses even though the call shape is
/// otherwise valid; at GATEWAY (BONDS already passed) it admits.
BOOST_AUTO_TEST_CASE( gateway_requires_bonds_gate_level )
{
   const auto before_bonds = HARDFORK_H2_BONDS_TIME - 1;
   BOOST_CHECK_THROW( h2_require_gateway_leg( before_bonds ), fc::exception );
   BOOST_CHECK_THROW( h2_require_primitives( before_bonds ), fc::exception );
   BOOST_CHECK_NO_THROW( h2_require_primitives( HARDFORK_H2_BONDS_TIME ) );
   BOOST_CHECK_NO_THROW( h2_require_gateway_leg( HARDFORK_H2_GATEWAY_TIME ) );
   BOOST_CHECK_THROW( h2_require_price_leg( HARDFORK_H2_PRICE_TIME - 1 ), fc::exception );
   BOOST_CHECK_NO_THROW( h2_require_price_leg( HARDFORK_H2_PRICE_TIME ) );
}

/// H1-exclusion is consensus-reject at the custody door: a market-issued
/// pair and an H1-bound pair are both refused, while a plain UIA registers.
BOOST_AUTO_TEST_CASE( h1_pairs_excluded_from_bonded_custody )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 100000000000LL ) );
   h2g_make_committee_member( *this, alice );
   const auto bts_ref = h2g_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2g_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const oracle_id_type oid =
         h2g_make_oracle( *this, alice_id, alice_private_key, "H1X.USD", usd_ref, bts_ref );

   // Plain market-issued pair: refused as legacy-track (never H2 custody).
   const asset_id_type mia_id = create_bitasset( "H1MIAX", alice_id ).get_id();
   {
      vault_register_operation rop =
            h2g_register_op( alice_id, mia_id, authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // H1-bound pair (mapping + explicit oracle binding, the H1 shape): refused
   // as H1-priced, with the H1 reason firing before the track reason. The
   // H1 binding validity needs the full T7c shape: a mapped UIA backing
   // home (core BTS carries no reference mapping), the MIA's own 1:1
   // mapping declared first (bind-time reads the CURRENT effective
   // mapping), then the explicit bind against the matching oracle.
   const asset_id_type coll_id = h2g_create_uia( *this, alice_id, alice_private_key, "H1COLL" );
   {
      asset_update_operation uop;
      uop.issuer          = alice_id;
      uop.asset_to_update = coll_id;
      uop.new_options     = coll_id( db ).options;
      reference_mapping cm;
      cm.reference        = bts_ref;
      cm.asset_amount     = 1;
      cm.reference_amount = 1;
      uop.new_options.extensions.value.reference_asset_mapping = cm;
      signed_transaction tx;
      tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE( coll_id( db ).options.extensions.value
                  .reference_asset_mapping.valid() );
   const asset_id_type bound_id = create_bitasset( "H1BOUNDX", alice_id, 100,
         charge_market_fee, 4, coll_id ).get_id();
   {
      asset_update_bitasset_operation mop;
      mop.issuer          = alice_id;
      mop.asset_to_update = bound_id;
      mop.new_options     = bound_id( db ).bitasset_data( db ).options;
      reference_mapping m;
      m.reference        = usd_ref;
      m.asset_amount     = 1;
      m.reference_amount = 1;
      mop.new_options.extensions.value.reference_asset_mapping = m;
      signed_transaction tx;
      tx.operations.push_back( mop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   {
      asset_update_bitasset_operation bop;
      bop.issuer          = alice_id;
      bop.asset_to_update = bound_id;
      bop.new_options     = bound_id( db ).bitasset_data( db ).options;
      price_oracle b;
      b.oracle_id = oid;
      b.series    = 0;
      // Far-future consensus expiry (rev2 precedent): the bind must be valid
      // for the H1-priced refusal below to isolate the custody gate, never
      // the expiry default.
      b.expiry_height = db.head_block_num() + 1000000000;
      bop.new_options.extensions.value.price_oracle_binding = b;
      signed_transaction tx;
      tx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE( bound_id( db ).bitasset_data( db ).options.extensions.value
                  .price_oracle_binding.valid() );
   {
      vault_register_operation rop =
            h2g_register_op( alice_id, bound_id, authority( 1, alice_id, 1 ) );
      signed_transaction tx;
      tx.operations.push_back( rop );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // Control: a plain UIA on the same terms registers.
   const asset_id_type free_id = h2g_create_uia( *this, alice_id, alice_private_key, "FREE" );
   const vault_id_type vid = h2g_register_vault(
         *this, alice_id, alice_private_key, free_id, authority( 1, alice_id, 1 ) );
   BOOST_CHECK( vid( db ).vault_pair == free_id );
} FC_LOG_AND_RETHROW() }

/// Operation tags 83-103 are the on-chain numbering and must never move: a
/// later edit that appends out of order or renumbers fails here, not on a
/// live chain. Tag 97 is the R-02 committee oracle_unfreeze (price leg);
/// tag 98 is the X-02 committee seasoning_verify (price leg); tags 99/100
/// are the ISSUANCE-1 hybrid_mint / hybrid_redeem door ops (price leg);
/// tags 101/102/103 are the ISSUANCE-2 offset_deposit / offset_claim /
/// issuance_exit_request ops (price leg).
BOOST_AUTO_TEST_CASE( h2_op_tags_pinned_83_to_103 )
{
   using graphene::protocol::operation;
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_register_operation>::value ), 83 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_bond_lock_operation>::value ), 84 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_bond_lock_operation>::value ), 85 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_bond_release_operation>::value ), 86 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_challenge_operation>::value ), 87 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_dispute_operation>::value ), 88 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_dispute_escalate_operation>::value ), 89 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::challenge_vote_operation>::value ), 90 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_rotate_operation>::value ), 91 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_bond_release_operation>::value ), 92 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::vault_resolve_operation>::value ), 93 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::pair_freeze_operation>::value ), 94 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::winddown_claim_operation>::value ), 95 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_fallback_set_operation>::value ), 96 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::oracle_unfreeze_operation>::value ), 97 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::seasoning_verify_operation>::value ), 98 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::hybrid_mint_operation>::value ), 99 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::hybrid_redeem_operation>::value ), 100 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::offset_deposit_operation>::value ), 101 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::offset_claim_operation>::value ), 102 );
   BOOST_CHECK_EQUAL( int( operation::tag<graphene::protocol::issuance_exit_request_operation>::value ), 103 );
}

/// Protocol-space object IDs 1.25.x-1.38.x are the on-chain numbering and
/// must never move.
BOOST_AUTO_TEST_CASE( h2_object_ids_pinned_25_to_38 )
{
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_object_type ), 25 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_bond_object_type ), 26 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::producer_bond_object_type ), 27 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::vault_challenge_object_type ), 28 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::oracle_dispute_object_type ), 29 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::winddown_vault_object_type ), 30 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::winddown_claim_object_type ), 31 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::reward_pool_object_type ), 32 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::guard_state_object_type ), 33 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::tripwire_state_object_type ), 34 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::recovery_state_object_type ), 35 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::seasoning_object_type ), 36 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::reserve_object_type ), 37 );
   BOOST_CHECK_EQUAL( int( graphene::protocol::offset_pool_object_type ), 38 );
}

/// Appended-last fields survive pack/unpack with positions intact: the H2c
/// rotate co_signers (before extensions per the append-last rule, fixed in
/// audit-round-2 E-04), the wind-down claim, and the H2d fallback set.
BOOST_AUTO_TEST_CASE( h2_appended_fields_round_trip )
{
   {
      vault_rotate_operation op;
      op.rotator       = account_id_type( 1 );
      op.vault         = vault_id_type( 2 );
      op.new_authority = authority( 2, account_id_type( 1 ), 1 );
      op.memo          = std::string( "rotate" );
      op.co_signers.insert( account_id_type( 3 ) );
      auto back = fc::raw::unpack<vault_rotate_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.rotator == op.rotator );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.co_signers == op.co_signers );
      BOOST_CHECK( back.memo == op.memo );
   }
   {
      winddown_claim_operation op;
      op.claimant     = account_id_type( 4 );
      op.winddown     = winddown_vault_id_type( 5 );
      op.claim_amount = share_type( 1000000 );
      op.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
      auto back = fc::raw::unpack<winddown_claim_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.claimant == op.claimant );
      BOOST_CHECK( back.winddown == op.winddown );
      BOOST_CHECK( back.claim_amount == op.claim_amount );
      BOOST_CHECK_EQUAL( int( back.tranche ), int( op.tranche ) );
   }
   {
      oracle_fallback_set_operation op;
      op.owner  = account_id_type( 6 );
      op.oracle = oracle_id_type( 7 );
      price_oracle b;
      b.oracle_id = oracle_id_type( 8 );
      b.series    = 1;
      op.fallback = b;
      auto back = fc::raw::unpack<oracle_fallback_set_operation>( fc::raw::pack( op ) );
      BOOST_REQUIRE( back.fallback.valid() );
      BOOST_CHECK( back.fallback->oracle_id == oracle_id_type( 8 ) );
      BOOST_CHECK_EQUAL( int( back.fallback->series ), 1 );
   }
   {
      // R-02 unfreeze op (tag 97): extensions appended-last round-trips.
      oracle_unfreeze_operation op;
      op.unfreezer = account_id_type( 9 );
      op.oracle    = oracle_id_type( 10 );
      auto back = fc::raw::unpack<oracle_unfreeze_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.unfreezer == op.unfreezer );
      BOOST_CHECK( back.oracle == op.oracle );
   }
   {
      // X-02 seasoning verify op (tag 98): extensions appended-last round-trips.
      seasoning_verify_operation op;
      op.verifier = account_id_type( 11 );
      op.pair     = asset_id_type( 12 );
      auto back = fc::raw::unpack<seasoning_verify_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.verifier == op.verifier );
      BOOST_CHECK( back.pair == op.pair );
   }
   {
      // ISSUANCE-1 hybrid mint (tag 99): every field incl. appended-last
      // extensions round-trips with positions intact.
      hybrid_mint_operation op;
      op.minter        = account_id_type( 13 );
      op.vault         = vault_id_type( 14 );
      op.deposit       = asset( share_type( 130000 ), asset_id_type() );
      op.stable_amount = share_type( 1000 );
      op.fxr_asset     = asset_id_type( 15 );
      auto back = fc::raw::unpack<hybrid_mint_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.minter == op.minter );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.deposit.amount == op.deposit.amount );
      BOOST_CHECK( back.stable_amount == op.stable_amount );
      BOOST_CHECK( back.fxr_asset == op.fxr_asset );
   }
   {
      // ISSUANCE-1 hybrid redeem (tag 100): same appended-last contract.
      hybrid_redeem_operation op;
      op.redeemer = account_id_type( 16 );
      op.vault    = vault_id_type( 17 );
      op.burn     = asset( share_type( 1000 ), asset_id_type( 18 ) );
      auto back = fc::raw::unpack<hybrid_redeem_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.redeemer == op.redeemer );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.burn.amount == op.burn.amount );
      BOOST_CHECK( back.burn.asset_id == op.burn.asset_id );
   }
   {
      // ISSUANCE-2 offset deposit (tag 101): appended-last extensions intact.
      offset_deposit_operation op;
      op.depositor = account_id_type( 19 );
      op.vault     = vault_id_type( 20 );
      op.deposit   = asset( share_type( 50000 ), asset_id_type() );
      auto back = fc::raw::unpack<offset_deposit_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.depositor == op.depositor );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.deposit.amount == op.deposit.amount );
   }
   {
      // ISSUANCE-2 offset claim (tag 102): same contract.
      offset_claim_operation op;
      op.claimant = account_id_type( 21 );
      op.vault    = vault_id_type( 22 );
      op.amount   = share_type( 40000 );
      auto back = fc::raw::unpack<offset_claim_operation>( fc::raw::pack( op ) );
      BOOST_CHECK( back.claimant == op.claimant );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.amount == op.amount );
   }
   {
      // ISSUANCE-2 exit request (tag 103): same contract.
      issuance_exit_request_operation op;
      op.requester = account_id_type( 23 );
      op.vault     = vault_id_type( 24 );
      op.face      = share_type( 300 );
      auto back = fc::raw::unpack<issuance_exit_request_operation>(
            fc::raw::pack( op ) );
      BOOST_CHECK( back.requester == op.requester );
      BOOST_CHECK( back.vault == op.vault );
      BOOST_CHECK( back.face == op.face );
   }
}

BOOST_AUTO_TEST_SUITE_END()
