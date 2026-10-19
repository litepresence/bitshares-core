/*
 * ISSUANCE-1 issuance door ops: hybrid_mint / hybrid_redeem + reserve/FXR
 * objects (BSIP-1 section 4 core paths; bands/offset-pool/batch-settle arrive
 * in ISSUANCE-2).
 *
 * Attack-input-first: every gate below is exercised from the refusal side at
 * exact integer boundaries before the happy path is asserted.
 *
 * Pilot basis inherited from H2a-H2d ($0.001/BTS: 1e6 raw units per USD
 * cent). Suite price leg (100, 1): 100 BTS per face unit, so face(D) =
 * floor(D / 100) and payout(F) = floor(F * 100). The wind-down dilution
 * case republishes (1, 1) for unit-exact junior accounting.
 *
 * Proposal constants pinned here (BSIP-1 section 7b): rmin 13000bps (the
 * Terra prohibition), surplus target 20000bps, door cap 2e11 BTS base units
 * ($2,000 pilot-basis), conversion fee 30bps both legs, redeem vest 86400s.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/committee_member.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/fee_schedule.hpp>
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// H1-03 vacuity pin: pre-price refusals must reach the hardfork gate, never
// stop at the fee check (fee set, funded CORE payer; refusal must name H2).
void h2i_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
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
   BOOST_FAIL( what << " was ACCEPTED pre-price" );
}

// ---- Pinned proposal constants (BSIP-1 section 7b mirrors) ----
static_assert( GRAPHENE_H2_ISSUE_RMIN_BPS == 13000,
               "rmin floor must stay 13000bps (Terra prohibition)" );
static_assert( GRAPHENE_H2_ISSUE_TARGET_BPS == 20000,
               "surplus target must stay 20000bps" );
static_assert( GRAPHENE_H2_ISSUE_DOOR_CAP_BTS == 200000000000ULL,
               "per-block door cap must stay $2,000 pilot-basis" );
static_assert( GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS == 30,
               "conversion fee must stay 30bps" );
static_assert( GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC == 86400,
               "redeem vesting must stay 24h linear" );
static_assert( GRAPHENE_H2_WINDDOWN_RMAX_JUNIOR_X == 2,
               "wind-down rmax junior cap must stay 2x senior-paid" );

// Suite price: base bond units per quote face unit (100 BTS per face).
constexpr int64_t H2I_BASE = 100;
constexpr int64_t H2I_QUOTE = 1;

// Pilot basis ($0.001/BTS: 1e6 raw units per USD cent), pinned to consensus.
constexpr int64_t H2I_RAW_PER_USD_CENT = 1000000LL;
static_assert( uint64_t( H2I_RAW_PER_USD_CENT ) == GRAPHENE_H2_USD_BASIS_RAW_PER_CENT,
               "H2i pilot-basis mirror must equal the protocol escrow basis" );
constexpr uint64_t H2I_VAULT_USD_CENTS = 1340000;   // $13,400 vault min_bond
constexpr uint64_t H2I_ORACLE_USD_CENTS = 1005000;  // $10,050 oracle min_bond
// Full-size locks at the pilot basis (not constexpr: fc::safe has no constexpr ctor).
const share_type H2I_VAULT_RAW =
      share_type( int64_t( H2I_VAULT_USD_CENTS ) * H2I_RAW_PER_USD_CENT );    // 1.34e12
const share_type H2I_ORACLE_RAW =
      share_type( int64_t( H2I_ORACLE_USD_CENTS ) * H2I_RAW_PER_USD_CENT );  // 1.005e12

void h2i_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

reference_asset_id_type h2i_create_reference(
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

oracle_id_type h2i_make_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      const string& name, reference_asset_id_type base, reference_asset_id_type quote,
      const oracle_options& opts )
{
   oracle_create_operation op;
   op.owner   = owner;
   op.name    = name;
   op.base    = base;
   op.quote   = quote;
   op.series  = { oracle_series( oracle_series_kind::mid,
                                 oracle_series_rounding::unspecified ) };
   op.options = opts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vesting_balance_id_type h2i_make_cdd_vesting(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      share_type amount )
{
   vesting_balance_create_operation op;
   op.creator = owner;
   op.owner   = owner;
   op.amount  = asset( amount, asset_id_type() );
   op.policy  = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, f.db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vesting_balance_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

producer_bond_id_type h2i_lock_producer_bond(
      database_fixture& f, account_id_type producer, const fc::ecc::private_key& key,
      oracle_id_type oracle, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents )
{
   oracle_bond_lock_operation op;
   op.producer          = producer;
   op.oracle            = oracle;
   op.vesting_balance   = vesting;
   op.bond_amount       = amount;
   op.bond_usd_cents    = usd_cents;
   op.bootstrap_weight  = 0;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return producer_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2i_publish(
      database_fixture& f, oracle_id_type oid,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = { oracle_value( base_amount, quote_amount ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Creates a plain UIA to serve as the senior pair or the FXR junior token.
asset_id_type h2i_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol )
{
   asset_create_operation op;
   op.issuer      = issuer;
   op.symbol      = symbol;
   op.precision   = 5;
   op.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   op.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_id_type h2i_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth, share_type min_bond, uint64_t min_bond_usd,
      asset_id_type pair )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = min_bond;
   op.min_bond_usd_cents   = min_bond_usd;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000;
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_bond_id_type h2i_lock_vault_bond(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      vault_id_type vault, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents )
{
   vault_bond_lock_operation op;
   op.owner           = owner;
   op.vault           = vault;
   op.vesting_balance = vesting;
   op.bond_amount     = amount;
   op.bond_usd_cents  = usd_cents;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2i_freeze(
      database_fixture& f, account_id_type freezer, const fc::ecc::private_key& key,
      vault_id_type vault, oracle_id_type oracle )
{
   pair_freeze_operation op;
   op.freezer = freezer;
   op.vault   = vault;
   op.oracle  = oracle;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

struct h2i_door
{
   vault_id_type vault;
   asset_id_type pair;
   asset_id_type fxr;
   oracle_id_type oracle;
};

void h2i_season_pair(
      database_fixture& f,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const h2i_door& d );

/**
 * Full door setup: committee seat, references, bonded oracle (producer bond
 * + live publish at H2I_BASE/H2I_QUOTE), UIA pair + FXR junior, vault bound
 * through the first freeze. The freeze pin is then surgically reopened
 * (h2_oracle_tests fallback-switch precedent: the binding persists, the
 * test needs an open door, and no consensus reopen path exists for a
 * healthy pair).
 */
h2i_door h2i_open_door(
      database_fixture& f,
      const account_object& alice, const fc::ecc::private_key& alice_key,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const string& pair_sym, const string& fxr_sym,
      share_type min_bond, uint64_t min_bond_usd )
{
   h2i_make_committee_member( f, alice );
   const auto bts_ref = h2i_create_reference( f, alice.get_id(), alice_key, "BTS", 5 );
   const auto usd_ref = h2i_create_reference( f, alice.get_id(), alice_key, "USD", 4 );

   oracle_options opts;
   opts.producers[ bob.get_id() ] = oracle_producer_entry( 1 );
   const oracle_id_type oid = h2i_make_oracle(
         f, alice.get_id(), alice_key, "H2I.USD", bts_ref, usd_ref, opts );
   // Producer bond sized in pilot raw units (weight comes from the entry).
   const share_type oracle_bond = H2I_ORACLE_RAW;
   const auto vb = h2i_make_cdd_vesting( f, bob.get_id(), bob_key, oracle_bond );
    h2i_lock_producer_bond( f, bob.get_id(), bob_key, oid, vb, oracle_bond,
                            GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS );

    const asset_id_type pair = h2i_create_uia( f, alice.get_id(), alice_key, pair_sym );
    const asset_id_type fxr = h2i_create_uia( f, alice.get_id(), alice_key, fxr_sym );
    authority vault_auth( 1, alice.get_id(), 1 );
    const vault_id_type vid = h2i_register_vault(
          f, alice.get_id(), alice_key, vault_auth, min_bond, min_bond_usd, pair );
    // Vault bond (mint-gate book): one full-size live-covered bond, so every
    // door mint below inherits a 200%-gated book. Owner is the oracle
    // producer (a stranger to the vault authority may bond; only minting is
    // authority-gated).
    const auto bond_vest = h2i_make_cdd_vesting( f, bob.get_id(), bob_key, min_bond );
    h2i_lock_vault_bond( f, bob.get_id(), bob_key, vid, bond_vest, min_bond,
                         min_bond_usd );

   h2i_freeze( f, alice.get_id(), alice_key, vid, oid );
   BOOST_REQUIRE( vid( f.db ).bound_oracle.valid() );
   f.generate_block();
   f.db.modify( vid( f.db ), []( vault_object& v ) { v.frozen = false; } );
   f.db.modify( oid( f.db ), []( oracle_object& o ) { o.options.frozen = false; } );

   h2i_publish( f, oid, bob.get_id(), bob_key, H2I_BASE, H2I_QUOTE );
   BOOST_REQUIRE( h2_read_pair_price( f.db, vid( f.db ), 0, f.db.head_block_time() ).valid() );

   h2i_door d;
   d.vault = vid;
   d.pair = pair;
   d.fxr = fxr;
   d.oracle = oid;
   // AC-08: every door pair seasons at open (h2j twin); pre-existing mints
   // exercise the seasoned path unchanged.
   h2i_season_pair( f, bob, bob_key, d );
   return d;
}

void h2i_mint(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2i_door& d, share_type deposit_bts, share_type stable )
{
   hybrid_mint_operation op;
   op.minter        = minter;
   op.vault         = d.vault;
   op.deposit       = asset( deposit_bts, asset_id_type() );
   op.stable_amount = stable;
   op.fxr_asset     = d.fxr;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2i_mint_throws(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2i_door& d, share_type deposit_bts, share_type stable )
{
   hybrid_mint_operation op;
   op.minter        = minter;
   op.vault         = d.vault;
   op.deposit       = asset( deposit_bts, asset_id_type() );
   op.stable_amount = stable;
   op.fxr_asset     = d.fxr;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

/**
 * AC-08 test fixture (h2j_season_pair twin): season @p d's pair so the mint
 * door admits -- independent verifier (bob is neither the pair's issuer nor
 * in its vault-authority walk) plus the 90-day production clock via backdate
 * (hand-set twin precedent, no test-only constants). Coverage holds by
 * construction (full-size vault bond vs tiny books reads saturated).
 */
void h2i_season_pair(
      database_fixture& f,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const h2i_door& d )
{
   // Idempotent seat (h2j_make_committee_member twin: the opener seats
   // alice unconditionally, and multi-door tests re-enter this helper with
   // the same bob -- a bare create would double-seat).
   {
      const account_object& live = bob.get_id()( f.db );
      if( !live.is_lifetime_member() )
         f.upgrade_to_lifetime_member( live );
      const auto& idx = f.db.get_index_type<committee_member_index>()
                           .indices().get<by_account>();
      if( idx.find( bob.get_id() ) == idx.end() )
         f.create_and_seat_committee_member( live );
   }
   seasoning_verify_operation vop;
   vop.verifier = bob.get_id();
   vop.pair     = d.pair;
   signed_transaction vtx;
   vtx.operations.push_back( vop );
   f.db.current_fee_schedule().set_fee( vtx.operations.back() );
   set_expiration( f.db, vtx );
   vtx.sign( bob_key, f.db.get_chain_id() );
   PUSH_TX( f.db, vtx );
   f.generate_block();
   const auto& idx = f.db.get_index_type<seasoning_record_index>()
                        .indices().get<by_seasoning_pair>();
   const auto itr = idx.find( d.pair );
   BOOST_REQUIRE( itr != idx.end() );
   const fc::time_point_sec backdate = f.db.head_block_time()
         - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
   f.db.modify( *itr, [&backdate]( seasoning_record_object& m ) {
      m.window_start = backdate;
   } );
   BOOST_REQUIRE( h2_seasoning_complete( f.db, d.pair ) );
}

vesting_balance_id_type h2i_redeem(
      database_fixture& f, account_id_type redeemer, const fc::ecc::private_key& key,
      const h2i_door& d, share_type burn_face )
{
   hybrid_redeem_operation op;
   op.redeemer = redeemer;
   op.vault    = d.vault;
   op.burn     = asset( burn_face, d.pair );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vesting_balance_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2i_redeem_throws(
      database_fixture& f, account_id_type redeemer, const fc::ecc::private_key& key,
      const h2i_door& d, share_type burn_face )
{
   hybrid_redeem_operation op;
   op.redeemer = redeemer;
   op.vault    = d.vault;
   op.burn     = asset( burn_face, d.pair );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

void h2i_exit_request(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2i_door& d, share_type face )
{
   issuance_exit_request_operation op;
   op.requester = who;
   op.vault     = d.vault;
   op.face      = face;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

const reserve_object* h2i_find_reserve( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<reserve_index>().indices().get<by_reserve_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

/// NC-08: exact partition sum (the verifier's own definition, recomputed
/// independently so a wrong verifier cannot pass its own test).
share_type h2i_band_sum( const vector<share_type>& bands )
{
   share_type total( 0 );
   for( const share_type& band : bands )
      total += band;
   return total;
}

/// NC-08: push @p op and return the refusal text ("" when accepted), so the
/// verifier's message is pinned rather than a bare throw (a bare throw could
/// be any unrelated gate).
string h2i_outcome( database_fixture& f, const graphene::protocol::operation& op,
                    const fc::ecc::private_key& key )
{
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   try { PUSH_TX( f.db, tx ); }
   catch( const fc::exception& e ) { return e.to_string(); }
   return string();
}

/**
 * NC-08: corrupt one band leg of @p pair, run @p push against the corrupted
 * book, then restore -- inside a scoped undo session. The pending-session
 * rule is NOT a safe vehicle for this: a bare db.modify is permanent when no
 * undo session is open (which is the state right after generate_block) and
 * discarded when one is, so the corruption would leak into the final
 * positive control. The explicit session pops back to the pre-corrupt state
 * whatever the push did (refusal, rollback of a partial apply, or success).
 */
template< typename Corrupt, typename Push >
string h2i_corrupt_and_push( database_fixture& f, asset_id_type pair,
                             Corrupt corrupt, Push push )
{
   const reserve_object* r = h2i_find_reserve( f, pair );
   BOOST_REQUIRE( r != nullptr );
   auto session = f.db._undo_db.start_undo_session( true );
   f.db.modify( *r, corrupt );
   const string err = push();
   session.undo();
   return err;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_issuance_tests, database_fixture )

/// Both door ops, the fee-vote schedule, and proposal containment refuse
/// before the price leg: no bonded valuation exists yet, so nothing that
/// values through bonded prices may execute, be priced, or be proposed.
BOOST_AUTO_TEST_CASE( issuance_gates_refuse_before_the_price_leg )
{ try {
   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   // Direct execution refuses (price-leg pre-check runs before vault lookup,
   // so a dangling vault reference still fails on the leg, not the lookup).
   // Fee set on a funded payer so the refusal reaches the gate (H1-03).
   {
      hybrid_mint_operation op;
      op.minter        = alice_id;
      op.vault         = vault_id_type( 0 );
      op.deposit       = asset( share_type( 130000 ), asset_id_type() );
      op.stable_amount = share_type( 1000 );
      op.fxr_asset     = asset_id_type( 1 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2i_require_gate_refusal( db, tx, "hybrid_mint pre-price" );
   }
   {
      hybrid_redeem_operation op;
      op.redeemer = alice_id;
      op.vault    = vault_id_type( 0 );
      op.burn     = asset( share_type( 1000 ), asset_id_type( 1 ) );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2i_require_gate_refusal( db, tx, "hybrid_redeem pre-price" );
   }
   // Fee-schedule votes naming hybrid fees refuse (E-01: committees cannot
   // price what cannot execute).
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.get_mutable_fees() = fee_schedule::get_default();
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<hybrid_mint_operation>() );
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<hybrid_redeem_operation>() );
      cop.proposed_ops.emplace_back( cmuop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }
   // Proposal containment refuses: a hybrid op inside a proposal still hits
   // the price-leg pre-check.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      hybrid_mint_operation mop;
      mop.minter        = alice_id;
      mop.vault         = vault_id_type( 0 );
      mop.deposit       = asset( share_type( 130000 ), asset_id_type() );
      mop.stable_amount = share_type( 1000 );
      mop.fxr_asset     = asset_id_type( 1 );
      cop.proposed_ops.emplace_back( mop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }

   // Post-leg control: the same fee schedule (hybrid fees included) proposes
   // cleanly once the leg passes.
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.get_mutable_fees() = fee_schedule::get_default();
      cop.proposed_ops.emplace_back( cmuop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      PUSH_TX( db, tx, ~0 );
   }
} FC_LOG_AND_RETHROW() }

/// Spam-math basis (R2 audit E-01 pattern): both door ops price mempool
/// noise at a nonzero 5-BTS default -- the default schedule the fee-vote
/// gate admits post-leg names exactly these params. The load-bearing spam
/// bound is capital (every mint locks an rmin-covering deposit) plus the
/// per-block door cap, never the fee level: a block-filling grief costs N
/// x 5 BTS in fees PLUS N locked over-collateralized deposits for no
/// protocol loss. Pinned here (not only in h2_mempool_tests, which covers
/// tags 83-98): tags 99/100 must never drift to zero silently.
BOOST_AUTO_TEST_CASE( issuance_fee_defaults_pinned_nonzero )
{ try {
   BOOST_CHECK_EQUAL( hybrid_mint_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( hybrid_redeem_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<hybrid_mint_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<hybrid_redeem_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
} FC_LOG_AND_RETHROW() }

/// Genesis mint at the exact rmin boundary: D=130000/M=1000 meets (130000 x
/// 1 x 10000 == 1000 x 100 x 13000, equality MEETS), D=129999 refuses. The
/// net-of-fee coverage passes in both (fee 390/389, net face 1296 >= 1000),
/// so the refusal isolates the rmin floor, not the fee.
BOOST_AUTO_TEST_CASE( mint_meets_rmin_at_exact_boundary_and_refuses_below )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYBND", "HYBNDF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // One unit below the floor refuses.
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 129999 ), share_type( 1000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair ) == nullptr );

   const share_type alice_bts_before = db.get_balance( alice_id, asset_id_type() ).amount;
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 130000 ), share_type( 1000 ) );

   // Reserve state: full deposit backs the book (fee slice included), face
   // supply is exactly the request, door counts the gross leg.
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->pair == d.pair );
   BOOST_CHECK( r->fxr_asset == d.fxr );
   BOOST_CHECK( r->bts_balance == share_type( 130000 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1000 ) );
   BOOST_CHECK( r->fxr_supply == share_type( 0 ) );
   // Coverage snapshot: floor(1300 x 10000 / 1000) = 13000 (the floor itself).
   BOOST_CHECK_EQUAL( r->last_ratio_bps, 13000u );
   BOOST_CHECK_EQUAL( r->snapshot_block, db.head_block_num() );
   BOOST_CHECK( r->door_used_bts == share_type( 130000 ) );
   BOOST_CHECK_EQUAL( r->door_block, db.head_block_num() );
   // No surplus above the 200% target (1300 < 2 x 1000): no FXR minted.
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 0 ) );
   // Minter holds exactly the requested face; the pair supply mirrors it.
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 1000 ) );
   // Vault outstanding mirrors the reserve supply (the mirror invariant).
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 1000 ) );
    // Fee routing: the minter paid the deposit plus exactly the chain-charged
    // op fee (zero under the fixture's zeroed fee schedule -- the nonzero
    // 5-BTS default the fee-vote gate prices is pinned in
    // issuance_fee_defaults_pinned_nonzero), and the reserve kept the whole
    // deposit (130000, fee slice 390 inside it).
    const share_type op_fee = db.current_fee_schedule().calculate_fee(
          graphene::protocol::operation( hybrid_mint_operation() ) ).amount;
    BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                 == alice_bts_before - share_type( 130000 ) - op_fee );
} FC_LOG_AND_RETHROW() }

/// The conversion fee is load-bearing on the mint leg: on a 260% book a
/// request covered by the GROSS deposit but not by the NET deposit refuses
/// (M=1297: gross face 1300 covers, net face 1296 does not), while M=1296
/// passes. rmin passes in both (post 3900/2297 and 3900/2296 > 130%), so
/// the refusal isolates the fee gate.
BOOST_AUTO_TEST_CASE( mint_net_of_fee_coverage_refuses_gross_covered_requests )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYFEE", "HYFEEF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Genesis book at 260%: D=260000/M=1000 (face 2600, surplus 600 -> 600 FXR
   // at genesis parity 1:1 -- asserted below).
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 260000 ), share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 600 ) );
   BOOST_REQUIRE( h2i_find_reserve( *this, d.pair ) != nullptr );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->fxr_supply == share_type( 600 ) );
   // FXR mirror: the reserve ledger equals the token's issued supply.
   BOOST_CHECK( d.fxr( db ).dynamic_asset_data_id( db ).current_supply == share_type( 600 ) );

   // D=130000: fee floor(130000 x 30/10000)=390, net face 1296.
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 130000 ), share_type( 1297 ) );
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 130000 ), share_type( 1296 ) );
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 390000 ) );
   BOOST_CHECK( r->stable_supply == share_type( 2296 ) );
   // The near-par second mint REDUCED surplus (3900 < 2 x 2296): no new FXR.
   BOOST_CHECK( r->fxr_supply == share_type( 600 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 600 ) );
} FC_LOG_AND_RETHROW() }

/// Per-block door cap: one op filling the $2,000 door (2e11 BTS) admits; a
/// second conversion in the same block refuses; the next block admits again
/// with a reset counter. DEX legs are uncapped by construction (no DEX leg
/// runs here -- the cap counts door conversions only).
BOOST_AUTO_TEST_CASE( door_cap_holds_second_conversion_until_next_block )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDOOR", "HYDOORF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Fill the door exactly: D=2e11 (face 2e9), M=1e9 -> 200%, surplus 0.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 1000000000LL ) );
   const reserve_object* r0 = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r0 != nullptr );
   BOOST_CHECK( r0->door_used_bts == share_type( 200000000000LL ) );
   const uint32_t block0 = db.head_block_num();

   // Same-block top-up of even 100 BTS refuses (cap is exact, not slack).
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 100 ), share_type( 1 ) );
   // A same-block redeem refuses too: mint + redeem share one counter.
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000000000LL ) );
   h2i_redeem_throws( *this, alice_id, alice_private_key, d, share_type( 1 ) );

   // Next block: the counter resets by head-block number and the dust of
   // the book admits (D=100/M=1: net face 1 covers; post ratio ~200%).
   generate_block();
   BOOST_REQUIRE( db.head_block_num() != block0 );
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 100 ), share_type( 1 ) );
   const reserve_object* r1 = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r1 != nullptr );
   BOOST_CHECK( r1->door_used_bts == share_type( 100 ) );
   BOOST_CHECK_EQUAL( r1->door_block, db.head_block_num() );
} FC_LOG_AND_RETHROW() }

/// Redeem happy path: burn 500 of a 200% book vests floor(500 x 100) minus
/// the floored 30bps fee (50000 - 150 = 49850) in a 24h-linear escrow. The
/// liquid balance never sees the payout; the reserve keeps the fee slice
/// (150150, not 150000); the snapshot re-stamps what the gate proved.
BOOST_AUTO_TEST_CASE( redeem_above_gate_vests_24h_and_keeps_the_fee )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYRED", "HYREDF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // 200% book, no FXR (face 2000 == 2 x 1000: surplus exactly 0).
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );

   const share_type alice_liquid_before = db.get_balance( alice_id, asset_id_type() ).amount;
   const vesting_balance_id_type escrow = h2i_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );

   // Escrow terms: 49850 BTS, linear, 24h, owned by the redeemer, beginning now.
   const vesting_balance_object& vb = escrow( db );
   BOOST_CHECK( vb.owner == alice_id );
   BOOST_CHECK( vb.balance == asset( share_type( 49850 ), asset_id_type() ) );
   BOOST_REQUIRE( vb.policy.is_type<linear_vesting_policy>() );
   const linear_vesting_policy& lin = vb.policy.get<linear_vesting_policy>();
   BOOST_CHECK_EQUAL( lin.vesting_duration_seconds, GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC );
   BOOST_CHECK_EQUAL( lin.vesting_cliff_seconds, 0u );
   BOOST_CHECK( lin.begin_balance == share_type( 49850 ) );
   BOOST_CHECK( lin.begin_timestamp == db.head_block_time() );
    // Never booked as capitalization: liquid BTS fell only by the
    // chain-charged op fee (zero under the fixture's zeroed fee schedule);
    // the 49850 sits in escrow, countable but unspendable.
    const share_type redeem_fee = db.current_fee_schedule().calculate_fee(
          graphene::protocol::operation( hybrid_redeem_operation() ) ).amount;
    BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                 == alice_liquid_before - redeem_fee );

   // Fee routing: 200000 - 49850 = 150150 stays (the 150 slice kept).
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 150150 ) );
   BOOST_CHECK( r->stable_supply == share_type( 500 ) );
   // Snapshot: floor(1501 x 10000 / 500) = 30020.
   BOOST_CHECK_EQUAL( r->last_ratio_bps, 30020u );
   BOOST_CHECK_EQUAL( r->snapshot_block, db.head_block_num() );
   // Mirrors: burned face leaves supply and outstanding together.
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 500 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 500 ) );
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 500 ) );
} FC_LOG_AND_RETHROW() }

/// Price decline strands the book: minted at (100,1) into 200%, repriced to
/// (200,1), a partial burn of 500 refuses (remainder 501/500 = 100.2% < 130%)
/// while the exact full-book exit bypasses the floor and vests. The
/// bypassed book closes with supply 0 and only retained fees in reserve.
BOOST_AUTO_TEST_CASE( redeem_refuses_below_gate_but_full_book_exits )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDECL", "HYDECLF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );

   // Halve the BTS price: 200 BTS per face from here.
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, 200, 1 );
   BOOST_REQUIRE( h2_read_pair_price( db, d.vault( db ), 0, db.head_block_time() ).valid() );

   // Partial exit would leave 100.2%: refused, holders take wind-down instead.
   h2i_redeem_throws( *this, alice_id, alice_private_key, d, share_type( 500 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) );

   // Full-book exit (burn == supply == outstanding) bypasses: gross
   // floor(1000 x 200) = 200000, fee 600, payout 199400 <= 200000 reserve.
   const vesting_balance_id_type escrow = h2i_redeem(
         *this, alice_id, alice_private_key, d, share_type( 1000 ) );
   BOOST_CHECK( escrow( db ).balance == asset( share_type( 199400 ), asset_id_type() ) );
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 600 ) );
   BOOST_CHECK( r->stable_supply == share_type( 0 ) );
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 0 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Dust redeem refused: at (1,100) a 1-face burn converts to floor(1/100) =
/// 0 gross, so there is nothing to vest (the fee cannot eat what was never
/// there -- this isolates conversion dust from fee dust).
BOOST_AUTO_TEST_CASE( dust_redeem_that_pays_nothing_is_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDUST", "HYDUSTF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, 1, 100 );
   h2i_redeem_throws( *this, alice_id, alice_private_key, d, share_type( 1 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// Unbonded inputs never mint bonded stable: a vault with no binding (never
/// frozen, no price leg) refuses mints, and a redeem against a pair with no
/// reserve refuses (nothing was issued, nothing exits).
BOOST_AUTO_TEST_CASE( unbonded_mint_and_reserveless_redeem_refuse )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2i_make_committee_member( *this, alice );

   const asset_id_type pair = h2i_create_uia( *this, alice_id, alice_private_key, "HYUNB" );
   const asset_id_type fxr = h2i_create_uia( *this, alice_id, alice_private_key, "HYUNBF" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2i_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2I_VAULT_RAW, H2I_VAULT_USD_CENTS, pair );
   BOOST_REQUIRE( !vid( db ).bound_oracle.valid() );

   h2i_door d;
   d.vault = vid;
   d.pair = pair;
   d.fxr = fxr;
   d.oracle = oracle_id_type( 0 );
   // No bonded live set anywhere near this vault: mint refuses.
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 200000 ), share_type( 1000 ) );
   // No reserve was ever created: redeem refuses before any price read.
   h2i_redeem_throws( *this, alice_id, alice_private_key, d, share_type( 1 ) );
   BOOST_CHECK( h2i_find_reserve( *this, pair ) == nullptr );
} FC_LOG_AND_RETHROW() }

/// FXR junior economics end-to-end (unit-exact at price (1,1)): a 400%
/// genesis mint prices 1e11 FXR at parity, ten 144% top-ups scale
/// outstanding to 9.5e11 against the full-size $13,400 vault bond, the vault
/// winds down; a senior claims first (payout 850000, haircut binds); a junior
/// claim past 2x senior-paid refuses under the REUSED rmax cap; a junior
/// claim inside it burns FXR from the claimant, the token supply, and the
/// reserve ledger together; a second senior then settles at the SAME
/// haircut -- junior dilution never deepens senior settlement (burned FIRST).
/// PILOT-NARROWED (AC-02, Task 10): disabled for the pilot phase, body
/// kept byte-identical for the scale phase. This test builds a real
/// 9.5e11-face book through consensus mints to breach 150% coverage with
/// full-size bonds -- a state unreachable under the $20,000-face pilot
/// ceiling (any mint past it refuses at the pilot gate before reaching
/// the wind-down machinery). RE-ENTRY: re-enable in the scale binary
/// that lifts the cap (new binary + audit); the wind-down dilution order
/// must be re-proven there before scale activation.
BOOST_AUTO_TEST_CASE( fxr_dilution_order_in_winddown_burns_junior_first,
                      * boost::unit_test::disabled() )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000LL ) );
   fund( dave, asset( 30000000000LL ) );

   const share_type bond = H2I_VAULT_RAW; // $13,400 full-size vault bond
   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYJR", "HYJRF", bond, H2I_VAULT_USD_CENTS );
   const auto vest = h2i_make_cdd_vesting( *this, alice_id, alice_private_key, bond );
   h2i_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, vest, bond,
                        H2I_VAULT_USD_CENTS );

   // Unit-exact junior accounting from here (republish, then mint).
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, 1, 1 );
   // 400% book: D=2e11 (fills the door exactly), M=5e10. Surplus 1e11 mints
   // 1e11 FXR at genesis parity.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 50000000000LL ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 100000000000LL ) );
   BOOST_REQUIRE( h2i_find_reserve( *this, d.pair ) != nullptr );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->fxr_supply
                == share_type( 100000000000LL ) );

   // Scale outstanding past the 150% vault edge: ten 144% top-ups
   // (D=1.3e11/M=9e10 each, one per block for the shared door counter).
   // Every leg still admits: the door takes 1.3e11 of 2e11, headroom grows
   // +1.3e10 per step from 1.35e11, net-of-fee 129.61e9 covers 9e10, and the
   // post-book never drops below 144% (genesis 400% declining toward the
   // 144% marginal). No new FXR (144% < 200% target: no surplus).
   for( int i = 0; i < 10; ++i )
   {
      generate_block(); // reset the door counter
      h2i_mint( *this, alice_id, alice_private_key, d,
                share_type( 130000000000LL ), share_type( 90000000000LL ) );
   }
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->stable_supply
                == share_type( 950000000000LL ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 100000000000LL ) );

   // Breach (1.34e12/9.5e11 = 141% < 150%) -> top-up -> wind-down. The price
   // ages past its 24h lifetime on the way, so republish fresh before the
   // wind-down sweep (the seat needs a live price) and again at (1,1) before
   // claiming, where the claim-time conversion is what the haircut leg uses.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   // Design 3 (section 3.2): the wind-down seat converts the frozen claim
   // book through the bonded price, so the sweep that expires the top-up
   // window needs a live price; with a dead price it defers the wind-down
   // to the next sweep instead of seating a half-empty book. Land just
   // before that sweep, republish there (the price is live for one print
   // lifetime), then cross it.
   while( db.get_dynamic_global_properties().next_maintenance_time
          < d.vault( db ).top_up_deadline )
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time - 60 );
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, H2I_BASE, H2I_QUOTE );
   generate_block();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
   generate_block();
   BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, 1, 1 );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };
   BOOST_REQUIRE( wdid( db ).total_claims == share_type( 950000000000LL ) );
   // Two full-size vault bonds seized (the door bond plus the top-up bond
   // below), PLUS the extinguished reserve's 1.5e12 BTS backing swept into
   // the remainder (ISS-13 terminal disposition): 2.68e12 + 1.5e12.
   BOOST_REQUIRE( wdid( db ).segregated_bond
                  == H2I_VAULT_RAW + H2I_VAULT_RAW + share_type( 1500000000000LL ) );

   // Senior first: 1e6 face -> min(850000 haircut leg, 1410526 pro-rata).
   // The full-size bond overcollateralizes the share leg, so the haircut binds.
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   winddown_claim_operation cop;
   cop.claimant     = carol_id;
   cop.winddown     = wdid;
   cop.claim_amount = share_type( 1000000 );
   cop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction ctx; ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( carol_private_key, db.get_chain_id() );
   PUSH_TX( db, ctx );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 850000 ) );
   BOOST_REQUIRE( wdid( db ).senior_paid == share_type( 850000 ) );

   // Junior past the reused rmax cap refuses: haircut payout
   // floor(2100000 x 8500/10000) = 1785000 > 2 x 850000 (alice holds 1e11
   // FXR, so the refusal is the cap, not her balance).
   winddown_claim_operation rop;
   rop.claimant     = alice_id;
   rop.winddown     = wdid;
   rop.claim_amount = share_type( 2100000 );
   rop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, rtx ), fc::exception );

   // Junior inside the cap burns FIRST: 400000 FXR leaves the claimant, the
   // token supply, and the reserve ledger together (payout 340000 <= 1700000).
   const share_type alice_fxr_before = db.get_balance( alice_id, d.fxr ).amount;
   winddown_claim_operation jop;
   jop.claimant     = alice_id;
   jop.winddown     = wdid;
   jop.claim_amount = share_type( 400000 );
   jop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction jtx; jtx.operations.push_back( jop );
   db.current_fee_schedule().set_fee( jtx.operations.back() );
   set_expiration( db, jtx );
   jtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, jtx );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount
                == alice_fxr_before - share_type( 400000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->fxr_supply
                == share_type( 100000000000LL - 400000 ) );
   BOOST_CHECK( d.fxr( db ).dynamic_asset_data_id( db ).current_supply
                == share_type( 100000000000LL - 400000 ) );

   // Senior settlement never deepens under junior dilution: dave's 1e6-face
   // claim pays exactly carol's 850000.
   const share_type dave_before = db.get_balance( dave_id, asset_id_type() ).amount;
   winddown_claim_operation dop;
   dop.claimant     = dave_id;
   dop.winddown     = wdid;
   dop.claim_amount = share_type( 1000000 );
   dop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction dtx; dtx.operations.push_back( dop );
   db.current_fee_schedule().set_fee( dtx.operations.back() );
   set_expiration( db, dtx );
   dtx.sign( dave_private_key, db.get_chain_id() );
   PUSH_TX( db, dtx );
   BOOST_CHECK( db.get_balance( dave_id, asset_id_type() ).amount
                == dave_before + share_type( 850000 ) );
} FC_LOG_AND_RETHROW() }

/// Secure-ratio mint gate (H2-07/SUP-12): the vault's live-covered bonds
/// gate every mint at the genesis 20000bps pin. At price (1,100) one
/// full-size bond (1.34e12) covers at most 6.7e11 face: S=6.73e11 reads
/// 199.1% and refuses (rmin and net-of-fee both pass, isolating the gate),
/// while S=6.6e11 reads 203% and mints.
/// PILOT-NARROWED (AC-02, Task 10): disabled for the pilot phase, body
/// kept byte-identical for the scale phase. The secure-ratio boundary
/// (6.6e11 face with full-size bonds, raw-vs-face 1:1 against the
/// $13,400 bond floor) sits 330x above the $20,000-face pilot ceiling,
/// so the gate is vacuous-but-live under pilot consensus: every
/// pilot-reachable mint passes it, and any mint reaching it refuses at
/// the pilot gate first. RE-ENTRY: re-enable in the scale binary that
/// lifts the cap (new binary + audit); the boundary pin must be
/// re-proven there before scale activation.
BOOST_AUTO_TEST_CASE( mint_below_secure_ratio_refused,
                      * boost::unit_test::disabled() )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSEC", "HYSECF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );
   BOOST_REQUIRE_EQUAL( d.vault( db ).secure_ratio_bps, 20000u );

   // Unit BTS-expensive price: 1 BTS buys 100 face (rmin needs D >= 1.3S/100,
   // the door admits D <= 2e11, both satisfiable at 6e11 face).
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, 1, 100 );
   BOOST_REQUIRE( h2_read_pair_price( db, d.vault( db ), 0, db.head_block_time() ).valid() );

   // 199.1% coverage refuses: rmin (8.8e11 face value vs 8.749e11 required)
   // and net-of-fee (8.7736e11 vs 6.73e11) both pass, so only the gate throws.
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 8800000000LL ), share_type( 673000000000LL ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair ) == nullptr );

   // 203% control mints: gate, rmin (8.6e11 vs 8.58e11), net, door all pass.
   h2i_mint( *this, alice_id, alice_private_key, d,
            share_type( 8600000000LL ), share_type( 660000000000LL ) );
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->stable_supply == share_type( 660000000000LL ) );
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 660000000000LL ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Genesis secure-ratio pin: registrations below 20000bps refuse at
/// validate() time (10001 = old floor + 1; 19999 = pin - 1). 20000 itself
/// registers (every other test in this suite is the passing pin).
BOOST_AUTO_TEST_CASE( register_below_genesis_secure_ratio_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 30000000000LL ) );

   auto try_register = [&]( uint32_t ratio )
   {
      vault_register_operation op;
      op.registrar            = alice_id;
      op.pair                 = asset_id_type();
      op.vault_authority      = authority( 1, alice_id, 1 );
      op.min_bond             = H2I_VAULT_RAW;
      op.min_bond_usd_cents   = H2I_VAULT_USD_CENTS;
      op.bond_asset           = asset_id_type();
      op.secure_ratio_bps     = ratio;
      op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   };
   BOOST_CHECK_THROW( try_register( 10001 ), fc::exception );
   BOOST_CHECK_THROW( try_register( 19999 ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Stranger-mint closed: the mint authorization sits with the vault
/// authority, never with whoever funds a deposit. Bob (bonded producer and
/// vault bonder, but no authority member) names the foreign vault and
/// refuses on a book that admits alice's identical mint.
BOOST_AUTO_TEST_CASE( stranger_mint_to_foreign_vault_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSTR", "HYSTRF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );
   BOOST_REQUIRE( d.vault( db ).vault_authority.account_auths.find( bob_id )
                  == d.vault( db ).vault_authority.account_auths.end() );

   h2i_mint_throws( *this, bob_id, bob_private_key, d,
                    share_type( 200000 ), share_type( 1000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair ) == nullptr );

   // Authority-member control: alice's identical mint admits.
   h2i_mint( *this, alice_id, alice_private_key, d,
            share_type( 200000 ), share_type( 1000 ) );
   BOOST_REQUIRE( h2i_find_reserve( *this, d.pair ) != nullptr );
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// Coverage honesty (ISS-11/SUP-04): while the absorb pass records an
/// uncovered shortfall the book is underwater past the offset pool, and no
/// new senior may print into it (RED: pre-fix uncovered_shortfall is
/// write-only and mints admit regardless).
BOOST_AUTO_TEST_CASE( mint_halted_while_uncovered_shortfall_stands )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSHORT", "HYSHORTF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // 200% book: D=200000/M=1000. A follow-up D=50000/M=100 admits on every
   // other gate (net 498 covers, post 250000/1100 well above rmin, headroom
   // 70000 covers the leg), isolating the shortfall gate below.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   BOOST_REQUIRE( h2i_find_reserve( *this, d.pair )->uncovered_shortfall
                  == share_type( 0 ) );

   // A standing uncovered shortfall (as the absorb pass records it) halts
   // mints; clearing it reopens the door.
   db.modify( *h2i_find_reserve( *this, d.pair ), []( reserve_object& r ) {
      r.uncovered_shortfall = share_type( 1 );
   } );
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 50000 ), share_type( 100 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->stable_supply
                == share_type( 1000 ) );
   db.modify( *h2i_find_reserve( *this, d.pair ), []( reserve_object& r ) {
      r.uncovered_shortfall = share_type( 0 );
   } );
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 50000 ), share_type( 100 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->stable_supply
                == share_type( 1100 ) );
} FC_LOG_AND_RETHROW() }

/// FXR junior leg rounds in the protocol's favour (ISS-09): the junior price
/// ceils, so a surplus below one FXR still prices at >= 1 and later surplus
/// mints keep minting (RED: pre-fix floor(2100/3000) = 0 silently halts all
/// future FXR). Three surplus-raising mints with a diluting mint between the
/// second and third: per-raising-mint FXR is non-increasing and nonzero.
BOOST_AUTO_TEST_CASE( fxr_price_ceils_and_never_silently_halts )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYFXR3", "HYFXR3F", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Mint 1 (surplus-raising): D=400000/M=1000 at (100,1) -> face 4000 over
   // supply 1000, surplus 2000, genesis parity -> 2000 FXR.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 400000 ), share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 2000 ) );

   // Mint 2 (surplus-raising): D=200000/M=500 -> surplus 3000, contrib 1000
   // at price 1 -> 1000 FXR.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 500 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 3000 ) );

   // Diluting mint: D=110000/M=1000 lifts the book to surplus 2100 against
   // 3000 FXR (ratio 0.7) and mints nothing.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 110000 ), share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 3000 ) );

   // Mint 3 (surplus-raising): D=200000/M=500 -> contrib 1000 at ceil price
   // ceil(2100/3000) = 1 -> 1000 FXR. Pre-fix the floored price is 0 and this
   // mints nothing, permanently (FXR never burns outside wind-down). Sealed
   // into its own block: the byte-identical Mint 2 above shares head time
   // and expiration, so without a block between they are the same signed
   // transaction and the second push is refused as a duplicate (fixture
   // mechanics, never enforcement).
   generate_block();
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 500 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 4000 ) );
   // Raising-mint deltas non-increasing: 2000, 1000, 1000.
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->fxr_supply
                == share_type( 4000 ) );
} FC_LOG_AND_RETHROW() }

/// Cap-function k1 runs at zero supply (ISS-05): after an exact full-book
/// exit the standing headroom is the retained-fee BTS, and a mint above it
/// refuses while one inside it admits (RED: pre-fix the leg skips at zero
/// supply and any deposit up to the $2,000 ceiling admits).
BOOST_AUTO_TEST_CASE( k1_headroom_binds_after_full_book_exit )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYK1", "HYK1F", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2i_redeem( *this, alice_id, alice_private_key, d, share_type( 1000 ) );
   const reserve_object* r0 = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r0 != nullptr );
   BOOST_REQUIRE( r0->stable_supply == share_type( 0 ) );
   // Standing headroom is the retained fee: 200000 - 99700 = 100300.
   BOOST_REQUIRE( r0->bts_balance == share_type( 100300 ) );

   // D=130000/M=1000 passes net, rmin, and the secure gate but exceeds the
   // 100300 standing headroom: refused.
   h2i_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 130000 ), share_type( 1000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->stable_supply
                == share_type( 0 ) );

   // Inside headroom: D=50000/M=100 admits (net 498, post 150300/100).
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 50000 ), share_type( 100 ) );
   const reserve_object* r1 = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r1 != nullptr );
   BOOST_CHECK( r1->stable_supply == share_type( 100 ) );
   BOOST_CHECK( r1->bts_balance == share_type( 150300 ) );
} FC_LOG_AND_RETHROW() }

/// Terminal disposition (ISS-13): on wind-down the reserve's BTS backing
/// follows the liability into the segregated remainder (holders' backstop),
/// queued face refunds for wind-down claiming, and the reserve extinguishes
/// (RED: pre-fix the backing sits frozen in the reserve, readable by nobody,
/// while the reserve still reports a solvent book for a settled liability).
BOOST_AUTO_TEST_CASE( winddown_sweeps_reserve_backing_and_refunds_queue )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYTERM", "HYTERMF", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Book: D=700000/M=1000, then a 200-face batch exit queued (supply and
   // outstanding 800, alice holds 800 face).
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );
   generate_block();
   // Keep the imminent maintenance out of the stale landing below: a live
   // read against the surgical book would TOPUP (intended) but ALSO
   // batch-settle the queue (nothing left to refund). With a healthy book
   // and no queue yet the sweep is a no-op either way.
   if( ( db.get_dynamic_global_properties().next_maintenance_time
         - db.head_block_time() ).to_seconds() < 900 )
      generate_blocks( db.head_block_time() + 1200 );
   h2i_exit_request( *this, alice_id, alice_private_key, d, share_type( 200 ) );
   // Seal the door flow into a block: a bare db.modify issued while pushed
   // transactions are still open records into the pending undo session, and
   // the next block rebuilds pending state from transactions only -- the
   // surgical book below would be silently discarded (h2s_set_books
   // precedent). Sealed, the modify lands on base state and persists.
   generate_block();
   BOOST_REQUIRE( d.vault( db ).outstanding == share_type( 800 ) );

   // Breach far past the 150% priced edge (surgical liabilities, no new
   // economics: the maintenance read itself is what this exercises).
    db.modify( d.vault( db ), []( vault_object& v ) {
      v.outstanding = share_type( 10000000000LL );
    } );
   // Land past the print lifetime in one leap: maintenance runs once on the
   // stale bonded read, so the vault TOPUPs fail-closed while the issuance
   // batch HOLDS (never settles) the queued exit for the wind-down refund
   // below. A live read would settle the queue first, leaving nothing to
   // refund (LL-10: the hold, not the settle, is what this test needs).
   const auto seal_time = db.head_block_time();
   const uint32_t print_lifetime = d.oracle( db ).options.value_lifetime_sec;
   generate_blocks( seal_time + print_lifetime + 600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   // Design 3 (section 3.2): the wind-down seat converts the frozen claim
   // book through the bonded price, so the sweep that expires the top-up
   // window needs a live price; with a dead price it defers the wind-down
   // to the next sweep instead of seating a half-empty book. Land just
   // before that sweep, republish there (the price is live for one print
   // lifetime), then cross it.
   while( db.get_dynamic_global_properties().next_maintenance_time
          < d.vault( db ).top_up_deadline )
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time - 60 );
   h2i_publish( *this, d.oracle, bob_id, bob_private_key, H2I_BASE, H2I_QUOTE );
   generate_block();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
   generate_block();
   BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );

    // The queued 200 refunded to face (alice whole again), the 700000 reserve
   // BTS joined the seized full-size bond in the segregated remainder, and
   // the reserve extinguished around a frozen liability record.
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };
    BOOST_CHECK( wdid( db ).total_claims == share_type( 10000000200LL ) );
   // Design 3: the seat is bounded by what the filed exit formula can ever
   // pay. claims 10000000200 face -> 85% scratch 8500000170 face -> converted
   // at the bonded price (100 base / 1 quote) 850000017000 bond units. The
   // reserve's 700000 BTS is swept first (the cheapest money for the frozen
   // book) and the bond fills the rest (849999317000 of the 1.34e12 bond);
   // the bond's unseized remainder stays with its owner.
   BOOST_CHECK( wdid( db ).segregated_bond == share_type( 850000017000LL ) );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) );
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 0 ) );
   BOOST_CHECK( r->exit_queue.empty() );
   BOOST_CHECK( r->uncovered_shortfall == share_type( 0 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1000 ) );
   for( const share_type& b : r->band_bts )
      BOOST_CHECK( b == share_type( 0 ) );
   BOOST_CHECK_EQUAL( r->last_ratio_bps, 0u );
} FC_LOG_AND_RETHROW() }

// ---------------------------------------------------------------------------
// NC-08: the band partition is a consensus invariant, not a
// construction argument
// ---------------------------------------------------------------------------

/// RED: sum(band_bts) == bts_balance and sum(band_stable) == stable_supply
/// were cited "by construction" at every writer and asserted at none. The
/// verifier below (declared with the other band helpers and called at each
/// reserve writer) turns that argument into a fail-closed invariant: corrupt
/// either partition directly -- the exact shape of a future writer that moves
/// a total without its band -- and every reserve-mutating apply refuses, in
/// the writer that inherited the corruption, with the same message.
BOOST_AUTO_TEST_CASE( band_partition_conservation_enforced_at_every_writer )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "NC08", "NC08F", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );
   // Genesis book at 260% (D=260000/M=1000): headroom 130000 admits the
   // 130000 marginal mint below, so the only gate that can refuse it is the
   // verifier -- a 130% book has zero headroom and would refuse for the door.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 260000 ), share_type( 1000 ) );

   // Positive control: the happy path holds both partitions exactly, so the
   // corruption below is the only moving part.
   const reserve_object* fresh = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( fresh != nullptr );
   BOOST_REQUIRE_EQUAL( fresh->band_bts.size(), GRAPHENE_H2_ISSUE_N_BANDS );
   BOOST_REQUIRE_EQUAL( fresh->band_stable.size(), GRAPHENE_H2_ISSUE_N_BANDS );
   BOOST_CHECK( h2i_band_sum( fresh->band_bts ) == fresh->bts_balance );
   BOOST_CHECK( h2i_band_sum( fresh->band_stable ) == fresh->stable_supply );

   // The partition corruption is scoped (h2i_corrupt_and_push): nested undo
   // session around corrupt+push, so the book is whole again on return
   // whatever the writer did.
   auto corrupt_bts = []( reserve_object& m ) { m.band_bts[3] += share_type( 1 ); };
   auto corrupt_stable = []( reserve_object& m ) { m.band_stable[3] += share_type( 1 ); };
   auto mint_outcome = [&]() {
      hybrid_mint_operation op;
      op.minter        = alice_id;
      op.vault         = d.vault;
      op.deposit       = asset( share_type( 130000 ), asset_id_type() );
      op.stable_amount = share_type( 1000 );
      op.fxr_asset     = d.fxr;
      return h2i_outcome( *this, op, alice_private_key );
   };
   auto redeem_outcome = [&]() {
      hybrid_redeem_operation op;
      op.redeemer = alice_id;
      op.vault    = d.vault;
      op.burn     = asset( share_type( 100 ), d.pair );
      return h2i_outcome( *this, op, alice_private_key );
   };
   auto exit_outcome = [&]() {
      issuance_exit_request_operation op;
      op.requester = alice_id;
      op.vault     = d.vault;
      op.face      = share_type( 500 );
      return h2i_outcome( *this, op, alice_private_key );
   };
   auto expect_conservation_refusal = []( const string& what, const string& err ) {
      BOOST_CHECK_MESSAGE( err.find( "conservation broken" ) != std::string::npos,
                           what << " did not refuse the broken partition: " << err );
   };

   expect_conservation_refusal( "mint",
         h2i_corrupt_and_push( *this, d.pair, corrupt_bts, mint_outcome ) );
   expect_conservation_refusal( "redeem",
         h2i_corrupt_and_push( *this, d.pair, corrupt_stable, redeem_outcome ) );
   expect_conservation_refusal( "exit_request",
         h2i_corrupt_and_push( *this, d.pair, corrupt_bts, exit_outcome ) );

   // The refusals never repaired the partition (they never ran), and the
   // scoping restored it exactly: one clean block later the door opens.
   generate_block();
   const reserve_object* r = h2i_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( h2i_band_sum( r->band_bts ) == r->bts_balance );
   BOOST_CHECK( h2i_band_sum( r->band_stable ) == r->stable_supply );
   BOOST_CHECK_NO_THROW( h2i_mint( *this, alice_id, alice_private_key, d,
                                   share_type( 130000 ), share_type( 1000 ) ) );
} FC_LOG_AND_RETHROW() }

// ---------------------------------------------------------------------------
// R11R2 (AC-R11-01/02, PC-R11-01/02): first-mint reachability -- door race +
// seasoning poison. Both legs run on public ops only with zero DB surgery,
// over live 91-day head-block-time travel with a daily publish.
// ---------------------------------------------------------------------------

/// R11R2 leg (a), door race: register -> pair_freeze -> sweep -> mint. The
/// freeze was the sole bound_oracle writer and co-set frozen=true, while mint
/// needs the bound price and refuses frozen doors -- so no consensus path
/// reached first mint (suites reopened the flags by surgery). Post-fix the
/// bind at zero debt leaves the door and the debt tap open, and this path
/// reaches a real mint.
BOOST_AUTO_TEST_CASE( r11r2_first_mint_reachable_after_zero_debt_bind )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2i_make_committee_member( *this, alice );
   h2i_make_committee_member( *this, bob );
   const auto bts_ref = h2i_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2i_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[ bob_id ] = oracle_producer_entry( 1 );
   // 120-day print lifetime: the 91-day hold below must read live throughout.
   opts.value_lifetime_sec = 120 * 86400;
   const oracle_id_type oid = h2i_make_oracle(
         *this, alice_id, alice_private_key, "R11R2A.USD", bts_ref, usd_ref, opts );
   const auto obvest = h2i_make_cdd_vesting( *this, bob_id, bob_private_key, H2I_ORACLE_RAW );
   h2i_lock_producer_bond( *this, bob_id, bob_private_key, oid, obvest,
                           H2I_ORACLE_RAW, GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS );

   const asset_id_type pair = h2i_create_uia( *this, alice_id, alice_private_key, "R11R2A" );
   const asset_id_type fxr = h2i_create_uia( *this, alice_id, alice_private_key, "R11R2AF" );
   const vault_id_type vid = h2i_register_vault(
         *this, alice_id, alice_private_key, authority( 1, alice_id, 1 ),
         H2I_VAULT_RAW, H2I_VAULT_USD_CENTS, pair );
   const auto vbvest = h2i_make_cdd_vesting( *this, bob_id, bob_private_key, H2I_VAULT_RAW );
   h2i_lock_vault_bond( *this, bob_id, bob_private_key, vid, vbvest,
                        H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Bind at zero outstanding: the pin lands, the door and the debt tap stay open.
   h2i_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   BOOST_CHECK( *vid( db ).bound_oracle == oid );
   BOOST_CHECK_MESSAGE( !vid( db ).frozen,
         "R11R2(a): zero-debt bind shut the vault door" );
   BOOST_CHECK_MESSAGE( !oid( db ).options.frozen,
         "R11R2(a): zero-debt bind froze the debt tap" );

   h2i_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_CHECK_MESSAGE(
         h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid(),
         "R11R2(a): no bonded live price after bind+publish" );

   // Independent verifier: bob is neither the pair's issuer nor in its
   // vault-authority walk (h2i_season_pair precedent).
   {
      seasoning_verify_operation vop;
      vop.verifier = bob_id;
      vop.pair     = pair;
      signed_transaction vtx;
      vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx );
      vtx.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, vtx );
   }

   // Live 91-day hold: the daily publish keeps the bonded-live set ahead of
   // its advancing unlock; every hop crosses maintenance (real sweeps).
   // Seal setup into a block first: the pre-loop publish above and the day-1
   // publish below would otherwise share head time and collide as duplicates.
   generate_block();
   for( int day = 1; day <= 91; ++day )
   {
      h2i_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      generate_blocks( db.head_block_time() + 86400 );
   }
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );

   BOOST_CHECK_MESSAGE( h2_seasoning_complete( db, pair ),
         "R11R2(a): pair not seasoned after 91 bound covered days" );

   hybrid_mint_operation mop;
   mop.minter        = alice_id;
   mop.vault         = vid;
   mop.deposit       = asset( share_type( 260000 ), asset_id_type() );
   mop.stable_amount = share_type( 1000 );
   mop.fxr_asset     = fxr;
   const string err = h2i_outcome( *this, mop, alice_private_key );
   BOOST_CHECK_MESSAGE( err.empty(),
         "R11R2(a): first mint refused after zero-debt bind: " << err );
   BOOST_CHECK( db.get_balance( alice_id, pair ).amount == share_type( 1000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, pair ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// R11R2 leg (b), seasoning poison: register -> maintenance sweep ->
/// pair_freeze -> covered sweeps -> mint. Any pre-bind sweep poisoned
/// min_oracle_bps to 0 with circular recovery (covered sweeps fold min(), so
/// the poison stuck forever past binding). Post-fix the unbound sweep is
/// skipped outright and the bind reseeds the clock, so this path mints.
BOOST_AUTO_TEST_CASE( r11r2_pre_bind_sweep_does_not_poison_seasoning )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2i_make_committee_member( *this, alice );
   h2i_make_committee_member( *this, bob );
   const auto bts_ref = h2i_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2i_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[ bob_id ] = oracle_producer_entry( 1 );
   opts.value_lifetime_sec = 120 * 86400;
   const oracle_id_type oid = h2i_make_oracle(
         *this, alice_id, alice_private_key, "R11R2B.USD", bts_ref, usd_ref, opts );
   const auto obvest = h2i_make_cdd_vesting( *this, bob_id, bob_private_key, H2I_ORACLE_RAW );
   h2i_lock_producer_bond( *this, bob_id, bob_private_key, oid, obvest,
                           H2I_ORACLE_RAW, GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS );

   const asset_id_type pair = h2i_create_uia( *this, alice_id, alice_private_key, "R11R2B" );
   const asset_id_type fxr = h2i_create_uia( *this, alice_id, alice_private_key, "R11R2BF" );
   const vault_id_type vid = h2i_register_vault(
         *this, alice_id, alice_private_key, authority( 1, alice_id, 1 ),
         H2I_VAULT_RAW, H2I_VAULT_USD_CENTS, pair );
   const auto vbvest = h2i_make_cdd_vesting( *this, bob_id, bob_private_key, H2I_VAULT_RAW );
   h2i_lock_vault_bond( *this, bob_id, bob_private_key, vid, vbvest,
                        H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   auto find_record = [&]( asset_id_type p ) -> const seasoning_record_object& {
      const auto& idx = db.get_index_type<seasoning_record_index>()
                           .indices().get<by_seasoning_pair>();
      const auto itr = idx.find( p );
      BOOST_REQUIRE( itr != idx.end() );
      return *itr;
   };
   const fc::time_point_sec genesis = find_record( pair ).genesis_time;

   // A maintenance sweep lands while the pair is still unbound. Post-fix it
   // is skipped outright: no window move, no minimums touch, no breach
   // counted (0xFFFFFFFF = the saturating genesis minimums).
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   BOOST_CHECK( find_record( pair ).window_start == genesis );
   BOOST_CHECK_EQUAL( find_record( pair ).min_vault_bps, 0xFFFFFFFFu );
   BOOST_CHECK_EQUAL( find_record( pair ).min_oracle_bps, 0xFFFFFFFFu );
   BOOST_CHECK_EQUAL( find_record( pair ).breach_count, 0u );

   // Bind: pins the oracle, reseeds the clock to the bind head time with
   // reopened minimums, and leaves the zero-debt door open.
   h2i_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   BOOST_CHECK( find_record( pair ).window_start == db.head_block_time() );
   BOOST_CHECK_EQUAL( find_record( pair ).min_vault_bps, 0xFFFFFFFFu );
   BOOST_CHECK_EQUAL( find_record( pair ).min_oracle_bps, 0xFFFFFFFFu );
   BOOST_CHECK_EQUAL( find_record( pair ).breach_count, 0u );
   BOOST_CHECK_MESSAGE( !vid( db ).frozen,
         "R11R2(b): zero-debt bind shut the vault door" );
   BOOST_CHECK_MESSAGE( !oid( db ).options.frozen,
         "R11R2(b): zero-debt bind froze the debt tap" );

   h2i_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   {
      seasoning_verify_operation vop;
      vop.verifier = bob_id;
      vop.pair     = pair;
      signed_transaction vtx;
      vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx );
      vtx.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, vtx );
   }
   // Seal setup into a block first (same-head duplicate rule, see leg (a)).
   generate_block();
   for( int day = 1; day <= 91; ++day )
   {
      h2i_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      generate_blocks( db.head_block_time() + 86400 );
   }
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );

   BOOST_CHECK_MESSAGE( h2_seasoning_complete( db, pair ),
         "R11R2(b): pair not seasoned after bind + 91 covered days" );

   hybrid_mint_operation mop;
   mop.minter        = alice_id;
   mop.vault         = vid;
   mop.deposit       = asset( share_type( 260000 ), asset_id_type() );
   mop.stable_amount = share_type( 1000 );
   mop.fxr_asset     = fxr;
   const string err = h2i_outcome( *this, mop, alice_private_key );
   BOOST_CHECK_MESSAGE( err.empty(),
         "R11R2(b): first mint refused after bind + covered hold: " << err );
   BOOST_CHECK( db.get_balance( alice_id, pair ).amount == share_type( 1000 ) );
   BOOST_CHECK( h2i_find_reserve( *this, pair ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// R11R3 (LEG-R11-01) legacy attach gate, hybrid_mint reserve-creation door:
/// the first mint pins the named FXR token permanently (reserves are never
/// removed, and asset_issue refuses pinned juniors forever), so a first mint
/// naming somebody else's zero-supply UIA as the junior must refuse. Control:
/// the same door mints fine on the issuer's own FXR (the refused attempt
/// creates no reserve).
BOOST_AUTO_TEST_CASE( r11r3_third_party_fxr_pin_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2i_door d = h2i_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "R11R3P", "R11R3F", H2I_VAULT_RAW, H2I_VAULT_USD_CENTS );

   // Somebody else's zero-supply UIA (bob's "legacy" token): pinning it as
   // junior would clamp bob's issuance forever with no removal path.
   const asset_id_type victim = h2i_create_uia( *this, bob_id, bob_private_key, "R11R3V" );

   // Attack leg: alice is a vault-authority member, but she does not issue
   // the named junior -- must refuse, and no reserve may exist afterwards.
   hybrid_mint_operation attack;
   attack.minter        = alice_id;
   attack.vault         = d.vault;
   attack.deposit       = asset( share_type( 130000 ), asset_id_type() );
   attack.stable_amount = share_type( 1000 );
   attack.fxr_asset     = victim;
   const string attack_err = h2i_outcome( *this, attack, alice_private_key );
   BOOST_CHECK_MESSAGE( !attack_err.empty(),
         "R11R3: third-party FXR pin ADMITTED (legacy attach open)" );
   if( !attack_err.empty() )
      BOOST_CHECK_MESSAGE( attack_err.find( "issuer" ) != std::string::npos,
            "third-party FXR pin refused off-gate: " << attack_err );
   BOOST_CHECK_MESSAGE( h2i_find_reserve( *this, d.pair ) == nullptr,
         "R11R3: refused FXR pin still created a reserve" );

   // Control: the issuer's own FXR pins fine on the same door.
   h2i_mint( *this, alice_id, alice_private_key, d,
             share_type( 130000 ), share_type( 1000 ) );
   BOOST_REQUIRE( h2i_find_reserve( *this, d.pair ) != nullptr );
   BOOST_CHECK( h2i_find_reserve( *this, d.pair )->fxr_asset == d.fxr );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()