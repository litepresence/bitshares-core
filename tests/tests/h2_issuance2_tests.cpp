/*
 * ISSUANCE-2: soft bands + offset pool + batch-settle + REVERT/ABSORB + cap
 * function (BSIP-1 section 4 remainder, closes E-08).
 *
 * Attack-input-first throughout: every gate is exercised from the refusal
 * side at exact integer boundaries before the happy path is asserted.
 *
 * Suite price leg (100, 1): 100 BTS per face unit, so face(D) =
 * floor(D / 100) and payout(F) = floor(F * 100). Depth cases republish to
 * move bands/haircuts; every republished price is asserted live before use.
 *
 * Proposal constants pinned here (BSIP-1 section 7b + ISSUANCE-2): N_BANDS
 * 7, band tick 250bps (half-tick 125), exit fee 200bps, offset vest 604800s,
 * offset cap 64, pending cap 64, queue caps 8 / 1e11 BTS, k1/k2 5000bps.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
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
#include <graphene/app/database_api.hpp>

#include <algorithm>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// H1-03 vacuity pin: pre-price refusals must reach the hardfork gate, never
// stop at the fee check (fee set, funded CORE payer; refusal must name H2).
void h2j_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
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

// ---- Pinned ISSUANCE-2 proposal constants ----
static_assert( GRAPHENE_H2_ISSUE_N_BANDS == 7, "soft bands must stay 7" );
static_assert( GRAPHENE_H2_ISSUE_BAND_TICK_BPS == 250, "band tick must stay 250bps" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_FEE_BPS == 200, "exit fee must stay 2%" );
static_assert( GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC == 604800, "offset vesting must stay 7 days" );
static_assert( GRAPHENE_H2_ISSUE_OFFSET_MAX_CLAIMANTS == 64, "offset ledger must stay capped at 64" );
static_assert( GRAPHENE_H2_ISSUE_PENDING_VEST_CAP == 64, "pending list must stay capped at 64" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_COUNT == 8, "exit queue count cap must stay 8" );
static_assert( GRAPHENE_H2_ISSUE_EXIT_QUEUE_MAX_BTS == 100000000000ULL, "exit queue value cap must stay 1e11" );
static_assert( GRAPHENE_H2_ISSUE_CAP_K1_BPS == 10000, "cap k1 must stay unity (load-bearing: cap memo)" );
static_assert( GRAPHENE_H2_ISSUE_CAP_K2_BPS == 5000, "cap k2 must stay 1/2" );
// Band edges pin the discretized LLAMMA grid (anchor at edges[3] = par).
static_assert( true, "band edge pins live in the cases below" );

// Suite price: base bond units per quote face unit (100 BTS per face).
constexpr int64_t H2J_BASE = 100;
constexpr int64_t H2J_QUOTE = 1;

// Pilot basis ($0.001/BTS: 1e6 raw units per USD cent), pinned to consensus.
constexpr int64_t H2J_RAW_PER_USD_CENT = 1000000LL;
static_assert( uint64_t( H2J_RAW_PER_USD_CENT ) == GRAPHENE_H2_USD_BASIS_RAW_PER_CENT,
               "H2j pilot-basis mirror must equal the protocol escrow basis" );
constexpr uint64_t H2J_VAULT_USD_CENTS = 1340000;   // $13,400 vault min_bond
constexpr uint64_t H2J_ORACLE_USD_CENTS = 1005000;  // $10,050 oracle min_bond
// Full-size locks at the pilot basis (not constexpr: fc::safe has no constexpr ctor).
const share_type H2J_VAULT_RAW =
      share_type( int64_t( H2J_VAULT_USD_CENTS ) * H2J_RAW_PER_USD_CENT );    // 1.34e12
const share_type H2J_ORACLE_RAW =
      share_type( int64_t( H2J_ORACLE_USD_CENTS ) * H2J_RAW_PER_USD_CENT );  // 1.005e12

void h2j_make_committee_member( database_fixture& f, const account_object& account )
{
   const account_object& live = account.get_id()( f.db );
   if( !live.is_lifetime_member() )
      f.upgrade_to_lifetime_member( live );
   const auto& idx = f.db.get_index_type<committee_member_index>()
                     .indices().get<by_account>();
   if( idx.find( account.get_id() ) == idx.end() )
      f.create_and_seat_committee_member( live );
}

reference_asset_id_type h2j_create_reference(
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

oracle_id_type h2j_make_oracle(
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

vesting_balance_id_type h2j_make_cdd_vesting(
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

producer_bond_id_type h2j_lock_producer_bond(
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

void h2j_publish(
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

asset_id_type h2j_create_uia(
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

vault_id_type h2j_register_vault(
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

vault_bond_id_type h2j_lock_vault_bond(
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

void h2j_freeze(
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

struct h2j_door
{
   vault_id_type vault;
   asset_id_type pair;
   asset_id_type fxr;
   oracle_id_type oracle;
};

void h2j_season_pair(
      database_fixture& f,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const h2j_door& d );

h2j_door h2j_open_door(
      database_fixture& f,
      const account_object& alice, const fc::ecc::private_key& alice_key,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const string& pair_sym, const string& fxr_sym,
      share_type min_bond, uint64_t min_bond_usd,
      const string& tag )
{
   h2j_make_committee_member( f, alice );
   const auto bts_ref = h2j_create_reference( f, alice.get_id(), alice_key, "BTS" + tag, 5 );
   const auto usd_ref = h2j_create_reference( f, alice.get_id(), alice_key, "USD" + tag, 4 );

   oracle_options opts;
   opts.producers[ bob.get_id() ] = oracle_producer_entry( 1 );
   const oracle_id_type oid = h2j_make_oracle(
         f, alice.get_id(), alice_key, "H2J.USD" + tag, bts_ref, usd_ref, opts );
   const share_type oracle_bond = H2J_ORACLE_RAW;
   const auto vb = h2j_make_cdd_vesting( f, bob.get_id(), bob_key, oracle_bond );
   h2j_lock_producer_bond( f, bob.get_id(), bob_key, oid, vb, oracle_bond,
                           GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS );

    const asset_id_type pair = h2j_create_uia( f, alice.get_id(), alice_key, pair_sym );
    const asset_id_type fxr = h2j_create_uia( f, alice.get_id(), alice_key, fxr_sym );
    authority vault_auth( 1, alice.get_id(), 1 );
    const vault_id_type vid = h2j_register_vault(
          f, alice.get_id(), alice_key, vault_auth, min_bond, min_bond_usd, pair );
    // Vault bond (mint-gate book): one full-size live-covered bond, so every
    // door mint below inherits a 200%-gated book. Owner is the oracle
    // producer (a stranger to the vault authority may bond; only minting is
    // authority-gated).
    const auto bond_vest = h2j_make_cdd_vesting( f, bob.get_id(), bob_key, min_bond );
    h2j_lock_vault_bond( f, bob.get_id(), bob_key, vid, bond_vest, min_bond,
                         min_bond_usd );

   h2j_freeze( f, alice.get_id(), alice_key, vid, oid );
   BOOST_REQUIRE( vid( f.db ).bound_oracle.valid() );
   f.generate_block();
   f.db.modify( vid( f.db ), []( vault_object& v ) { v.frozen = false; } );
   f.db.modify( oid( f.db ), []( oracle_object& o ) { o.options.frozen = false; } );

   h2j_publish( f, oid, bob.get_id(), bob_key, H2J_BASE, H2J_QUOTE );
   BOOST_REQUIRE( h2_read_pair_price( f.db, vid( f.db ), 0, f.db.head_block_time() ).valid() );

   h2j_door d;
   d.vault = vid;
   d.pair = pair;
   d.fxr = fxr;
   d.oracle = oid;
   // AC-08: every door pair seasons at open, so the pre-existing mint cases
   // below exercise the seasoned path unchanged (the unseasoned refusal is
   // pinned once, in seasoning_gate_refuses_unseasoned_mint_ac08).
   h2j_season_pair( f, bob, bob_key, d );
   return d;
}

void h2j_mint(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2j_door& d, share_type deposit_bts, share_type stable )
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

void h2j_mint_throws(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2j_door& d, share_type deposit_bts, share_type stable )
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
 * AC-08 test fixture: season @p d's pair so the mint door admits. Three
 * legs, mirroring the hand-set twin precedent in h2_seasoning_tests:
 * independent verifier (bob is neither the pair's issuer nor in its
 * vault-authority walk -- both name alice -- so the AC-16 gate admits him),
 * then the 90-day production clock via backdate (no test-only constants:
 * GRAPHENE_H2_SEASONING_WINDOW_SEC). Coverage holds by construction (vault
 * bond 1.34e12 vs tiny books reads saturated). Sealing generate_block calls
 * follow the h2s_set_books pending-session precedent.
 */
void h2j_season_pair(
      database_fixture& f,
      const account_object& bob, const fc::ecc::private_key& bob_key,
      const h2j_door& d )
{
   h2j_make_committee_member( f, bob );
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

vesting_balance_id_type h2j_redeem(
      database_fixture& f, account_id_type redeemer, const fc::ecc::private_key& key,
      const h2j_door& d, share_type burn_face )
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

void h2j_transfer(
      database_fixture& f, account_id_type from, const fc::ecc::private_key& key,
      account_id_type to, asset amount )
{
   transfer_operation op;
   op.from   = from;
   op.to     = to;
   op.amount = amount;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_deposit(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_deposit_operation op;
   op.depositor = who;
   op.vault     = d.vault;
   op.deposit   = asset( amount_bts, asset_id_type() );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_deposit_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_deposit_operation op;
   op.depositor = who;
   op.vault     = d.vault;
   op.deposit   = asset( amount_bts, asset_id_type() );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

void h2j_offset_claim(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_claim_operation op;
   op.claimant = who;
   op.vault    = d.vault;
   op.amount   = amount_bts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_offset_claim_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type amount_bts )
{
   offset_claim_operation op;
   op.claimant = who;
   op.vault    = d.vault;
   op.amount   = amount_bts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

void h2j_exit_request(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type face )
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

void h2j_exit_request_throws(
      database_fixture& f, account_id_type who, const fc::ecc::private_key& key,
      const h2j_door& d, share_type face )
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
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

const reserve_object* h2j_find_reserve( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<reserve_index>().indices().get<by_reserve_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

const offset_pool_object* h2j_find_pool( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<offset_pool_index>().indices().get<by_offset_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

/**
 * Refresh the bonded price, then cross the next maintenance with it live.
 * Maintenance-interval jumps age the consumed price past its 1-day lifetime,
 * so crossing cold would hold every queue/shortfall fail-closed (correct
 * consensus, useless test): approaching first, republishing (same value at
 * a new time IS a new promotion record), then crossing keeps the read live
 * AT the sweep. No vault/tripwire assertions here -- callers own them.
 */
void h2j_cross_maintenance_with_price(
      database_fixture& f, const h2j_door& d,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time - 300 );
   h2j_publish( f, d.oracle, who, key, base_amount, quote_amount );
   BOOST_REQUIRE( h2_read_pair_price( f.db, d.vault( f.db ), 0, f.db.head_block_time() ).valid() );
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time + 60 );
   f.generate_block();
}

share_type h2j_band_sum_bts( const reserve_object* r )
{
   share_type s( 0 );
   for( const share_type& b : r->band_bts )
      s += b;
   return s;
}

share_type h2j_band_sum_face( const reserve_object* r )
{
   share_type s( 0 );
   for( const share_type& b : r->band_stable )
      s += b;
   return s;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_issuance2_tests, database_fixture )

/// Half-tick move predicate pins (pure exact math, no chain needed):
/// 1% inside the 125bps half-tick is NOT a move; 10% is; the exact 125bps
/// boundary (81/80 at anchor 80/1) is NOT a move (inclusive headroom);
/// degenerate anchors never move (fail-closed).
BOOST_AUTO_TEST_CASE( band_move_predicate_pins )
{ try {
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 101, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 110, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 110, 1 ), oracle_value( 95, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 80, 1 ), oracle_value( 81, 1 ) ) );
   BOOST_CHECK( h2_issue_price_moved( oracle_value( 80, 1 ), oracle_value( 82, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 0, 0 ), oracle_value( 100, 1 ) ) );
   BOOST_CHECK( !h2_issue_price_moved( oracle_value( 100, 1 ), oracle_value( 0, 1 ) ) );
   // (LL-02: the band-edge grid was dead consensus code -- no price was ever
   // compared to an edge -- so it was deleted, with its pins, rather than
   // wired into any gate.)
   BOOST_CHECK_EQUAL( GRAPHENE_H2_ISSUE_N_BANDS, 7u );
} FC_LOG_AND_RETHROW() }

/// Absorb trigger + shortfall pins (pure exact math): exactly 100% does NOT
/// trigger; one unit under does; the shortfall CEILS (favoring the protocol:
/// a fractional hair absorbs whole).
BOOST_AUTO_TEST_CASE( absorb_trigger_and_shortfall_pins )
{ try {
   BOOST_CHECK( !h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                         oracle_value( 200, 1 ) ) );
   BOOST_CHECK( h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                        oracle_value( 201, 1 ) ) );
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 200000 ), share_type( 1000 ),
                                              oracle_value( 201, 1 ) ).value, 1000 );
   // Fractional shortfall ceils: (1000x201 - 200000)/1 = 1000 exact above;
   // at (1000, 7) vs 700000/7000: (7000x1000 - 700000x7)/7 = 300000 -> exact.
   // Ceil case: bts 1000, supply 11, price (100,1): (1100-1000)=100 exact;
   // bts 1000, supply 101, price (10,1): (1010-1000)=10 exact; fractional:
   // bts 1000, supply 100, price (201,20): (100x201 - 1000x20)/20 = 5 exact.
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 999 ), share_type( 100 ),
                                              oracle_value( 201, 20 ) ).value, 6 );
   BOOST_CHECK_EQUAL( h2_offset_shortfall_bts( share_type( 200000 ), share_type( 1000 ),
                                              oracle_value( 200, 1 ) ).value, 0 );
   BOOST_CHECK( !h2_offset_should_absorb( share_type( 200000 ), share_type( 1000 ),
                                         oracle_value( 0, 1 ) ) );
} FC_LOG_AND_RETHROW() }

/// Soft bands on the live book: genesis opens centered, sub-half-tick moves
/// never churn, consumed moves shift one step with floored quanta, drift
/// reverses, and the partition always sums to the totals.
BOOST_AUTO_TEST_CASE( bands_rebalance_on_consumed_moves_with_hysteresis )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYBAND", "HYBANDF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "1" );

   // Genesis: whole book in the active band 3, anchored at (100,1).
   // D=700000/M=1000: surplus 6000 face mints 6000 FXR at genesis parity.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );
   const reserve_object* r0 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r0 != nullptr );
   BOOST_REQUIRE_EQUAL( r0->band_bts.size(), 7u );
   BOOST_REQUIRE_EQUAL( r0->band_stable.size(), 7u );
   BOOST_CHECK( r0->band_bts[3] == share_type( 700000 ) );
   BOOST_CHECK( r0->band_stable[3] == share_type( 1000 ) );
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r0->band_bts[i] == share_type( 0 ) );
         BOOST_CHECK( r0->band_stable[i] == share_type( 0 ) );
      }
   BOOST_CHECK( r0->band_anchor == oracle_value( 100, 1 ) );

   // Sub-half-tick (+1%): a conversion adds to band 3 but shifts NOTHING.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 101, 1 );
   generate_block(); // reset the door counter (effective cap < used same-block)
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r1 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r1 != nullptr );
   BOOST_CHECK( r1->band_bts[3] == share_type( 707000 ) );
   BOOST_CHECK( r1->band_stable[3] == share_type( 1010 ) );
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r1->band_bts[i] == share_type( 0 ) );
         BOOST_CHECK( r1->band_stable[i] == share_type( 0 ) );
      }
   BOOST_CHECK( r1->band_anchor == oracle_value( 100, 1 ) );

   // Consumed move (+8.9%): one step up with FLOORED quanta.
   // Pre-shift band 3: (707000, 1010); quanta floor(707000/7)=101000 BTS,
   // floor(1010/7)=144 face. The mint below adds first (D=7003/M=10), so the
   // pre-shift source reads (714003, 1020): quanta 102000 / 145.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 110, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7003 ), share_type( 10 ) );
   const reserve_object* r2 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r2 != nullptr );
   BOOST_CHECK( r2->band_bts[4] == share_type( 102000 ) );
   BOOST_CHECK( r2->band_stable[4] == share_type( 145 ) );
   BOOST_CHECK( r2->band_bts[3] == share_type( 714003 - 102000 ) );
   BOOST_CHECK( r2->band_stable[3] == share_type( 1020 - 145 ) );
   BOOST_CHECK( r2->band_anchor == oracle_value( 110, 1 ) );
   // Conservation: the partition sums to the totals exactly.
   BOOST_CHECK( h2j_band_sum_bts( r2 ) == r2->bts_balance );
   BOOST_CHECK( h2j_band_sum_face( r2 ) == r2->stable_supply );

   // Drift down (-13.6%): one step back toward discount bands.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 95, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r3 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r3 != nullptr );
   BOOST_CHECK( r3->band_anchor == oracle_value( 95, 1 ) );
   BOOST_CHECK( r3->band_bts[2] > share_type( 0 ) );
   BOOST_CHECK( h2j_band_sum_bts( r3 ) == r3->bts_balance );
   BOOST_CHECK( h2j_band_sum_face( r3 ) == r3->stable_supply );

   // Half-tick boundary equality never moves: re-anchor at (80,1) via a down
   // move, then publish exactly +1.25% (81,1) and convert: no shift, anchor
   // holds. rmin still admits (book deep).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 80, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r4 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r4 != nullptr );
   BOOST_REQUIRE( r4->band_anchor == oracle_value( 80, 1 ) );
   const vector<share_type> before_bts = r4->band_bts;
   const vector<share_type> before_face = r4->band_stable;
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 81, 1 );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 10 ) );
   const reserve_object* r5 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r5 != nullptr );
   BOOST_CHECK( r5->band_anchor == oracle_value( 80, 1 ) );
   // Only band 3 grew (the new deposit); every other band is untouched.
   for( uint32_t i = 0; i < 7; ++i )
      if( i != 3 )
      {
         BOOST_CHECK( r5->band_bts[i] == before_bts[i] );
         BOOST_CHECK( r5->band_stable[i] == before_face[i] );
      }
} FC_LOG_AND_RETHROW() }

/// Cap function, split gate: the fixed $2,000 keeps the shared per-block
/// counter semantics (genesis exact-fill admits), while the headroom leg
/// binds the MARGINAL conversion at the standing buffer (refuse/admit pair
/// at the exact leg boundary). k1 = UNITY is load-bearing (see the constant
/// memo): any k1 < 1 refuses healthy half-book redeems and at-headroom
/// top-ups, proven by the live-book cases elsewhere in this suite.
BOOST_AUTO_TEST_CASE( cap_function_three_way_min_with_k1 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   // Fixed-ceiling pins (genesis: headroom skipped, no tripwire): the full
   // $2,000 leg admits, one unit past it refuses -- the DOS bound is
   // unchanged from ISSUANCE-1.
   {
      const h2j_door d0 = h2j_open_door(
            *this, alice, alice_private_key, bob, bob_private_key,
            "HYCAP0", "HYCAP0F", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "A" );
      const auto price = h2_read_pair_price( db, d0.vault( db ), 0, db.head_block_time() );
      BOOST_REQUIRE( price.valid() );
      BOOST_CHECK( h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                        share_type( 0 ),
                                        share_type( 200000000000LL ) ) );
      BOOST_CHECK( !h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                         share_type( 0 ),
                                         share_type( 200000000001LL ) ) );
      BOOST_CHECK( !h2_issue_door_admits( db, nullptr, d0.pair, *price,
                                         share_type( 200000000000LL ),
                                         share_type( 1 ) ) );
   }

   // Headroom leg binds the marginal leg: D=140000/M=1000 opens at 140%
   // (headroom 100 face = 10000 BTS, leg bound 10000 at k1 = unity).
   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYCAP", "HYCAPF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "B" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 140000 ), share_type( 1000 ) );
   generate_block(); // reset the door counter; the headroom leg persists
   // Leg 12000 > 10000 refuses (rmin would admit: post 152000/1030 = 147%).
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 12000 ), share_type( 30 ) );
   // Leg 8000 <= 10000 admits (post 148000/1030 = 143.7% >= 130%).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 8000 ), share_type( 30 ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 148000 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1030 ) );
} FC_LOG_AND_RETHROW() }

/// Depth leg: unqualified depth (single pool, one window) REFUSES the door
/// outright, while the pool-less control pair admits on the same terms.
BOOST_AUTO_TEST_CASE( cap_function_unqualified_depth_refuses )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEP", "HYDEEPF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "C" );
   const h2j_door c = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEPC", "HYDEEPCF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "D" );

   // Both books open identically at 200% (D=2e10/M=1e8, inside the fixed
   // door): alice needs 1e7 face for the pool deposit below.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 100000000LL ) );
   h2j_mint( *this, alice_id, alice_private_key, c,
             share_type( 20000000000LL ), share_type( 100000000LL ) );
   generate_block();

   // One pool on d's pair, one deep exchange (2e8 BTS >= MIN_DEPTH) in the
   // current window only: the tripwire state exists but is unqualified
   // (empty old window AND a single pool) -- the door refuses.
   const asset_id_type lpa = h2j_create_uia( *this, alice_id, alice_private_key, "HYDEEPLP" );
   const liquidity_pool_object& pool = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpa, 0, 0 );
   deposit_to_liquidity_pool( alice_id, pool.get_id(),
                              asset( share_type( 1000000000 ), asset_id_type() ),
                              asset( share_type( 10000000 ), d.pair ) );
   exchange_with_liquidity_pool( alice_id, pool.get_id(),
                                 asset( share_type( 200000000 ), asset_id_type() ),
                                 asset( share_type( 1 ), d.pair ) );

   // Refusal side first: any conversion on the touched pair refuses...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 7000 ), share_type( 10 ) );
   // ...while the untouched control pair admits on identical terms.
   h2j_mint( *this, alice_id, alice_private_key, c,
             share_type( 7000 ), share_type( 10 ) );
   BOOST_CHECK( h2j_find_reserve( *this, c.pair )->bts_balance == share_type( 20000007000LL ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 20000000000LL ) );
} FC_LOG_AND_RETHROW() }

/// Depth leg binds when qualified: two pools observed across both windows
/// price door flow at half the demonstrated absorption.
BOOST_AUTO_TEST_CASE( cap_function_qualified_depth_binds )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDEEP2", "HYDEEP2F", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "E" );

   // Deep 200% book (D=4.2e10/M=2.1e8, one block, inside the fixed door).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 42000000000LL ), share_type( 210000000LL ) );
    // Vault bond keeps the pair HEALTHY through the maintenance rotation
    // below (full-size lock covers outstanding 2.1e8 many times over).
    const auto vest = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                            H2J_VAULT_RAW );
   h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, vest,
                        H2J_VAULT_RAW, H2J_VAULT_USD_CENTS );

   // Two pools at the feed ratio (100:1), 1e10 BTS + 1e8 face each.
   const asset_id_type lpa = h2j_create_uia( *this, alice_id, alice_private_key, "HYDP2A" );
   const asset_id_type lpb = h2j_create_uia( *this, alice_id, alice_private_key, "HYDP2B" );
   const liquidity_pool_object& p1 = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpa, 0, 0 );
   const liquidity_pool_object& p2 = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpb, 0, 0 );
   deposit_to_liquidity_pool( alice_id, p1.get_id(),
                              asset( share_type( 10000000000LL ), asset_id_type() ),
                              asset( share_type( 100000000LL ), d.pair ) );
   deposit_to_liquidity_pool( alice_id, p2.get_id(),
                              asset( share_type( 10000000000LL ), asset_id_type() ),
                              asset( share_type( 100000000LL ), d.pair ) );
    // Round 1: 1e8 BTS through each pool (1% of pool: deviation ~1%, clean).
    exchange_with_liquidity_pool( alice_id, p1.get_id(),
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    exchange_with_liquidity_pool( alice_id, p2.get_id(),
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    // Pool IDs by value: object references do not survive the maintenance
    // rotation below, IDs do (diagnostic pin while the stale-ref mechanism
    // is characterized -- see task report).
    const liquidity_pool_id_type p1_id = p1.get_id();
    const liquidity_pool_id_type p2_id = p2.get_id();
    BOOST_REQUIRE( db.find( p1_id ) != nullptr );
    BOOST_REQUIRE( db.find( p2_id ) != nullptr );
    // Rotate: old window takes round 1 (evaluation stays clean: ~1% moves).
    // The opening publish aged on the way, so approach, republish, then
    // cross: the sweep must read a live bonded price (stale reads breach
    // fail-closed), and publishing touches no tripwire window.
    generate_blocks( db.get_dynamic_global_properties().next_maintenance_time - 300 );
    h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
    generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
    generate_block();
    BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
    // The pools must survive the rotation as objects (IDs stay valid even
    // if the pre-rotation references went stale).
    BOOST_REQUIRE( db.find( p1_id ) != nullptr );
    BOOST_REQUIRE( db.find( p2_id ) != nullptr );
    // Round 2: same again into the fresh window.
    exchange_with_liquidity_pool( alice_id, p1_id,
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
    exchange_with_liquidity_pool( alice_id, p2_id,
                                  asset( share_type( 100000000LL ), asset_id_type() ),
                                  asset( share_type( 1 ), d.pair ) );
   // Refresh the consumed price for the probes below (the rotation jump
   // aged the opening publish): same value at a new time is a new record.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   generate_block(); // reset the door counter for the probes below

   // Qualified depth 4e8 -> leg floor(4e8 x 5000/10000) = 2e8 binds below
   // the headroom leg (~7.35e9) and the fixed ceiling.
   // D=2.5e8 refuses (rmin would admit: post ~199.9%)...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 250000000LL ), share_type( 1000000LL ) );
   // ...D=1.5e8 admits.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 150000000LL ), share_type( 1000000LL ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance
                == share_type( 42150000000LL ) );
} FC_LOG_AND_RETHROW() }

/// Offset pool: trigger boundary on the live book, 7-day vesting claims,
/// non-transferability by construction (no transfer path exists: every
/// transfer-like attempt leaves the ledger untouched), merge semantics.
BOOST_AUTO_TEST_CASE( offset_pool_absorbs_claims_vest_and_refuse_theft )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000LL ) );
   fund( dave, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYOFF", "HYOFFF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "F" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
    // Real vault bond: the pair must stay HEALTHY through the three
    // maintenance crossings below (full-size lock covers outstanding 1000;
    // otherwise the top-up ladder winds the vault down mid-test).
    {
       const auto hoard = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                                H2J_VAULT_RAW );
      h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, hoard,
                           H2J_VAULT_RAW, H2J_VAULT_USD_CENTS );
   }
   generate_block();

   // Exactly 100% is NOT absorbable: no pool exists and maintenance books
   // nothing (uncovered stays 0).
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 200, 1 );
   BOOST_CHECK( h2j_find_pool( *this, d.pair ) == nullptr );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );

   // Below 100% with no pool: the remainder is RECORDED for the rmax junior
   // path (absorb-dilute with an empty pool).
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 201, 1 );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 1000 ) );

   // Bob funds the absorber: one entry, 7-day maturity.
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 50000 ) );
   const offset_pool_object* p0 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p0 != nullptr );
   BOOST_CHECK( p0->balance == share_type( 50000 ) );
   BOOST_REQUIRE_EQUAL( p0->claims.size(), 1u );
   BOOST_CHECK( p0->claims[0].owner == bob_id );
   BOOST_CHECK( p0->claims[0].amount == share_type( 50000 ) );
   const time_point_sec avail0 = p0->claims[0].available_after;
   BOOST_CHECK( avail0 == db.head_block_time() + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC );

   // Maintenance absorbs the recorded 1000 shortfall from the pool first.
   // Absorbers take the first loss pro-rata: balance 50000->49000 and the
   // claim 50000->floor(50000x49000/50000)=49000.
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 201, 1 );
   const offset_pool_object* p1 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p1 != nullptr );
   BOOST_CHECK( p1->balance == share_type( 49000 ) );
   BOOST_CHECK( p1->claims[0].amount == share_type( 49000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 201000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );

   // Premature claims refuse (time lock), strangers refuse (ownership),
   // over-claims refuse (mirror).
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, d, share_type( 1000 ) );
   h2j_offset_claim_throws( *this, carol_id, carol_private_key, d, share_type( 1000 ) );
    // Transfer-like attempts cannot touch the ledger: a plain BTS transfer
    // between strangers leaves pool balance and claims byte-identical...
    h2j_transfer( *this, carol_id, carol_private_key, dave_id,
                  asset( share_type( 1000 ), asset_id_type() ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 49000 ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims[0].amount == share_type( 49000 ) );
    // ...a vesting_balance_create from liquid BTS likewise leaves the ledger
    // untouched (pool claims fund only via offset_deposit and pay only via
    // offset_claim/absorb: there is no claim-derived source any
    // BTS-moving op can consume)...
    const vesting_balance_id_type carol_vb = h2j_make_cdd_vesting(
          *this, carol_id, carol_private_key, share_type( 1000 ) );
    BOOST_REQUIRE( db.find( carol_vb ) != nullptr );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 49000 ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims[0].amount == share_type( 49000 ) );
    // ...and the blind variants (transfer_to_blind / transfer_from_blind /
    // blind_transfer) have no ledger path by construction: they move account
    // balances into/out of blind commitments (protocol/confidential.hpp),
    // while the pool ledger is an internal vector on offset_pool_object that
    // only offset_deposit / offset_claim / h2_issue_absorb_pair ever
    // create/modify (grep: offset_pool_object appears only in
    // issuance.cpp + issuance_object.hpp/evaluator decls/index; zero
    // references in confidential_evaluator.cpp, transfer/market/vesting
    // evaluators). A blind op funded from claim-derived BTS would move the
    // already-paid liquid BTS (same as the plain transfer above), never the
    // ledger entry itself -- non-transferable by construction
    // (issuance_object.hpp:158-160).
   // ...repeat deposits MERGE (one entry per owner, latest maturity wins)...
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 10000 ) );
   const offset_pool_object* p2 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE_EQUAL( p2->claims.size(), 1u );
   BOOST_CHECK( p2->claims[0].amount == share_type( 59000 ) );
   BOOST_CHECK( p2->balance == share_type( 59000 ) );
   BOOST_CHECK( p2->claims[0].available_after >= avail0 );
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, d, share_type( 59001 ) );

    // After the 7-day vesting the claim pays liquid and the entry closes.
    // (The jump crosses ~7 maintenances on an expired price: the vault tops
    // up, then winds down fail-closed mid-jump. The funded pool is untouched
    // -- absorbs hold without a bonded price -- so the matured claim still
    // pays in full; wind-down claims are the separate terminal path.)
    generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC + 100 );
    generate_block();
    const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
    h2j_offset_claim( *this, bob_id, bob_private_key, d, share_type( 59000 ) );
    BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount
                 == bob_before + share_type( 59000 ) );
    BOOST_CHECK( h2j_find_pool( *this, d.pair )->claims.empty() );

    // Re-live the price and cross once: the jump's stale sweeps suspended
    // Recovery (zero priced collateral), and the second door below registers
    // new debt -- it must observe a live book, not the stale jump.
    h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 201, 1 );

   // No pool, no claim: the reserveless door refuses.
   const h2j_door e = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYOFFE", "HYOFFEF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "G" );
   h2j_offset_claim_throws( *this, bob_id, bob_private_key, e, share_type( 1 ) );
} FC_LOG_AND_RETHROW() }

/// Batch exits: two requests settle in ONE maintenance pass at ONE clearing
/// haircut (zero here: the book is covered), minus the floored 2% exit fee
/// that stays in the reserve. Face burns at request; the queue clears.
BOOST_AUTO_TEST_CASE( batch_exits_single_haircut_and_exit_fee )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYEXIT", "HYEXITF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "H" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 2000000 ), share_type( 10000 ) );
   // Carol holds exit face via a plain transfer (no new economics).
   h2j_transfer( *this, alice_id, alice_private_key, carol_id,
                 asset( share_type( 3000 ), d.pair ) );

   // Refusal side: dust (1 face -> gross floor(1x100)=100, fee eats 2, net
   // 98 -- admits; true dust needs a tiny price, covered elsewhere), the
   // full book (10000 == supply: redeem path only), and over-face.
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 10000 ) );

   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 3000 ) );
   h2j_exit_request( *this, carol_id, carol_private_key, d, share_type( 3000 ) );
   const reserve_object* rq = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( rq != nullptr );
   BOOST_REQUIRE_EQUAL( rq->exit_queue.size(), 2u );
   BOOST_CHECK( rq->stable_supply == share_type( 4000 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 4000 ) );

   const share_type alice_before = db.get_balance( alice_id, asset_id_type() ).amount;
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );

   // Covered book -> haircut 0 for the WHOLE batch: each pays
   // floor(300000 x 9800/10000) = 294000, identical per-face (no queue
   // jumping: position in the queue never matters).
   BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                == alice_before + share_type( 294000 ) );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 294000 ) );
   const reserve_object* rs = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( rs != nullptr );
   BOOST_CHECK( rs->exit_queue.empty() );
   // Fee routing: 2000000 - 588000 = 1412000 stays (2 x 6000 kept).
   BOOST_CHECK( rs->bts_balance == share_type( 1412000 ) );
   BOOST_CHECK( rs->stable_supply == share_type( 4000 ) );
} FC_LOG_AND_RETHROW() }

/// Suspension: a full queue (count cap) suspends FXR minting but not senior
/// flow; the batch settle lifts it. Both caps pin the same predicate.
BOOST_AUTO_TEST_CASE( exit_queue_suspends_fxr_mint_until_settled )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

    const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSUSP", "HYSUSPF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "I" );
   // 200% book with zero surplus (value 20000 == 2 x 10000): no FXR yet.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 2000000 ), share_type( 10000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount == share_type( 0 ) );

   // Fill the queue to the count cap (8 requests; faces differ so no two
   // transactions share an ID -- duplicate txids are refused, not queued).
   for( int i = 0; i < 8; ++i )
      h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 100 + i ) );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->exit_queue.size(), 8u );
   // Ninth request refuses (count cap).
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 200 ) );
   generate_block(); // reset the door counter: the probes below must refuse
                     // on suspension alone, never on the shared door counter

   // A surplus-raising mint (D=260000/M=1000: over-collateralized, FXR>0)
   // refuses while suspended...
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 260000 ), share_type( 1000 ) );
    // ...but senior-only flow still admits (near-par mint prices no FXR).
    h2j_mint( *this, alice_id, alice_private_key, d,
              share_type( 130000 ), share_type( 1000 ) );
     // Real vault bond: the pair must stay HEALTHY through the maintenance
     // crossing below (full-size lock covers the ~10172 peak outstanding;
     // otherwise the sweep freezes the door mid-test
     // and the post-settle mint refuses on the freeze, not the suspension).
     {
        const auto hoard = h2j_make_cdd_vesting( *this, alice_id, alice_private_key,
                                                 H2J_VAULT_RAW );
       h2j_lock_vault_bond( *this, alice_id, alice_private_key, d.vault, hoard,
                            H2J_VAULT_RAW, H2J_VAULT_USD_CENTS );
    }

    // The batch settles (haircut 0, 100-face nets floor(10000x0.98)=9800)
   // and the suspension lifts: the same FXR mint now admits.
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->exit_queue.empty() );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 260000 ), share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( alice_id, d.fxr ).amount > share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Value cap: queued value at the ceiling admits then suspends; past it
/// refuses. (Count leg pinned in the case above; both feed one predicate.)
BOOST_AUTO_TEST_CASE( exit_queue_value_cap_suspends_fxr )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYVAL", "HYVALF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "J" );
   // 3.6e11 BTS / 1.8e9 face across three blocks. The headroom leg
   // (k1 = unity) permits geometric scale-up only: each mint fits inside
   // the standing buffer (2e11 genesis, then 7e10 of 7e10 headroom, then
   // 9e10 of 9.45e10) -- no single conversion doubles a fat book.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 1000000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 70000000000LL ), share_type( 350000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 90000000000LL ), share_type( 450000000LL ) );

   // 6e8 face = 6e10 BTS queued (under the 1e11 value cap)...
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 600000000LL ) );
   // ...+4e8 face lands exactly ON the cap (equality admits)...
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 400000000LL ) );
   // ...any further face refuses (past the cap)...
   h2j_exit_request_throws( *this, alice_id, alice_private_key, d, share_type( 1 ) );
   // ...and FXR minting suspends at the cap (value leg of the predicate).
   h2j_mint_throws( *this, alice_id, alice_private_key, d,
                    share_type( 260000 ), share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// R-06 front-run closure: the attacker's later request settles at the SAME
/// batch haircut as the victim's earlier one (no queue jumping, no
/// face-minus-haircut arber residual in the 36h window -- by construction).
BOOST_AUTO_TEST_CASE( frontrun_attempt_settles_at_batch_haircut )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYFRONT", "HYFRONTF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "K" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_transfer( *this, alice_id, alice_private_key, bob_id,
                 asset( share_type( 300 ), d.pair ) );

   // Victim queues first, attacker jumps the queue after seeing it.
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 300 ) );
   generate_block();
   h2j_exit_request( *this, bob_id, bob_private_key, d, share_type( 300 ) );

   // Price collapses 6x before the batch: obligations are 400 supply + 600
   // queued = 1000 face against 200000 BTS. Value floor(200000/600)=333 ->
   // coverage floor(333x10000/1000)=3330 -> haircut 6670 for the WHOLE batch
   // (queued face counts: a crash cannot overpay past the reserve).
   // The crash crosses maintenance live (refreshed right before the sweep).
   const share_type alice_before = db.get_balance( alice_id, asset_id_type() ).amount;
   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   h2j_cross_maintenance_with_price( *this, d, bob_id, bob_private_key, 600, 1 );

   // Both settle at the batch haircut: gross floor(300x600)=180000, factor
   // 10000-6670-200=3130 -> floor(180000x3130/10000)=56340, under the
   // pro-rata 60000. Identical per-face (position never matters),
   // haircutten (below gross), fee-bearing (below haircut-only 59715).
   BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount
                == alice_before + share_type( 56340 ) );
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount
                == bob_before + share_type( 56340 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->exit_queue.empty() );
   // The uncovered remainder (shortfall ceil((1000x600-200000)/1)=400000,
   // no pool) is recorded for the rmax junior path, not silently dropped.
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 400000 ) );
} FC_LOG_AND_RETHROW() }

/// REVERT: an unvested door output returns to its source on halt entry
/// (escrow cancelled, face back for claiming, reserve made whole).
BOOST_AUTO_TEST_CASE( halt_reverts_unvested_door_outputs )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYREV", "HYREVF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "L" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   // Redeem 500: escrow floor(500x100)-150 = 49850, pending list holds 1.
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(), 1u );

    // Halt entry (committee freeze): the unvested output REVERTS.
    h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );
    BOOST_CHECK( db.find( escrow ) == nullptr ); // escrow cancelled
    BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 1000 ) ); // face back
    BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 1000 ) );
    BOOST_CHECK( d.vault( db ).outstanding == share_type( 1000 ) );
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 200000 ) ); // whole
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->pending_vestings.empty() );
    // REVERT is the exact inverse of redeem-apply (issuance.cpp:1166-1171):
    // the burned 500 face returns to the reserve liability AND its band
    // partition, so the round-trip closes (stable_supply 500->1000, band
    // face sum == supply). Without the stable leg the reserve would strand
    // 500 of restored BTS against 500 of missing liability.
    BOOST_CHECK( h2j_find_reserve( *this, d.pair )->stable_supply == share_type( 1000 ) );
    BOOST_CHECK( h2j_band_sum_bts( h2j_find_reserve( *this, d.pair ) )
                 == h2j_find_reserve( *this, d.pair )->bts_balance );
    BOOST_CHECK( h2j_band_sum_face( h2j_find_reserve( *this, d.pair ) )
                 == h2j_find_reserve( *this, d.pair )->stable_supply );
} FC_LOG_AND_RETHROW() }

/// ABSORB (pool leg): a below-100% position drinks from the offset pool
/// first on halt entry; the reserve is made whole, remainder zero.
BOOST_AUTO_TEST_CASE( halt_absorbs_shortfall_from_pool_first )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYABS", "HYABSF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "M" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 100000 ) );

   // Crash to (250,1): value floor(200000/250)=800 < 1000, shortfall
   // ceil((1000x250-200000)/1) = 50000. No pending (no redeems).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 250, 1 );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 50000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 250000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// ABSORB (dilute leg): when the pool cannot cover, it drains fully and the
/// remainder is RECORDED for the existing rmax junior path (never dropped).
BOOST_AUTO_TEST_CASE( halt_absorb_dilute_records_remainder )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDIL", "HYDILF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "N" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   h2j_offset_deposit( *this, bob_id, bob_private_key, d, share_type( 20000 ) );

   // Same crash (shortfall 50000), pool holds 20000: drains, records 30000.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 250, 1 );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   BOOST_CHECK( h2j_find_pool( *this, d.pair )->balance == share_type( 0 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 220000 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->uncovered_shortfall == share_type( 30000 ) );
} FC_LOG_AND_RETHROW() }

/// STAND: a matured (settled) door output is never repriced -- the halt
/// prunes it and leaves escrow, face, supply, and reserve untouched.
BOOST_AUTO_TEST_CASE( halt_stands_settled_positions )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSTAND", "HYSTANDF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "O" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );

   // Let the 24h escrow mature (maintenance passes; the vault may TOPUP but
   // no halt transition runs outside freeze/wind-down entries), then refresh
   // the price (aged past its lifetime) and halt.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC + 100 );
   generate_block();
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   BOOST_REQUIRE( h2_read_pair_price( db, d.vault( db ), 0, db.head_block_time() ).valid() );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   // Stood: escrow intact, face NOT re-minted, book untouched, list pruned.
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_CHECK( db.find( escrow )->balance == asset( share_type( 49850 ), asset_id_type() ) );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 500 ) );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply == share_type( 500 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->bts_balance == share_type( 150150 ) );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->pending_vestings.empty() );
} FC_LOG_AND_RETHROW() }

/// New-op gates: offset deposit/claim and exit requests refuse before the
/// price leg (direct + fee-vote + proposal containment, E-01 pattern) and
/// price post-leg.
BOOST_AUTO_TEST_CASE( issuance2_gates_refuse_before_the_price_leg )
{ try {
   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   {
      offset_deposit_operation op;
      op.depositor = alice_id;
      op.vault     = vault_id_type( 0 );
      op.deposit   = asset( share_type( 1000 ), asset_id_type() );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_gate_refusal( db, tx, "offset_deposit pre-price" );
   }
   {
      offset_claim_operation op;
      op.claimant = alice_id;
      op.vault    = vault_id_type( 0 );
      op.amount   = share_type( 1000 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_gate_refusal( db, tx, "offset_claim pre-price" );
   }
   {
      issuance_exit_request_operation op;
      op.requester = alice_id;
      op.vault     = vault_id_type( 0 );
      op.face      = share_type( 1000 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_gate_refusal( db, tx, "issuance_exit_request pre-price" );
   }
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      cmuop.new_parameters.get_mutable_fees() = fee_schedule::get_default();
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<offset_deposit_operation>() );
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<offset_claim_operation>() );
      BOOST_REQUIRE( cmuop.new_parameters.current_fees->exists<issuance_exit_request_operation>() );
      cop.proposed_ops.emplace_back( cmuop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      offset_deposit_operation oop;
      oop.depositor = alice_id;
      oop.vault     = vault_id_type( 0 );
      oop.deposit   = asset( share_type( 1000 ), asset_id_type() );
      cop.proposed_ops.emplace_back( oop );
      signed_transaction tx; tx.operations.push_back( cop );
      set_expiration( db, tx );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx, ~0 ), fc::exception );
   }

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

/// Fee defaults pin (spam math, E-01 pattern): all three new ops price
/// mempool noise at nonzero 5-BTS defaults, matching the door-op basis.
BOOST_AUTO_TEST_CASE( issuance2_fee_defaults_pinned_nonzero )
{ try {
   BOOST_CHECK_EQUAL( offset_deposit_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( offset_claim_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( issuance_exit_request_operation::fee_params_t().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<offset_deposit_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<offset_claim_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
   BOOST_CHECK_EQUAL( fee_schedule::get_default().get<issuance_exit_request_operation>().fee,
                      5 * GRAPHENE_BLOCKCHAIN_PRECISION );
} FC_LOG_AND_RETHROW() }

/// Collects database_api FC_API member names without a node connection.
/// File scope: local classes cannot carry the member template the
/// per-method functor types require.
struct h2_api_method_name_collector {
   std::vector<std::string>& out;
   template<typename Member>
   void operator()( const char* name, Member )const { out.emplace_back( name ); }
};

/// F3 depth-median API gap: the F1 cap consumes h2_issue_qualified_depth
/// (pool-observe tripwire inputs), but no database_api accessor exposes
/// it, so wallets and tooling cannot price door flow. API clients read
/// exactly the FC_API table, so presence in the vtable == served.
BOOST_AUTO_TEST_CASE( depth_median_api_exposes_qualified_depth )
{ try {
   fc::vtable<graphene::app::database_api,
              fc::identity_member_with_optionals> vt;
   std::vector<std::string> names;
   vt.visit( h2_api_method_name_collector{ names } );
   BOOST_CHECK( std::find( names.begin(), names.end(), "get_h2_qualified_depth" )
                != names.end() );
} FC_LOG_AND_RETHROW() }

/// The accessor reads live tripwire state exactly: pre-pool it reads empty
/// (bootstrap, depth leg skipped), single-pool/single-window it reads zero
/// (fail-closed refuse) — mirroring h2_issue_qualified_depth call-for-call.
BOOST_AUTO_TEST_CASE( depth_median_api_reads_live_tripwire_state )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 100000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYAPI", "HYAPIF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "G" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 100000000LL ) );
   generate_block();

   graphene::app::database_api db_api( db );
   // Pre-pool: the chain helper and the API both read empty.
   BOOST_CHECK( !h2_issue_qualified_depth( db, d.pair ).valid() );
   BOOST_CHECK( !db_api.get_h2_qualified_depth( "HYAPI" ).valid() );

   // One pool, one deep exchange in the current window only: state exists
   // but is unqualified (empty old window and a single pool).
   const asset_id_type lpa = h2j_create_uia( *this, alice_id, alice_private_key, "HYAPILP" );
   const liquidity_pool_object& pool = create_liquidity_pool(
         alice_id, asset_id_type(), d.pair, lpa, 0, 0 );
   deposit_to_liquidity_pool( alice_id, pool.get_id(),
                              asset( share_type( 1000000000 ), asset_id_type() ),
                              asset( share_type( 10000000 ), d.pair ) );
   exchange_with_liquidity_pool( alice_id, pool.get_id(),
                                 asset( share_type( 200000000 ), asset_id_type() ),
                                 asset( share_type( 1 ), d.pair ) );

   // Unqualified: the chain helper and the API both read zero.
   const auto chain_depth = h2_issue_qualified_depth( db, d.pair );
   const auto api_depth = db_api.get_h2_qualified_depth( "HYAPI" );
   BOOST_REQUIRE( chain_depth.valid() );
   BOOST_REQUIRE( api_depth.valid() );
   BOOST_CHECK_EQUAL( *chain_depth, 0u );
   BOOST_CHECK_EQUAL( *api_depth, 0u );
} FC_LOG_AND_RETHROW() }

/// LL-10 frozen-oracle explicit halt: a queued exit the maintenance sweep
/// cannot settle (no bonded live price) is an EXPLICIT vault halt, never a
/// silent stall (RED: pre-fix the sweep `continue`s with the vault untouched).
/// Isolation: the vault carries zero outstanding, so the coverage sweep meets
/// and never top-ups -- HEALTHY throughout proves the freeze below comes
/// from the issuance sweep alone, not the TOPUP path.
BOOST_AUTO_TEST_CASE( frozen_oracle_holds_queued_exits_as_explicit_halt )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYHALT", "HYHALTF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "H" );

   // Book: D=700000/M=1000 at (100,1). Queue a 600-face batch exit (supply
   // and outstanding fall to 400), then take the exact full-book redeem path
   // for the remaining 400: supply and outstanding reach 0 while the queued
   // 600 (face already burned) waits for its maintenance batch.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 600 ) );
   BOOST_REQUIRE( d.vault( db ).outstanding == share_type( 400 ) );
   h2j_redeem( *this, alice_id, alice_private_key, d, share_type( 400 ) );
   BOOST_REQUIRE( d.vault( db ).outstanding == share_type( 0 ) );
   BOOST_REQUIRE( h2j_find_reserve( *this, d.pair )->exit_queue.size() == 1u );

   // Shorten the print lifetime (owner path, no dispute standing), then cross
   // the next maintenance with the print aged far past it: the sweep reads
   // no bonded price. The approach crosses no maintenance (queue-safe); the
   // final crossing lands 600s past the grid with print age >> 120s.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time - 1800 );
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = d.oracle;
      oracle_options live = d.oracle( db ).options;
      live.value_lifetime_sec = 120;
      uop.new_options = live;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 600 );
   generate_block();

   // Premise: the bonded read is absent at the sweep.
   BOOST_REQUIRE( !h2_read_pair_price( db, d.vault( db ), 0, db.head_block_time() ).valid() );
   // Explicit halt, not silent stall: the door reads frozen while the queue
   // sits intact for the live-price resume.
   BOOST_CHECK_EQUAL( d.vault( db ).frozen, true );
   BOOST_CHECK_EQUAL( d.vault( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_REQUIRE( r->exit_queue.size() == 1u );
   BOOST_CHECK( r->exit_queue.front().face == share_type( 600 ) );
} FC_LOG_AND_RETHROW() }

/// Offset ledger honesty (ISS-12): the 64-claimant cap PRUNES, never refuses
/// honest absorbers out of the shock absorber (RED: pre-fix the 65th
/// distinct deposit is refused, so 64 dust accounts lock every honest
/// depositor out of the pool for 7 days). The victim is the smallest MATURED
/// claim, paid liquid at prune time (matured = already claimable, so nothing
/// strands); with no matured claim the 65th still refuses fail-closed.
BOOST_AUTO_TEST_CASE( offset_ledger_prunes_smallest_matured_claim )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPRUNE", "HYPRUNEF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "P" );

   // 65 distinct depositors (no mints on this pair: the vault carries no
   // outstanding, so the 7-day jump below crosses maintenances safely).
   vector<account_id_type> fillers;
   vector<fc::ecc::private_key> fill_keys;
   for( int i = 0; i < 65; ++i )
   {
      const string name = string( "prunefill" ) + fc::to_string( i );
      const fc::ecc::private_key key = generate_private_key( name );
      const account_object& acct = create_account( name, key.get_public_key() );
      fund( acct, asset( 10000000 ) );
      fillers.push_back( acct.get_id() );
      fill_keys.push_back( key );
   }
   for( int i = 0; i < 64; ++i )
      h2j_offset_deposit( *this, fillers[i], fill_keys[i], d, share_type( 1000 ) );
   const offset_pool_object* p0 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p0 != nullptr );
   BOOST_REQUIRE_EQUAL( p0->claims.size(), 64u );

   // Nothing matured yet: the 65th refuses fail-closed (no prune candidate).
   h2j_offset_deposit_throws( *this, fillers[64], fill_keys[64], d, share_type( 1000 ) );

   // Past the 7-day vest every claim matured: the 65th admits, pruning the
   // smallest matured claim (all equal here: the first, fill00) with a
   // liquid payout, so no funds strand and the ledger stays bounded.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_OFFSET_VEST_SEC + 600 );
   generate_block();
   const share_type victim_before =
         db.get_balance( fillers[0], asset_id_type() ).amount;
   h2j_offset_deposit( *this, fillers[64], fill_keys[64], d, share_type( 1000 ) );
   const offset_pool_object* p1 = h2j_find_pool( *this, d.pair );
   BOOST_REQUIRE( p1 != nullptr );
   BOOST_CHECK_EQUAL( p1->claims.size(), 64u );
   BOOST_CHECK( p1->balance == share_type( 64000 ) );
   bool victim_gone = true, newcomer_present = false;
   for( const h2_offset_claim& c : p1->claims )
   {
      if( c.owner == fillers[0] )
         victim_gone = false;
      if( c.owner == fillers[64] )
      {
         newcomer_present = true;
         BOOST_CHECK( c.amount == share_type( 1000 ) );
      }
   }
   BOOST_CHECK( victim_gone );
   BOOST_CHECK( newcomer_present );
   BOOST_CHECK( db.get_balance( fillers[0], asset_id_type() ).amount
                == victim_before + share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// Pending-vest bound (issuance.cpp h2_issue_pending_unmatured + the redeem
/// evaluate "Too many unvested door outputs" gate): 64 unvested escrows fill
/// the bounded list; the 65th redeem refuses while none matured (RED: pre-fix
/// the bound is absent so the list grows unbounded across blocks), and admits
/// once the 24h vest matures (apply prunes matured entries, never strands).
BOOST_AUTO_TEST_CASE( pending_vest_cap_refuses_65th_redeem )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPEND", "HYPENDF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "V" );

   // Book D=700000/M=1000 at (100,1): 64 ten-face redeems stay far above
   // rmin (remainder ~636000/360 ≈ 1767%) and far below the door cap, so the
   // only binding constraint below is the pending-vest bound.
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );
   for( int i = 0; i < 64; ++i )
   {
      generate_block(); // unique TaPoS per identical redeem (dupe-check)
      h2j_redeem( *this, alice_id, alice_private_key, d, share_type( 10 ) );
   }
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(), 64u );

   // Nothing matured (minutes old vs 24h vest): the 65th refuses fail-closed.
   // Fresh block first so the attempt is not a byte-duplicate of the 64th.
   generate_block();
   {
      hybrid_redeem_operation op;
      op.redeemer = alice_id;
      op.vault    = d.vault;
      op.burn     = asset( share_type( 10 ), d.pair );
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      try
      {
         PUSH_TX( db, tx );
         BOOST_FAIL( "65th unmatured redeem must refuse at the pending-vest bound" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_string().find( "Too many unvested" ) != std::string::npos,
                              e.to_string() );
      }
   }
   BOOST_CHECK_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(), 64u );

   // Past the 24h vest every entry matured: the same redeem admits, pruning
   // the stood outputs (never repriced) down to the single fresh entry.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC + 600 );
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   generate_block();
   h2j_redeem( *this, alice_id, alice_private_key, d, share_type( 10 ) );
   BOOST_CHECK_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(), 1u );
} FC_LOG_AND_RETHROW() }

/// Band edge clamps (issuance.cpp h2_issue_maybe_rebalance dst clamp
/// `src + 1 < N_BANDS` / `src > 0`): sustained up-moves migrate mass toward
/// band 6 and clamp there (no wrap past the top, no out-of-range write),
/// sustained down-moves clamp at band 0; the anchor advances on every
/// consumed move and the partition sums to the totals exactly throughout
/// (RED: without the clamp a top-band up-move writes past the vector).
BOOST_AUTO_TEST_CASE( band_edge_clamps_hold_across_sustained_moves )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYCLAMP", "HYCLAMPF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "C" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 700000 ), share_type( 1000 ) );

   auto check_partition = [&]( const char* where, int64_t anchor_base )
   {
      const reserve_object* r = h2j_find_reserve( *this, d.pair );
      BOOST_REQUIRE_MESSAGE( r != nullptr, where );
      BOOST_REQUIRE_EQUAL( r->band_bts.size(), 7u );
      BOOST_REQUIRE_EQUAL( r->band_stable.size(), 7u );
      BOOST_CHECK_MESSAGE( h2j_band_sum_bts( r ) == r->bts_balance, where );
      BOOST_CHECK_MESSAGE( h2j_band_sum_face( r ) == r->stable_supply, where );
      BOOST_CHECK_MESSAGE( r->band_anchor == oracle_value( anchor_base, 1 ), where );
   };

   // Up-leg: 28 x +2% consumed moves with small conversions (each step above
   // the 1.25% half-tick, so each step shifts exactly once and re-anchors;
   // the excursion stays small so the rmin floor never binds: the clamp, not
   // rmin, is under test).
   int64_t px = H2J_BASE;
   for( int i = 0; i < 28; ++i )
   {
      px = px * 102 / 100;
      h2j_publish( *this, d.oracle, bob_id, bob_private_key, px, 1 );
      generate_block(); // unique TaPoS per identical small mint (dupe-check)
      h2j_mint( *this, alice_id, alice_private_key, d,
                share_type( 7000 ), share_type( 10 ) );
      check_partition( "up-leg partition", px );
   }
   // Migration reached the top band (the clamp path executed: a fullest-6
   // up-move shifts nothing, anchor still advances).
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->band_bts[6] > share_type( 0 ) );

   // Down-leg: 28 x -2% consumed moves back through and below the start.
   for( int i = 0; i < 28; ++i )
   {
      px = px * 100 / 102;
      h2j_publish( *this, d.oracle, bob_id, bob_private_key, px, 1 );
      generate_block(); // unique TaPoS per identical small mint (dupe-check)
      h2j_mint( *this, alice_id, alice_private_key, d,
                share_type( 7000 ), share_type( 10 ) );
      check_partition( "down-leg partition", px );
   }
   BOOST_CHECK( h2j_find_reserve( *this, d.pair )->band_anchor == oracle_value( px, 1 ) );
} FC_LOG_AND_RETHROW() }

/// Per-leg floored quanta (issuance.cpp h2_issue_maybe_rebalance q_bts /
/// q_face with the `q_bts > 0 || q_face > 0` move gate): a book whose face
/// leg is dust floors the face quantum to zero while the BTS leg still
/// shifts — each leg moves its own floored quantum, the anchor still
/// advances on the consumed move, and conservation holds per leg.
BOOST_AUTO_TEST_CASE( band_quantas_floor_per_leg_with_anchor_advance )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYDUST", "HYDUSTF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "D" );

   // Dust-face book: band 3 holds (60000, 1), anchored at (100,1).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 60000 ), share_type( 1 ) );
   const reserve_object* r0 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r0 != nullptr );
   BOOST_REQUIRE( r0->band_bts[3] == share_type( 60000 ) );
   BOOST_REQUIRE( r0->band_stable[3] == share_type( 1 ) );

   // Consumed up-move (+15%) with a second tiny mint: pre-shift source is
   // (67000, 2), so q_bts = 67000/7 = 9571 while q_face = 2/7 = 0.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, 115, 1 );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 7000 ), share_type( 1 ) );
   const reserve_object* r1 = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r1 != nullptr );
   // The BTS leg shifted one step up by its floored quantum...
   BOOST_CHECK( r1->band_bts[4] == share_type( 9571 ) );
   BOOST_CHECK( r1->band_bts[3] == share_type( 67000 - 9571 ) );
   // ...the dust face leg moved nothing (its quantum floored to zero)...
   BOOST_CHECK( r1->band_stable[4] == share_type( 0 ) );
   BOOST_CHECK( r1->band_stable[3] == share_type( 2 ) );
   // ...yet the anchor still advanced on the observed price (dust never
   // pins the basis: the partition catches up, the price basis moves once
   // observed).
   BOOST_CHECK( r1->band_anchor == oracle_value( 115, 1 ) );
   BOOST_CHECK( h2j_band_sum_bts( r1 ) == r1->bts_balance );
   BOOST_CHECK( h2j_band_sum_face( r1 ) == r1->stable_supply );
} FC_LOG_AND_RETHROW() }

/// Pilot ceiling (AC-02, audit-round-7): total senior outstanding per pair is
/// consensus-capped at $20,000 face. Red test for the mint-door gate in
/// `hybrid_mint_evaluator::do_evaluate` (issuance.cpp) and the issuer-direct
/// gate in `asset_issue_evaluator::do_evaluate` (asset_evaluator.cpp): the
/// book fills to exactly the cap across blocks (door-cap scale chunks, every
/// other gate passing), cap+1 face refuses on BOTH paths with a "Pilot
/// ceiling" refusal, while cap itself admits. Pair precision is 5, so the
/// cap is 20000 * 10^5 = 2000000000 face units.
static_assert( GRAPHENE_H2_ISSUE_PILOT_MAX_STABLE_FACE_USD == 20000ULL,
               "pilot ceiling must stay $20,000 face (lift = new binary + audit)" );


/// ISS-R14-16 test adaptation: grant a season record the production shape by
/// backdating its window and stamping the verifier bit (hand-set precedent in
/// h2_seasoning_tests). Records only exist for registered pairs; for anything
/// else the issuer-direct gate is already inert and this is a no-op.
void h2x_grant_seasoning( database_fixture& f, asset_id_type pair )
{
   const auto& by_pair = f.db.get_index_type<seasoning_record_index>()
                            .indices().get<by_seasoning_pair>();
   if( by_pair.find( pair ) == by_pair.end() )
      return; // never-vaulted pair: no record exists and the gate is inert
   f.generate_block(); // seal setup: a backdate issued back-to-back would be discarded
   // Re-locate after the flush: the pre-flush iterator belongs to the session
   // the flush discards, so the modify must run against committed state.
   const auto itr = by_pair.find( pair );
   if( itr == by_pair.end() )
      return; // structural surprise: leave the record untouched
   const fc::time_point_sec backdate = f.db.head_block_time()
         - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
   f.db.modify( *itr, [&backdate]( seasoning_record_object& m ) {
      m.window_start  = backdate;
      m.min_vault_bps  = 50000;  // > the 2.0 (20000bps) and 1.0 (10000bps) floors
      m.min_oracle_bps = 50000;
      m.verifier_set   = true;
      m.complete       = true;
   } );
}

void h2j_pilot_issue(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      asset_id_type pair, account_id_type to, share_type amount )
{
   asset_issue_operation op;
   op.issuer            = issuer;
   op.asset_to_issue    = asset( amount, pair );
   op.issue_to_account  = to;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2j_require_pilot_refusal(
      database_fixture& f, signed_transaction& tx, const char* what )
{
   try { PUSH_TX( f.db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( "Pilot ceiling" ) != std::string::npos,
            what << " refused off-gate (not the pilot ceiling): " << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED past the pilot ceiling" );
}

BOOST_AUTO_TEST_CASE( pilot_ceiling_caps_pair_scale )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   // Door A: fill the BOOK to exactly the cap. Genesis skips the headroom
   // leg, so one door-cap-scale mint opens deep; later chunks respect the
   // standing headroom (k1 unity) with a block per chunk resetting the
   // shared door counter. Post-chunk1 headroom ~= 200B - 50M*130 ~= 193B,
   // so the 180.54B second leg admits (grossed for the 30bps fee: net
   // 180541624874 - 541624874 = 180000000000 exact); post-chunk2 headroom
   // ~= 139B admits the 20B third leg. Every non-pilot gate passes at each
   // step below (rmin 4000%/205%/200%, door, headroom, secure 6x+).
   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPILOT", "HYPILOTF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "P" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 50000000LL ) );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 180541624874LL ), share_type( 1800000000LL ) );
   generate_block(); // reset the door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 150000000LL ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_REQUIRE_EQUAL( r->stable_supply.value, 2000000000LL );
   // Cap + 1 face through the mint door refuses AT the pilot gate.
   {
      hybrid_mint_operation op;
      op.minter        = alice_id;
      op.vault         = d.vault;
      op.deposit       = asset( share_type( 200 ), asset_id_type() );
      op.stable_amount = share_type( 1 );
      op.fxr_asset     = d.fxr;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "mint past $20k cap" );
   }
   // Issuer-direct path on the same pair refuses too (same cap, token leg).
   {
      asset_issue_operation op;
      op.issuer           = alice_id;
      op.asset_to_issue   = asset( share_type( 1 ), d.pair );
      op.issue_to_account = alice_id;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "issuer-direct past $20k cap" );
   }

   // Door B: pin the issuer-path BOUNDARY (exact cap admits, +1 refuses)
   // and the mint token-leg (book small, token at cap, mint refuses).
   const h2j_door e = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPILOTB", "HYPILOTBF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "Q" );
   h2j_mint( *this, alice_id, alice_private_key, e,
             share_type( 140000 ), share_type( 1000 ) );
   h2j_pilot_issue( *this, alice_id, alice_private_key, e.pair, alice_id,
                    share_type( 2000000000LL - 1000 ) );
   BOOST_CHECK_EQUAL( e.pair( db ).dynamic_asset_data_id( db ).current_supply.value,
                      2000000000LL );
   {
      asset_issue_operation op;
      op.issuer           = alice_id;
      op.asset_to_issue   = asset( share_type( 1 ), e.pair );
      op.issue_to_account = alice_id;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "issuer-direct cap+1" );
   }
   // Token at cap, book at 1000: a 1-face mint passes every book-side gate
   // (rmin 140%, headroom, door) and refuses on the pilot token leg only.
   h2j_mint_throws( *this, alice_id, alice_private_key, e,
                    share_type( 200 ), share_type( 1 ) );
} FC_LOG_AND_RETHROW() }

/// Pilot ceiling pre-bind closure (AC-02 follow-up): vault registration
/// itself refuses when the pair already carries over-cap supply. Attack:
/// issue large supply before any vault exists (issuer-direct gate inert:
/// no vault row), then register -- future mints refuse but the over-cap
/// remains. Defense `vault_evaluator.cpp vault_register_evaluator::
/// do_evaluate`: pair current_supply <= h2_issue_pilot_cap_face(precision).
BOOST_AUTO_TEST_CASE( pilot_ceiling_binds_vault_registration )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );

   // Over-cap pre-issue (no vault yet: issuer-direct gate inert, admits).
   const asset_id_type over = h2j_create_uia( *this, alice_id, alice_private_key, "HYPREOV" );
   h2j_pilot_issue( *this, alice_id, alice_private_key, over, alice_id,
                    share_type( 2000000000LL + 1 ) );
   BOOST_REQUIRE_EQUAL( over( db ).dynamic_asset_data_id( db ).current_supply.value,
                        2000000000LL + 1 );
   // Registration over the standing over-cap supply refuses at the pilot gate.
   {
      vault_register_operation op;
      op.registrar            = alice_id;
      op.pair                 = over;
      op.vault_authority      = authority( 1, alice_id, 1 );
      op.min_bond             = H2J_VAULT_RAW;
      op.min_bond_usd_cents   = H2J_VAULT_USD_CENTS;
      op.bond_asset           = asset_id_type();
      op.secure_ratio_bps     = 20000;
      op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "vault register with over-cap supply" );
   }

   // At-cap pre-issue registers OK (inclusive boundary).
   const asset_id_type ok = h2j_create_uia( *this, alice_id, alice_private_key, "HYPREOK" );
   h2j_pilot_issue( *this, alice_id, alice_private_key, ok, alice_id,
                    share_type( 2000000000LL ) );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2j_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, ok );
   BOOST_REQUIRE( db.find( vid ) != nullptr );
   BOOST_CHECK( vid( db ).vault_pair == ok );
} FC_LOG_AND_RETHROW() }

/// PC-01 (audit-round-9, Critical): the $20,000 face pilot ceiling must hold
/// across the SUPPLY-RESTORING paths, not only the mint doors. Exploit shape:
/// fill the pair to the cap, redeem X (the face parks in an unvested door
/// escrow), mint X back (pre-fix: BOTH door legs still read `<= cap`), then
/// force a pair halt so the revert re-mints X on top of the refilled cap and
/// standing supply lands at cap+X. Two independent defenses, both pinned in
/// this file:
///  (a) the doors hold current/book + PENDING + QUEUED restore face under the
///      cap, so the refill leg that made the attack possible refuses at the
///      pilot gate -- the restore can never be handed face the doors did not
///      already count;
///  (b) `h2_issue_on_pair_halt` / `h2_create_winddown` project their own
///      restore and refuse fail-closed before any state moves
///      (`pilot_ceiling_refuses_over_cap_halt_revert` and
///      `pilot_ceiling_refuses_over_cap_winddown_refund` drive it directly).
/// This case drives (a) end to end and then proves the halt lands at EXACTLY
/// the cap -- never above it.
BOOST_AUTO_TEST_CASE( pilot_ceiling_holds_across_halt_revert )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const share_type cap = h2_issue_pilot_cap_face( 5 ); // 20000 x 10^5
   BOOST_REQUIRE_EQUAL( cap.value, 2000000000LL );      // precision-5 pin

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPCAP", "HYPCAPF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "R" );

   // Fill BOOK and token to exactly the cap (the pilot_ceiling_caps_pair_scale
   // door-fill: three door-cap-scale chunks, one block each so the shared
   // per-block door counter resets between legs).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 50000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 180541624874LL ), share_type( 1800000000LL ) );
   generate_block();
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 150000000LL ) );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, cap.value );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->stable_supply.value,
                        cap.value );

   // BURN 500 into an unvested door escrow: supply and book drop, the face
   // parks in pending_vestings as restore face.
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value,
         cap.value - 500 );
   generate_block(); // seal the redeem; fresh door counter for the refill leg

   // MINT the 500 back -- the refill that made PC-01 possible. Pre-fix both
   // door legs read (cap - 500) + 500 = cap and ADMIT; post-fix the doors
   // count the pending restore face, so the leg reads cap + 500 and refuses
   // at the pilot gate. Deposit sized to clear the net-face gate (floor of
   // the 100 BTS/face suite price) first: 100000 - 30bps fee -> 997 >= 500.
   {
      hybrid_mint_operation op;
      op.minter        = alice_id;
      op.vault         = d.vault;
      op.deposit       = asset( share_type( 100000 ), asset_id_type() );
      op.stable_amount = share_type( 500 );
      op.fxr_asset     = d.fxr;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "mint refill of redeemed face" );
   }
   BOOST_REQUIRE_EQUAL( db.get_balance( alice_id, d.pair ).amount.value,
                        cap.value - 500 );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value,
         cap.value - 500 );

   // HALT: the revert restores exactly the 500 the doors refused to re-mint,
   // so it lands AT the cap and never over it.
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   h2j_freeze( *this, alice_id, alice_private_key, d.vault, d.oracle );

   BOOST_CHECK( db.find( escrow ) == nullptr ); // escrow cancelled
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == cap );
   BOOST_CHECK( d.pair( db ).dynamic_asset_data_id( db ).current_supply <= cap );
   BOOST_CHECK_EQUAL( d.pair( db ).dynamic_asset_data_id( db ).current_supply.value,
                      cap.value );
   BOOST_CHECK( d.vault( db ).outstanding <= cap );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->stable_supply <= cap );
   BOOST_CHECK( r->pending_vestings.empty() );
} FC_LOG_AND_RETHROW() }

/// PC-01 defense (b), halt leg driven DIRECTLY: `h2_issue_on_pair_halt` must
/// refuse fail-closed when the standing token supply already sits at the cap
/// while an unvested door escrow is still owed its revert face, so the revert
/// would print cap+X. White-box construction: the doors now refuse exactly
/// this state (case above), so the only way left to hand it to the restore
/// path is to raise the standing supply surgically. Pre-fix pair_freeze is
/// ACCEPTED and re-mints 500 on top of the cap (supply cap+500, escrow gone,
/// book/stock mirrors moved); post-fix the FC_ASSERT fires inside
/// `h2_issue_on_pair_halt`, the freeze transaction is rejected, and NOTHING
/// moves.
BOOST_AUTO_TEST_CASE( pilot_ceiling_refuses_over_cap_halt_revert )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const share_type cap = h2_issue_pilot_cap_face( 5 );
   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPCAPX", "HYPCAPXF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "S" );

   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   generate_block(); // reset the door counter (redeem is a second leg)
   const vesting_balance_id_type escrow = h2j_redeem(
         *this, alice_id, alice_private_key, d, share_type( 500 ) );
   BOOST_REQUIRE( db.find( escrow ) != nullptr );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, 500 );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->pending_vestings.size(),
                        1u );

   // Stand the token AT the cap with 500 of revert face still pending.
   // Applied immediately after a block (no pushed transactions open), so it
   // lands on base state and persists (h2s_set_books precedent). The fixture
   // asserts sum(balances) == current_supply at teardown, so the phantom
   // standing supply must sit somewhere: bob carries it, which keeps alice's
   // real 500 intact as the "was the face returned?" probe below.
   db.modify( d.pair( db ).dynamic_asset_data_id( db ),
              [cap]( asset_dynamic_data_object& data ) {
                 data.current_supply = cap;
              } );
   db.adjust_balance( bob_id, asset( cap - 500, d.pair ) );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, cap.value );
   BOOST_REQUIRE_EQUAL( db.get_balance( alice_id, d.pair ).amount.value, 500 );

   // Halt entry with a LIVE bonded price (the revert path needs one).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );
   {
      pair_freeze_operation op;
      op.freezer = alice_id;
      op.vault   = d.vault;
      op.oracle  = d.oracle;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      h2j_require_pilot_refusal( *this, tx, "pair_freeze over-cap halt revert" );
   }

   // Fail-closed: no partial revert, no silent clamp, nothing restored.
   BOOST_CHECK( db.find( escrow ) != nullptr ); // escrow untouched
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 500 ) );
   BOOST_CHECK_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, cap.value );
   BOOST_CHECK( d.vault( db ).outstanding == share_type( 500 ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->stable_supply == share_type( 500 ) );
   BOOST_CHECK_EQUAL( r->pending_vestings.size(), 1u );
} FC_LOG_AND_RETHROW() }

/// PC-01 defense (b), wind-down leg driven DIRECTLY: `h2_create_winddown`
/// refunds every queued exit to face with no cap check pre-fix, so a
/// cap-standing token plus a queued exit prints cap+X the moment the vault
/// winds down. Same white-box construction as the halt case (the doors now
/// refuse this state); the wind-down itself is driven through the REAL
/// maintenance sweep -- coverage breach -> 36h top-up -> auto wind-down --
/// which is the only production entry into `h2_create_winddown` besides
/// vault_resolve. Pre-fix the sweep completes and refunds 200 on top of the
/// cap; post-fix the FC_ASSERT rejects the maintenance block and no wind-down
/// object, refund, or supply change is written.
BOOST_AUTO_TEST_CASE( pilot_ceiling_refuses_over_cap_winddown_refund )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const share_type cap = h2_issue_pilot_cap_face( 5 );
   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYPCAPW", "HYPCAPWF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "T" );

   // Book: mint 1000, queue a 200-face exit (face burns at request time:
   // supply and outstanding 800, alice holds 800, queue holds 200 of
   // restore face).
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000 ), share_type( 1000 ) );
   generate_block();
   // Keep the imminent maintenance out of the stale landing below: a live
   // maintenance while the book is healthy is a no-op either way, but the
   // queue must never be batch-settled before the wind-down refunds it.
   if( ( db.get_dynamic_global_properties().next_maintenance_time
         - db.head_block_time() ).to_seconds() < 900 )
      generate_blocks( db.head_block_time() + 1200 );
   h2j_exit_request( *this, alice_id, alice_private_key, d, share_type( 200 ) );
   generate_block(); // seal the door flow onto base state
   BOOST_REQUIRE_EQUAL( d.vault( db ).outstanding.value, 800 );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->exit_queue.size(), 1u );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, 800 );

   // Two surgical writes, both applied immediately after a block (no pushed
   // transactions open -> they land on base state and persist): stand the
   // token AT the cap while 200 of refund face is queued, and breach the
   // 150% coverage rule so the maintenance sweep drives the vault into the
   // top-up -> wind-down ladder (surgical-liability precedent:
   // winddown_sweeps_reserve_backing_and_refunds_queue). Bob carries the
   // phantom standing supply so the fixture's teardown
   // sum(balances) == current_supply holds while alice's real 800 stays
   // intact as the "was the refund paid?" probe below.
   db.modify( d.pair( db ).dynamic_asset_data_id( db ),
              [cap]( asset_dynamic_data_object& data ) {
                 data.current_supply = cap;
              } );
   db.adjust_balance( bob_id, asset( cap - 800, d.pair ) );
   db.modify( d.vault( db ), []( vault_object& v ) {
      v.outstanding = share_type( 10000000000LL );
   } );

   // Land past the oracle print lifetime in one leap: that maintenance reads
   // a STALE bonded price, so the exit batch HOLDS (never settles) the queued
   // 200 while the vault breaches into TOPUP. A live read would settle the
   // queue first and leave nothing to refund.
   const auto seal_time = db.head_block_time();
   const uint32_t print_lifetime = d.oracle( db ).options.value_lifetime_sec;
   generate_blocks( seal_time + print_lifetime + 600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( d.vault( db ).maintenance_state,
                        GRAPHENE_H2_VAULT_TOPUP );
   BOOST_REQUIRE_EQUAL( h2j_find_reserve( *this, d.pair )->exit_queue.size(), 1u );
   BOOST_REQUIRE_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, cap.value );

   // Past the 36h top-up deadline the sweep auto-winds-down. That is the
   // entry that must refuse fail-closed: the refund would push cap + 200.
   bool refused = false;
   try {
      generate_blocks( d.vault( db ).top_up_deadline + 2 * 86400 );
   }
   catch ( const fc::exception& e )
   {
      refused = true;
      BOOST_CHECK_MESSAGE( e.to_string().find( "Pilot ceiling" ) != std::string::npos,
                           "over-cap wind-down refused off-gate (not the pilot "
                           "ceiling): " << e.to_string() );
   }
   BOOST_CHECK_MESSAGE( refused,
                        "over-cap wind-down refund was ACCEPTED past the pilot "
                        "ceiling" );

   // Fail-closed: the wind-down never happened and the refund never moved.
   BOOST_CHECK_EQUAL( d.vault( db ).maintenance_state,
                      int( GRAPHENE_H2_VAULT_TOPUP ) );
   for( const auto& w : db.get_index_type<winddown_vault_index>().indices() )
      BOOST_CHECK( w.source_vault != d.vault );
   BOOST_CHECK_EQUAL( h2j_find_reserve( *this, d.pair )->exit_queue.size(), 1u );
   BOOST_CHECK_EQUAL(
         d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, cap.value );
   BOOST_CHECK( db.get_balance( alice_id, d.pair ).amount == share_type( 800 ) );
} FC_LOG_AND_RETHROW() }

// ---- ISS-R9-07 / R9-I8: FXR junior provenance and pin ----

/// Generic refusal probe (pilot-ceiling precedent): PUSH_TX must fail AND the
/// failure must name THIS guard's needle. A refusal off-guard (some other
/// gate firing first) is a wrong-reason pass and fails the check, so each
/// case below proves its own defense, not merely "a refusal happened".
void h2j_require_refusal( database_fixture& f, signed_transaction& tx,
                          const char* needle, const char* what )
{
   try { PUSH_TX( f.db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( needle ) != std::string::npos,
            what << " refused off-guard (not '" << needle << "'): "
                 << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED" );
}

/// Build a hybrid_mint transaction without pushing it (refusal probes need
/// the tx, not a direct push). Same fields h2j_mint pushes.
signed_transaction h2j_build_mint_tx(
      database_fixture& f, account_id_type minter, const fc::ecc::private_key& key,
      const h2j_door& d, share_type deposit_bts, share_type stable )
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
   return tx;
}

/// Build an asset_issue transaction without pushing it (issuer-direct
/// refusal probes). Same fields h2j_pilot_issue pushes.
signed_transaction h2j_build_issue_tx(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      asset_id_type token, account_id_type to, share_type amount )
{
   asset_issue_operation op;
   op.issuer           = issuer;
   op.asset_to_issue   = asset( amount, token );
   op.issue_to_account = to;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return tx;
}

/// ISS-R9-07 pre-mint attack: the issuer prints junior supply BEFORE any
/// reserve pins the FXR, then the first mint pins the reserve over phantom
/// supply -- wind-down junior claims burn FXR from balances, so that phantom
/// would pay out. Defense (guard 1, fresh pin): reserve creation refuses any
/// FXR whose current_supply is nonzero. Before the fix this mint is ACCEPTED.
BOOST_AUTO_TEST_CASE( h2_iss_r9_07_pre_mint_fresh_pin_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYR907A", "HYR907AF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "R" );

   // Issuer-direct print before any pin: the issuer-direct pilot gate is
   // inert here (FXR is not a vault pair), so this ADMITS pre-fix and
   // post-fix alike -- the guard under test is the pin, not the issue.
   h2j_pilot_issue( *this, alice_id, alice_private_key, d.fxr, alice_id,
                    share_type( 1000 ) );
   BOOST_REQUIRE_EQUAL( d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value,
                        1000 );

   // The mint that would CREATE the reserve over that phantom supply must
   // refuse at the fresh-pin guard.
   signed_transaction tx = h2j_build_mint_tx(
         *this, alice_id, alice_private_key, d,
         share_type( 200000000000LL ), share_type( 50000000LL ) );
   h2j_require_refusal( *this, tx, "zero supply",
                        "reserve pinning a pre-minted FXR" );
   BOOST_CHECK( h2j_find_reserve( *this, d.pair ) == nullptr );
} FC_LOG_AND_RETHROW() }

/// ISS-R9-07 issue lock: after a reserve pins the FXR, issuer-direct
/// asset_issue on that token would grow supply WITHOUT moving the reserve's
/// fxr_supply ledger (mirror drift -> phantom burn headroom). Defense
/// (guard 2): asset_issue refuses any asset pinned as a junior. Scope pin:
/// the PAIR's issuer-direct door stays open on the same reserve. Before the
/// fix the FXR issue below is ACCEPTED.
BOOST_AUTO_TEST_CASE( h2_iss_r9_07_post_pin_issue_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYR907B", "HYR907BF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "S" );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 50000000LL ) );
   BOOST_REQUIRE( h2j_find_reserve( *this, d.pair ) != nullptr );
   const int64_t pinned_supply =
         d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value;

   signed_transaction tx = h2j_build_issue_tx(
         *this, alice_id, alice_private_key, d.fxr, alice_id, share_type( 1 ) );
   h2j_require_refusal( *this, tx, "pinned as an FXR junior",
                        "issuer-direct issue on a pinned FXR" );
   BOOST_CHECK_EQUAL( d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value,
                      pinned_supply );

   // Guard scope: the senior PAIR is not a junior pin -- its issuer-direct
   // door must still admit post-pin (pilot-cap paths depend on it).
   h2j_pilot_issue( *this, alice_id, alice_private_key, d.pair, alice_id,
                    share_type( 1 ) );
} FC_LOG_AND_RETHROW() }

/// ISS-R9-07 double pin: two reserves pinning ONE FXR token would run two
/// fxr_supply ledgers over one shared asset current_supply -- wind-down
/// burns against either ledger draw down the same balance pool. Defense
/// (guard 3): reserve creation refuses an FXR already pinned by a live
/// reserve (unique by_reserve_fxr index backs the check). Before the fix
/// this second mint is ACCEPTED.
BOOST_AUTO_TEST_CASE( h2_iss_r9_07_double_pin_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door a = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYR907C", "HYR907CF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "C" );
   h2j_mint( *this, alice_id, alice_private_key, a,
             share_type( 200000000000LL ), share_type( 50000000LL ) );
   BOOST_REQUIRE( h2j_find_reserve( *this, a.pair ) != nullptr );

   const h2j_door b = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYR907D", "HYR907DF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "D" );
   // Second door reaches for the ALREADY-PINNING junior token.
   h2j_door reach = b;
   reach.fxr = a.fxr;
   signed_transaction tx = h2j_build_mint_tx(
         *this, alice_id, alice_private_key, reach,
         share_type( 200000000000LL ), share_type( 50000000LL ) );
   h2j_require_refusal( *this, tx, "already pinned",
                        "second reserve pinning the same FXR" );
   BOOST_CHECK( h2j_find_reserve( *this, b.pair ) == nullptr );
   BOOST_CHECK( h2j_find_reserve( *this, a.pair ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// GREEN: a normal reserve creation with a fresh FXR still succeeds, the
/// pin lands, the reserve ledger mirrors the token supply, the post-pin
/// mint door still works (mint moves both sides of the mirror), and the
/// issuer-direct PAIR door stays open (the lock is FXR-only).
BOOST_AUTO_TEST_CASE( h2_iss_r9_07_fresh_pin_admits )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYR907E", "HYR907EF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "E" );
   BOOST_REQUIRE_EQUAL( d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value,
                        0 );

   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 200000000000LL ), share_type( 50000000LL ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->fxr_asset == d.fxr );
   // Mirror invariant: reserve ledger == token supply at the pin.
   BOOST_CHECK_EQUAL( r->fxr_supply.value,
                      d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value );

   // Post-pin mint door still moves BOTH sides of the mirror.
   generate_block(); // reset the shared door counter
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 20000000000LL ), share_type( 150000000LL ) );
   r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK_EQUAL( r->fxr_supply.value,
                      d.fxr( db ).dynamic_asset_data_id( db ).current_supply.value );

   // Lock scope: issuer-direct issue on the PAIR still admits post-pin.
   h2j_pilot_issue( *this, alice_id, alice_private_key, d.pair, alice_id,
                    share_type( 1 ) );
} FC_LOG_AND_RETHROW() }

/// AC-08 (T4): the mint door is seasoning-gated (BSIP-1 section 5). An
/// unseasoned pair refuses naming seasoning; the same mint admits once the
/// pair seasons (independent verifier + 90-day clock + coverage). The
/// un-seasoning below resets the continuous-hold start to head-block time,
/// proving the gate reads live clock state rather than a one-time flag.
BOOST_AUTO_TEST_CASE( seasoning_gate_refuses_unseasoned_mint_ac08 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSEAS", "HYSEASF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "S" );
   // Un-season: the opener seasons every door, so restart the hold at head
   // time (sealed into a block first, h2s_set_books precedent).
   generate_block();
   {
      const auto& idx = db.get_index_type<seasoning_record_index>()
                           .indices().get<by_seasoning_pair>();
      const auto itr = idx.find( d.pair );
      BOOST_REQUIRE( itr != idx.end() );
      const fc::time_point_sec fresh = db.head_block_time();
      db.modify( *itr, [&fresh]( seasoning_record_object& m ) {
         m.window_start = fresh;
      } );
   }
   BOOST_REQUIRE( !h2_seasoning_complete( db, d.pair ) );

   // Refusal side first: the mint names seasoning, never another gate.
   {
      hybrid_mint_operation op;
      op.minter        = alice_id;
      op.vault         = d.vault;
      op.deposit       = asset( share_type( 140000 ), asset_id_type() );
      op.stable_amount = share_type( 1000 );
      op.fxr_asset     = d.fxr;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      try { PUSH_TX( db, tx ); }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_string().find( "seasoning" ) != std::string::npos,
               "unseasoned mint refused off-gate: " << e.to_string() );
      }
      catch( ... ) { BOOST_FAIL( "unseasoned mint refused without an fc::exception" ); }
      BOOST_CHECK_MESSAGE( h2j_find_reserve( *this, d.pair ) == nullptr,
            "unseasoned mint was ACCEPTED: the door must stay shut before seasoning" );
   }

   // Seasoned: the same mint admits (fixture satisfiable in-test: verifier
   // + backdated 90-day clock + saturated coverage, no consensus change).
   // The verifier bit is once-only and survives the un-seasoning above, so
   // re-seasoning only rewinds the continuous-hold start (no second verify:
   // double attestation is refused by construction).
   generate_block();
   {
      const auto& idx = db.get_index_type<seasoning_record_index>()
                           .indices().get<by_seasoning_pair>();
      const auto itr = idx.find( d.pair );
      BOOST_REQUIRE( itr != idx.end() );
      const fc::time_point_sec backdate = db.head_block_time()
            - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
      db.modify( *itr, [&backdate]( seasoning_record_object& m ) {
         m.window_start = backdate;
      } );
   }
   BOOST_REQUIRE( h2_seasoning_complete( db, d.pair ) );
   h2j_mint( *this, alice_id, alice_private_key, d,
             share_type( 140000 ), share_type( 1000 ) );
   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   BOOST_CHECK( r->bts_balance == share_type( 140000 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// ISS-R14-16 (round-14, carried to round-17): the issuer-direct supply door
/// must clear the SAME seasoning gate the mint door enforces (AC-08). Twin of
/// seasoning_gate_refuses_unseasoned_mint_ac08: un-seasoned pair, direct
/// issue refused at the seasoning assertion, then the seasoned backdate
/// admits the boundary face. Pre-fix this direct issue printed senior face
/// on a 0-day pair, bypassing BSIP-1 section-5 staging through the twin door.
BOOST_AUTO_TEST_CASE( seasoning_gate_refuses_unseasoned_issue_ac08 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 500000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYSEASI", "HYSEASIF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "I" );
   generate_block();
   {
      const auto& idx = db.get_index_type<seasoning_record_index>()
                           .indices().get<by_seasoning_pair>();
      const auto itr = idx.find( d.pair );
      BOOST_REQUIRE( itr != idx.end() );
      const fc::time_point_sec fresh = db.head_block_time();
      db.modify( *itr, [&fresh]( seasoning_record_object& m ) {
         m.window_start = fresh;
      } );
   }
   BOOST_REQUIRE( !h2_seasoning_complete( db, d.pair ) );

   // Refusal: names the seasoning assertion, never the pilot cap.
   {
      signed_transaction tx = h2j_build_issue_tx(
            *this, alice_id, alice_private_key, d.pair, alice_id, share_type( 1 ) );
      try { PUSH_TX( db, tx ); }
      catch ( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE(
               e.to_string().find( "not seasoned" ) != std::string::npos,
               "issuer-direct issue on an unseasoned pair refused off-gate: "
               + e.to_string() );
      }
      BOOST_CHECK_EQUAL( d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, 0 );
   }
   // Seasoned backdate admits the boundary face (gate correctness leg).
   h2x_grant_seasoning( *this, d.pair );
   BOOST_REQUIRE( h2_seasoning_complete( db, d.pair ) );
   h2j_pilot_issue( *this, alice_id, alice_private_key, d.pair, alice_id,
                    share_type( 1 ) );
   BOOST_CHECK_EQUAL( d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, 1 );
} FC_LOG_AND_RETHROW() }

/// R17-A (round-17): the R11-R1 senior wind-down burn moved the reserve
/// stable ledger WITHOUT the band partition (vault_lifecycle_evaluator.cpp
/// senior leg), so sum(band_stable) diverged from stable_supply at the very
/// first settled senior claim and every later verify (next settle sweep,
/// next writer, or the settling re-wrap below) asserts -- the pilot's own
/// exit path halts the chain. Reproduction drives the production path end
/// to end: real signed mint funds the book and its bands, the 150%
/// maintenance trigger is set by the h2c_set_outstanding surgery precedent
/// (the only debt knob reachable without a second issuer live timeline),
/// the deadline sweep enters WINDDOWN, and the senior claimant burns her
/// whole face. GREEN here: the burn moves its band legs and the partition
/// verify passes from here on.
BOOST_AUTO_TEST_CASE( winddown_senior_burn_moves_bands_r17a )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   const h2j_door d = h2j_open_door(
         *this, alice, alice_private_key, bob, bob_private_key,
         "HYWBNDX", "HYWBNDXF", H2J_VAULT_RAW, H2J_VAULT_USD_CENTS, "W" );

   // A real signed mint funds the book AND its bands (partition on entry);
   // alice holds all 1000 stable face, so she is the whole senior class.
   h2j_mint( *this, alice_id, alice_private_key, d, share_type( 140000 ), share_type( 1000 ) );
   generate_block();   
   BOOST_REQUIRE_EQUAL( db.get_balance( alice_id, d.pair ).amount.value, 1000 );

   // Force the 150% maintenance trigger next sweep (surgery precedent;
   // outstanding far above any 150% cover at this bonded price).
   db.modify( d.vault( db ), []( vault_object& m ) {
      m.outstanding = share_type( 2000000 );
   } );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE( d.vault( db ).maintenance_state == GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( d.vault( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE( d.vault( db ).maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN );

   const reserve_object* r = h2j_find_reserve( *this, d.pair );
   BOOST_REQUIRE( r != nullptr );
   // Settle sweep zeroed ONLY the BTS leg; the stable leg survived.
   BOOST_CHECK( r->bts_balance == share_type( 0 ) );
   BOOST_CHECK( r->stable_supply == share_type( 1000 ) );
   // Partition is consistent entering the claim window.
   h2_issue_verify_bands( *r );

   // Deposit the oracle's bonded-price leg before any claim: claims are
   // conversion-dependent (vault_lifecycle_evaluator.cpp:631-634) and halt
   // on a dual-stale bound price by design (round-16 price-validity gate).
   h2j_publish( *this, d.oracle, bob_id, bob_private_key, H2J_BASE, H2J_QUOTE );

   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Senior claim burns the whole face: payout at the 15% haircut comes
   // from the swept book; the stable ledger must move WITH its bands.
   share_type before_bts = db.get_balance( alice_id, asset_id_type() ).amount;
   winddown_claim_operation sop;
   sop.claimant     = alice_id;
   sop.winddown     = wdid;
   sop.claim_amount = share_type( 1000 );
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, stx );

   // Face burned from the asset side.
   BOOST_CHECK_EQUAL( db.get_balance( alice_id, d.pair ).amount.value, 0 );
   BOOST_CHECK_EQUAL( d.pair( db ).dynamic_asset_data_id( db ).current_supply.value, 0 );
   BOOST_CHECK( r->stable_supply == share_type( 0 ) );
   // Payout landed (haircut bound; exact economics pinned elsewhere).
   BOOST_CHECK( db.get_balance( alice_id, asset_id_type() ).amount >
                before_bts );

   // RED (defect): sum(band_stable) != stable_supply -- verify throws.
   // GREEN (fix): the burn carried its band legs; both go to zero exactly.
   share_type band_sum( 0 );
   for( const share_type& band : r->band_stable )
      band_sum += band;
   BOOST_CHECK( band_sum == r->stable_supply );
   h2_issue_verify_bands( *r );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
