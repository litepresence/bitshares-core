/*
 * H2c vault lifecycle ops: rotate, wind-down, resolve, pair_freeze + HTLC griefing.
 *
 * USD-terms-at-lock basis inherited from H2a/H2b ($0.001/BTS pilot basis:
 * 1,000,000 raw units per USD cent, pinned to
 * GRAPHENE_H2_USD_BASIS_RAW_PER_CENT by static_assert below). All proposal
 * values from BSIP-1 section
 * 7b: 150% maintenance trigger, 36h top-up window, 15% wind-down haircut,
 * rmax 2x junior dilution cap, $83.75 griefing per direction, sub-vault cap 64.
 * Full LLAMMA issuance engine is deferred (H2 plan self-review): H2c covers
 * vault-side lifecycle + wind-down accounting only.
 *
 * Vehicle decisions (reversible minima, logged in the H2c report):
 * - OQ-08 rotate = new vault_rotate op (in-place authority replacement;
 *   liabilities migrate by staying put; old bonds release via the new
 *   vault_bond_release op gated on unlock + zero outstanding).
 * - OQ-14 griefing = existing htlc_create + deposit-ID memo convention +
 *   auto-refund (no new op); sha256 only for griefing locks.
 * - OQ-19 maintenance hook evaluates the 150% rule (no trigger op).
 * - OQ-21 double-claim = one claim object per (winddown, claimant);
 *   a second claim by the same claimant is refused.
 * - Wind-down pay order: seniors first at last-good-minus-15%; juniors dilute
 *   with a running cap of 2x senior-paid (rmax); only the segregated bond of
 *   the failed vault ever pays (never cross-reserve, never the issuance
 *   reserve).
 * - Claim math: payout = min(claim * (10000 - haircut) / 10000,
 *   claim * segregated / total), every division rounding DOWN against
 *   claimants (declared). Same-asset units in H2c (live price leg is H2d).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/htlc_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/htlc.hpp>
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

#include <limits>

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

/// H1-03 vacuity pin: pre-fork refusals must reach the hardfork gate, never
/// stop at the fee check (fee set, funded CORE payer; refusal must name H2).
void h2c_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
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

// Pilot basis inherited from H2a/H2b: 1e6 raw BTS units per USD cent.
constexpr int64_t H2C_RAW_PER_USD_CENT = 1000000LL;
// The suite mirror above is pinned to the enforced protocol basis, so the
// pilot ratio can never drift silently on either side.
static_assert( uint64_t( H2C_RAW_PER_USD_CENT ) == GRAPHENE_H2_USD_BASIS_RAW_PER_CENT,
               "H2c pilot-basis mirror must equal the protocol escrow basis" );
constexpr uint64_t H2C_VAULT_USD_CENTS = 1340000;    // $13,400 vault min_bond
constexpr uint64_t H2C_FLOOR_USD_CENTS = 83750;      // $837.50 challenge floor
constexpr uint64_t H2C_ORACLE_USD_CENTS = 1005000;   // $10,050 oracle min_bond
constexpr uint64_t H2C_GRIEF_USD_CENTS = 8375;       // $83.75 griefing/direction
// H2c F2: the suite mirror above is pinned to the protocol proposal, so the
// griefing constant can never drift silently (it has no consensus reader:
// griefing travels via htlc_create + memo convention, OQ-14).
static_assert( H2C_GRIEF_USD_CENTS == GRAPHENE_H2_GRIEFING_BOND_USD_CENTS,
               "H2c griefing mirror must equal the protocol proposal" );
const share_type H2C_VAULT_RAW =
      share_type( int64_t( H2C_VAULT_USD_CENTS ) * H2C_RAW_PER_USD_CENT );
const share_type H2C_ROUND1_RAW =
      share_type( int64_t( H2C_FLOOR_USD_CENTS ) * H2C_RAW_PER_USD_CENT );
const share_type H2C_ORACLE_RAW =
      share_type( int64_t( H2C_ORACLE_USD_CENTS ) * H2C_RAW_PER_USD_CENT );
const share_type H2C_GRIEF_RAW =
      share_type( int64_t( H2C_GRIEF_USD_CENTS ) * H2C_RAW_PER_USD_CENT );

string h2c_evidence( const string& tag )
{ return string( "evidence:" ) + tag; }

void h2c_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

reference_asset_id_type h2c_create_reference(
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

oracle_id_type h2c_make_oracle(
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

asset_id_type h2c_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol );

/// Pilot-scale default pair (AC-02): vault scaffolding binds a fresh
/// zero-supply UIA, never CORE (whose 1e15 genesis supply is now correctly
/// refused at the pilot gate in vault_register::do_evaluate). Find-or-create
/// keeps the suite's fixed-pair semantics: repeat registrations in one test
/// still hit the duplicate-pair gate, exactly as with the old CORE default.
asset_id_type h2c_default_pair(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key )
{
   const auto& sym_idx =
         f.db.get_index_type<asset_index>().indices().get<by_symbol>();
   const auto itr = sym_idx.find( "H2CPAIR" );
   if( itr != sym_idx.end() )
      return itr->get_id();
   return h2c_create_uia( f, issuer, key, "H2CPAIR" );
}

vault_id_type h2c_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth, share_type min_bond, uint64_t min_bond_usd,
      asset_id_type pair = asset_id_type() )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = ( pair == asset_id_type() )
         ? h2c_default_pair( f, registrar, key ) : pair;
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

vault_id_type h2c_register_vault_default(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth )
{
   return h2c_register_vault( f, registrar, key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
}

vesting_balance_id_type h2c_make_cdd_vesting(
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

vault_bond_id_type h2c_lock_vault_bond(
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

vault_challenge_id_type h2c_post_challenge(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      vault_id_type vault, const string& memo )
{
   vault_challenge_operation op;
   op.challenger          = challenger;
   op.vault               = vault;
   op.challenge_bond      = H2C_ROUND1_RAW;
   op.challenge_bond_usd_cents = H2C_FLOOR_USD_CENTS;
   op.evidence_memo       = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_challenge_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2c_vote(
      database_fixture& f, account_id_type voter, const fc::ecc::private_key& key,
      object_id_type target, uint8_t decision )
{
   challenge_vote_operation op;
   op.voter    = voter;
   op.target   = target;
   op.decision = decision;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Builds + signs one transaction without pushing it, so a benchmark batch
/// can be fully staged before the clock starts (validators verify, they do
/// not sign — signing inside the window would pollute the measurement).
template< typename Op >
signed_transaction e06_staged_tx(
      database_fixture& f, Op op, const fc::ecc::private_key& key )
{
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return tx;
}

/// Votes a sustain supermajority from the genesis seated set (init0..initN).
void h2c_sustain_from_genesis( database_fixture& f, object_id_type target )
{
   const uint64_t n =
         f.db.get_index_type<committee_member_index>().indices().size();
   BOOST_REQUIRE( n > 0 );
   const uint64_t need = ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
   for( uint64_t i = 0; i < need; ++i )
      h2c_vote( f, f.get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                f.init_account_priv_key, target, GRAPHENE_H2_DISPUTE_SUSTAIN );
}

void h2c_set_outstanding( database_fixture& f, vault_id_type vid, share_type amount )
{
   const vault_object& v = vid( f.db );
   f.db.modify( v, [&amount]( vault_object& m ) { m.outstanding = amount; } );
}

/// Asset-side twin of h2c_set_outstanding (R11-R1): credits pair-token face
/// to a holder and raises current_supply together, so senior-claim
/// entitlement checks exercise against surgery-set books the same way the
/// liability side already does. Full-book faces sit far above the $20k
/// issuer-direct pilot cap, so no public path could fund them in-test;
/// test-only, no consensus path changes.
void h2c_fund_pair_face( database_fixture& f, account_id_type holder,
                         asset_id_type pair, share_type amount )
{
   f.db.adjust_balance( holder, asset( amount, pair ) );
   const asset_object& pair_asset = pair( f.db );
   const auto& pair_dyn = pair_asset.dynamic_asset_data_id( f.db );
   f.db.modify( pair_dyn, [&amount]( asset_dynamic_data_object& data ) {
      data.current_supply += amount;
   } );
}

/// Creates a plain UIA to serve as a second vault pair (one live vault set
/// per pair, so a cross-reserve sibling must live on another pair).
asset_id_type h2c_create_uia(
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

producer_bond_id_type h2c_lock_producer_bond(
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

void h2c_publish(
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

void h2c_freeze(
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

/**
 * Cross the next maintenance with a live bonded price (issuance-suite
 * precedent): approach the boundary, republish (same value at a new time IS
 * a new promotion record), then cross, so the sweep reads live.
 */
void h2c_cross_maintenance_with_price(
      database_fixture& f, vault_id_type vid, oracle_id_type oid,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time - 300 );
   h2c_publish( f, oid, who, key, base_amount, quote_amount );
   BOOST_REQUIRE( h2_read_pair_price( f.db, vid( f.db ), 0,
                                      f.db.head_block_time() ).valid() );
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time + 60 );
   f.generate_block();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_vault_tests, database_fixture )

/// New lifecycle ops must be refused before the H2 bonds hardfork.
BOOST_AUTO_TEST_CASE( h2c_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );

   {
      vault_rotate_operation op;
      op.rotator       = alice_id;
      op.vault         = vault_id_type( 0 );
      op.new_authority = authority( 1, bob_id, 1 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2c_require_gate_refusal( db, tx, "vault_rotate pre-fork" );
   }
   {
      vault_bond_release_operation op;
      op.owner = alice_id;
      op.bond  = vault_bond_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2c_require_gate_refusal( db, tx, "vault_bond_release pre-fork" );
   }
   {
      vault_resolve_operation op;
      op.resolver  = alice_id;
      op.challenge = vault_challenge_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2c_require_gate_refusal( db, tx, "vault_resolve pre-fork" );
   }
   {
      pair_freeze_operation op;
      op.freezer = alice_id;
      op.vault   = vault_id_type( 0 );
      op.oracle  = oracle_id_type( 0 );
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2c_require_gate_refusal( db, tx, "pair_freeze pre-fork" );
   }
   {
      winddown_claim_operation op;
      op.claimant     = alice_id;
      op.winddown     = winddown_vault_id_type( 0 );
      op.claim_amount = share_type( 1 );
      op.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( alice_private_key, db.get_chain_id() );
      h2c_require_gate_refusal( db, tx, "winddown_claim pre-fork" );
   }
} FC_LOG_AND_RETHROW() }

/// Rotate replaces the authority; liabilities migrate by staying put; the old
/// bond releases only after the challenge window at zero open liabilities.
BOOST_AUTO_TEST_CASE( vault_rotate_moves_authority_and_gates_old_release )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority old_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, old_auth );

   // Old set bonds first.
   const auto vest_a = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   const vault_bond_id_type bond_a = h2c_lock_vault_bond(
         *this, alice_id, alice_private_key, vid, vest_a, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // New set bonds before rotation (the incoming set proves capital first).
   const auto vest_b = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   const vault_bond_id_type bond_b = h2c_lock_vault_bond(
         *this, bob_id, bob_private_key, vid, vest_b, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Simulate live liabilities: rotation must carry them, never drop them.
   // NOTE (pending-session rule): the bond locks above leave a pending undo
   // session active, and direct db.modify below would land in it and be
   // discarded by the next block production (which resets pending and only
   // re-applies pushed transactions). Committing with a block first puts the
   // modify on head state, where it survives. Same pattern at every
   // h2c_set_outstanding call site in this suite.
   generate_block();
   h2c_set_outstanding( *this, vid, share_type( 1000000 ) );
   const share_type liabilities_before = vid( db ).outstanding;

   authority new_auth( 1, bob_id, 1 );
   vault_rotate_operation rop;
   rop.rotator       = alice_id;
   rop.vault         = vid;
   rop.new_authority = new_auth;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx );

   BOOST_CHECK( vid( db ).vault_authority == new_auth );
   BOOST_CHECK( vid( db ).outstanding == liabilities_before );

   // Old bond cannot release while liabilities are open ...
   vault_bond_release_operation rel;
   rel.owner = alice_id;
   rel.bond  = bond_a;
   signed_transaction ltx; ltx.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ltx ), fc::exception );

   // ... nor before its unlock even at zero liabilities ...
   // (generate_block first: the failed ltx push above leaves a pending
   // session active, which would swallow the modify at the next production.)
   generate_block();
   h2c_set_outstanding( *this, vid, share_type( 0 ) );
   signed_transaction ltx2; ltx2.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx2.operations.back() );
   set_expiration( db, ltx2 );
   ltx2.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ltx2 ), fc::exception );

   // ... but releases after the challenge window at zero open liabilities.
   generate_blocks( bond_a( db ).unlock_time + 3600 );
   generate_block();
   signed_transaction ltx3; ltx3.operations.push_back( rel );
   db.current_fee_schedule().set_fee( ltx3.operations.back() );
   set_expiration( db, ltx3 );
   ltx3.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, ltx3 );
   BOOST_CHECK( db.find( bond_a ) == nullptr );
   // The incoming set's bond still secures the vault.
   BOOST_CHECK( db.find( bond_b ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// E-06 H2 worst-case block benchmark (WARN-only, never a hard gate): one
/// block's maximum plausible new-op load — max concurrent challenges (3,
/// one per pair under the per-pair cap) + dispute escalation + votes +
/// publishes + bond locks + freeze + rotate + resolve — is staged fully
/// signed, then verified+applied under a clock. The elapsed time is asserted
/// against the 3s block envelope with BOOST_WARN_MESSAGE and both numbers
/// are recorded. If the load ever exceeds the envelope, the answer is a
/// report — caps and checks are NEVER loosened to make the WARN pass.
BOOST_AUTO_TEST_CASE( e06_h2_worst_case_block_benchmark )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   fund( dave, asset( 3000000000000LL ) );
   fund( get_account( "init0" ), asset( 1000000 ) );
   fund( get_account( "init1" ), asset( 1000000 ) );
   h2c_make_committee_member( *this, alice );
   const account_id_type init0 = get_account( "init0" ).get_id();
   const account_id_type init1 = get_account( "init1" ).get_id();

   // Four full-size vaults on four pairs (one live set per pair) for the timed
   // challenge/vote/lock/freeze/rotate legs. Full pilot-basis min_bonds: the
   // $13,400 floor + raw-vs-USD basis (H2-03/H2-05) forbid toy-money vaults.
   authority vault_auth( 1, alice_id, 1 );
   const asset_id_type pair_a = h2c_create_uia( *this, alice_id, alice_private_key, "E06A" );
   const asset_id_type pair_b = h2c_create_uia( *this, alice_id, alice_private_key, "E06B" );
   const asset_id_type pair_c = h2c_create_uia( *this, alice_id, alice_private_key, "E06C" );
   const asset_id_type pair_d = h2c_create_uia( *this, alice_id, alice_private_key, "E06D" );
   const vault_id_type va = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair_a );
   const vault_id_type vb = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair_b );
   const vault_id_type vc = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair_c );
   const vault_id_type vd = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair_d );
   // A block per deposit (suite duplicate rule): back-to-back identical
   // vesting creates would otherwise collide as duplicate transactions
   // (same ops, expiration, and key); per-deposit blocks also mirror real
   // sub-vault funding cadence.
   generate_block();
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, va,
         h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW ),
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vb,
         h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW ),
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vc,
         h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW ),
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vd,
         h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW ),
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // Pre-created vestings so the second locks land in the timed batch.
   generate_block();
   const auto vest_a2 = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   generate_block();
   const auto vest_b2 = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );

   // Full-size resolve leg on the core pair at 200% cover (stays
   // maintenance-healthy; sustained in setup so the timed resolve fires).
   // Block first (suite duplicate rule): vest_r below is now identical to
   // vest_b2 (both full-size), so it needs its own head time.
   generate_block();
   const vault_id_type vr = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest_r = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vr, vest_r, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_set_outstanding( *this, vr, H2C_VAULT_RAW / 2 );
   const vault_challenge_id_type cr = h2c_post_challenge(
         *this, carol_id, carol_private_key, vr, h2c_evidence( "e06-real" ) );
   h2c_sustain_from_genesis( *this, object_id_type( cr ) );
   BOOST_REQUIRE_EQUAL( cr( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );

   // Oracle leg: producers bob + carol, one retained print, one open
   // round-1 dispute (carol accuses bob); the escalation is timed.
   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2c_make_oracle( *this, alice_id, alice_private_key, "E06.USD", bts_ref, usd_ref, opts );
   oracle_publish_operation first_pub;
   first_pub.producer  = bob_id;
   first_pub.oracle_id = oid;
   first_pub.values    = { oracle_value( 1, 100 ) };
   signed_transaction ptx0; ptx0.operations.push_back( first_pub );
   db.current_fee_schedule().set_fee( ptx0.operations.back() );
   set_expiration( db, ptx0 );
   ptx0.sign( bob_private_key, db.get_chain_id() );
   PUSH_TX( db, ptx0 );
   const fc::time_point_sec accused = oid( db ).history.back().first;
   oracle_dispute_operation dop;
   dop.challenger            = carol_id;
   dop.oracle                = oid;
   dop.defender              = bob_id;
   dop.accused_time          = accused;
   dop.accused_series        = 0;
   dop.dispute_bond          = H2C_ROUND1_RAW;
   dop.dispute_bond_usd_cents = H2C_FLOOR_USD_CENTS;
   dop.evidence_memo         = h2c_evidence( "e06-dispute" );
   signed_transaction dtx0; dtx0.operations.push_back( dop );
   db.current_fee_schedule().set_fee( dtx0.operations.back() );
   set_expiration( db, dtx0 );
   dtx0.sign( carol_private_key, db.get_chain_id() );
   const oracle_dispute_id_type did {
      PUSH_TX( db, dtx0 ).operation_results.front().get<object_id_type>() };

   // Stage the worst-case batch fully signed. Challenges are never pruned,
   // so the challenge index size is the next instance number; each push
   // below verifies it landed on its predicted id before any vote names it.
   const uint64_t ch_base = db.get_index_type<vault_challenge_index>().indices().size();
   const vault_challenge_id_type ca( ch_base ), cb( ch_base + 1 ), cc( ch_base + 2 );
   vector<signed_transaction> batch;
   for( uint32_t i = 0; i < 3; ++i )
   {
      const vault_id_type v = ( i == 0 ) ? va : ( ( i == 1 ) ? vb : vc );
      vault_challenge_operation cop;
      cop.challenger               = bob_id;
      cop.vault                    = v;
      cop.challenge_bond           = H2C_ROUND1_RAW;
      cop.challenge_bond_usd_cents = H2C_FLOOR_USD_CENTS;
      cop.evidence_memo            = h2c_evidence( string( "e06-" ) + fc::to_string( i ) );
      batch.push_back( e06_staged_tx( *this, cop, bob_private_key ) );
   }
   const vault_challenge_id_type cids[3] = { ca, cb, cc };
   for( uint32_t i = 0; i < 3; ++i )
      for( uint32_t k = 0; k < 2; ++k )
      {
         challenge_vote_operation vop;
         vop.voter    = ( k == 0 ) ? init0 : init1;
         vop.target   = object_id_type( cids[i] );
         vop.decision = GRAPHENE_H2_DISPUTE_SUSTAIN;
         batch.push_back( e06_staged_tx( *this, vop, init_account_priv_key ) );
      }
   for( uint32_t k = 0; k < 2; ++k )
   {
      // Values 101/102: the setup print is (1,100), and a staged tx staged
      // at the same head time with identical content would collide with it
      // as a duplicate transaction (same ops, expiration, and key).
      oracle_publish_operation pub;
      pub.producer  = ( k == 0 ) ? bob_id : carol_id;
      pub.oracle_id = oid;
      pub.values    = { oracle_value( 1, 101 + int64_t( k ) ) };
      batch.push_back( e06_staged_tx(
            *this, pub, ( k == 0 ) ? bob_private_key : carol_private_key ) );
   }
   oracle_dispute_escalate_operation eop;
   eop.escalator             = bob_id;
   eop.dispute               = did;
   eop.round_bond            = H2C_ROUND1_RAW * 2;
   eop.round_bond_usd_cents  = H2C_FLOOR_USD_CENTS * 2;
   batch.push_back( e06_staged_tx( *this, eop, bob_private_key ) );
   for( uint32_t k = 0; k < 2; ++k )
   {
      challenge_vote_operation dvop;
      dvop.voter    = ( k == 0 ) ? init0 : init1;
      dvop.target   = object_id_type( did );
      dvop.decision = GRAPHENE_H2_DISPUTE_SUSTAIN;
      batch.push_back( e06_staged_tx( *this, dvop, init_account_priv_key ) );
   }
   vault_bond_lock_operation la;
   la.owner           = alice_id;
   la.vault           = va;
   la.vesting_balance = vest_a2;
   la.bond_amount     = H2C_VAULT_RAW;
   la.bond_usd_cents  = H2C_VAULT_USD_CENTS;
   batch.push_back( e06_staged_tx( *this, la, alice_private_key ) );
   vault_bond_lock_operation lb = la;
   lb.vault           = vb;
   lb.vesting_balance = vest_b2;
   batch.push_back( e06_staged_tx( *this, lb, alice_private_key ) );
   pair_freeze_operation fop;
   fop.freezer = alice_id;
   fop.vault   = va;
   fop.oracle  = oid;
   batch.push_back( e06_staged_tx( *this, fop, alice_private_key ) );
   vault_rotate_operation rop;
   rop.rotator       = alice_id;
   rop.vault         = vd;
   rop.new_authority = authority( 1, bob_id, 1 );
   batch.push_back( e06_staged_tx( *this, rop, alice_private_key ) );
   vault_resolve_operation rop2;
   rop2.resolver  = alice_id;
   rop2.challenge = cr;
   batch.push_back( e06_staged_tx( *this, rop2, alice_private_key ) );
   BOOST_REQUIRE_EQUAL( batch.size(), 19u );

   // Clock starts: validators verify, they do not sign.
   const fc::time_point t0 = fc::time_point::now();
   for( uint32_t i = 0; i < 3; ++i )
   {
      const auto res = PUSH_TX( db, batch[i] ).operation_results.front().get<object_id_type>();
      BOOST_REQUIRE( res == object_id_type( cids[i] ) );
   }
   for( size_t i = 3; i < batch.size(); ++i )
      PUSH_TX( db, batch[i] );
   const fc::time_point t1 = fc::time_point::now();
   const int64_t elapsed_us = ( t1 - t0 ).count();
   constexpr int64_t E06_H2_BLOCK_ENVELOPE_US = 3000000; // 3s block interval
   BOOST_TEST_MESSAGE( "E-06 H2 worst-case block: " << batch.size()
         << " ops verify+apply in " << elapsed_us << "us vs "
         << E06_H2_BLOCK_ENVELOPE_US << "us envelope" );
   BOOST_WARN_MESSAGE( elapsed_us < E06_H2_BLOCK_ENVELOPE_US,
         "E-06 H2 worst-case block exceeded the 3s envelope: " << elapsed_us
         << "us for " << batch.size() << " ops — report, never loosen checks" );

   // The timed resolve really executed: R wound down on the segregated slice.
   BOOST_REQUIRE_EQUAL( vr( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_object* wd = nullptr;
   for( const auto& w : db.get_index_type<winddown_vault_index>().indices() )
      if( w.source_vault == vr )
         wd = &w;
   BOOST_REQUIRE( wd != nullptr );
   BOOST_CHECK( wd->segregated_bond == H2C_VAULT_RAW );
} FC_LOG_AND_RETHROW() }

/// Griefing convention (OQ-14 vehicle): stock htlc_create with a sha256 lock
/// and a deposit-ID memo; after the timeout the challenger posts a challenge
/// whose evidence names the timed-out HTLC, and it is accepted as proof.
BOOST_AUTO_TEST_CASE( htlc_griefing_lock_and_timeout_evidence_posts_challenge )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );

   // HTLC creates require committee HTLC options (max timeout/preimage size);
   // the fixture helper pushes them through a committee proposal.
   set_htlc_committee_parameters();

   // sha256 griefing lock of $83.75 from bob to carol with a deposit-ID memo.
   std::vector<char> preimage( 32, 'g' );
   htlc_create_operation hop;
   hop.from = bob_id;
   hop.to   = carol_id;
   hop.amount = asset( H2C_GRIEF_RAW, asset_id_type() );
   hop.preimage_hash = fc::sha256::hash( preimage.data(), preimage.size() );
   hop.preimage_size = 32;
   hop.claim_period_seconds = 3600;
   memo_data md;
   md.from = bob_public_key;
   md.to   = carol_public_key;
   md.set_message( bob_private_key, carol_public_key, "h2-grief:7" );
   hop.extensions.value.memo = md;
   signed_transaction htx; htx.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx.operations.back() );
   set_expiration( db, htx );
   htx.sign( bob_private_key, db.get_chain_id() );
   const htlc_id_type htid {
      PUSH_TX( db, htx ).operation_results.front().get<object_id_type>() };
   BOOST_CHECK( htid( db ).conditions.hash_lock.preimage_hash.which() == 2 ); // sha256 slot

   // sha1 griefing locks are refused past the H2 gate (audit sunset rule).
   htlc_create_operation shop = hop;
   shop.preimage_hash = fc::sha1::hash( preimage.data(), preimage.size() );
   signed_transaction stx; stx.operations.push_back( shop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, stx ), fc::exception );

   // Timeout passes; the timeout evidence names the HTLC and is accepted.
   generate_blocks( db.head_block_time() + 7200 );
   generate_block();
   const string evidence = string( "htlc-timeout:" ) + h2c_evidence( "grief-7" );
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, evidence );
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
} FC_LOG_AND_RETHROW() }

/// H2-03 vault-lock mirror: a (1 raw, $13,400 face) vault registers (the USD
/// floor passes), so the 1-satoshi lock below isolates the raw-vs-USD basis
/// branch (RED: pre-fix it locks).
BOOST_AUTO_TEST_CASE( vault_bond_lock_raw_shortfall_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         share_type( 1 ), H2C_VAULT_USD_CENTS );
   const auto vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, share_type( 1000000 ) );
   vault_bond_lock_operation op;
   op.owner           = bob_id;
   op.vault           = vid;
   op.vesting_balance = vest;
   op.bond_amount     = share_type( 1 );
   op.bond_usd_cents  = H2C_VAULT_USD_CENTS;
   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// H2-05: a $13,400-minus-one-cent min_bond is refused at registration, at
/// full-size raw (isolates the USD-terms floor, RED: pre-fix `> 0` passes it).
BOOST_AUTO_TEST_CASE( vault_dust_min_bond_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 30000000000000LL ) );

   vault_register_operation op;
   op.registrar            = alice_id;
   op.pair                 = asset_id_type();
   op.vault_authority      = authority( 1, alice_id, 1 );
   op.min_bond             = H2C_VAULT_RAW;
   op.min_bond_usd_cents   = H2C_VAULT_USD_CENTS - 1;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000;
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// H2-06/SUP-05: a bond lock against a non-forward-locked CDD vesting is
/// refused — both under-duration and already-claimable variants (RED: pre-fix
/// the lock only checks the CDD type, so both lock).
BOOST_AUTO_TEST_CASE( vault_cdd_instant_withdraw_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default(
         *this, alice_id, alice_private_key, vault_auth );

   // Variant 1: zero vesting_seconds (instant, no forward lock).
   vesting_balance_create_operation vop1;
   vop1.creator = bob_id;
   vop1.owner   = bob_id;
   vop1.amount  = asset( H2C_VAULT_RAW, asset_id_type() );
   vop1.policy  = cdd_vesting_policy_initializer(
         0, db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction vtx1;
   vtx1.operations.push_back( vop1 );
   db.current_fee_schedule().set_fee( vtx1.operations.back() );
   set_expiration( db, vtx1 );
   vtx1.sign( bob_private_key, db.get_chain_id() );
   const vesting_balance_id_type instant_vest {
      PUSH_TX( db, vtx1 ).operation_results.front().get<object_id_type>() };
   generate_block();
   BOOST_CHECK_THROW( h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid,
         instant_vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS ), fc::exception );

   // Variant 2: full 7d duration but start_claim already past (claimable now).
   generate_block();
   vesting_balance_create_operation vop2;
   vop2.creator = bob_id;
   vop2.owner   = bob_id;
   vop2.amount  = asset( H2C_VAULT_RAW, asset_id_type() );
   vop2.policy  = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, db.head_block_time() - 3600 );
   signed_transaction vtx2;
   vtx2.operations.push_back( vop2 );
   db.current_fee_schedule().set_fee( vtx2.operations.back() );
   set_expiration( db, vtx2 );
   vtx2.sign( bob_private_key, db.get_chain_id() );
   const vesting_balance_id_type stale_vest {
      PUSH_TX( db, vtx2 ).operation_results.front().get<object_id_type>() };
   generate_block();
   BOOST_CHECK_THROW( h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid,
         stale_vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// H2-05/V-03: withdrawing the encumbered vesting balance drains live cover
/// while the nominal bond object still reads full — maintenance must gate on
/// the live balance (TOPUP + Recovery suspension), never the nominal record
/// (RED: pre-fix the nominal sum still reads 200% and stays HEALTHY).
BOOST_AUTO_TEST_CASE( vault_maintenance_ignores_withdrawn_vesting )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default(
         *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW / 2 );

   // Accrue past the 7d vest + 7d claim delay so the full balance is
   // withdrawable, then drain the encumbered vesting in one op (the bond
   // object is pointer-only: the withdraw succeeds, cover does not).
   generate_blocks( db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC + 3600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   vesting_balance_withdraw_operation wop;
   wop.owner           = alice_id;
   wop.vesting_balance = vest;
   wop.amount          = asset( H2C_VAULT_RAW, asset_id_type() );
   signed_transaction wtx;
   wtx.operations.push_back( wop );
   db.current_fee_schedule().set_fee( wtx.operations.back() );
   set_expiration( db, wtx );
   wtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, wtx );
   BOOST_REQUIRE( vest( db ).balance.amount == share_type( 0 ) );

   // Next maintenance: nominal bond still 1.34e12, live cover 0 → TOPUP, and
   // the Recovery scope (0 / 50%) suspends new debt.
   generate_block();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   const auto& rec_idx = db.get_index_type<recovery_state_index>().indices();
   BOOST_REQUIRE( !rec_idx.empty() );
   BOOST_CHECK_EQUAL( rec_idx.begin()->new_debt_suspended, true );
   BOOST_CHECK( rec_idx.begin()->last_collateral == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// 150% maintenance rule: breach halts mints, opens a 36h top-up window, and
/// expiry at maintenance auto-creates the wind-down and seizes the bonds.
BOOST_AUTO_TEST_CASE( maintenance_breach_halts_topup_expires_into_winddown )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Healthy at 200%: bonds cover twice the liabilities.
   // (generate_block first: see the pending-session rule noted above.)
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW / 2 );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );

   // Breach below 150%: 100% coverage trips the rule at next maintenance.
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW );
   const auto breach_time = db.head_block_time();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true ); // mint halt; redemptions continue
   BOOST_CHECK( vid( db ).top_up_deadline == vid( db ).last_breach_time + GRAPHENE_H2_TOP_UP_WINDOW_SEC );
   BOOST_CHECK( vid( db ).top_up_deadline > breach_time );

   // Top-up still open just before the deadline: no wind-down yet.
   generate_blocks( vid( db ).top_up_deadline - 7200 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );

   // Past the 36h deadline the next maintenance winds down + seizes.
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   const winddown_vault_object& wd = *wd_idx.begin();
   BOOST_CHECK( wd.source_vault == vid );
   BOOST_CHECK( wd.segregated_bond == H2C_VAULT_RAW );
   BOOST_CHECK( wd.total_claims == H2C_VAULT_RAW );
   BOOST_CHECK_EQUAL( wd.haircut_bps, GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS );
   // Seized bonds never roll back.
   for( const auto& b : db.get_index_type<vault_bond_index>().indices() )
      if( b.vault == vid )
         BOOST_CHECK_EQUAL( b.seized, true );
} FC_LOG_AND_RETHROW() }

/// Wind-down pay order: seniors at last-good-minus-15%, juniors dilute capped
/// at 2x senior-paid, double-claims refused, sibling vaults never touched.
BOOST_AUTO_TEST_CASE( winddown_claim_pays_seniors_first_juniors_dilute_no_cross_reserve )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );

   // Failed vault: full-bond backing against equal liabilities (100% cover).
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // (generate_block first: see the pending-session rule noted above.)
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Sibling vault: a DIFFERENT pair (one live set per pair, OQ-03), stays
   // healthy and unseized while its neighbor winds down (no cross-reserve).
   // A same-pair sibling cannot exist, so cross-pair isolation is the
   // strongest observable no-cross-collateralization check in H2c.
   const auto sib_pair = h2c_create_uia( *this, bob_id, bob_private_key, "SIBPAIR" );
   authority sib_auth( 1, bob_id, 1 );
   const vault_id_type sib = h2c_register_vault(
         *this, bob_id, bob_private_key, sib_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, sib_pair );
   const auto sib_vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   const vault_bond_id_type sib_bond = h2c_lock_vault_bond(
         *this, bob_id, bob_private_key, sib, sib_vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Senior claims first at 85%: haircut face binds (fully backed here).
   // Claim faces must fit inside the frozen liabilities (claimed_total can
   // never exceed total_claims — the H2c stand-in for per-holder frozen
   // balances, which arrive with the issuance engine): seniors take a third,
   // juniors two thirds, summing to (just under) the whole book.
   // R11-R1 entitlement: carol's senior face must exist before she claims
   // (asset-side twin of the surgery-set book above).
   h2c_fund_pair_face( *this, carol_id, wdid( db ).pair, H2C_VAULT_RAW / 3 );
   const share_type senior_claim = H2C_VAULT_RAW / 3;
   const share_type senior_expect =
         share_type( senior_claim.value * ( 10000 - GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS ) / 10000 );
   winddown_claim_operation sop;
   sop.claimant     = carol_id;
   sop.winddown     = wdid;
   sop.claim_amount = senior_claim;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( carol_private_key, db.get_chain_id() );
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   PUSH_TX( db, stx );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= carol_before + senior_expect - share_type( 100000 ) );

   // Double-claim by the same account is refused.
   signed_transaction dtx; dtx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( dtx.operations.back() );
   set_expiration( db, dtx );
   dtx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, dtx ), fc::exception );

   // Juniors dilute within 2x of senior-paid: 2x senior claim is accepted ...
   winddown_claim_operation jop;
   jop.claimant     = dave_id;
   jop.winddown     = wdid;
   jop.claim_amount = senior_claim * 2;
   jop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction jtx; jtx.operations.push_back( jop );
   db.current_fee_schedule().set_fee( jtx.operations.back() );
   set_expiration( db, jtx );
   jtx.sign( dave_private_key, db.get_chain_id() );
   PUSH_TX( db, jtx );

   // ... but junior claims past 2x senior-paid are refused (rmax).
   winddown_claim_operation xop;
   xop.claimant     = erin_id;
   xop.winddown     = wdid;
   xop.claim_amount = share_type( 1 );
   xop.tranche      = GRAPHENE_H2_WINDDOWN_JUNIOR;
   signed_transaction xtx; xtx.operations.push_back( xop );
   db.current_fee_schedule().set_fee( xtx.operations.back() );
   set_expiration( db, xtx );
   xtx.sign( erin_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, xtx ), fc::exception );

   // Sibling bond untouched by the failed vault's wind-down.
   BOOST_CHECK_EQUAL( sib_bond( db ).seized, false );
   BOOST_CHECK_EQUAL( sib( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
} FC_LOG_AND_RETHROW() }

/// R11-R1 (LL-R11-01) senior entitlement: a wind-down senior claim must
/// prove pair-face holding. A token-less account claiming the FULL frozen
/// book is refused; a funded entitlement pays exactly once (face burned,
/// second claim refused).
BOOST_AUTO_TEST_CASE( r11r1_winddown_senior_claim_requires_pair_face )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(erin) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );

   // Failed vault: full-bond backing against equal liabilities (100% cover).
   // Alice registers first, so she is the H2CPAIR issuer (funding source below).
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE( vid( db ).maintenance_state == GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };
   BOOST_REQUIRE( wdid( db ).total_claims == H2C_VAULT_RAW );
   const asset_id_type pair = wdid( db ).pair;
   BOOST_REQUIRE( pair( db ).issuer == alice_id );

   // Theft probe: erin holds zero pair face but claims the whole book.
   BOOST_CHECK( db.get_balance( erin_id, pair ).amount == share_type( 0 ) );
   winddown_claim_operation top;
   top.claimant     = erin_id;
   top.winddown     = wdid;
   top.claim_amount = wdid( db ).total_claims;
   top.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction ttx; ttx.operations.push_back( top );
   db.current_fee_schedule().set_fee( ttx.operations.back() );
   set_expiration( db, ttx );
   ttx.sign( erin_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ttx ), fc::exception );
   BOOST_CHECK( wdid( db ).claimed_total == share_type( 0 ) );

   // Entitlement: carol is issued exactly the senior face, then claims.
   // Pilot-scale face (AC-02): the issuer-direct path holds the same $20k
   // cap the mint doors enforce, so entitlement funding uses a cap-fitting
   // face while the frozen book stays full-scale (surgery-set, as before).
   const share_type senior_claim = share_type( 1000000 );
   const share_type senior_expect =
         share_type( senior_claim.value * ( 10000 - GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS ) / 10000 );
   asset_issue_operation iop;
   iop.issuer           = alice_id;
   iop.asset_to_issue   = asset( senior_claim, pair );
   iop.issue_to_account = carol_id;
   signed_transaction itx; itx.operations.push_back( iop );
   db.current_fee_schedule().set_fee( itx.operations.back() );
   set_expiration( db, itx );
   itx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, itx );
   BOOST_REQUIRE( db.get_balance( carol_id, pair ).amount == senior_claim );
   const share_type supply_before = pair( db ).dynamic_asset_data_id( db ).current_supply;

   winddown_claim_operation sop;
   sop.claimant     = carol_id;
   sop.winddown     = wdid;
   sop.claim_amount = senior_claim;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( carol_private_key, db.get_chain_id() );
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   PUSH_TX( db, stx );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= carol_before + senior_expect - share_type( 100000 ) );
   // Pays exactly once: the claimed face burns from holder and supply ...
   BOOST_CHECK( db.get_balance( carol_id, pair ).amount == share_type( 0 ) );
   BOOST_CHECK( pair( db ).dynamic_asset_data_id( db ).current_supply == supply_before - senior_claim );
   // ... and the second claim by the same account is refused.
   signed_transaction dtx; dtx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( dtx.operations.back() );
   set_expiration( db, dtx );
   dtx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, dtx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Resolve executes a sustained challenge: committee execution seizes the bond
/// slice into a segregated wind-down (no cross-collateralization).
BOOST_AUTO_TEST_CASE( vault_resolve_executes_sustained_challenge_into_winddown )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, bob_id, bob_private_key, vid, h2c_evidence( "real-theft" ) );
   h2c_sustain_from_genesis( *this, object_id_type( cid ) );
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );

   // Non-committee execution is refused; committee execution segregates.
   vault_resolve_operation bad;
   bad.resolver  = bob_id;
   bad.challenge = cid;
   signed_transaction btx; btx.operations.push_back( bad );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx );
   btx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );

   vault_resolve_operation op;
   op.resolver  = alice_id;
   op.challenge = cid;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx );

   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   BOOST_CHECK( wd_idx.begin()->source_vault == vid );
   BOOST_CHECK( wd_idx.begin()->segregated_bond == H2C_VAULT_RAW );
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   // Resolving twice is refused (challenge already executed).
   signed_transaction tx2; tx2.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx2 ), fc::exception );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Expired-resolve-to-winddown (R5C fail-closed split): an EXPIRED_FROZEN
/// challenge executes into the IDENTICAL wind-down path as SUSTAINED —
/// segregated bond, seniors first, rmax cap, haircut math — exit-only.
/// Expiry is inconclusive (no 48h supermajority; the committee here never
/// votes, the cartel-abstention shape), so it is never exoneration: the
/// freeze holds and guilty history sticks. But the brick is not permanent:
/// any seated member triggers the exit, while the non-committee owner
/// cannot self-resolve. The vault NEVER returns to HEALTHY on any path.
BOOST_AUTO_TEST_CASE( vault_resolve_accepts_expired_challenge_into_winddown )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   // Bob owns the vault but sits outside the committee: he can register and
   // bond, but he cannot resolve.
   authority vault_auth( 1, bob_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, bob_id, bob_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // Half leverage (200% cover): the vault stays maintenance-healthy while
   // the challenge window lapses, so only the expiry sweep — never the
   // top-up path — moves this vault.
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW / 2 );

   // Carol challenges; nobody votes. The window lapses and the maintenance
   // sweep expires it fail-closed (bond returns, vault stays frozen).
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, h2c_evidence( "no-quorum" ) );
   generate_blocks( cid( db ).deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );
   BOOST_REQUIRE_EQUAL( vid( db ).open_challenges, 0u );
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );

   // Owner self-resolve refused: bob owns the vault but is not seated.
   vault_resolve_operation self;
   self.resolver  = bob_id;
   self.challenge = cid;
   signed_transaction stx; stx.operations.push_back( self );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, stx ), fc::exception );
   // A seated stranger is not the owner either: dave is refused the same way.
   vault_resolve_operation stranger;
   stranger.resolver  = dave_id;
   stranger.challenge = cid;
   signed_transaction gtx; gtx.operations.push_back( stranger );
   db.current_fee_schedule().set_fee( gtx.operations.back() );
   set_expiration( db, gtx );
   gtx.sign( dave_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, gtx ), fc::exception );

   // Any seated member triggers the exit-only wind-down (alice never voted
   // on this challenge: no vote is needed because a wind-down cannot steal).
   vault_resolve_operation op;
   op.resolver  = alice_id;
   op.challenge = cid;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx );

   // Identical wind-down to the sustained path: same segregated slice.
   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   BOOST_CHECK( wd_idx.begin()->source_vault == vid );
   BOOST_CHECK( wd_idx.begin()->segregated_bond == H2C_VAULT_RAW );
   BOOST_CHECK( wd_idx.begin()->total_claims == H2C_VAULT_RAW / 2 );
   BOOST_CHECK_EQUAL( cid( db ).executed, true );
   // Exit-only: the vault never returns to HEALTHY; the freeze holds until
   // wind-down claims complete per the existing claim rules.
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   BOOST_CHECK( vid( db ).maintenance_state != GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );

   // Segregated economics on the expired path: a senior claim pays
   // last-good-minus-15% from the seized slice (fully backed here).
   const winddown_vault_id_type wdid { wd_idx.begin()->id };
   // R11-R1 entitlement: dave's senior face must exist before he claims.
   h2c_fund_pair_face( *this, dave_id, wdid( db ).pair, ( H2C_VAULT_RAW / 2 ) / 3 );
   const share_type senior_claim = ( H2C_VAULT_RAW / 2 ) / 3;
   const share_type senior_expect =
         share_type( senior_claim.value * ( 10000 - GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS ) / 10000 );
   winddown_claim_operation sop;
   sop.claimant     = dave_id;
   sop.winddown     = wdid;
   sop.claim_amount = senior_claim;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction ctx; ctx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( dave_private_key, db.get_chain_id() );
   const share_type dave_before = db.get_balance( dave_id, asset_id_type() ).amount;
   PUSH_TX( db, ctx );
   BOOST_CHECK( db.get_balance( dave_id, asset_id_type() ).amount >= dave_before + senior_expect - share_type( 100000 ) );

   // Resolving twice is refused (challenge already executed).
   signed_transaction tx2; tx2.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx2 ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Challenge-vs-winddown refusal (R6C fail-closed): a vault_challenge
/// against an already-WINDDOWN vault is refused with fc::exception (pure
/// state noise: the challenger would lock bond for nothing — resolve is
/// already refused on WINDDOWN vaults). An otherwise-identical challenge
/// against a HEALTHY sibling vault on another pair proceeds (control case:
/// the gate rejects more, never less). Reuses h2c_post_challenge, no new
/// fixtures.
BOOST_AUTO_TEST_CASE( vault_challenge_refused_against_winddown_vault )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   // Doomed vault: driven to terminal WINDDOWN via sustain + resolve below.
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Healthy sibling on a different pair (one live set per pair): the
   // control target. Bonded identically so the control challenge is
   // otherwise-identical to the refused one.
   const auto sib_pair = h2c_create_uia( *this, bob_id, bob_private_key, "SIBPAIR" );
   authority sib_auth( 1, bob_id, 1 );
   const vault_id_type sib = h2c_register_vault(
         *this, bob_id, bob_private_key, sib_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, sib_pair );
   const auto sib_vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, bob_id, bob_private_key, sib, sib_vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Drive vid to terminal WINDDOWN via the sustained path.
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, h2c_evidence( "real-theft" ) );
   h2c_sustain_from_genesis( *this, object_id_type( cid ) );
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   vault_resolve_operation rop;
   rop.resolver  = alice_id;
   rop.challenge = cid;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx );
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );

   // Past the 24h per-pair cooldown, so the refusal pins to the WINDDOWN
   // gate and never to the cooldown (fail-closed ordering is verified by
   // the gate sitting before the cooldown branch in do_evaluate).
   generate_blocks( db.head_block_time() + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC + 3600 );
   generate_block();

   // Refusal: an identical challenge against the WINDDOWN vault throws.
   BOOST_CHECK_THROW( h2c_post_challenge(
         *this, dave_id, dave_private_key, vid, h2c_evidence( "winddown-noise" ) ),
      fc::exception );

   // Control: the otherwise-identical challenge against the HEALTHY sibling
   // proceeds (fail-closed direction only: rejects more, never less).
   const vault_challenge_id_type ok = h2c_post_challenge(
         *this, erin_id, erin_private_key, sib, h2c_evidence( "winddown-noise" ) );
   BOOST_CHECK_EQUAL( ok( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
   BOOST_CHECK_EQUAL( sib( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
} FC_LOG_AND_RETHROW() }

/// pair_freeze closes the protocol door AND the debt tap in one atomic apply:
/// after one op the vault blocks mints and the oracle stops promoting.
BOOST_AUTO_TEST_CASE( pair_freeze_closes_door_and_debt_atomically )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );
   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   const oracle_id_type oid =
         h2c_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default( *this, alice_id, alice_private_key, vault_auth );

   BOOST_REQUIRE_EQUAL( vid( db ).frozen, false );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, false );

   // Non-committee freezers are refused and freeze nothing (atomic no-op).
   pair_freeze_operation bad;
   bad.freezer = bob_id;
   bad.vault   = vid;
   bad.oracle  = oid;
   signed_transaction btx; btx.operations.push_back( bad );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx );
   btx.sign( bob_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );

   // Committee freeze closes both in one atomic apply: PUSH_TX applies
   // without producing a block, so both flags flip with no intervening block
   // in which the door could read closed while debt reads open (or reverse).
   const uint32_t block_before = db.head_block_num();
   pair_freeze_operation op;
   op.freezer = alice_id;
   op.vault   = vid;
   op.oracle  = oid;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   BOOST_CHECK_EQUAL( db.head_block_num(), block_before );
} FC_LOG_AND_RETHROW() }

/// Sub-vault bound: at most 64 bond locks per vault (tBTC per-deposit lesson);
/// the 65th lock is refused while the first 64 stand.
BOOST_AUTO_TEST_CASE( subvault_bond_cap_64 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   // 65 full-size sub-vault bonds: 65 x $13,400 face at the pilot basis.
   fund( alice, asset( 90000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   for( uint32_t i = 0; i < GRAPHENE_H2_SUBVAULT_CAP; ++i )
   {
      // A block per deposit: back-to-back identical creates would otherwise
      // collide as duplicate transactions (same ops, expiration, and key),
      // and per-deposit blocks mirror real sub-vault funding cadence.
      generate_block();
      const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
      h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                           H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   }
   BOOST_CHECK_EQUAL( db.get_index_type<vault_bond_index>().indices().size(), 64u );
   // The 65th vesting needs its own block too, or it duplicates the 64th's.
   generate_block();
   const auto vest65 = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   vault_bond_lock_operation op;
   op.owner           = alice_id;
   op.vault           = vid;
   op.vesting_balance = vest65;
   op.bond_amount     = H2C_VAULT_RAW;
   op.bond_usd_cents  = H2C_VAULT_USD_CENTS;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Priced maintenance: a BOUND vault converts live-covered bonds through the
/// bonded price before comparing to outstanding. At (100,1) the 1.34e12 bond
/// prices 1.34e10 face against 1e10 outstanding (134% < 150%: TOPUP plus
/// Recovery suspension), where raw parity would read 13400% healthy.
BOOST_AUTO_TEST_CASE( vault_maintenance_prices_bonds_at_bonded_price )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BTSP", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USDP", 4 );
   oracle_options opts;
   opts.producers[ bob_id ] = oracle_producer_entry( 1 );
   const oracle_id_type oid = h2c_make_oracle(
         *this, alice_id, alice_private_key, "H2C.USD", bts_ref, usd_ref, opts );
   const auto obvest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_ORACLE_RAW );
   h2c_lock_producer_bond( *this, bob_id, bob_private_key, oid, obvest,
                           H2C_ORACLE_RAW, H2C_ORACLE_USD_CENTS );

   const asset_id_type pair = h2c_create_uia( *this, alice_id, alice_private_key, "PRICED" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // Bind through the freeze, then surgically reopen (issuance-suite
   // precedent): the binding persists, the test needs a live price leg.
   h2c_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // 1e10 face: raw parity reads 13400% (healthy); priced at (100,1) it is
   // 134% (breach). Maintenance must read the priced book.
   h2c_set_outstanding( *this, vid, share_type( 10000000000LL ) );
   h2c_cross_maintenance_with_price( *this, vid, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   // Recovery prices the same book: 1.34e10 face collateral over 1e10 face
   // debt suspends new debt.
   const auto& rec_idx = db.get_index_type<recovery_state_index>().indices();
   BOOST_REQUIRE( !rec_idx.empty() );
   BOOST_CHECK_EQUAL( rec_idx.begin()->new_debt_suspended, true );
} FC_LOG_AND_RETHROW() }

/// Fail-closed maintenance on dual-stale: a bound vault whose bonded price
/// expired reads breach even at tiny outstanding (live-priced 1.34e6%
/// healthy; raw parity agrees). No live price, no clean bill.
BOOST_AUTO_TEST_CASE( vault_maintenance_fails_closed_on_dual_stale )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BTSS", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USDS", 4 );
   oracle_options opts;
   opts.producers[ bob_id ] = oracle_producer_entry( 1 );
   opts.value_lifetime_sec = 7200; // 2h: age past it without a week-long jump
   const oracle_id_type oid = h2c_make_oracle(
         *this, alice_id, alice_private_key, "H2C.STALE", bts_ref, usd_ref, opts );
   const auto obvest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_ORACLE_RAW );
   h2c_lock_producer_bond( *this, bob_id, bob_private_key, oid, obvest,
                           H2C_ORACLE_RAW, H2C_ORACLE_USD_CENTS );

   const asset_id_type pair = h2c_create_uia( *this, alice_id, alice_private_key, "STALE" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   h2c_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // 1e6 face: live-priced 1.34e6% healthy. Age the print past its lifetime,
   // then cross a maintenance with no live price: TOPUP, never a clean bill.
   h2c_set_outstanding( *this, vid, share_type( 1000000 ) );
   h2c_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_REQUIRE( h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );
   const auto pub_time = db.head_block_time();
   generate_blocks( pub_time + 7200 + 600 );
   generate_block();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 60 );
   generate_block();
   BOOST_REQUIRE( !h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   // Recovery counts the stale book at zero collateral: suspends.
   const auto& rec_idx = db.get_index_type<recovery_state_index>().indices();
   BOOST_REQUIRE( !rec_idx.empty() );
   BOOST_CHECK_EQUAL( rec_idx.begin()->new_debt_suspended, true );
} FC_LOG_AND_RETHROW() }

/// V-11 withdraw-then-coverage, refusal half: the encumbered CDD vesting has
/// zero withdrawable balance before anything vests, so withdrawing the full
/// bond pre-unlock refuses at the legacy allowed-withdraw gate (never a
/// partial drain the coverage math must chase). The coverage half lives in
/// vault_maintenance_ignores_withdrawn_vesting (post-maturity drain reads
/// live zero, never nominal full).
BOOST_AUTO_TEST_CASE( vesting_withdraw_pre_unlock_overdraw_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2c_register_vault_default(
         *this, alice_id, alice_private_key, vault_auth );
   const auto vest = h2c_make_cdd_vesting( *this, alice_id, alice_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );

   // Immediately (nothing vested, nothing claimable): the full-bond
   // withdrawal refuses, and the encumbered balance is untouched.
   {
      vesting_balance_withdraw_operation wop;
      wop.owner           = alice_id;
      wop.vesting_balance = vest;
      wop.amount          = asset( H2C_VAULT_RAW, asset_id_type() );
      signed_transaction wtx;
      wtx.operations.push_back( wop );
      db.current_fee_schedule().set_fee( wtx.operations.back() );
      set_expiration( db, wtx );
      wtx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, wtx ), fc::exception );
   }
   BOOST_CHECK( vest( db ).balance.amount == H2C_VAULT_RAW );

   // Control: the bond object still reads full and live cover is intact, so
   // maintenance with no liabilities prices HEALTHY (no false TOPUP while
   // nothing was ever withdrawn).
   generate_block();
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
} FC_LOG_AND_RETHROW() }

/// R9-I9 / H2-09: the documented recovery path ("fresh re-registration" after
/// wind-down) actually exists in consensus. Adversarial shape: expiry-freeze
/// (cartel-abstention inconclusive finding) -> committee resolve -> settle the
/// whole frozen-liability book -> re-register the SAME pair -> mint again.
/// Guards pinned along the way: while claims are open the pair stays closed
/// (the live register still owns it); after settlement the terminal vault
/// object is REMOVED, the wind-down book survives its source vault, and the
/// fresh vault mints through the issuance door.
BOOST_AUTO_TEST_CASE( h2_09_winddown_settled_pair_reregisters_and_mints_again )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   // Original vault on the default pair; bob holds the authority (so bob can
   // re-register and mint later), alice seats the committee leg that resolves.
   authority vault_auth( 1, bob_id, 1 );
   const asset_id_type pair = h2c_default_pair( *this, bob_id, bob_private_key );
   const vault_id_type vid = h2c_register_vault(
         *this, bob_id, bob_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   const auto vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   // 200% cover: the vault stays maintenance-healthy while the challenge
   // window lapses, so only the expiry sweep moves it (R5C test shape).
   generate_block();
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW / 2 );

   // Expiry-freeze: carol challenges; nobody votes; the window lapses
   // fail-closed (EXPIRED_FROZEN, vault frozen, challenge count drained).
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, h2c_evidence( "no-quorum" ) );
   generate_blocks( cid( db ).deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );

   // A seated member resolves: exit-only wind-down (R5C fail-closed split).
   vault_resolve_operation rop;
   rop.resolver  = alice_id;
   rop.challenge = cid;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx );
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   const winddown_vault_id_type wdid { wd_idx.begin()->id };
   BOOST_REQUIRE( wdid( db ).source_vault == vid );
   BOOST_REQUIRE( wdid( db ).claimed_total != wdid( db ).total_claims );

   // Guard: re-registration while claims are OPEN stays refused (the wound
   // down book still owns the pair until settlement).
   BOOST_CHECK_THROW( h2c_register_vault(
         *this, bob_id, bob_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair ), fc::exception );

    // Settle the whole frozen-liability book in one senior claim (fully
    // backed: the haircut leg pays before the pro-rata cap binds).
    // R11-R1 entitlement: carol must hold the full book face before settling it.
    // Flush first: the resolve above leaves the pending session open and a
    // direct funding surgery into it would be rolled back by the next block
    // (pending-session rule noted above); after the flush the funding
    // commits directly and survives the re-application at later blocks.
    generate_block();
    h2c_fund_pair_face( *this, carol_id, wdid( db ).pair, H2C_VAULT_RAW / 2 );
    winddown_claim_operation sop;
    sop.claimant     = carol_id;
   sop.winddown     = wdid;
   sop.claim_amount = H2C_VAULT_RAW / 2; // == total_claims
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( carol_private_key, db.get_chain_id() );
   PUSH_TX( db, stx );
   BOOST_REQUIRE( wdid( db ).claimed_total == wdid( db ).total_claims );
   const share_type carried_shell = vid( db ).forfeit_pool_balance;
   BOOST_REQUIRE( carried_shell > share_type( 0 ) );

   // Recovery path (R9-I9): fresh registration replaces the terminal vault
   // object on the same pair.
   const vault_id_type vid2 = h2c_register_vault(
         *this, bob_id, bob_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   BOOST_CHECK( vid2 != vid );
   BOOST_CHECK( db.find( vid ) == nullptr );
   BOOST_CHECK( vid2( db ).vault_pair == pair );
   BOOST_CHECK_EQUAL( vid2( db ).outstanding.value, 0 );
   BOOST_CHECK_EQUAL( vid2( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK_EQUAL( vid2( db ).frozen, false );
   // The terminal vault's forfeit shell carries to the fresh vault (supply
   // must stay counted across the removal; see vault_evaluator do_apply).
   BOOST_CHECK_EQUAL( vid2( db ).forfeit_pool_balance.value, carried_shell.value );
   // The wind-down book survives its source vault: claims history is never
   // rewritten by re-registration (the claim path already tolerates the
   // missing source; nothing else consumes a terminal vault object).
   BOOST_CHECK( wdid( db ).source_vault == vid );
   BOOST_CHECK( wdid( db ).claimed_total == wdid( db ).total_claims );
   // Further claims against the settled book are still refused (next_claimed
   // would break the frozen-liability ceiling).
   winddown_claim_operation xop = sop;
   xop.claimant = alice_id; // fresh claimant: only the ceiling can refuse
   signed_transaction xtx; xtx.operations.push_back( xop );
   db.current_fee_schedule().set_fee( xtx.operations.back() );
   set_expiration( db, xtx );
   xtx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, xtx ), fc::exception );

   // The re-registered vault can mint again. Bond the fresh book, pin the
   // canonical oracle binding (first freeze), reopen the door (issuance
   // suite open-door precedent: the pin persists; the sweep freeze flags are
   // surgically reopened so the test has a live price leg), then mint.
   const auto bts_ref = h2c_create_reference( *this, alice_id, alice_private_key, "BT9", 5 );
   const auto usd_ref = h2c_create_reference( *this, alice_id, alice_private_key, "USD9", 4 );
   oracle_options opts;
   opts.producers[ bob_id ] = oracle_producer_entry( 1 );
   const oracle_id_type oid = h2c_make_oracle(
         *this, alice_id, alice_private_key, "R9I9.USD", bts_ref, usd_ref, opts );
   const auto ovest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_ORACLE_RAW );
   h2c_lock_producer_bond( *this, bob_id, bob_private_key, oid, ovest,
                           H2C_ORACLE_RAW, H2C_ORACLE_USD_CENTS );
   generate_block();
   const auto vest2 = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid2, vest2,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   h2c_freeze( *this, alice_id, alice_private_key, vid2, oid );
   BOOST_REQUIRE( vid2( db ).bound_oracle.valid() );
   generate_block();
   db.modify( vid2( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );
   h2c_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_REQUIRE( h2_read_pair_price( db, vid2( db ), 0, db.head_block_time() ).valid() );

   // AC-08: the re-registered pair inherits its standing seasoning record
   // (R9-I9: the window does NOT restart on recovery), but the record never
   // completed in-test (no verifier, clock fresh) -- season it here so the
   // mint below exercises the seasoned path. Verifier is alice: the pair's
   // issuer and vault authority are both bob, so seated alice is independent
   // under AC-16.
   //
   // Hand-set swept state (both legs, documented): this pair spent its whole
   // pre-recovery life UNBOUND across many maintenance crossings, and every
   // unbound sweep is a recorded breach reset with min_oracle_bps reopened
   // at 0. Covered folds only ever take min(old, cur), so a 0 minimum never
   // recovers through any public path -- backdating the start alone cannot
   // season this pair. The minimums below therefore reconstruct the
   // creation-open state (saturating, the same values a first covered sweep
   // folds on a promptly-bound production pair) that the unbound era
   // destroyed; the breach_count is deliberately LEFT in place, so the
   // ungated history stays reconstructable. No mint assert below is touched.
   // CONCERN (T4 report): one breaching sweep permanently bricks a pair's
   // seasoning under these fold semantics -- see the task report.
   {
      seasoning_verify_operation vop;
      vop.verifier = alice_id;
      vop.pair     = pair;
      signed_transaction vtx; vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx );
      vtx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, vtx );
   }
   generate_block();
   {
      const auto& idx = db.get_index_type<seasoning_record_index>()
                           .indices().get<by_seasoning_pair>();
      const auto itr = idx.find( pair );
      BOOST_REQUIRE( itr != idx.end() );
      const fc::time_point_sec backdate = db.head_block_time()
            - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
      db.modify( *itr, [&backdate]( seasoning_record_object& m ) {
         m.window_start = backdate;
         // Saturating-bps open (== H2_SEASONING_BPS_SATURATE, local to
         // seasoning.cpp): the creation-open state, so the next covered
         // fold takes current coverages verbatim.
         m.min_vault_bps = std::numeric_limits<uint32_t>::max();
         m.min_oracle_bps = std::numeric_limits<uint32_t>::max();
      } );
   }
   BOOST_REQUIRE( h2_seasoning_complete( db, pair ) );

   const asset_id_type fxr = h2c_create_uia( *this, alice_id, alice_private_key, "R9I9F" );
   hybrid_mint_operation mop;
   mop.minter        = bob_id; // vault-authority member; deposit from bob's BTS
   mop.vault         = vid2;
   mop.deposit       = asset( 130000, asset_id_type() );
   mop.stable_amount = share_type( 1000 );
   mop.fxr_asset     = fxr;
   signed_transaction mtx; mtx.operations.push_back( mop );
   db.current_fee_schedule().set_fee( mtx.operations.back() );
   set_expiration( db, mtx );
   mtx.sign( bob_private_key, db.get_chain_id() );
   PUSH_TX( db, mtx );
   BOOST_CHECK( vid2( db ).outstanding == share_type( 1000 ) );
   BOOST_CHECK( db.get_balance( bob_id, pair ).amount == share_type( 1000 ) );
} FC_LOG_AND_RETHROW() }

/// R9-I9 second settlement shape: the wind-down reached COMPLETE (the
/// segregated bond exhausted exactly -- pro-rata-bound book where the full
/// claim face pays out the whole seized slice). COMPLETE must admit
/// re-registration exactly like the claimed-total leg pinned above.
BOOST_AUTO_TEST_CASE( h2_09_complete_winddown_state_also_reregisters )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   h2c_make_committee_member( *this, alice );

   authority vault_auth( 1, bob_id, 1 );
   const asset_id_type pair = h2c_create_uia( *this, bob_id, bob_private_key, "R9I9C" );
   const vault_id_type vid = h2c_register_vault(
         *this, bob_id, bob_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   const auto vest = h2c_make_cdd_vesting( *this, bob_id, bob_private_key, H2C_VAULT_RAW );
   h2c_lock_vault_bond( *this, bob_id, bob_private_key, vid, vest,
                        H2C_VAULT_RAW, H2C_VAULT_USD_CENTS );
   generate_block();

   // Expiry at zero book (maintenance-healthy: zero outstanding always
   // meets), so only the expiry sweep moves the challenge.
   const vault_challenge_id_type cid = h2c_post_challenge(
         *this, carol_id, carol_private_key, vid, h2c_evidence( "no-quorum" ) );
   generate_blocks( cid( db ).deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );

   // Load the doomed book DOUBLE the segregated slice, then resolve: a
   // full-face senior claim pays exactly the segregated bond (pro-rata leg
   // binds below the haircut), driving paid_total to segregated_bond and
   // the wind-down state to COMPLETE.
   h2c_set_outstanding( *this, vid, H2C_VAULT_RAW * 2 );
   vault_resolve_operation rop;
   rop.resolver  = alice_id;
   rop.challenge = cid;
   signed_transaction rtx; rtx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx );
   const auto& wd_idx = db.get_index_type<winddown_vault_index>().indices();
   BOOST_REQUIRE_EQUAL( wd_idx.size(), 1u );
   const winddown_vault_id_type wdid { wd_idx.begin()->id };
   BOOST_REQUIRE( wdid( db ).total_claims == H2C_VAULT_RAW * 2 );
   BOOST_REQUIRE( wdid( db ).segregated_bond == H2C_VAULT_RAW );

    // R11-R1 entitlement: dave must hold the full double-book face.
    h2c_fund_pair_face( *this, dave_id, wdid( db ).pair, H2C_VAULT_RAW * 2 );
    winddown_claim_operation sop;
    sop.claimant     = dave_id;
    sop.winddown     = wdid;
    sop.claim_amount = H2C_VAULT_RAW * 2;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( dave_private_key, db.get_chain_id() );
   PUSH_TX( db, stx );
   BOOST_REQUIRE_EQUAL( wdid( db ).state, GRAPHENE_H2_WINDDOWN_COMPLETE );
   BOOST_REQUIRE( wdid( db ).paid_total == wdid( db ).segregated_bond );
   const share_type carried_shell = vid( db ).forfeit_pool_balance;
   BOOST_REQUIRE( carried_shell > share_type( 0 ) );

   // COMPLETE admits the fresh registration; the terminal object is removed.
   const vault_id_type vid2 = h2c_register_vault(
         *this, bob_id, bob_private_key, vault_auth,
         H2C_VAULT_RAW, H2C_VAULT_USD_CENTS, pair );
   BOOST_CHECK( vid2 != vid );
   BOOST_CHECK( db.find( vid ) == nullptr );
   BOOST_CHECK( vid2( db ).vault_pair == pair );
   BOOST_CHECK_EQUAL( vid2( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK( wdid( db ).state == GRAPHENE_H2_WINDDOWN_COMPLETE );
   BOOST_CHECK_EQUAL( vid2( db ).forfeit_pool_balance.value, carried_shell.value );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
