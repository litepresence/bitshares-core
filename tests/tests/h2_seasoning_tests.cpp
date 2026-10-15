/*
 * X-02 90-day BTC seasoning clock: object + sweep + verifier op + gate helper.
 *
 * BSIP-1 section 5 staging: BTC ACCS live with coverage >= 2.0 / >= 1.0
 * for 90 days with an independent verifier before USD issuance. This suite
 * proves the scaffolding (no mint/convert op exists yet):
 *
 * - Record creation: vault_register (gateway-leg activation) creates one
 *   seasoning record per pair (genesis = window start, minimums open,
 *   verifier unset, incomplete); the create helper refuses duplicates.
 * - Verifier op (tag 98, price leg): committee-gated like oracle_unfreeze,
 *   sets the bit once with the verifier identity recorded; double-set,
 *   non-committee, unknown-pair, and pre-price posts are refused. AC-16 adds
 *   the independence gate: the pair's issuer and its vault authority (within
 *   the bounded authority walk) cannot attest it. Dual gating (evaluator +
 *   proposal visitor) and the fee-vote gate are pinned.
 * - Sweep: covered sweeps fold minimums and leave the start alone; any
 *   sweep with vault < 2.0 or oracle < 1.0 resets the start (continuous
 *   hold, never cumulative). The clock reads head-block time and H2 bonded
 *   state only.
 * - Isolation: freezing an H1-bound oracle mid-seasoning plus a publish
 *   storm cannot move the clock (H1 inputs absent by construction).
 * - Unbound pairs never complete: without the canonical binding there is
 *   no oracle leg, so every sweep is a recorded breach reset.
 * - Complete end-to-end on the REAL 90-day head-block-time path (fast
 *   jumps model missed slots: unobservable intervals stay unobserved, and
 *   the landing sweep evaluates real elapsed time), with 30/60-day
 *   not-yet controls and an unverified-pair control; plus the hand-set
 *   variant the brief explicitly allows (backdated start + one real
 *   sweep), documented below as the CI-feasible twin. No test-only
 *   consensus constants anywhere: the 90-day threshold is the production
 *   GRAPHENE_H2_SEASONING_WINDOW_SEC in both variants.
 *
 * Pilot basis inherited from H2a-H2d ($0.001/BTS: 1e6 raw units/USD cent).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/proposal_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// Pilot basis: 1e6 raw BTS units per USD cent.
constexpr int64_t H2S_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2S_VAULT_USD_CENTS = 1340000;    // $13,400 vault min_bond
constexpr uint64_t H2S_ORACLE_USD_CENTS = 1005000;   // $10,050 oracle min_bond
const share_type H2S_VAULT_RAW =
      share_type( int64_t( H2S_VAULT_USD_CENTS ) * H2S_RAW_PER_USD_CENT );
const share_type H2S_ORACLE_RAW =
      share_type( int64_t( H2S_ORACLE_USD_CENTS ) * H2S_RAW_PER_USD_CENT );

void h2s_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

reference_asset_id_type h2s_create_reference(
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

oracle_id_type h2s_make_oracle(
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

asset_id_type h2s_create_uia(
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

vault_id_type h2s_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      asset_id_type pair, const authority& vault_auth )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = H2S_VAULT_RAW;
   op.min_bond_usd_cents   = H2S_VAULT_USD_CENTS;
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

vesting_balance_id_type h2s_make_cdd_vesting(
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

void h2s_lock_vault_bond(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      vault_id_type vault, vesting_balance_id_type vesting )
{
   vault_bond_lock_operation op;
   op.owner           = owner;
   op.vault           = vault;
   op.vesting_balance = vesting;
   op.bond_amount     = H2S_VAULT_RAW;
   op.bond_usd_cents  = H2S_VAULT_USD_CENTS;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2s_lock_producer_bond(
      database_fixture& f, account_id_type producer, const fc::ecc::private_key& key,
      oracle_id_type oracle, vesting_balance_id_type vesting )
{
   oracle_bond_lock_operation op;
   op.producer          = producer;
   op.oracle            = oracle;
   op.vesting_balance   = vesting;
   op.bond_amount       = H2S_ORACLE_RAW;
   op.bond_usd_cents    = H2S_ORACLE_USD_CENTS;
   op.bootstrap_weight  = 0;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2s_freeze(
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

void h2s_publish(
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

void h2s_set_outstanding( database_fixture& f, vault_id_type vid, share_type amount )
{
   const vault_object& v = vid( f.db );
   f.db.modify( v, [&amount]( vault_object& m ) { m.outstanding = amount; } );
}

const seasoning_record_object& h2s_find_record( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<seasoning_record_index>()
                        .indices().get<by_seasoning_pair>();
   const auto itr = idx.find( pair );
   BOOST_REQUIRE( itr != idx.end() );
   return *itr;
}

void h2s_verify(
      database_fixture& f, account_id_type verifier, const fc::ecc::private_key& key,
      asset_id_type pair )
{
   seasoning_verify_operation op;
   op.verifier = verifier;
   op.pair     = pair;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// AC-16: push the attestation and return the refusal text ("" when
/// accepted), so the finding-specific independence message is pinned rather
/// than a bare throw.
string h2s_verify_outcome(
      database_fixture& f, account_id_type verifier, const fc::ecc::private_key& key,
      asset_id_type pair )
{
   seasoning_verify_operation op;
   op.verifier = verifier;
   op.pair     = pair;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   try { PUSH_TX( f.db, tx ); }
   catch( const fc::exception& e ) { return e.to_string(); }
   return string();
}

/// One maintenance sweep, then return. Jumps just past the next maintenance
/// boundary (fast-forward: intermediate slots are missed, one sweep lands).
void h2s_run_maintenance( database_fixture& f )
{
   f.generate_blocks( f.db.get_dynamic_global_properties().next_maintenance_time + 3600 );
}

/**
 * Full covered+bound pair fixture: UIA pair, vault + bond, H2 oracle with a
 * bonded producer, canonical binding pinned by pair_freeze. Books
 * (outstanding) are NOT set here: bare db.modify only survives into blocks
 * from a clean pending session, so callers set books via h2s_set_books
 * after a generate_block (h2e_set_outstanding precedent), never back-to-back
 * with PUSH_TX setup.
 */
struct h2s_covered_pair
{
   asset_id_type pair;
   vault_id_type vault;
   oracle_id_type oracle;
};

h2s_covered_pair h2s_make_covered_pair(
      database_fixture& f,
      account_id_type alice_id, const fc::ecc::private_key& alice_key,
      account_id_type bob_id, const fc::ecc::private_key& bob_key,
      const string& pair_symbol, const string& oracle_name,
      reference_asset_id_type bts_ref, reference_asset_id_type usd_ref )
{
   const asset_id_type pair = h2s_create_uia( f, alice_id, alice_key, pair_symbol );
   const vault_id_type vid = h2s_register_vault(
         f, alice_id, alice_key, pair, authority( 1, alice_id, 1 ) );
   h2s_lock_vault_bond( f, alice_id, alice_key, vid,
         h2s_make_cdd_vesting( f, alice_id, alice_key, H2S_VAULT_RAW ) );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   // 120-day print lifetime: the 90-day clock crosses ~90 maintenances, and
   // every sweep must read live (stale reads breach fail-closed).
   opts.value_lifetime_sec = 120 * 86400;
   const oracle_id_type oid = h2s_make_oracle(
         f, alice_id, alice_key, oracle_name, bts_ref, usd_ref, opts );
   h2s_lock_producer_bond( f, bob_id, bob_key, oid,
         h2s_make_cdd_vesting( f, bob_id, bob_key, H2S_ORACLE_RAW ) );
   h2s_freeze( f, alice_id, alice_key, vid, oid );
   // Live price leg (priced-maintenance fixture): the binding above freezes
   // the oracle, so reopen both flags and publish (1,1) -- at unit price the
   // priced book matches the raw-parity books below exactly. The lifetime
   // spans the 90-day clock (republished value would need a sweep-synchronous
   // helper; a long-lived print keeps every sweep live instead).
   f.generate_block();
   f.db.modify( vid( f.db ), []( vault_object& v ) { v.frozen = false; } );
   f.db.modify( oid( f.db ), []( oracle_object& o ) { o.options.frozen = false; } );
   h2s_publish( f, oid, bob_id, bob_key, 1, 1 );
   return h2s_covered_pair{ pair, vid, oid };
}

/**
 * Set a vault's books so the next sweep observes them. The generate_block
 * first is load-bearing, not cosmetic: bare db.modify records into the
 * pending undo session, and _generate_block resets that session keeping
 * only pushed transactions -- a modify issued back-to-back with PUSH_TX
 * setup is silently discarded at the next block. Sealing setup into a
 * block first (clear_pending invalidates the session, so the modify lands
 * on base state) is the h2e_set_outstanding precedent. It also advances
 * head time, so later setup transactions cannot collide as duplicates.
 */
void h2s_set_books( database_fixture& f, vault_id_type vid, share_type outstanding )
{
   f.generate_block();
   h2s_set_outstanding( f, vid, outstanding );
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_seasoning_tests, database_fixture )

/// Gateway-leg activation creates the clock: one record per pair, genesis =
/// window start = register time, minimums open, verifier unset, incomplete.
BOOST_AUTO_TEST_CASE( record_created_at_gateway_activation )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const asset_id_type pair = h2s_create_uia( *this, alice_id, alice_private_key, "SEASN" );
   const fc::time_point_sec before = db.head_block_time();
   const vault_id_type vid = h2s_register_vault(
         *this, alice_id, alice_private_key, pair, authority( 1, alice_id, 1 ) );
   const seasoning_record_object& rec = h2s_find_record( *this, pair );
   BOOST_CHECK( rec.pair == pair );
   BOOST_CHECK( rec.genesis_time == rec.window_start );
   BOOST_CHECK( rec.genesis_time >= before );
   BOOST_CHECK( rec.genesis_time <= db.head_block_time() );
   BOOST_CHECK_EQUAL( rec.verifier_set, false );
   BOOST_CHECK_EQUAL( rec.complete, false );
   BOOST_CHECK( !h2_seasoning_complete( db, pair ) );
   BOOST_CHECK( vid( db ).vault_pair == pair );
} FC_LOG_AND_RETHROW() }

/// The create helper refuses duplicates: at most one record per pair ever
/// exists (vault_register's own pair-uniqueness fires first on the op path;
//  this pins the defense-in-depth assert directly).
BOOST_AUTO_TEST_CASE( duplicate_record_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 100000000000LL ) );
   const asset_id_type pair = h2s_create_uia( *this, alice_id, alice_private_key, "SEASD" );
   h2_create_seasoning_record( db, pair, db.head_block_time() );
   BOOST_CHECK_THROW( h2_create_seasoning_record( db, pair, db.head_block_time() ),
                      fc::exception );
} FC_LOG_AND_RETHROW() }

/// Verifier bit: committee member sets it once with identity recorded;
/// double-set (same or rotating verifier), non-committee, unknown pair,
/// and pre-price posts are all refused.
BOOST_AUTO_TEST_CASE( verifier_sets_bit_once_only )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   fund( carol, asset( 100000000000LL ) );
   h2s_make_committee_member( *this, alice );
   h2s_make_committee_member( *this, bob );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair cp = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASV", "SEASV.USD", bts_ref, usd_ref );

   // Non-committee carol cannot attest.
   {
      seasoning_verify_operation op;
      op.verifier = carol_id;
      op.pair     = cp.pair;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( carol_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // Unknown pair (no record) fails closed.
   {
      const asset_id_type stray = h2s_create_uia( *this, alice_id, alice_private_key, "STRAY" );
      seasoning_verify_operation op;
      op.verifier = alice_id;
      op.pair     = stray;
      signed_transaction tx;
      tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // AC-16: alice (the pair's issuer AND its vault authority) is no longer an
   // admissible verifier -- the attestation now seats carol (below).
   h2s_make_committee_member( *this, carol );

   // Committee attestation sets the bit with identity recorded.
   h2s_verify( *this, carol_id, carol_private_key, cp.pair );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).verifier_set, true );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).verifier == carol_id );

   // Double-set refused, same verifier...
   BOOST_CHECK_THROW( h2s_verify( *this, carol_id, carol_private_key, cp.pair ),
                      fc::exception );
   // ...and rotating verifier (no anonymous overwrite).
   BOOST_CHECK_THROW( h2s_verify( *this, bob_id, bob_private_key, cp.pair ),
                      fc::exception );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).verifier == carol_id );
} FC_LOG_AND_RETHROW() }

/// Pre-price the verifier op is refused at the evaluator gate...
BOOST_AUTO_TEST_CASE( verifier_refused_before_price_leg )
{ try {
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const asset_id_type pair = h2s_create_uia( *this, alice_id, alice_private_key, "SEASP" );
   h2s_register_vault( *this, alice_id, alice_private_key, pair,
         authority( 1, alice_id, 1 ) );
   BOOST_CHECK_THROW( h2s_verify( *this, alice_id, alice_private_key, pair ),
                      fc::exception );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, pair ).verifier_set, false );
} FC_LOG_AND_RETHROW() }

/// ...and refused inside proposals too (proposal visitor dual gate): a
/// leg-dark nested verify is rejected at proposal creation, not execution.
BOOST_AUTO_TEST_CASE( verifier_in_proposal_refused_before_price_leg )
{ try {
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const asset_id_type pair = h2s_create_uia( *this, alice_id, alice_private_key, "SEASQ" );
   h2s_register_vault( *this, alice_id, alice_private_key, pair,
         authority( 1, alice_id, 1 ) );

   proposal_create_operation prop;
   prop.fee_paying_account = alice_id;
   seasoning_verify_operation vop;
   vop.verifier = alice_id;
   vop.pair     = pair;
   prop.proposed_ops.emplace_back( vop );
   prop.expiration_time = db.head_block_time() + fc::days( 1 );
   signed_transaction tx;
   tx.operations.push_back( prop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// Fee-vote gating (E-01 pattern): a committee fee schedule naming the
/// verifier op is refused pre-price and admitted at the price height.
BOOST_AUTO_TEST_CASE( verifier_fee_vote_gated_by_price_leg )
{ try {
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   set_expiration( db, trx );

   auto push_fee_proposal = [&]() {
      const chain_parameters& existing = db.get_global_properties().parameters;      std::shared_ptr<fee_schedule> new_fees = std::make_shared<fee_schedule>();
      new_fees->scale = existing.current_fees->scale;
      new_fees->parameters = existing.current_fees->parameters;
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      // Fee payer is the auto-approved temp account (htlc hardfork-test
      // shape: committee_proposal creation requires no active authority).
      // Temp carries no balance, so the outer fee stays zero (see below);
      // the vote gate inspects the INNER fee schedule, not this payer.
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
      committee_member_update_global_parameters_operation uop;
      chain_parameters new_params = db.get_global_properties().parameters;
      new_params.current_fees = new_fees;
      uop.new_parameters = new_params;
      cop.proposed_ops.emplace_back( uop );
      // Outer proposal fee stays zero (htlc hardfork-test shape): a nonzero
      // fee would debit the empty temp account before evaluation and mask
      // the gate; the vote gate inspects the INNER fee schedule, not this.
      signed_transaction tx;
      tx.operations.push_back( cop );
      // Unsigned (htlc hardfork-test shape): committee_proposal creation
      // requires no active authority, so any signature would be refused as
      // irrelevant; the fee gate fires at proposal evaluation. Fee payer is
      // the temp account, as in the precedent.
      set_expiration( db, tx );
      PUSH_TX( db, tx );
   };

   // Genesis fees already name every op in the variant (fee schedule is
   // variant-derived), so the price-gate fires pre-PRICE.
   BOOST_REQUIRE( db.get_global_properties().parameters
                  .current_fees->exists<seasoning_verify_operation>() );
   GRAPHENE_REQUIRE_THROW( push_fee_proposal(), fc::exception );

   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   push_fee_proposal();
   BOOST_CHECK( !db.get_index_type<proposal_index>().indices().empty() );
} FC_LOG_AND_RETHROW() }

/// Continuous hold, not cumulative: a covered sweep folds minimums and
/// leaves the start alone; a breaching sweep restarts the clock at
/// head-block time with minimums reopened at the breaching values; restored
/// coverage resumes from the restart, never from genesis.
BOOST_AUTO_TEST_CASE( breach_resets_start_continuous_hold )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair cp = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASB", "SEASB.USD", bts_ref, usd_ref );
   const fc::time_point_sec genesis = h2s_find_record( *this, cp.pair ).genesis_time;
   // Half-book liabilities: vault 2.0x / oracle 1.5x integer-exact.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );

   // Covered sweep: vault 2.0x / oracle 1.5x integer-exact, start untouched.
   h2s_run_maintenance( *this );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).window_start == genesis );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_vault_bps, 20000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_oracle_bps, 15000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).complete, false );

   // Breach: full-book liabilities read vault 1.0x / oracle 0.75x.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW );
   h2s_run_maintenance( *this );
   const fc::time_point_sec restarted = h2s_find_record( *this, cp.pair ).window_start;
   BOOST_CHECK( restarted > genesis );
   BOOST_CHECK( restarted <= db.head_block_time() );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_vault_bps, 10000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_oracle_bps, 7500u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).complete, false );
   BOOST_CHECK( !h2_seasoning_complete( db, cp.pair ) );

   // Restored coverage resumes the clock from the restart, not genesis.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );
   h2s_run_maintenance( *this );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).window_start == restarted );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_vault_bps, 10000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_oracle_bps, 7500u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).complete, false );
} FC_LOG_AND_RETHROW() }

/// H1 isolation: freezing an H1-bound oracle mid-seasoning plus a publish
/// storm runs real H1 state changes through a real sweep, and the seasoning
/// start does not move. The clock reads H2 bonded state only.
BOOST_AUTO_TEST_CASE( h1_freeze_and_publish_storm_cannot_move_clock )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair cp = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASH", "SEASH.USD", bts_ref, usd_ref );
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );

   // A plain H1 oracle: live values, no bonds, never frozen into H2 state.
   oracle_options h1_opts;
   h1_opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type h1 = h2s_make_oracle(
         *this, alice_id, alice_private_key, "H1.USD", bts_ref, usd_ref, h1_opts );
   h2s_run_maintenance( *this );
   const fc::time_point_sec start = h2s_find_record( *this, cp.pair ).window_start;

   // Mid-seasoning: the owner freezes the H1 oracle (Track A path) and the
   // producer storms 25 publishes through it.
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = h1;
      oracle_options frozen_opts = h1( db ).options;
      frozen_opts.frozen = true;
      uop.new_options = frozen_opts;
      signed_transaction tx;
      tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE_EQUAL( h1( db ).options.frozen, true );
   for( int i = 0; i < 25; ++i )
      h2s_publish( *this, h1, bob_id, bob_private_key, 100 + i, 1 );

   h2s_run_maintenance( *this );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).window_start == start );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_vault_bps, 20000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).min_oracle_bps, 15000u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).complete, false );
   BOOST_CHECK( !h2_seasoning_complete( db, cp.pair ) );
} FC_LOG_AND_RETHROW() }

/// No binding, no clock: an unbound pair names no bonded price series, so
/// every sweep is a recorded breach reset (oracle minimum reads 0) and the
/// pair can never complete -- even verified, even after 90 days. The window
/// floats to binding by construction.
BOOST_AUTO_TEST_CASE( unbound_pair_never_completes )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   fund( carol, asset( 100000000000LL ) );
   h2s_make_committee_member( *this, alice );
   // AC-16: the verifier must be independent of the pair -- carol is neither
   // the pair's issuer nor inside its vault-authority walk.
   h2s_make_committee_member( *this, carol );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const asset_id_type pair = h2s_create_uia( *this, alice_id, alice_private_key, "SEASU" );
   const vault_id_type vid = h2s_register_vault(
         *this, alice_id, alice_private_key, pair, authority( 1, alice_id, 1 ) );
   h2s_lock_vault_bond( *this, alice_id, alice_private_key, vid,
         h2s_make_cdd_vesting( *this, alice_id, alice_private_key, H2S_VAULT_RAW ) );
   h2s_set_books( *this, vid, H2S_VAULT_RAW / 2 );
   h2s_verify( *this, carol_id, carol_private_key, pair );
   const fc::time_point_sec genesis = h2s_find_record( *this, pair ).genesis_time;

   generate_blocks( genesis + GRAPHENE_H2_SEASONING_WINDOW_SEC + 86400 );
   h2s_run_maintenance( *this );
   BOOST_CHECK( h2s_find_record( *this, pair ).window_start > genesis );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, pair ).min_oracle_bps, 0u );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, pair ).complete, false );
   BOOST_CHECK( !h2_seasoning_complete( db, pair ) );
} FC_LOG_AND_RETHROW() }

/// Complete end-to-end on real head-block-time travel: verified + covered +
/// bound, the flag stays false at 30 and 60 days and turns true past 90,
/// while an unverified twin on identical books never completes.
BOOST_AUTO_TEST_CASE( complete_flag_end_to_end_on_real_time_travel )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 8000000000000LL ) );
   fund( bob, asset( 8000000000000LL ) );
   fund( carol, asset( 100000000000LL ) );
   h2s_make_committee_member( *this, alice );
   // AC-16: independent verifier (neither the pair's issuer nor in its
   // vault-authority walk); bob stays the bonded producer.
   h2s_make_committee_member( *this, carol );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair good = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASG", "SEASG.USD", bts_ref, usd_ref );
   // Seal the first pair into a block: the twin's identical-amount vesting
   // locks would otherwise repeat the same signed transaction (same head
   // time, same expiration) and be refused as duplicates.
   generate_block();
   const h2s_covered_pair twin = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEAST", "SEAST.USD", bts_ref, usd_ref );
   h2s_set_books( *this, good.vault, H2S_VAULT_RAW / 2 );
   h2s_set_books( *this, twin.vault, H2S_VAULT_RAW / 2 );
   h2s_verify( *this, carol_id, carol_private_key, good.pair );
   const fc::time_point_sec start = h2s_find_record( *this, good.pair ).window_start;

   // The bonded-live gate needs now < producer-bond unlock, and each publish
   // advances unlock by only ADVANCE (1d): a silent producer's read lapses
   // ~8 days after its last print, and the vault fail-closes (TOPUP, then
   // wind-down), resetting the clock. An active producer publishes ~daily,
   // so the 90-day clock hops day-by-day with a fresh (1,1) print on both
   // oracles. Same-day prints name different oracles and day-apart prints
   // carry different head times, so no two signed publishes collide as
   // duplicates. The twin stays live-but-unverified: identical books, no
   // verifier, never completes.
   for( int day = 1; day <= 91; ++day )
   {
      h2s_publish( *this, good.oracle, bob_id, bob_private_key, 1, 1 );
      h2s_publish( *this, twin.oracle, bob_id, bob_private_key, 1, 1 );
      generate_blocks( db.head_block_time() + 86400 );
      if( day == 30 || day == 60 )
      {
         h2s_run_maintenance( *this );
         BOOST_CHECK_EQUAL( h2s_find_record( *this, good.pair ).complete, false );
         BOOST_CHECK( !h2_seasoning_complete( db, good.pair ) );
      }
   }
   h2s_run_maintenance( *this );
   // The clock really traveled: head sits past start + the 90-day window,
   // so the flag below reflects a full continuous hold, not a short clock.
   BOOST_REQUIRE( db.head_block_time() >= start + GRAPHENE_H2_SEASONING_WINDOW_SEC );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, good.pair ).complete, true );
   BOOST_CHECK( h2_seasoning_complete( db, good.pair ) );
   // Identical books, no verifier: never completes.
   BOOST_CHECK_EQUAL( h2s_find_record( *this, twin.pair ).complete, false );
   BOOST_CHECK( !h2_seasoning_complete( db, twin.pair ) );
} FC_LOG_AND_RETHROW() }

/// Hand-set twin of the travel above (the brief's explicit option):
/// backdate the window start past the production 90-day threshold, run one
/// real sweep, and the flag + helper agree. Same predicate, same constant,
/// no test-only consensus values -- the backdate only buys CI-feasible
/// time, since the comparison is head-block time minus start either way.
BOOST_AUTO_TEST_CASE( complete_predicate_against_hand_set_state )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   fund( carol, asset( 100000000000LL ) );
   h2s_make_committee_member( *this, alice );
   // AC-16: independent verifier (neither the pair's issuer nor in its
   // vault-authority walk).
   h2s_make_committee_member( *this, carol );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair cp = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASC", "SEASC.USD", bts_ref, usd_ref );
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );
   h2s_verify( *this, carol_id, carol_private_key, cp.pair );
   BOOST_CHECK( !h2_seasoning_complete( db, cp.pair ) );

   const fc::time_point_sec backdate = db.head_block_time()
         - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
   // Seal the verify into a block first: same pending-session rule as
   // h2s_set_books -- a backdate issued back-to-back with PUSH_TX setup
   // would be discarded at the next block.
   generate_block();
   const seasoning_record_object& rec = h2s_find_record( *this, cp.pair );
   db.modify( rec, [&backdate]( seasoning_record_object& m ) { m.window_start = backdate; } );
   // Helper reads swept state + head-block time: true even before the next
   // sweep runs (the predicate, not the flag, is the issuance gate).
   BOOST_CHECK( h2_seasoning_complete( db, cp.pair ) );
   h2s_run_maintenance( *this );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).complete, true );
   BOOST_CHECK( h2_seasoning_complete( db, cp.pair ) );
} FC_LOG_AND_RETHROW() }

// ---------------------------------------------------------------------------
// AC-16 (round-9): an attestation cannot be issued by a party to the pair
// ---------------------------------------------------------------------------

/// RED: the verifier op only checked committee membership, so the pair's own
/// issuer AND its vault authority could "independently" verify it. The gate
/// below walks both graphs (the same bounded authority walk the challenge
/// self-dealing ban uses) and refuses either leg fail-closed.
BOOST_AUTO_TEST_CASE( related_party_verifier_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   fund( carol, asset( 100000000000LL ) );
   h2s_make_committee_member( *this, alice );
   h2s_make_committee_member( *this, bob );
   h2s_make_committee_member( *this, carol );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   (void)bts_ref; (void)usd_ref;

   // Pair A: issuer = alice, vault authority = alice -> alice refused on the
   // issuer leg; an independent seat (carol) attests the same record.
   const asset_id_type pair_a = h2s_create_uia( *this, alice_id, alice_private_key, "SEASX" );
   h2s_register_vault( *this, alice_id, alice_private_key, pair_a,
                       authority( 1, alice_id, 1 ) );
   const string issuer_err = h2s_verify_outcome( *this, alice_id, alice_private_key, pair_a );
   BOOST_CHECK_MESSAGE( issuer_err.find( "issuer" ) != std::string::npos,
                        "AC-16 issuer-side verifier not refused: " << issuer_err );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, pair_a ).verifier_set, false );
   h2s_verify( *this, carol_id, carol_private_key, pair_a );
   BOOST_CHECK( h2s_find_record( *this, pair_a ).verifier == carol_id );

   // Pair B: issuer = alice, vault authority = bob -> bob (seated, but the
   // vault's authority) refused on the vault-authority leg.
   generate_block();
   const asset_id_type pair_b = h2s_create_uia( *this, alice_id, alice_private_key, "SEASY" );
   h2s_register_vault( *this, alice_id, alice_private_key, pair_b,
                       authority( 1, bob_id, 1 ) );
   const string auth_err = h2s_verify_outcome( *this, bob_id, bob_private_key, pair_b );
   BOOST_CHECK_MESSAGE( auth_err.find( "vault authority" ) != std::string::npos,
                        "AC-16 vault-authority-side verifier not refused: " << auth_err );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, pair_b ).verifier_set, false );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( breach_count_monotonic_ac15c )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 5000000000000LL ) );
   fund( bob, asset( 5000000000000LL ) );
   h2s_make_committee_member( *this, alice );
   const auto bts_ref = h2s_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2s_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   const h2s_covered_pair cp = h2s_make_covered_pair(
         *this, alice_id, alice_private_key, bob_id, bob_private_key,
         "SEASC15", "SEASC15.USD", bts_ref, usd_ref );
   // Genesis: no breach observed yet.
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).breach_count, 0u );
   // Half-book liabilities: vault 2.0x / oracle 1.5x integer-exact.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );

   // Covered sweep: no breach counted, start untouched.
   h2s_run_maintenance( *this );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).breach_count, 0u );

   // Breach: full-book liabilities read vault 1.0x / oracle 0.75x.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW );
   h2s_run_maintenance( *this );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).breach_count, 1u );
   const fc::time_point_sec restarted = h2s_find_record( *this, cp.pair ).window_start;

   // Restored coverage resumes without clearing the count: the breach stays
   // reconstructable (count 1 + window_start > genesis proves ungated days).
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW / 2 );
   h2s_run_maintenance( *this );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).window_start == restarted );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).breach_count, 1u );

   // Second breach: the counter advances again, never resets.
   h2s_set_books( *this, cp.vault, H2S_VAULT_RAW );
   h2s_run_maintenance( *this );
   BOOST_CHECK_EQUAL( h2s_find_record( *this, cp.pair ).breach_count, 2u );
   BOOST_CHECK( h2s_find_record( *this, cp.pair ).window_start > restarted );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
