/*
 * H2b dispute/challenge machinery + fail-closed arbitration.
 *
 * One rulebook for both legs (inventory sections 1.5-1.7 vault challenges,
 * 2.4 oracle disputes, 2.5 arbitration params): anyone posts a bond, the
 * committee votes on-chain inside a 48h window, exoneration/sustain/fast-reject
 * need a 2/3 supermajority of the deciding set (all seated committee members),
 * and a missed deadline fails closed (auto-freeze) at the next maintenance.
 *
 * USD-terms-at-lock basis (recorded, not recomputed): every bond floor below is
 * denominated in USD cents at lock, converted to raw BTS smallest units at the
 * fixed pilot basis of $0.001/BTS (1000 BTS per USD, BTS precision 5, so exactly
 * 1,000,000 raw units per USD cent) inherited from H2a. Raw/usd consistency
 * enforcement against a live bonded-oracle price arrives with the H2d price leg;
 * H2b records the basis, exactly like H2a.
 *
 * Proposals used (BSIP-1 section 7b + inventory): challenger/dispute base floor
 * $837.50, escalation doubles per round capped at 3 rounds, finder cap $83.75,
 * forfeit split 80% burn / 15% reward-pool accumulator / remainder finder,
 * 48h vote window, 24h per-pair cooldown, max 3 concurrent per pair,
 * supermajority 6667 bps, quorum 5000 bps participation, evidence memo 1..1000
 * chars, authority-graph walk depth <= 2 width <= 15.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// Pilot basis inherited from H2a: 1e6 raw BTS units per USD cent.
constexpr int64_t H2D_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2D_FLOOR_USD_CENTS = 83750;    // $837.50 challenger/dispute base
constexpr uint64_t H2D_FINDER_CAP_USD_CENTS = 8375; // $83.75 finder cap
const share_type H2D_ROUND1_RAW =
      share_type( int64_t( H2D_FLOOR_USD_CENTS ) * H2D_RAW_PER_USD_CENT );

string h2d_evidence( const string& tag )
{ return string( "evidence:" ) + tag; }

void h2d_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_committee_member( account );
}

reference_asset_id_type h2d_create_reference(
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

oracle_id_type h2d_make_oracle(
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

void h2d_publish( database_fixture& f, oracle_id_type oid,
                  account_id_type who, const fc::ecc::private_key& key, int64_t quote )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = { oracle_value( 1, quote ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

vault_id_type h2d_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = asset_id_type();
   op.vault_authority      = vault_auth;
   op.min_bond             = share_type( 1340000LL * H2D_RAW_PER_USD_CENT );
   op.min_bond_usd_cents   = 1340000;
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

/// Live 2/3-supermajority threshold over the seated deciding set (genesis seats
/// init0..init9, so N is 10 unless the test seats more). Mirrors the
/// evaluator's BPS-constant helper exactly (H2c cleanup: was ceil(2N/3)).
uint64_t h2d_vote_threshold( database_fixture& f )
{
   const uint64_t n =
         f.db.get_index_type<committee_member_index>().indices().size();
   BOOST_REQUIRE( n > 0 );
   return ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
}

vault_challenge_id_type h2d_post_challenge(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      vault_id_type vault, share_type bond, uint64_t bond_usd, const string& memo )
{
   vault_challenge_operation op;
   op.challenger          = challenger;
   op.vault               = vault;
   op.challenge_bond      = bond;
   op.challenge_bond_usd_cents = bond_usd;
   op.evidence_memo       = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_challenge_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

oracle_dispute_id_type h2d_post_dispute(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      oracle_id_type oracle, account_id_type defender,
      fc::time_point_sec accused_time, uint16_t accused_series, const string& memo )
{
   oracle_dispute_operation op;
   op.challenger          = challenger;
   op.oracle              = oracle;
   op.defender            = defender;
   op.accused_time        = accused_time;
   op.accused_series      = accused_series;
   op.dispute_bond        = H2D_ROUND1_RAW;
   op.dispute_bond_usd_cents = H2D_FLOOR_USD_CENTS;
   op.evidence_memo       = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_dispute_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2d_escalate(
      database_fixture& f, account_id_type escalator, const fc::ecc::private_key& key,
      oracle_dispute_id_type dispute, share_type round_bond, uint64_t round_usd )
{
   oracle_dispute_escalate_operation op;
   op.escalator          = escalator;
   op.dispute            = dispute;
   op.round_bond         = round_bond;
   op.round_bond_usd_cents = round_usd;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2d_vote(
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

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_dispute_tests, database_fixture )

/// A node running old code must never see an H2 dispute op it cannot validate.
BOOST_AUTO_TEST_CASE( h2_dispute_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (alice) );
   fund( alice );

   vault_challenge_operation cop;
   cop.challenger = alice_id;
   cop.vault = vault_id_type( 0 );
   cop.challenge_bond = H2D_ROUND1_RAW;
   cop.challenge_bond_usd_cents = H2D_FLOOR_USD_CENTS;
   cop.evidence_memo = h2d_evidence( "prefork" );
   signed_transaction tx;
   tx.operations.push_back( cop );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );

   oracle_dispute_operation dop;
   dop.challenger = alice_id;
   dop.oracle = oracle_id_type( 0 );
   dop.defender = alice_id;
   dop.accused_time = db.head_block_time();
   dop.accused_series = 0;
   dop.dispute_bond = H2D_ROUND1_RAW;
   dop.dispute_bond_usd_cents = H2D_FLOOR_USD_CENTS;
   dop.evidence_memo = h2d_evidence( "prefork" );
   signed_transaction tx2;
   tx2.operations.push_back( dop );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx2 ), fc::exception );

   oracle_dispute_escalate_operation eop;
   eop.escalator = alice_id;
   eop.dispute = oracle_dispute_id_type( 0 );
   eop.round_bond = H2D_ROUND1_RAW * 2;
   eop.round_bond_usd_cents = H2D_FLOOR_USD_CENTS * 2;
   signed_transaction tx3;
   tx3.operations.push_back( eop );
   set_expiration( db, tx3 );
   tx3.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx3 ), fc::exception );

   challenge_vote_operation vop;
   vop.voter = alice_id;
   vop.target = object_id_type( vault_challenge_id_type( 0 ) );
   vop.decision = 0;
   signed_transaction tx4;
   tx4.operations.push_back( vop );
   set_expiration( db, tx4 );
   tx4.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx4 ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( challenge_posts_with_floor_memo_and_open_state )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   const vault_challenge_id_type cid = h2d_post_challenge(
         *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "theft" ) );
   const vault_challenge_object& c = cid( db );

   // Lifecycle opens correctly: bond escrowed, 48h window, one concurrent slot used.
   BOOST_CHECK( c.vault == vid );
   BOOST_CHECK( c.challenger == bob_id );
   BOOST_CHECK( c.challenge_bond == H2D_ROUND1_RAW );
   BOOST_CHECK( c.opened == c.deadline - GRAPHENE_H2_VOTE_WINDOW_SEC );
   BOOST_CHECK_EQUAL( c.state, GRAPHENE_H2_CHALLENGE_OPEN );
   BOOST_CHECK( c.votes.empty() );
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount <= bob_before - H2D_ROUND1_RAW );
   BOOST_CHECK_EQUAL( vid( db ).open_challenges, 1u );
   BOOST_CHECK( vid( db ).last_challenge_time == c.opened );

   // Below-floor USD records are refused. (The $837.50 floor is USD-terms
   // only: raw-vs-USD price consistency needs the H2d price leg, so a short
   // raw amount with a full USD record is NOT refused in H2c as long as it is
   // funded — the evaluator's floor branch only reads usd_cents. A prior
   // revision asserted a raw shortfall throw here; that expectation was
   // vacuous pre-isolation (it threw on cooldown, never on floor) and is
   // unimplementable without a consensus price, so it is removed, not
   // isolated. H2d must revisit this site when it adds the consistency
   // check.)
   generate_blocks( db.head_block_time() + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC + 3600 );
   generate_block();
   BOOST_CHECK_THROW( h2d_post_challenge( *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS - 1, h2d_evidence( "short-usd" ) ),
      fc::exception );

   // Evidence is transparent and bounded: empty and oversize memos are refused.
   BOOST_CHECK_THROW( h2d_post_challenge( *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, "" ), fc::exception );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS,
         string( GRAPHENE_H2_EVIDENCE_MAX_LENGTH + 1, 'x' ) ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( blind_funded_challenge_is_rejected )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   // Small numbers on purpose: blind range proofs grow with the proven amount
   // and the chain caps transactions at 2kB, so this test blinds thousands,
   // not billions. The posted bond is small in raw terms but still meets the
   // $837.50 USD-terms floor: raw/usd consistency is H2d's live-price job, and
   // H2b records the basis exactly like H2a does.
   fund( bob, asset( 24000 ) );
   fund( carol, asset( 24000 ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

   // Bob moves nearly everything into blind commitments, twice over: his
   // wealth still exists, but almost none of it is attributable transparent
   // funds anymore. Each blind is small enough for its range proof to fit.
   const asset_object& core = asset_id_type()( db );
   for( int i = 0; i < 2; ++i )
   {
      transfer_to_blind_operation to_blind;
      to_blind.amount = core.amount( 8000 );
      to_blind.from   = bob_id;
      auto owner_key = fc::ecc::private_key::generate();
      blind_output out;
      out.owner = authority( 1, public_key_type( owner_key.get_public_key() ), 1 );
      auto blind_in = fc::sha256::hash( string( "h2b-blind-in" ) + fc::to_string( i ) );
      auto nonce = fc::sha256::hash( string( "h2b-blind-nonce" ) + fc::to_string( i ) );
      out.commitment  = fc::ecc::blind( blind_in, 8000 );
      out.range_proof = fc::ecc::range_proof_sign( 0, out.commitment, blind_in, nonce, 0, 0, 8000 );
      to_blind.blinding_factor = fc::ecc::blind_sum( { blind_in }, 1 );
      to_blind.outputs = { out };
      signed_transaction btx;
      btx.operations.push_back( to_blind );
      set_expiration( db, btx );
      btx.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, btx );
   }

   // The blind money cannot fund the challenge escrow: only transparent
   // balances are debited, and Bob's 8000 remainder is short of the 9000 bond.
   BOOST_CHECK_EQUAL( db.get_balance( bob_id, asset_id_type() ).amount.value, 8000 );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, bob_id, bob_private_key, vid,
         share_type( 9000 ), H2D_FLOOR_USD_CENTS, h2d_evidence( "blind" ) ),
      fc::exception );

   // Positive control: the same small bond posts fine from transparent funds.
   const vault_challenge_id_type ok = h2d_post_challenge(
         *this, carol_id, carol_private_key, vid,
         share_type( 9000 ), H2D_FLOOR_USD_CENTS, h2d_evidence( "transparent" ) );
   BOOST_CHECK_EQUAL( ok( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( dispute_rounds_double_and_cap_at_three )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // Round 1 opens against a retained aggregate with the base bond.
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0, h2d_evidence( "bad-print" ) );
   BOOST_CHECK_EQUAL( did( db ).round, 1u );
   BOOST_CHECK( did( db ).challenger_bonds == H2D_ROUND1_RAW );
   BOOST_CHECK_EQUAL( oid( db ).open_disputes, 1u );

   // Accusations must name retained history: unknown times and series are refused.
   // Isolation: same cooldown-advance as the challenge floor negatives above —
   // without it these posts die on the per-pair cooldown before reaching the
   // retained-history branch under test. The 25h hop stays inside the 48h
   // round window, so the escalation ladder below is unaffected.
   generate_blocks( db.head_block_time() + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC + 3600 );
   generate_block();
   BOOST_CHECK_THROW( h2d_post_dispute( *this, bob_id, bob_private_key, oid, carol_id,
         accused - 1, 0, h2d_evidence( "no-history" ) ), fc::exception );
   BOOST_CHECK_THROW( h2d_post_dispute( *this, bob_id, bob_private_key, oid, carol_id,
         accused, 7, h2d_evidence( "no-series" ) ), fc::exception );
   // The defender must be a producer of the oracle.
   BOOST_CHECK_THROW( h2d_post_dispute( *this, bob_id, bob_private_key, oid, alice_id,
         accused, 0, h2d_evidence( "not-producer" ) ), fc::exception );

   // Either side may escalate; each round bond doubles the last, and each
   // escalation opens a fresh 48h vote window from its own head time.
   const fc::time_point_sec d0 = did( db ).round_deadline;
   generate_blocks( db.head_block_time() + 3600 );
   generate_block();
   h2d_escalate( *this, carol_id, carol_private_key, did,
                 H2D_ROUND1_RAW * 2, H2D_FLOOR_USD_CENTS * 2 );
   BOOST_CHECK_EQUAL( did( db ).round, 2u );
   BOOST_CHECK( did( db ).defender_bonds == H2D_ROUND1_RAW * 2 );
   BOOST_CHECK( did( db ).round_deadline == db.head_block_time() + GRAPHENE_H2_VOTE_WINDOW_SEC );
   BOOST_CHECK( did( db ).round_deadline > d0 );
   h2d_escalate( *this, bob_id, bob_private_key, did,
                 H2D_ROUND1_RAW * 4, H2D_FLOOR_USD_CENTS * 4 );
   BOOST_CHECK_EQUAL( did( db ).round, 3u );
   BOOST_CHECK( did( db ).challenger_bonds == H2D_ROUND1_RAW + H2D_ROUND1_RAW * 4 );

   // Round 4 would cost a vault bond and bankrupt honest defenders first: refused.
   BOOST_CHECK_THROW( h2d_escalate( *this, bob_id, bob_private_key, did,
         H2D_ROUND1_RAW * 8, H2D_FLOOR_USD_CENTS * 8 ), fc::exception );
   // Outsiders and over-large bonds are refused (round 4 would cost a vault
   // bond and bankrupt honest defenders first).
   BOOST_CHECK_THROW( h2d_escalate( *this, alice_id, alice_private_key, did,
         H2D_ROUND1_RAW * 8, H2D_FLOOR_USD_CENTS * 8 ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( missed_deadline_expires_frozen_without_votes )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   const vault_challenge_id_type cid = h2d_post_challenge(
         *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "stall" ) );
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0, h2d_evidence( "stall" ) );
   const fc::time_point_sec deadline = cid( db ).deadline;

   // Silence: nobody votes. Past the deadline the next maintenance fails closed.
   generate_blocks( deadline + 2 * 86400 );
   generate_block();
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_CHECK_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   // The vault halts mints and the oracle stops promoting values, but both
   // keep aggregating transparently; the challenger is not punished for the
   // committee's silence, so escrow returns in full.
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   BOOST_CHECK_EQUAL( vid( db ).open_challenges, 0u );
   BOOST_CHECK_EQUAL( oid( db ).open_disputes, 0u );
   // Both escrows (one challenge bond + one round-1 dispute bond) return in
   // full: only fees are gone, never a forfeit.
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount > bob_before - H2D_ROUND1_RAW * 2 );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( same_authority_pairings_are_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(mallory)(outer)(ex)(why)(zed) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   fund( mallory, asset( 3000000000000LL ) );
   fund( outer, asset( 3000000000000LL ) );
   fund( ex, asset( 3000000000000LL ) );
   fund( why, asset( 3000000000000LL ) );
   fund( zed, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // Vault member dave sits on the threshold authority with alice.
   authority vault_auth( 2, alice_id, 1, dave_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

   // Depth 0/1: a member challenges their own vault, and the accused producer
   // challenges their own print. Both are self-dealing.
   fund( dave, asset( 3000000000000LL ) );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, dave_id, dave_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "self" ) ), fc::exception );
   BOOST_CHECK_THROW( h2d_post_dispute( *this, carol_id, carol_private_key, oid, carol_id,
         accused, 0, h2d_evidence( "self" ) ), fc::exception );

   // Depth 2: mallory's active authority names dave (on the vault) and carol
   // (the accused producer). Mallory never appears in either target authority
   // directly, but the walk finds both one step inside mallory's graph.
   account_update_operation uop;
   uop.account = mallory_id;
   uop.active = authority( 1, public_key_type( mallory_private_key.get_public_key() ), 1,
                           dave_id, 1, carol_id, 1 );
   signed_transaction utx;
   utx.operations.push_back( uop );
   db.current_fee_schedule().set_fee( utx.operations.back() );
   set_expiration( db, utx );
   utx.sign( mallory_private_key, db.get_chain_id() );
   PUSH_TX( db, utx );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, mallory_id, mallory_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "depth2" ) ), fc::exception );
   BOOST_CHECK_THROW( h2d_post_dispute( *this, mallory_id, mallory_private_key, oid, carol_id,
         accused, 0, h2d_evidence( "depth2" ) ), fc::exception );

   // Depth 2: outer's active authority names mallory, and mallory names dave,
   // who sits on the vault. Two hops is inside the bounded walk, so this is
   // still the vault's own circle challenging itself.
   account_update_operation oop;
   oop.account = outer_id;
   oop.active = authority( 1, public_key_type( outer_private_key.get_public_key() ), 1,
                           mallory_id, 1 );
   signed_transaction otx;
   otx.operations.push_back( oop );
   db.current_fee_schedule().set_fee( otx.operations.back() );
   set_expiration( db, otx );
   otx.sign( outer_private_key, db.get_chain_id() );
   PUSH_TX( db, otx );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, outer_id, outer_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "depth2" ) ), fc::exception );

   // Depth 3 stays out of reach: ex names why, why names zed, zed names dave.
   // The bounded walk stops after two hops, so dave is never visited from ex
   // and the challenge posts fine. This is the walk bound made visible: move
   // any link one hop closer and it refuses.
   auto h2d_link_active = [&]( account_id_type who, const fc::ecc::private_key& key,
                               account_id_type member )
   {
      account_update_operation lop;
      lop.account = who;
      lop.active = authority( 1, public_key_type( key.get_public_key() ), 1, member, 1 );
      signed_transaction ltx;
      ltx.operations.push_back( lop );
      db.current_fee_schedule().set_fee( ltx.operations.back() );
      set_expiration( db, ltx );
      ltx.sign( key, db.get_chain_id() );
      PUSH_TX( db, ltx );
   };
   h2d_link_active( why_id, why_private_key, zed_id );
   h2d_link_active( zed_id, zed_private_key, dave_id );
   h2d_link_active( ex_id, ex_private_key, why_id );
   const vault_challenge_id_type ok = h2d_post_challenge(
         *this, ex_id, ex_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "depth3-ok" ) );
   BOOST_CHECK_EQUAL( ok( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( fast_reject_forfeits_fully_with_exact_split )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

    // Bob opens; carol declines to feed the escalation, so bob climbs the
    // ladder himself one rung at a time. Skipping straight to round 3 with a
    // doubled-twice bond is refused: the ladder must be climbed in order.
    const oracle_dispute_id_type did = h2d_post_dispute(
          *this, bob_id, bob_private_key, oid, carol_id, accused, 0, h2d_evidence( "spam" ) );
    BOOST_CHECK_THROW( h2d_escalate( *this, bob_id, bob_private_key, did,
          H2D_ROUND1_RAW * 4, H2D_FLOOR_USD_CENTS * 4 ), fc::exception );
   h2d_escalate( *this, bob_id, bob_private_key, did,
                 H2D_ROUND1_RAW * 2, H2D_FLOOR_USD_CENTS * 2 );
   h2d_escalate( *this, bob_id, bob_private_key, did,
                 H2D_ROUND1_RAW * 4, H2D_FLOOR_USD_CENTS * 4 );
   BOOST_CHECK_EQUAL( did( db ).round, 3u );

   // Forfeit math, in integers: 80% burn, 15% pool, remainder finder capped at
   // $83.75. Bob's total exposure is 7x base ($5,862.50), so the 5% remainder
   // ($293.13) hits the cap and the excess burns.
   const int64_t total_raw = ( did( db ).challenger_bonds ).value;
   const uint64_t total_usd = H2D_FLOOR_USD_CENTS * 7;
   const int64_t burn_expect = total_raw * 8000 / 10000;
   const int64_t pool_expect = total_raw * 1500 / 10000;
   int64_t finder_expect = total_raw - burn_expect - pool_expect;
   const uint64_t finder_usd = total_usd * uint64_t( finder_expect ) / uint64_t( total_raw );
   BOOST_REQUIRE( finder_usd > H2D_FINDER_CAP_USD_CENTS );
   finder_expect = finder_expect * int64_t( H2D_FINDER_CAP_USD_CENTS ) / int64_t( finder_usd );
   const int64_t burn_capped = total_raw - pool_expect - finder_expect;

   const share_type supply_before = db.get_core_dynamic_data().current_supply;

   // Every genesis voter needs fee money; the decisive voter's balance is
   // tracked exactly (finder receipt minus the vote fee captured below).
   const uint64_t need = h2d_vote_threshold( *this );
   const string decisive_name = string( "init" ) + fc::to_string( need - 1 );
   for( uint64_t i = 0; i < need; ++i )
      fund( get_account( string( "init" ) + fc::to_string( i ) ), asset( 1000000 ) );
   const share_type decisive_before =
         db.get_balance( get_account( decisive_name ).get_id(), asset_id_type() ).amount;

   // One vote short of the supermajority: still open. The decisive vote is
   // built inline so its fee is known exactly.
   for( uint64_t i = 0; i + 1 < need; ++i )
      h2d_vote( *this, get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                init_account_priv_key, object_id_type( did ),
                GRAPHENE_H2_DISPUTE_FAST_REJECT );
   BOOST_CHECK_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
   challenge_vote_operation dvop;
   dvop.voter = get_account( decisive_name ).get_id();
   dvop.target = object_id_type( did );
   dvop.decision = GRAPHENE_H2_DISPUTE_FAST_REJECT;
   graphene::protocol::operation dop = dvop;
   db.current_fee_schedule().set_fee( dop );
   const share_type decisive_fee = dop.get<challenge_vote_operation>().fee.amount;
   signed_transaction dtx;
   dtx.operations.push_back( dop );
   set_expiration( db, dtx );
   dtx.sign( init_account_priv_key, db.get_chain_id() );
   PUSH_TX( db, dtx );

   BOOST_CHECK_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_FAST_REJECTED );
   BOOST_CHECK_EQUAL( oid( db ).open_disputes, 0u );
   BOOST_CHECK( db.get_core_dynamic_data().current_supply == supply_before - burn_capped );
   BOOST_CHECK( oid( db ).forfeit_pool_balance == pool_expect );
   BOOST_CHECK( db.get_balance( get_account( decisive_name ).get_id(), asset_id_type() ).amount
                == decisive_before - decisive_fee + finder_expect );

   // Settled challenges take no more votes, and double votes never counted.
   BOOST_CHECK_THROW( h2d_vote( *this, get_account( "init2" ).get_id(), init_account_priv_key,
         object_id_type( did ), GRAPHENE_H2_DISPUTE_EXONERATE ), fc::exception );
   // Non-committee accounts cannot vote.
   BOOST_CHECK_THROW( h2d_vote( *this, bob_id, bob_private_key,
         object_id_type( did ), GRAPHENE_H2_DISPUTE_EXONERATE ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( cooldown_and_concurrency_are_enforced )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   fund( dave, asset( 3000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

    // Time jumps land at most one maintenance (at the landing block) on the
    // fixed 24h grid, so each jump below is placed to either stay inside a
    // live window or sweep exactly the intended expired challenge.
    generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 600 );
    generate_block();
    const fc::time_point_sec grid = db.get_dynamic_global_properties().next_maintenance_time - 86400;

   // C1 opens; the pair goes quiet for 24h.
   const vault_challenge_id_type c1 = h2d_post_challenge(
         *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "c1" ) );
   const fc::time_point_sec t1 = c1( db ).opened;
   BOOST_REQUIRE( t1 > grid && t1 < grid + 86400 );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, carol_id, carol_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "too-soon" ) ), fc::exception );

   generate_blocks( t1 + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC + 3600 );
   generate_block();
   const vault_challenge_id_type c2 = h2d_post_challenge(
         *this, carol_id, carol_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "c2" ) );
   const fc::time_point_sec t2 = c2( db ).opened;
   BOOST_CHECK_EQUAL( vid( db ).open_challenges, 2u );
   BOOST_CHECK_THROW( h2d_post_challenge( *this, dave_id, dave_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "too-soon-2" ) ), fc::exception );

    // C3 opens with C1's 48h deadline already past. A 25h time jump always
    // crosses the 24h maintenance grid, so the landing block's maintenance
    // sweep expires C1 first and frees its slot: three natural opens can never
    // be concurrent (24h spacing x 2 gaps lands the third past the 48h
    // window), which is exactly why the cap-3 guard below is headroom. C3
    // posts into the freed slot, on the now frozen vault: halting mints never
    // blocks new challenges.
    generate_blocks( t2 + GRAPHENE_H2_DISPUTE_COOLDOWN_SEC + 3600 );
    generate_block();
    BOOST_REQUIRE_EQUAL( c1( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
    BOOST_CHECK_EQUAL( vid( db ).open_challenges, 1u );
    const vault_challenge_id_type c3 = h2d_post_challenge(
          *this, dave_id, dave_private_key, vid,
          H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "c3" ) );
    BOOST_CHECK_EQUAL( vid( db ).open_challenges, 2u );
    // V-08 headroom coverage (not natural reach): the 24h-cooldown x 48h-window
    // arithmetic above proves three natural opens can never be concurrent
    // (24h spacing x 2 gaps lands the third past the 48h window), so the
    // cap-3 refusal branch is exercised by forcing the counter to the cap
    // directly. The natural path proves the counter tracks opens and sweeps;
    // the forced state proves the guard refuses above the cap. Do NOT claim
    // natural cap-3 coverage: this is headroom pinning only. A natural-reach
    // variant would need a shortened test window (out of scope here).
    // The concurrency gate fires before the cooldown gate (capacity is the harder
    // constraint), so the refusal names it. The counter is restored after.
    db.modify( vid( db ), []( vault_object& v ) {
       v.open_challenges = GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR;
    } );
    try {
       h2d_post_challenge( *this, bob_id, bob_private_key, vid,
             H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "c4-full" ) );
       BOOST_FAIL( "fourth concurrent challenge posted above the cap" );
    } catch( const fc::exception& e ) {
       // what() carries only the generic code name; the guard's message lives
       // in the detail stack.
       BOOST_CHECK( e.to_detail_string().find( "concurrent" ) != std::string::npos );
    }
    db.modify( vid( db ), []( vault_object& v ) {
       v.open_challenges = 2;
    } );

    // C2's deadline passes next: jumping past it sweeps C2 and frees its
    // slot, but the 24h cooldown from C3's open still bars the door; once it
    // lapses, C4 posts (on the now frozen vault: halting mints never blocks
    // new challenges).
    generate_blocks( c2( db ).deadline + 86400 );
    generate_block();
    BOOST_REQUIRE_EQUAL( c2( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
    BOOST_CHECK_EQUAL( vid( db ).open_challenges, 1u );
    // The 24h cooldown from C3's open lapsed long before this jump landed, so
    // C4 posts straight into the freed slot (cooldown refusals are already
    // proven twice above: too-soon and too-soon-2).
    const vault_challenge_id_type c4 = h2d_post_challenge(
          *this, bob_id, bob_private_key, vid,
          H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "c4" ) );
    BOOST_CHECK_EQUAL( c4( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( release_is_blocked_by_an_open_dispute )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );

   vesting_balance_create_operation vop;
   vop.creator = bob_id;
   vop.owner   = bob_id;
   vop.amount  = asset( share_type( int64_t( 1005000 ) * H2D_RAW_PER_USD_CENT ), asset_id_type() );
   vop.policy  = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction vtx;
   vtx.operations.push_back( vop );
   db.current_fee_schedule().set_fee( vtx.operations.back() );
   set_expiration( db, vtx );
   vtx.sign( bob_private_key, db.get_chain_id() );
   const vesting_balance_id_type vbid {
      PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };

   oracle_bond_lock_operation lop;
   lop.producer        = bob_id;
   lop.oracle          = oid;
   lop.vesting_balance = vbid;
   lop.bond_amount     = share_type( int64_t( 1005000 ) * H2D_RAW_PER_USD_CENT );
   lop.bond_usd_cents  = 1005000;
   signed_transaction ltx;
   ltx.operations.push_back( lop );
   db.current_fee_schedule().set_fee( ltx.operations.back() );
   set_expiration( db, ltx );
   ltx.sign( bob_private_key, db.get_chain_id() );
   const producer_bond_id_type pbid {
      PUSH_TX( db, ltx ).operation_results.front().get<object_id_type>() };

   // An early publication seeds retained history (and pushes the advancing
   // unlock a day out, which the test reads live below rather than assuming).
   generate_blocks( db.head_block_time() + 3600 );
   generate_block();
   h2d_publish( *this, oid, bob_id, bob_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // A day before the unlock, carol disputes bob's print. The release attempt
   // lands an hour past the unlock — a full day inside the dispute window, so
   // no maintenance grid alignment can sweep it first.
   generate_blocks( pbid( db ).unlock_time - 86400 );
   generate_block();
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, carol_id, carol_private_key, oid, bob_id, accused, 0,
         h2d_evidence( "release-block" ) );
   generate_blocks( pbid( db ).unlock_time + 3600 );
   generate_block();
   BOOST_REQUIRE( did( db ).state == GRAPHENE_H2_CHALLENGE_OPEN );

   oracle_bond_release_operation rel;
   rel.producer = bob_id;
   rel.bond     = pbid;
   signed_transaction rtx;
   rtx.operations.push_back( rel );
   db.current_fee_schedule().set_fee( rtx.operations.back() );
   set_expiration( db, rtx );
   rtx.sign( bob_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, rtx ), fc::exception );

   // Once the dispute expires with no votes, the gate lifts and release proceeds.
   generate_blocks( did( db ).round_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   signed_transaction rtx2;
   rtx2.operations.push_back( rel );
   db.current_fee_schedule().set_fee( rtx2.operations.back() );
   set_expiration( db, rtx2 );
   rtx2.sign( bob_private_key, db.get_chain_id() );
   PUSH_TX( db, rtx2 );
   BOOST_CHECK( db.find( pbid ) == nullptr );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( vault_register_rejects_non_bts_bond_assets )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice) );
   fund( alice );

    asset_create_operation aop;
    aop.issuer = alice_id;
    aop.symbol = "TEST";
    aop.precision = 5;
    aop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
    aop.common_options.market_fee_percent = 0;
    aop.common_options.flags = 0;
    aop.common_options.issuer_permissions = 0;
    aop.common_options.core_exchange_rate = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   signed_transaction atx;
   atx.operations.push_back( aop );
   db.current_fee_schedule().set_fee( atx.operations.back() );
   set_expiration( db, atx );
   atx.sign( alice_private_key, db.get_chain_id() );
   const asset_id_type test_id {
      PUSH_TX( db, atx ).operation_results.front().get<object_id_type>() };

   // The bond-asset allow-list is BTS-only at genesis: registration naming any
   // other asset is refused, at validate time.
   vault_register_operation rop;
   rop.registrar            = alice_id;
   rop.pair                 = test_id;
   rop.vault_authority      = authority( 1, alice_id, 1 );
   rop.min_bond             = share_type( 1340000LL * H2D_RAW_PER_USD_CENT );
   rop.min_bond_usd_cents   = 1340000;
   rop.bond_asset           = test_id;
   rop.secure_ratio_bps     = 20000;
   rop.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( rop );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   GRAPHENE_REQUIRE_THROW( PUSH_TX( db, tx ), fc::exception );

   rop.bond_asset = asset_id_type();
   signed_transaction tx2;
   tx2.operations.push_back( rop );
   db.current_fee_schedule().set_fee( tx2.operations.back() );
   set_expiration( db, tx2 );
   tx2.sign( alice_private_key, db.get_chain_id() );
   PUSH_TX( db, tx2 );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( exonerate_forfeits_challenger_and_returns_defender )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // Bob disputes carol's print; carol answers by escalating (2x base on her
   // side). The committee deliberates and exonerates: bob was wrong.
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0, h2d_evidence( "wrong" ) );
   h2d_escalate( *this, carol_id, carol_private_key, did,
                 H2D_ROUND1_RAW * 2, H2D_FLOOR_USD_CENTS * 2 );
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;

   // Base-size forfeit: 80/15/remainder with the remainder (~5% = $41.88)
   // under the $83.75 cap, so no capping burn happens here.
   const int64_t base_raw = H2D_ROUND1_RAW.value;
   const int64_t burn_expect = base_raw * 8000 / 10000;
   const int64_t pool_expect = base_raw * 1500 / 10000;
   const int64_t finder_expect = base_raw - burn_expect - pool_expect;
   const share_type supply_before = db.get_core_dynamic_data().current_supply;

   const uint64_t need = h2d_vote_threshold( *this );
   const string decisive_name = string( "init" ) + fc::to_string( need - 1 );
   for( uint64_t i = 0; i < need; ++i )
      fund( get_account( string( "init" ) + fc::to_string( i ) ), asset( 1000000 ) );
   const share_type decisive_before =
         db.get_balance( get_account( decisive_name ).get_id(), asset_id_type() ).amount;
   for( uint64_t i = 0; i + 1 < need; ++i )
      h2d_vote( *this, get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                init_account_priv_key, object_id_type( did ),
                GRAPHENE_H2_DISPUTE_EXONERATE );
   challenge_vote_operation dvop;
   dvop.voter = get_account( decisive_name ).get_id();
   dvop.target = object_id_type( did );
   dvop.decision = GRAPHENE_H2_DISPUTE_EXONERATE;
   graphene::protocol::operation dop = dvop;
   db.current_fee_schedule().set_fee( dop );
   const share_type decisive_fee = dop.get<challenge_vote_operation>().fee.amount;
   signed_transaction dtx;
   dtx.operations.push_back( dop );
   set_expiration( db, dtx );
   dtx.sign( init_account_priv_key, db.get_chain_id() );
   PUSH_TX( db, dtx );

   // Loser pays: bob's base forfeits through the split, carol's escalation
   // bond returns in full, the oracle keeps promoting (no freeze on acquittal).
   BOOST_CHECK_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXONERATED );
   BOOST_CHECK( db.get_core_dynamic_data().current_supply == supply_before - burn_expect );
   BOOST_CHECK( oid( db ).forfeit_pool_balance == pool_expect );
   BOOST_CHECK( db.get_balance( get_account( decisive_name ).get_id(), asset_id_type() ).amount
                == decisive_before - decisive_fee + finder_expect );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount >= carol_before );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).open_disputes, 0u );

   // A settled dispute takes no more votes.
   BOOST_CHECK_THROW( h2d_vote( *this, get_account( "init2" ).get_id(), init_account_priv_key,
         object_id_type( did ), GRAPHENE_H2_DISPUTE_SUSTAIN ), fc::exception );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( sustain_freezes_vault_and_returns_challenger )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "CORE.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2d_register_vault( *this, alice_id, alice_private_key, vault_auth );

   // Bob's challenge is upheld: the vault freezes (mints halt, redemptions
   // continue) and his whole bond returns — vindication costs him only fees.
   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   const vault_challenge_id_type cid = h2d_post_challenge(
         *this, bob_id, bob_private_key, vid,
         H2D_ROUND1_RAW, H2D_FLOOR_USD_CENTS, h2d_evidence( "real-theft" ) );
   const uint64_t need = h2d_vote_threshold( *this );
   for( uint64_t i = 0; i < need; ++i )
      h2d_vote( *this, get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                init_account_priv_key, object_id_type( cid ),
                GRAPHENE_H2_DISPUTE_SUSTAIN );
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( vid( db ).open_challenges, 0u );
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount > bob_before - H2D_ROUND1_RAW );

    // A second dispute's window closes unvoted: late votes are refused even
    // before the sweep runs, then the sweep expires it. Alignment is exact:
    // posting 12h past a maintenance grid point puts the 48h deadline (an
    // exact multiple of the 24h grid spacing) 12h past its own grid point, so
    // the two 1h hops straddling the deadline cross no grid point at all and
    // no sweep can interleave before the refused vote.
    generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 12 * 3600 );
    generate_block();
    const oracle_dispute_id_type late = h2d_post_dispute(
          *this, bob_id, bob_private_key, oid, carol_id, accused, 0, h2d_evidence( "late" ) );
    generate_blocks( late( db ).round_deadline - 3600 );
    generate_block();
    generate_blocks( late( db ).round_deadline + 3600 );
    generate_block();
   BOOST_REQUIRE_EQUAL( late( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
   BOOST_REQUIRE( db.head_block_time() > late( db ).round_deadline );
   BOOST_CHECK_THROW( h2d_vote( *this, get_account( "init0" ).get_id(), init_account_priv_key,
         object_id_type( late ), GRAPHENE_H2_DISPUTE_EXONERATE ), fc::exception );
   generate_blocks( late( db ).round_deadline + 2 * 86400 );
   generate_block();
   BOOST_CHECK_EQUAL( late( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
} FC_LOG_AND_RETHROW() }

/// R-02: owner oracle_update MUST NOT clear `frozen` while the oracle has
/// open disputes OR the freeze was challenge-set (sustain/expiry). The
/// committee oracle_unfreeze op clears after resolution; slash stays
/// flag-only (slashed=true, no seizure here — follow-on phase).
BOOST_AUTO_TEST_CASE( owner_cannot_clear_sustain_freeze_committee_unfreezes )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "R02.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // Bob disputes carol's print; the committee sustains: frozen, slashed flag.
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0,
         h2d_evidence( "r02-sustain" ) );
   const uint64_t need = h2d_vote_threshold( *this );
   for( uint64_t i = 0; i < need; ++i )
      h2d_vote( *this, get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
                init_account_priv_key, object_id_type( did ),
                GRAPHENE_H2_DISPUTE_SUSTAIN );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 0u );

   // Owner clear refused: challenge-set freeze (sustained terminal history).
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = oid;
      oracle_options live = oid( db ).options;
      live.frozen = false;
      uop.new_options = live;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
      BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   }

   // Non-committee unfreeze refused.
   {
      oracle_unfreeze_operation uop;
      uop.unfreezer = bob_id;
      uop.oracle    = oid;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
      BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   }

   // Committee path clears after resolution (open==0, sustained history present).
   {
      oracle_unfreeze_operation uop;
      uop.unfreezer = alice_id;
      uop.oracle    = oid;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
   }

   // Slash stays flag-only: bond marked slashed, no seizure built here.
   // (No bond was locked in this vector; the flag path is covered by the
   // sustain resolution above. Seizure is an explicit follow-on phase.)
} FC_LOG_AND_RETHROW() }

/// R-02 expiry + open-dispute legs: owner clear refused with an open dispute
/// and after an expiry freeze; committee unfreezes only after resolution.
BOOST_AUTO_TEST_CASE( owner_cannot_clear_open_or_expiry_freeze )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2d_make_committee_member( *this, alice );
   const auto bts_ref = h2d_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2d_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2d_make_oracle( *this, alice_id, alice_private_key, "R02X.USD", bts_ref, usd_ref, opts );
   h2d_publish( *this, oid, carol_id, carol_private_key, 100 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   // Owner freezes first (Track A path, no disputes: allowed).
   {
      oracle_update_operation fop;
      fop.owner     = alice_id;
      fop.oracle_id = oid;
      oracle_options frozen = oid( db ).options;
      frozen.frozen = true;
      fop.new_options = frozen;
      signed_transaction tx; tx.operations.push_back( fop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );
   }

   // Open dispute lands: owner clear now refused (open>0), committee
   // unfreeze also refused until resolution.
   const oracle_dispute_id_type did = h2d_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0,
         h2d_evidence( "r02-open" ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_OPEN );
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = oid;
      oracle_options live = oid( db ).options;
      live.frozen = false;
      uop.new_options = live;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      oracle_unfreeze_operation uop;
      uop.unfreezer = alice_id;
      uop.oracle    = oid;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   // Let it expire with no votes: EXPIRED_FROZEN, still frozen.
   generate_blocks( did( db ).round_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );

   // Owner still refused (challenge-set expiry history); committee clears.
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = oid;
      oracle_options live = oid( db ).options;
      live.frozen = false;
      uop.new_options = live;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   {
      oracle_unfreeze_operation uop;
      uop.unfreezer = alice_id;
      uop.oracle    = oid;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
   }
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
