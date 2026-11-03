/*
 * R7C-H2: E-02 mempool smuggling fuzz + zero-fee floors cover.
 *
 * E-02 model (db_block.cpp:787-798): two central layers pin every H2 op
 * (tags 83-98) pre-fork -- (1) the proposal_operation_hardfork_visitor
 * refuses leg-dark ops at proposal CREATION, (2) the per-evaluator
 * h2_require_* gates refuse them at EXECUTION (proposals funnel through the
 * same apply path, so arrival route cannot matter). This suite fuzzes every
 * entry point pre-fork:
 *   (a) PROPOSE: each op nested in a proposal_create_operation -> refused.
 *   (b) PUSH: each op pushed directly (mempool path) -> refused.
 *   (c) VOTE/TRIGGER: the committee vote op, committee-signed trigger ops
 *       (resolve/freeze/unfreeze/verify), and the fee-schedule pricing vote
 *       (E-01) -> refused pre-leg.
 *
 * Gate attribution (the load-bearing rule): every push carries a sufficient
 * fee (set_fee) from a funded, correctly-signed payer, and every op is
 * validate()-clean, so validate/authority/fee checks all PASS and the ONLY
 * remaining refusal is the hardfork gate. Each refusal's message must name
 * the H2 gate ("H2" + "hardfork"/"activation"); any other refusal is a test
 * construction bug (fail the test, never the gate), and any ACCEPTANCE is a
 * Critical consensus finding (fix the gate, report loudly).
 *
 * Zero-fee floors (E-06/T-06): pins every H2 (83-98) and H1-oracle (78-82)
 * fee_params_t default. All H2 defaults are already nonzero; the single zero
 * (oracle_delete, op 80) is justified in place (oracle.hpp:465): owner-only
 * cleanup matching the chain-wide delete/cancel precedent, refused while
 * referenced, each deletable oracle costing 500 BTS to create -- spam is
 * bounded by creation, so a fee would only tax hygiene. No default moves in
 * this task; the E-01 pricing-vote refusal is re-pinned unchanged.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/proposal_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/committee_member.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/operations.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {

// Pilot basis inherited from H2a-H2d: 1e6 raw BTS units per USD cent.
constexpr int64_t H2M_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2M_VAULT_USD_CENTS = 1340000; // $13,400 vault min_bond
constexpr uint64_t H2M_FLOOR_USD_CENTS = 83750;   // $837.50 challenge floor
const share_type H2M_VAULT_RAW =
      share_type( int64_t( H2M_VAULT_USD_CENTS ) * H2M_RAW_PER_USD_CENT );
const share_type H2M_ROUND1_RAW =
      share_type( int64_t( H2M_FLOOR_USD_CENTS ) * H2M_RAW_PER_USD_CENT );

string h2m_evidence( const string& tag )
{ return string( "evidence:smuggle-" ) + tag; }

void h2m_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

/// Pushes tx; returns the refusal text, or "" on ACCEPTANCE (Critical).
static std::string h2m_try_push( database& db, signed_transaction& tx )
{
   try { PUSH_TX( db, tx ); }
   catch ( const fc::exception& e ) { return e.to_string(); }
   catch ( const std::exception& e ) { return std::string( "std::exception: " ) + e.what(); }
   return std::string();
}

/// True only for the H2 activation gates (never validate/fee/authority text).
static bool h2m_is_h2_gate( const std::string& msg )
{
   return msg.find( "H2" ) != std::string::npos
       && ( msg.find( "hardfork" ) != std::string::npos
         || msg.find( "activation" ) != std::string::npos );
}

/// All 16 H2 ops (tags 83-98), validate-clean, fee payer = alice throughout.
/// Gate fires first in every evaluator, so existence fields may dangle.
static std::vector<std::pair<const char*, operation>>
h2m_all_ops( account_id_type alice_id, fc::time_point_sec now )
{
   std::vector<std::pair<const char*, operation>> v;

   {  vault_register_operation op;                       // 83 gateway
      op.registrar            = alice_id;
      op.pair                 = asset_id_type();
      op.vault_authority      = authority( 1, alice_id, 1 );
      op.min_bond             = H2M_VAULT_RAW;
      op.min_bond_usd_cents   = H2M_VAULT_USD_CENTS;
      op.bond_asset           = asset_id_type();
      op.secure_ratio_bps     = 20000;
      op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
      v.emplace_back( "83 vault_register", operation( op ) ); }
   {  vault_bond_lock_operation op;                      // 84 gateway
      op.owner           = alice_id;
      op.vault           = vault_id_type( 0 );
      op.vesting_balance = vesting_balance_id_type( 0 );
      op.bond_amount     = H2M_VAULT_RAW;
      op.bond_usd_cents  = H2M_VAULT_USD_CENTS;
      v.emplace_back( "84 vault_bond_lock", operation( op ) ); }
   {  oracle_bond_lock_operation op;                     // 85 price
      op.producer        = alice_id;
      op.oracle          = oracle_id_type( 0 );
      op.vesting_balance = vesting_balance_id_type( 0 );
      op.bond_amount     = H2M_ROUND1_RAW;
      op.bond_usd_cents  = GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS;
      v.emplace_back( "85 oracle_bond_lock", operation( op ) ); }
   {  oracle_bond_release_operation op;                  // 86 price
      op.producer = alice_id;
      op.bond     = producer_bond_id_type( 0 );
      v.emplace_back( "86 oracle_bond_release", operation( op ) ); }
   {  vault_challenge_operation op;                      // 87 primitives
      op.challenger               = alice_id;
      op.vault                    = vault_id_type( 0 );
      op.challenge_bond           = H2M_ROUND1_RAW;
      op.challenge_bond_usd_cents = H2M_FLOOR_USD_CENTS;
      op.evidence_memo            = h2m_evidence( "challenge" );
      v.emplace_back( "87 vault_challenge", operation( op ) ); }
   {  oracle_dispute_operation op;                       // 88 primitives
      op.challenger            = alice_id;
      op.oracle                = oracle_id_type( 0 );
      op.defender              = alice_id;
      op.accused_time          = now;
      op.accused_series        = 0;
      op.dispute_bond          = H2M_ROUND1_RAW;
      op.dispute_bond_usd_cents = H2M_FLOOR_USD_CENTS;
      op.evidence_memo         = h2m_evidence( "dispute" );
      v.emplace_back( "88 oracle_dispute", operation( op ) ); }
   {  oracle_dispute_escalate_operation op;              // 89 primitives
      op.escalator              = alice_id;
      op.dispute                = oracle_dispute_id_type( 0 );
      op.round_bond             = H2M_ROUND1_RAW * 2;
      op.round_bond_usd_cents   = H2M_FLOOR_USD_CENTS * 2;
      v.emplace_back( "89 oracle_dispute_escalate", operation( op ) ); }
   {  challenge_vote_operation op;                       // 90 primitives
      op.voter    = alice_id;
      op.target   = object_id_type( vault_challenge_id_type( 0 ) );
      op.decision = 0;
      v.emplace_back( "90 challenge_vote", operation( op ) ); }
   {  vault_rotate_operation op;                         // 91 gateway
      op.rotator       = alice_id;
      op.vault         = vault_id_type( 0 );
      op.new_authority = authority( 1, alice_id, 1 );
      v.emplace_back( "91 vault_rotate", operation( op ) ); }
   {  vault_bond_release_operation op;                   // 92 gateway
      op.owner = alice_id;
      op.bond  = vault_bond_id_type( 0 );
      v.emplace_back( "92 vault_bond_release", operation( op ) ); }
   {  vault_resolve_operation op;                        // 93 price
      op.resolver  = alice_id;
      op.challenge = vault_challenge_id_type( 0 );
      v.emplace_back( "93 vault_resolve", operation( op ) ); }
   {  pair_freeze_operation op;                          // 94 price
      op.freezer = alice_id;
      op.vault   = vault_id_type( 0 );
      op.oracle  = oracle_id_type( 0 );
      v.emplace_back( "94 pair_freeze", operation( op ) ); }
   {  winddown_claim_operation op;                       // 95 price
      op.claimant     = alice_id;
      op.winddown     = winddown_vault_id_type( 0 );
      op.claim_amount = share_type( 1000000 );
      op.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
      v.emplace_back( "95 winddown_claim", operation( op ) ); }
   {  oracle_fallback_set_operation op;                  // 96 price
      op.owner  = alice_id;
      op.oracle = oracle_id_type( 0 );
      v.emplace_back( "96 oracle_fallback_set", operation( op ) ); }
   {  oracle_unfreeze_operation op;                      // 97 price
      op.unfreezer = alice_id;
      op.oracle    = oracle_id_type( 0 );
      v.emplace_back( "97 oracle_unfreeze", operation( op ) ); }
   {  seasoning_verify_operation op;                     // 98 price
      op.verifier = alice_id;
      op.pair     = asset_id_type( 0 );
      v.emplace_back( "98 seasoning_verify", operation( op ) ); }

   return v;
}

/// Committee fee-schedule proposal shape (E-01 pattern, htlc hardfork-test
/// lineage): unsigned, temp-account payer, inner schedule under test.
static proposal_create_operation h2m_fee_proposal( database& db )
{
   const chain_parameters& existing = db.get_global_properties().parameters;
   std::shared_ptr<fee_schedule> new_fees = std::make_shared<fee_schedule>();
   new_fees->scale = existing.current_fees->scale;
   new_fees->parameters = existing.current_fees->parameters;
   proposal_create_operation cop = proposal_create_operation::committee_proposal(
         db.get_global_properties().parameters, db.head_block_time() );
   cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
   cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
   committee_member_update_global_parameters_operation uop;
   chain_parameters new_params = db.get_global_properties().parameters;
   new_params.current_fees = new_fees;
   uop.new_parameters = new_params;
   cop.proposed_ops.emplace_back( uop );
   return cop;
}

/// Pushes a committee fee-schedule vote naming exactly @p sched; returns the
/// refusal text, or "" on acceptance.
static std::string h2m_try_fee_vote( database& db, std::shared_ptr<fee_schedule> sched )
{
   proposal_create_operation cop = proposal_create_operation::committee_proposal(
         db.get_global_properties().parameters, db.head_block_time() );
   cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
   cop.expiration_time = db.head_block_time() + *cop.review_period_seconds + 10;
   committee_member_update_global_parameters_operation uop;
   chain_parameters new_params = db.get_global_properties().parameters;
   new_params.current_fees = sched;
   uop.new_parameters = new_params;
   cop.proposed_ops.emplace_back( uop );
   signed_transaction tx;
   tx.operations.push_back( cop );
   set_expiration( db, tx );
   return h2m_try_push( db, tx );
}

/// Empty fee schedule shell (scale copied); callers insert exactly the
/// fee_params_t entries under test. Partial schedules are consensus-legal
/// (fee_schedule::validate is a no-op), and every legacy exists<> check
/// passes vacuously on them, so an H2 gate firing is attributable.
static std::shared_ptr<fee_schedule> h2m_partial_fees( database& db )
{
   auto sched = std::make_shared<fee_schedule>();
   sched->scale = db.get_global_properties().parameters.current_fees->scale;
   return sched;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_mempool_tests, database_fixture )

/// E-02 column (a): every H2 op nested in a proposal is refused at proposal
/// creation pre-fork (proposal_operation_hardfork_visitor leg gates).
BOOST_AUTO_TEST_CASE( h2_all_ops_refused_at_propose_pre_fork )
{ try {
   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );

   auto ops = h2m_all_ops( alice_id, db.head_block_time() );
   BOOST_REQUIRE_EQUAL( ops.size(), 16u );
   uint32_t gate_refusals = 0;
   for( const auto& named : ops )
   {
      proposal_create_operation prop;
      prop.fee_paying_account = alice_id;
      prop.proposed_ops.emplace_back( named.second );
      prop.expiration_time = db.head_block_time() + fc::days( 1 );
      signed_transaction tx;
      tx.operations.push_back( prop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      const std::string outcome = h2m_try_push( db, tx );
      BOOST_CHECK_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02): pre-fork PROPOSE of " << named.first << " was ACCEPTED" );
      if( outcome.empty() )
         continue;
      BOOST_CHECK_MESSAGE( h2m_is_h2_gate( outcome ),
            "Pre-fork PROPOSE of " << named.first
            << " refused off-gate (test bug, not gate proof): " << outcome );
      if( h2m_is_h2_gate( outcome ) )
         ++gate_refusals;
   }
   BOOST_CHECK_EQUAL( gate_refusals, 16u );
} FC_LOG_AND_RETHROW() }

/// E-02 column (b): every H2 op pushed directly (mempool path) is refused
/// pre-fork (evaluator h2_require_* gates). Fees set + funded + signed, so
/// the gate is the only possible refusal.
BOOST_AUTO_TEST_CASE( h2_all_ops_refused_at_push_pre_fork )
{ try {
   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );

   auto ops = h2m_all_ops( alice_id, db.head_block_time() );
   BOOST_REQUIRE_EQUAL( ops.size(), 16u );
   uint32_t gate_refusals = 0;
   for( const auto& named : ops )
   {
      signed_transaction tx;
      tx.operations.push_back( named.second );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      const std::string outcome = h2m_try_push( db, tx );
      BOOST_CHECK_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02): pre-fork PUSH of " << named.first << " was ACCEPTED" );
      if( outcome.empty() )
         continue;
      BOOST_CHECK_MESSAGE( h2m_is_h2_gate( outcome ),
            "Pre-fork PUSH of " << named.first
            << " refused off-gate (test bug, not gate proof): " << outcome );
      if( h2m_is_h2_gate( outcome ) )
         ++gate_refusals;
   }
   BOOST_CHECK_EQUAL( gate_refusals, 16u );
} FC_LOG_AND_RETHROW() }

/// E-02 column (c): vote and trigger entry points are refused pre-fork --
/// the committee vote op itself, committee-AUTHORIZED trigger pushes (a
/// seated member's signature must not open a leg-dark path), and the
/// fee-schedule pricing vote per leg (E-01 leg matrix over H2-only partial
/// schedules, so each refusal names its H2 leg).
BOOST_AUTO_TEST_CASE( h2_vote_and_trigger_paths_refused_pre_fork )
{ try {
   ACTORS( (alice) );
   fund( alice, asset( 5000000000000LL ) );
   h2m_make_committee_member( *this, alice );

   // Vote path: a committee vote on a challenge target, pre-primitives.
   {
      challenge_vote_operation vop;
      vop.voter    = alice_id;
      vop.target   = object_id_type( vault_challenge_id_type( 0 ) );
      vop.decision = GRAPHENE_H2_DISPUTE_SUSTAIN;
      signed_transaction tx;
      tx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      const std::string outcome = h2m_try_push( db, tx );
      BOOST_REQUIRE_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02): pre-fork committee VOTE was ACCEPTED" );
      BOOST_CHECK_MESSAGE( h2m_is_h2_gate( outcome ),
            "Pre-fork VOTE refused off-gate: " << outcome );
   }

   // Trigger paths: seated-member-signed execution ops, pre-price.
   std::vector<std::pair<const char*, operation>> triggers;
   {  vault_resolve_operation op;
      op.resolver  = alice_id;
      op.challenge = vault_challenge_id_type( 0 );
      triggers.emplace_back( "93 vault_resolve (committee trigger)", operation( op ) ); }
   {  pair_freeze_operation op;
      op.freezer = alice_id;
      op.vault   = vault_id_type( 0 );
      op.oracle  = oracle_id_type( 0 );
      triggers.emplace_back( "94 pair_freeze (committee trigger)", operation( op ) ); }
   {  oracle_unfreeze_operation op;
      op.unfreezer = alice_id;
      op.oracle    = oracle_id_type( 0 );
      triggers.emplace_back( "97 oracle_unfreeze (committee trigger)", operation( op ) ); }
   {  seasoning_verify_operation op;
      op.verifier = alice_id;
      op.pair     = asset_id_type( 0 );
      triggers.emplace_back( "98 seasoning_verify (committee trigger)", operation( op ) ); }
   uint32_t trigger_refusals = 0;
   for( const auto& named : triggers )
   {
      signed_transaction tx;
      tx.operations.push_back( named.second );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      const std::string outcome = h2m_try_push( db, tx );
      BOOST_CHECK_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02): pre-fork TRIGGER " << named.first << " was ACCEPTED" );
      if( outcome.empty() )
         continue;
      BOOST_CHECK_MESSAGE( h2m_is_h2_gate( outcome ),
            "Pre-fork TRIGGER " << named.first << " refused off-gate: " << outcome );
      if( h2m_is_h2_gate( outcome ) )
         ++trigger_refusals;
   }
   BOOST_CHECK_EQUAL( trigger_refusals, 4u );

   // Pricing-vote path (E-01 leg matrix): H2-only fee schedules refuse with
   // the H2 leg message while the leg is dark. A full genesis schedule would
   // trip earlier legacy fee gates first (htlc/oracle/BSIP40), masking the H2
   // verdict; partial schedules keep legacy exists<> checks vacuous so the H2
   // gate is attributable. Each leg is isolated by advancing time past the
   // earlier legs (BONDS < GATEWAY < PRICE ordering).
   {
      auto sched = h2m_partial_fees( db );
      sched->parameters.insert( vault_challenge_operation::fee_params_t() );
      sched->parameters.insert( oracle_dispute_operation::fee_params_t() );
      sched->parameters.insert( oracle_dispute_escalate_operation::fee_params_t() );
      sched->parameters.insert( challenge_vote_operation::fee_params_t() );
      const std::string outcome = h2m_try_fee_vote( db, sched );
      BOOST_REQUIRE_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02/E-01): pre-bonds challenge-ops fee VOTE was ACCEPTED" );
      BOOST_CHECK_MESSAGE( outcome.find( "H2 bonds hardfork" ) != std::string::npos,
            "Pre-bonds fee VOTE refused off-gate: " << outcome );
   }
   generate_blocks( HARDFORK_H2_BONDS_TIME );
   generate_block();
   {
      auto sched = h2m_partial_fees( db );
      sched->parameters.insert( vault_register_operation::fee_params_t() );
      sched->parameters.insert( vault_bond_lock_operation::fee_params_t() );
      sched->parameters.insert( vault_rotate_operation::fee_params_t() );
      sched->parameters.insert( vault_bond_release_operation::fee_params_t() );
      const std::string outcome = h2m_try_fee_vote( db, sched );
      BOOST_REQUIRE_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02/E-01): pre-gateway vault-ops fee VOTE was ACCEPTED" );
      BOOST_CHECK_MESSAGE( outcome.find( "H2 gateway" ) != std::string::npos,
            "Pre-gateway fee VOTE refused off-gate: " << outcome );
   }
   generate_blocks( HARDFORK_H2_GATEWAY_TIME );
   generate_block();
   {
      auto sched = h2m_partial_fees( db );
      sched->parameters.insert( oracle_bond_lock_operation::fee_params_t() );
      sched->parameters.insert( oracle_bond_release_operation::fee_params_t() );
      sched->parameters.insert( vault_resolve_operation::fee_params_t() );
      sched->parameters.insert( pair_freeze_operation::fee_params_t() );
      sched->parameters.insert( winddown_claim_operation::fee_params_t() );
      sched->parameters.insert( oracle_fallback_set_operation::fee_params_t() );
      sched->parameters.insert( oracle_unfreeze_operation::fee_params_t() );
      sched->parameters.insert( seasoning_verify_operation::fee_params_t() );
      const std::string outcome = h2m_try_fee_vote( db, sched );
      BOOST_REQUIRE_MESSAGE( !outcome.empty(),
            "CRITICAL (E-02/E-01): pre-price price-ops fee VOTE was ACCEPTED" );
      BOOST_CHECK_MESSAGE( outcome.find( "H2 price" ) != std::string::npos,
            "Pre-price fee VOTE refused off-gate: " << outcome );
   }
} FC_LOG_AND_RETHROW() }

/// Zero-fee floors (E-06/T-06): pin every H2 (83-98) and H1-oracle (78-82)
/// fee_params_t default. All H2 defaults are nonzero (committee-sensible:
/// 500 BTS custody-grade, 5 BTS machinery-grade); the single zero
/// (oracle_delete) is justified, not moved -- see oracle.hpp:465. Covering
/// proof that E-01 pre-fork pricing refusal still holds: the same fee vote
/// refused above is admitted once all legs are live.
BOOST_AUTO_TEST_CASE( h2_fee_floors_pinned_and_e01_pricing_refusal_holds )
{ try {
   const uint64_t BTS = GRAPHENE_BLOCKCHAIN_PRECISION; // 1e5 raw per BTS

   // H2 custody-grade (tag 83): 500 BTS + per-kbyte data leg.
   BOOST_CHECK_EQUAL( vault_register_operation::fee_params_t().fee, 500 * BTS );
   BOOST_CHECK_EQUAL( vault_register_operation::fee_params_t().price_per_kbyte, BTS );
   // H2 machinery-grade (tags 84-86, 89-98): 5 BTS each.
   BOOST_CHECK_EQUAL( vault_bond_lock_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_bond_lock_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_bond_release_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_dispute_escalate_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( challenge_vote_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( vault_rotate_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( vault_bond_release_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( vault_resolve_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( pair_freeze_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( winddown_claim_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_fallback_set_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_unfreeze_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( seasoning_verify_operation::fee_params_t().fee, 5 * BTS );
   // H2 evidence-grade (tags 87-88): 5 BTS + per-kbyte evidence leg.
   BOOST_CHECK_EQUAL( vault_challenge_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( vault_challenge_operation::fee_params_t().price_per_kbyte, BTS );
   BOOST_CHECK_EQUAL( oracle_dispute_operation::fee_params_t().fee, 5 * BTS );
   BOOST_CHECK_EQUAL( oracle_dispute_operation::fee_params_t().price_per_kbyte, BTS );

   // H1 oracle ops visible in this tree (tags 78-82): create/update/publish/
   // reference nonzero; delete is the documented zero (oracle.hpp:465).
   BOOST_CHECK_EQUAL( oracle_create_operation::fee_params_t().fee, 500 * BTS );
   BOOST_CHECK_EQUAL( oracle_update_operation::fee_params_t().fee, 50 * BTS );
   BOOST_CHECK_EQUAL( oracle_delete_operation::fee_params_t().fee, 0u );
   BOOST_CHECK_EQUAL( oracle_publish_operation::fee_params_t().fee, BTS / 10 );
   BOOST_CHECK_EQUAL( reference_asset_create_operation::fee_params_t().fee, 500 * BTS );

   // E-01 still holds with these defaults: admitted only once all legs live.
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );
   {
      proposal_create_operation cop = h2m_fee_proposal( db );
      signed_transaction tx;
      tx.operations.push_back( cop );
      set_expiration( db, tx );
      PUSH_TX( db, tx );
   }
   BOOST_CHECK( !db.get_index_type<proposal_index>().indices().empty() );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
